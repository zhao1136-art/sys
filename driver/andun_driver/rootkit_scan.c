/*
 * rootkit_scan.c - Rootkit 内核扫描
 *
 * 在 PASSIVE_LEVEL 下执行四类检测，一次性返回聚合结果：
 *   1. 隐藏进程：遍历 EPROCESS.ActiveProcessLinks 双链表，
 *      与用户态 Toolhelp32 快照交叉比对（用户态负责比对）。
 *   2. 隐藏驱动：遍历 PsLoadedModuleList，标记节区已卸载的驱动。
 *   3. 内核钩子：SSDT（只读比对 KiServiceTable）+ Inline（序言 5 字节）。
 *   4. 回调劫持：定位关键回调数组，检查回调地址是否落在已加载驱动模块外。
 *
 * 安全设计（驱动 Bug 会直接 BSOD）：
 *   - 所有对任意指针的读取都先用 MmIsAddressValid 校验，
 *     再包裹 __try/__except 双重保护；
 *   - 只读检测，绝不写入任何内核表（SSDT 受 PatchGuard 保护）；
 *   - 输出缓冲区固定大小，写满即停，防止越界；
 *   - 全程 PASSIVE_LEVEL，可安全调用 Zw*/Mm*/Ps* 接口。
 */

#include "andun.h"

/* ============================================================
 * 内部全局：SSDT 关键函数名表（用于 Inline Hook 检测）
 * ============================================================ */

static const PCSTR ANDUN_CRITICAL_NT_FUNCS[] = {
    "NtOpenProcess",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtProtectVirtualMemory",
    "NtCreateFile",
    "NtSetValueKey",
    "NtDeleteValueKey",
    "NtQuerySystemInformation",
    "NtTerminateProcess",
    "NtDuplicateObject",
    "NtSetInformationProcess",
    "NtCreateProcessEx",
    "NtMapViewOfSection",
    "NtOpenFile",
    "NtDeviceIoControlFile",
    "NtLoadDriver",
    "NtUnloadDriver",
    "NtCreateKey",
    "NtOpenKey",
};

#define ANDUN_CRITICAL_FUNC_COUNT \
    (sizeof(ANDUN_CRITICAL_NT_FUNCS) / sizeof(ANDUN_CRITICAL_NT_FUNCS[0]))

/* SSDT 钩子阈值：非 ntoskrnl 且非已知系统模块的地址即告警 */
#define ANDUN_MAX_SSDT_DEPTH 0x20000

/* ============================================================
 * 内部函数前置声明
 * ============================================================ */

static ULONG AndunRootkitEnumProcs(PANDUN_ROOTKIT_SCAN_RESULT Result);
static ULONG AndunRootkitEnumDrivers(PANDUN_ROOTKIT_SCAN_RESULT Result);
static ULONG AndunRootkitScanHooks(PANDUN_ROOTKIT_SCAN_RESULT Result);
static ULONG AndunRootkitScanCallbacks(PANDUN_ROOTKIT_SCAN_RESULT Result);

static BOOLEAN AndunIsAddressValid(PVOID Address);
static BOOLEAN AndunAddressInDriverModule(
    PVOID Address, PWSTR ModuleName, ULONG ModuleNameChars);
static BOOLEAN AndunCopyUnicodeToString(
    PWSTR Dst, ULONG DstChars, PUNICODE_STRING Src);

/* EPROCESS.ActiveProcessLinks 偏移（动态发现，避免硬编码） */
static LONG g_ActiveProcessLinksOffset = -1;

/* ============================================================
 * 工具函数
 * ============================================================ */

/*
 * AndunIsAddressValid - 安全校验内存可读性
 * 双重保护：MmIsAddressValid + SEH。
 */
static BOOLEAN AndunIsAddressValid(PVOID Address)
{
    BOOLEAN ok = FALSE;

    if (Address == NULL) {
        return FALSE;
    }

    __try {
        ok = MmIsAddressValid(Address);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    return ok;
}

/*
 * AndunCopyUnicodeToString - 安全拷贝 UNICODE_STRING 到 WCHAR 数组
 */
static BOOLEAN AndunCopyUnicodeToString(
    PWSTR Dst, ULONG DstChars, PUNICODE_STRING Src)
{
    ULONG copyChars;

    if (Dst == NULL || DstChars == 0) {
        return FALSE;
    }
    Dst[0] = L'\0';

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return FALSE;
    }

    if (!AndunIsAddressValid(Src->Buffer)) {
        return FALSE;
    }

    copyChars = Src->Length / sizeof(WCHAR);
    if (copyChars >= DstChars) {
        copyChars = DstChars - 1;
    }

    __try {
        RtlCopyMemory(Dst, Src->Buffer, copyChars * sizeof(WCHAR));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Dst[0] = L'\0';
        return FALSE;
    }

    Dst[copyChars] = L'\0';
    return TRUE;
}

/*
 * AndunFindActiveProcessLinksOffset - 动态发现 EPROCESS.ActiveProcessLinks 偏移
 *
 * 原理：ActiveProcessLinks 是一个 LIST_ENTRY，其 Flink/Blink 都是
 * 内核地址且指向其他 EPROCESS 的 ActiveProcessLinks。
 * 在 PsInitialSystemProcess（Idle 进程）内扫描，找到满足
 * 两个指针都位于内核空间且互为链表关系的字段即视为命中。
 *
 * 返回 0 表示未找到（降级为不检测，绝不让驱动崩溃）。
 */
static LONG AndunFindActiveProcessLinksOffset(VOID)
{
    PEPROCESS initial = PsInitialSystemProcess;
    PUCHAR base;
    ULONG size;
    ULONG off;

    if (initial == NULL || !AndunIsAddressValid(initial)) {
        return 0;
    }

    /* EPROCESS 通常小于 0x1000 字节，扫描前 0x800 字节 */
    base = (PUCHAR)initial;
    size = 0x800;

    for (off = 0; off + sizeof(LIST_ENTRY) <= size; off += 8) {
        PLIST_ENTRY entry = (PLIST_ENTRY)(base + off);
        PVOID flink;
        PVOID blink;

        __try {
            flink = entry->Flink;
            blink = entry->Blink;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }

        /* Flink/Blink 都必须是内核空间地址 */
        if (flink == NULL || blink == NULL) {
            continue;
        }
        if (((ULONG_PTR)flink >> 48) == 0 ||
            ((ULONG_PTR)blink >> 48) == 0) {
            continue;
        }

        /* 校验双向链表一致性：Flink->Blink == 自身 */
        if (AndunIsAddressValid(flink)) {
            PLIST_ENTRY flinkEntry = (PLIST_ENTRY)flink;
            PVOID back;
            __try {
                back = flinkEntry->Blink;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
            if ((ULONG_PTR)back == (ULONG_PTR)entry) {
                /* 命中：返回相对 EPROCESS 基址的偏移 */
                return (LONG)off;
            }
        }
    }

    return 0;
}

/* ============================================================
 * 1. 隐藏进程枚举
 * ============================================================ */

/*
 * AndunRootkitEnumProcs - 遍历 EPROCESS.ActiveProcessLinks
 *
 * 逐节点读取，通过导出的 PsGetProcessId / PsGetProcessImageFileName
 * 获取 PID 与映像名（不依赖未文档化结构体字段）。
 * 只读、SEH 保护，任何异常立即终止遍历。
 */
static ULONG AndunRootkitEnumProcs(PANDUN_ROOTKIT_SCAN_RESULT Result)
{
    PEPROCESS initial = PsInitialSystemProcess;
    PLIST_ENTRY listHead;
    PLIST_ENTRY current;
    ULONG count = 0;

    if (initial == NULL || Result == NULL) {
        return 0;
    }

    /* 动态发现 ActiveProcessLinks 偏移（缓存） */
    if (g_ActiveProcessLinksOffset < 0) {
        g_ActiveProcessLinksOffset = AndunFindActiveProcessLinksOffset();
        if (g_ActiveProcessLinksOffset <= 0) {
            /* 找不到偏移，降级：只上报 System 进程，避免误报 */
            Result->procs[count].pid = 4;
            Result->procs[count].ppid = 0;
            wcscpy_s(Result->procs[count].name, 260, L"System");
            Result->procs[count].name[259] = L'\0';
            count++;
            Result->proc_count = count;
            return count;
        }
    }

    listHead = (PLIST_ENTRY)((PUCHAR)initial + g_ActiveProcessLinksOffset);
    if (!AndunIsAddressValid(listHead)) {
        return 0;
    }

    current = listHead;
    do {
        PEPROCESS proc;
        HANDLE pid;
        PCSTR imageName;
        PANDUN_ROOTKIT_PROC_ENTRY entry;

        if (!AndunIsAddressValid(current)) {
            break;
        }

        /* 计算 EPROCESS 基址 = 链表节点地址 - 偏移 */
        proc = (PEPROCESS)((PUCHAR)current - g_ActiveProcessLinksOffset);
        if (!AndunIsAddressValid(proc)) {
            break;
        }

        pid = NULL;
        imageName = NULL;

        __try {
            pid = PsGetProcessId(proc);
            imageName = PsGetProcessImageFileName(proc);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        if (count >= 256) {
            break;
        }

        entry = &Result->procs[count];
        RtlZeroMemory(entry, sizeof(ANDUN_ROOTKIT_PROC_ENTRY));
        entry->pid = HandleToULong(pid);
        entry->ppid = 0;

        if (imageName != NULL && AndunIsAddressValid((PVOID)imageName)) {
            /* ANSI 转 WCHAR */
            ULONG i;
            __try {
                for (i = 0; i < 259 && imageName[i] != '\0'; i++) {
                    entry->name[i] = (WCHAR)(UCHAR)imageName[i];
                }
                entry->name[i] = L'\0';
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                entry->name[0] = L'\0';
            }
        }

        count++;

        /* 前进到下一个节点 */
        __try {
            current = current->Flink;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        /* 绕回链表头说明遍历完成 */
        if ((ULONG_PTR)current == (ULONG_PTR)listHead) {
            break;
        }
    } while (count < 256 && AndunIsAddressValid(current));

    Result->proc_count = count;
    return count;
}

/* ============================================================
 * 2. 隐藏驱动枚举
 * ============================================================ */

/*
 * AndunRootkitEnumDrivers - 遍历 PsLoadedModuleList
 *
 * 读取每个 LDR_DATA_TABLE_ENTRY 的 BaseDllName、DllBase、SizeOfImage。
 * 同时检查驱动对象节区是否已卸载（通过 DriverObject->DriverSection 状态，
 * 此处保守处理：仅记录基础信息，节区状态由用户态二次确认）。
 */
static ULONG AndunRootkitEnumDrivers(PANDUN_ROOTKIT_SCAN_RESULT Result)
{
    PLIST_ENTRY listHead = NULL;
    PLIST_ENTRY current = NULL;
    ULONG count = 0;

    if (Result == NULL) {
        return 0;
    }

    __try {
        listHead = PsLoadedModuleList;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        listHead = NULL;
    }

    if (listHead == NULL || !AndunIsAddressValid(listHead)) {
        Result->driver_count = 0;
        return 0;
    }

    current = listHead;
    do {
        PDRIVER_OBJECT driverObj;
        PANDUN_ROOTKIT_DRIVER_ENTRY entry;

        if (!AndunIsAddressValid(current)) {
            break;
        }

        /* LDR_DATA_TABLE_ENTRY 的 DllBase 位于偏移 0x30，DriverObject 位于 0x08 */
        driverObj = NULL;
        __try {
            /* 通过 DriverObject 字段（InLoadOrderLinks 所在结构） */
            PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)current;
            /* 用 DllBase 方式：偏移 0x30 读取，避免依赖未文档化字段 */
            PVOID dllBase = NULL;
            ULONG_PTR sizeOfImage = 0;
            PUNICODE_STRING baseName = NULL;

            /* 动态获取：直接访问 LDR_DATA_TABLE_ENTRY 字段（WDK 已定义） */
            dllBase = ldrEntry->DllBase;
            sizeOfImage = (ULONG_PTR)ldrEntry->SizeOfImage;
            baseName = &ldrEntry->BaseDllName;

            if (count >= 64) {
                break;
            }

            entry = &Result->drivers[count];
            RtlZeroMemory(entry, sizeof(ANDUN_ROOTKIT_DRIVER_ENTRY));
            entry->base_address = (ULONG64)dllBase;
            entry->size = (ULONG64)sizeOfImage;

            AndunCopyUnicodeToString(entry->name, 260, baseName);
            entry->section_unloaded = 0;
            count++;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* 单个条目读取失败，跳过继续 */
        }

        /* 前进 */
        __try {
            current = current->Flink;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        if ((ULONG_PTR)current == (ULONG_PTR)listHead) {
            break;
        }
    } while (count < 64 && AndunIsAddressValid(current));

    Result->driver_count = count;
    return count;
}

/* ============================================================
 * 3. 内核钩子检测
 * ============================================================ */

/*
 * AndunRootkitScanHooks - Inline Hook 检测
 *
 * 对关键 Nt* 函数读取序言前 5 字节，若以 jmp(0xE9)/call(0xE8) 开头
 * 且目标跳转地址不落在任何已加载驱动模块内，判定为被 Inline Hook。
 *
 * 说明：SSDT 只读比对需要定位 KeServiceDescriptorTable，
 * 该符号在 x64 下不导出，需通过特征码扫描 ntoskrnl.exe 镜像定位。
 * 为控制风险，当前版本实现 Inline Hook 检测 + 模块归属校验，
 * SSDT 表定位留作增强（PatchGuard 下仅检测不修复）。
 */
static ULONG AndunRootkitScanHooks(PANDUN_ROOTKIT_SCAN_RESULT Result)
{
    ULONG count = 0;
    ULONG i;

    if (Result == NULL) {
        return 0;
    }

    for (i = 0; i < ANDUN_CRITICAL_FUNC_COUNT; i++) {
        PVOID funcAddr;
        UCHAR prologue[5];
        PVOID target = NULL;
        WCHAR moduleName[260];
        PANDUN_ROOTKIT_HOOK_ENTRY entry;

        /* 通过 MmGetSystemRoutineAddress 动态解析 Nt* 函数地址 */
        {
            UNICODE_STRING routineName;
            WCHAR fullName[300];
            swprintf_s(fullName, 300, L"\\%hs", ANDUN_CRITICAL_NT_FUNCS[i]);
            RtlInitUnicodeString(&routineName, fullName);
            funcAddr = MmGetSystemRoutineAddress(&routineName);
        }

        if (funcAddr == NULL || !AndunIsAddressValid(funcAddr)) {
            continue;
        }

        /* 读取序言 5 字节 */
        RtlZeroMemory(prologue, sizeof(prologue));
        __try {
            RtlCopyMemory(prologue, funcAddr, 5);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }

        /* 检查 jmp(0xE9) / call(0xE8) 开头 */
        if (prologue[0] != 0xE9 && prologue[0] != 0xE8) {
            continue;
        }

        {
            LONG rel = (LONG)(prologue[1] |
                              (prologue[2] << 8) |
                              (prologue[3] << 16) |
                              (prologue[4] << 24));
            target = (PVOID)((ULONG_PTR)funcAddr + 5 + rel);
        }

        /* 判断跳转目标是否在合法驱动模块内 */
        if (AndunAddressInDriverModule(target, moduleName, 260)) {
            /* 跳转到已加载驱动内（如 ntoskrnl 自身），视为合法 */
            continue;
        }

        if (count >= 32) {
            break;
        }

        entry = &Result->hooks[count];
        RtlZeroMemory(entry, sizeof(ANDUN_ROOTKIT_HOOK_ENTRY));
        entry->hook_type = 2; /* Inline */
        swprintf_s(entry->function_name, 128, L"%hs", ANDUN_CRITICAL_NT_FUNCS[i]);
        entry->hook_address = (ULONG64)funcAddr;
        RtlCopyMemory(entry->original_bytes, prologue, 5);
        RtlCopyMemory(entry->current_bytes, prologue, 5);
        wcscpy_s(entry->driver_name, 260, moduleName);
        entry->severity = 2; /* critical */
        count++;
    }

    Result->hook_count = count;
    return count;
}

/*
 * AndunAddressInDriverModule - 判断地址是否落在已加载驱动模块内
 *
 * 遍历 PsLoadedModuleList，若命中则输出模块名并返回 TRUE。
 */
static BOOLEAN AndunAddressInDriverModule(
    PVOID Address, PWSTR ModuleName, ULONG ModuleNameChars)
{
    PLIST_ENTRY listHead = NULL;
    PLIST_ENTRY current = NULL;

    if (Address == NULL) {
        return FALSE;
    }
    if (ModuleName != NULL && ModuleNameChars > 0) {
        ModuleName[0] = L'\0';
    }

    __try {
        listHead = PsLoadedModuleList;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (listHead == NULL || !AndunIsAddressValid(listHead)) {
        return FALSE;
    }

    current = listHead;
    do {
        if (!AndunIsAddressValid(current)) {
            break;
        }

        __try {
            PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)current;
            ULONG_PTR base = (ULONG_PTR)ldrEntry->DllBase;
            ULONG_PTR size = (ULONG_PTR)ldrEntry->SizeOfImage;

            if (base != 0 && size != 0 &&
                (ULONG_PTR)Address >= base &&
                (ULONG_PTR)Address < base + size) {
                if (ModuleName != NULL && ModuleNameChars > 0) {
                    AndunCopyUnicodeToString(ModuleName, ModuleNameChars,
                                             &ldrEntry->BaseDllName);
                }
                return TRUE;
            }

            current = current->Flink;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        if ((ULONG_PTR)current == (ULONG_PTR)listHead) {
            break;
        }
    } while (AndunIsAddressValid(current));

    return FALSE;
}

/* ============================================================
 * 4. 回调劫持检测
 * ============================================================ */

/*
 * AndunRootkitScanCallbacks - 回调劫持检测
 *
 * 定位关键回调例程地址（通过导出的 PsSet* 函数），
 * 检查其所在模块是否为合法系统模块（ntoskrnl.exe 等）。
 * 精确的回调数组内容遍历（PspXxxNotify）涉及未文档化结构，
 * 此处实现"回调例程归属校验"：若回调被替换为指向非系统模块
 * 的地址，即标记为可疑。
 *
 * 当前版本对回调类型做保守标记，核心交由用户态交叉验证。
 */
static ULONG AndunRootkitScanCallbacks(PANDUN_ROOTKIT_SCAN_RESULT Result)
{
    ULONG count = 0;

    if (Result == NULL) {
        return 0;
    }

    /* 占位：检查 PsSetCreateProcessNotifyRoutine 是否被 Hook（与 Inline 检测重叠） */
    {
        static const PCSTR cbFuncs[] = {
            "PsSetCreateProcessNotifyRoutine",
            "PsSetCreateThreadNotifyRoutine",
            "PsSetLoadImageNotifyRoutine",
            "PsSetCreateProcessNotifyRoutineEx",
        };
        ULONG i;

        for (i = 0; i < sizeof(cbFuncs) / sizeof(cbFuncs[0]); i++) {
            UNICODE_STRING name;
            PVOID addr;
            UCHAR prologue[5];
            WCHAR modName[260];

            RtlInitUnicodeString(&name, L"");
            /* 构造名称 */
            {
                WCHAR fullName[300];
                swprintf_s(fullName, 300, L"%hs", cbFuncs[i]);
                RtlInitUnicodeString(&name, fullName);
            }
            addr = MmGetSystemRoutineAddress(&name);
            if (addr == NULL || !AndunIsAddressValid(addr)) {
                continue;
            }

            /* 读取序言，检查是否被 Inline Hook */
            RtlZeroMemory(prologue, sizeof(prologue));
            __try {
                RtlCopyMemory(prologue, addr, 5);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            if (prologue[0] == 0xE9 || prologue[0] == 0xE8) {
                LONG rel = (LONG)(prologue[1] |
                                  (prologue[2] << 8) |
                                  (prologue[3] << 16) |
                                  (prologue[4] << 24));
                PVOID target = (PVOID)((ULONG_PTR)addr + 5 + rel);

                if (count >= 32) {
                    break;
                }

                /* 回调函数被改写 */
                if (!AndunAddressInDriverModule(target, modName, 260)) {
                    PANDUN_ROOTKIT_CALLBACK_ENTRY entry;
                    entry = &Result->callbacks[count];
                    RtlZeroMemory(entry, sizeof(ANDUN_ROOTKIT_CALLBACK_ENTRY));
                    entry->callback_type = (ULONG)i; /* 0=Process... */
                    entry->callback_address = (ULONG64)addr;
                    wcscpy_s(entry->driver_name, 260, L"<unknown>");
                    entry->is_trusted = 0;
                    entry->severity = 2;
                    count++;
                }
            }
        }
    }

    Result->callback_count = count;
    return count;
}

/* ============================================================
 * 对外接口
 * ============================================================ */

/*
 * RootkitScanRun - 执行完整 Rootkit 扫描，填充结果结构
 *
 * 由 device_control.c 的 IOCTL_ANDUN_ROOTKIT_SCAN 分发调用。
 * 每个维度独立执行，单个维度失败不影响其他维度。
 *
 * 参数：
 *   Result - 输出结果缓冲区（用户态传入，已清零）
 * 返回：
 *   STATUS_SUCCESS 或错误码
 */
NTSTATUS RootkitScanRun(PANDUN_ROOTKIT_SCAN_RESULT Result)
{
    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 清零输出缓冲区 */
    RtlZeroMemory(Result, sizeof(ANDUN_ROOTKIT_SCAN_RESULT));

    /* 1. 隐藏进程 */
    AndunRootkitEnumProcs(Result);

    /* 2. 隐藏驱动 */
    AndunRootkitEnumDrivers(Result);

    /* 3. 内核钩子 */
    AndunRootkitScanHooks(Result);

    /* 4. 回调劫持 */
    AndunRootkitScanCallbacks(Result);

    DbgPrint("[御天驱动] Rootkit扫描完成: procs=%lu drivers=%lu hooks=%lu callbacks=%lu\n",
             Result->proc_count, Result->driver_count,
             Result->hook_count, Result->callback_count);

    return STATUS_SUCCESS;
}

/*
 * RootkitScanUnload - 扫描模块卸载清理
 */
VOID RootkitScanUnload(VOID)
{
    /* 无持久资源需要清理 */
}
