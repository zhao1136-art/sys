/*
 * process_callback.c - 进程创建 / 退出回调
 *
 * 使用 PsSetCreateProcessNotifyRoutineEx 注册进程通知，
 * 监控进程创建与退出：
 *   - 创建时根据规则引擎决定是否阻断（设置 CreationStatus）
 *   - 退出时填充终止事件，并从受保护 PID 列表中移除
 *   - 御天自身进程创建后加入受保护列表
 *
 * 回调运行环境：PASSIVE_LEVEL，可安全调用大部分系统服务。
 *
 * 注意：
 *   - CreateInfo->ImageFileName 可能为 NULL，需检查
 *   - HandleToULong 用于将 HANDLE 转为 ULONG
 *   - PsSetCreateProcessNotifyRoutineEx 反注册时第二参数传 TRUE
 */

#include "andun.h"

/* g_Config 在 device_control.c 中定义，andun.h 中已 extern 声明 */

/* ============================================================
 * 内部函数前置声明
 * ============================================================ */

static VOID AndunProcessNotifyCallback(
    _In_     PEPROCESS               Process,
    _In_     HANDLE                  ProcessId,
    _Inout_  PPS_CREATE_NOTIFY_INFO  CreateInfo);

static VOID AndunFillProcessEvent(
    _Out_    PANDUN_EVENT     Event,
    _In_     ANDUN_EVENT_TYPE EventType,
    _In_     ANDUN_ACTION     Action,
    _In_     HANDLE           Pid,
    _In_opt_ HANDLE           ParentPid,
    _In_opt_ PCUNICODE_STRING ProcessImage);

static BOOLEAN AndunIsSelfProcess(
    _In_opt_ PCUNICODE_STRING ProcessImage);

static VOID AndunCopyUnicodeToWChar(
    _Out_    PWSTR             Dst,
    _In_     ULONG             DstChars,
    _In_opt_ PCUNICODE_STRING  Src);

/* ============================================================
 * 初始化与卸载
 * ============================================================ */

/*
 * ProcessCallbackInit - 注册进程创建 / 退出回调
 *
 * 调用 PsSetCreateProcessNotifyRoutineEx 注册回调例程。
 * 注意：实际回调中会再次检查 g_Config.processCallbackEnabled，
 *       此处注册行为不受配置开关影响，保证退出事件始终可被记录。
 *
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 */
NTSTATUS ProcessCallbackInit(VOID)
{
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(AndunProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] PsSetCreateProcessNotifyRoutineEx 失败: 0x%08X\n", status);
        return status;
    }

    DbgPrint("[御天驱动] 进程回调初始化成功\n");
    return STATUS_SUCCESS;
}

/*
 * ProcessCallbackUnload - 反注册进程回调
 *
 * 调用 PsSetCreateProcessNotifyRoutineEx 并传 TRUE 移除已注册的回调。
 */
VOID ProcessCallbackUnload(VOID)
{
    PsSetCreateProcessNotifyRoutineEx(AndunProcessNotifyCallback, TRUE);

    DbgPrint("[御天驱动] 进程回调已卸载\n");
}

/* ============================================================
 * 进程通知回调
 * ============================================================ */

/*
 * AndunProcessNotifyCallback - 进程创建 / 退出回调
 *
 * 当 CreateInfo == NULL 时表示进程退出，
 * 当 CreateInfo != NULL 时表示进程创建。
 *
 * 进程创建流程：
 *   1. 检查 g_Config.processCallbackEnabled
 *   2. 获取进程映像名 / 完整路径 / 父进程 PID
 *   3. 调用 RuleMatchProcess 匹配规则
 *   4. ActionBlock: 填充事件并设置 CreationStatus 阻断创建
 *      ActionAsk  : 填充事件但不阻断（用户态决定后续）
 *      ActionAllow: 填充事件并允许
 *   5. 若创建成功且为御天自身，加入受保护 PID 列表
 */
static VOID AndunProcessNotifyCallback(
    PEPROCESS              Process,
    HANDLE                 ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    /* ----------------------------------------------------------
     * 1. CreateInfo == NULL：进程退出
     * ---------------------------------------------------------- */
    if (CreateInfo == NULL) {
        ANDUN_EVENT event;
        ULONG       pid = HandleToULong(ProcessId);

        RtlZeroMemory(&event, sizeof(event));
        AndunFillProcessEvent(&event,
                                EventProcessTerminate,
                                ActionAllow,
                                ProcessId,
                                NULL,
                                NULL);
        EventQueuePush(&event);

        /* 若该 PID 在受保护列表中，退出时移除 */
        if (ProtectedPidIsProtected(pid)) {
            ProtectedPidRemove(pid);
        }
        return;
    }

    /* ----------------------------------------------------------
     * 2. CreateInfo != NULL：进程创建
     * ---------------------------------------------------------- */

    /* 2.1 检查全局开关 */
    if (g_Config.processCallbackEnabled == 0) {
        return;
    }

    /* 2.2 收集进程信息 */
    {
        PCUNICODE_STRING imageName = NULL;
        ULONG            pid = HandleToULong(ProcessId);
        HANDLE           parentPid = CreateInfo->ParentProcessId;
        ULONG            action = ActionAllow;
        WCHAR            nameBuf[260];
        ULONG            chars;
        ULONG            i;
        ULONG            lastSlash = 0;

        /* ImageFileName 可能为 NULL，需检查 */
        if (CreateInfo->ImageFileName != NULL) {
            imageName = CreateInfo->ImageFileName;
        }

        /* 2.3 从完整路径提取文件名，用于规则匹配 */
        nameBuf[0] = L'\0';
        if (imageName != NULL && imageName->Buffer != NULL && imageName->Length > 0) {
            chars = imageName->Length / sizeof(WCHAR);
            if (chars >= 260) {
                chars = 259;
            }
            for (i = 0; i < chars; i++) {
                nameBuf[i] = imageName->Buffer[i];
                if (imageName->Buffer[i] == L'\\' || imageName->Buffer[i] == L'/') {
                    lastSlash = i + 1;
                }
            }
            nameBuf[chars] = L'\0';

            /* 调用规则引擎匹配文件名部分 */
            action = RuleMatchProcess(&nameBuf[lastSlash], pid);
        }

        /* 2.4 根据匹配结果处理 */
        if (action == ActionBlock) {
            /* 阻断进程创建 */
            ANDUN_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            AndunFillProcessEvent(&event,
                                    EventProcessCreate,
                                    ActionBlock,
                                    ProcessId,
                                    parentPid,
                                    imageName);
            EventQueuePush(&event);

            /* 设置创建状态为拒绝访问，阻断进程创建 */
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }

        if (action == ActionAsk) {
            /* 询问：记录事件但不阻断，由用户态决定后续 */
            ANDUN_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            AndunFillProcessEvent(&event,
                                    EventProcessCreate,
                                    ActionAsk,
                                    ProcessId,
                                    parentPid,
                                    imageName);
            EventQueuePush(&event);
        } else {
            /* ActionAllow：记录事件并允许 */
            ANDUN_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            AndunFillProcessEvent(&event,
                                    EventProcessCreate,
                                    ActionAllow,
                                    ProcessId,
                                    parentPid,
                                    imageName);
            EventQueuePush(&event);
        }

        /* 2.5 若创建成功且为御天自身进程，加入受保护列表 */
        if (CreateInfo->CreationStatus == STATUS_SUCCESS ||
            NT_SUCCESS(CreateInfo->CreationStatus)) {
            if (AndunIsSelfProcess(imageName)) {
                ProtectedPidAdd(pid);
            }
        }
    }
}

/* ============================================================
 * 辅助函数
 * ============================================================ */

/*
 * AndunFillProcessEvent - 填充进程事件 ANDUN_EVENT 结构
 *
 * 参数：
 *   Event        - 输出事件结构
 *   EventType    - 事件类型（EventProcessCreate / EventProcessTerminate）
 *   Action       - 动作（ActionAllow / ActionBlock / ActionAsk）
 *   Pid          - 进程 ID
 *   ParentPid    - 父进程 ID（终止事件可传 NULL）
 *   ProcessImage - 进程映像完整路径（可为 NULL）
 */
static VOID AndunFillProcessEvent(
    PANDUN_EVENT     Event,
    ANDUN_EVENT_TYPE EventType,
    ANDUN_ACTION     Action,
    HANDLE           Pid,
    HANDLE           ParentPid,
    PCUNICODE_STRING ProcessImage)
{
    LARGE_INTEGER now;

    if (Event == NULL) {
        return;
    }

    RtlZeroMemory(Event, sizeof(ANDUN_EVENT));

    Event->eventType = EventType;
    Event->action    = Action;
    Event->pid       = HandleToULong(Pid);

    if (ParentPid != NULL) {
        Event->ppid = HandleToULong(ParentPid);
    }

    /* 拷贝进程完整路径到 processPath，并提取文件名到 processName */
    if (ProcessImage != NULL && ProcessImage->Buffer != NULL && ProcessImage->Length > 0) {
        ULONG chars = ProcessImage->Length / sizeof(WCHAR);
        ULONG i;
        ULONG lastSlash = 0;
        ULONG nameLen;

        /* 限制到缓冲区容量内 */
        if (chars >= 520) {
            chars = 519;
        }

        /* 拷贝完整路径到 processPath */
        RtlCopyMemory(Event->processPath, ProcessImage->Buffer, chars * sizeof(WCHAR));
        Event->processPath[chars] = L'\0';

        /* 定位最后一个路径分隔符，提取文件名部分 */
        for (i = 0; i < chars; i++) {
            if (Event->processPath[i] == L'\\' || Event->processPath[i] == L'/') {
                lastSlash = i + 1;
            }
        }

        /* 拷贝文件名部分到 processName */
        nameLen = chars - lastSlash;
        if (nameLen >= 260) {
            nameLen = 259;
        }
        RtlCopyMemory(Event->processName,
                       &Event->processPath[lastSlash],
                       nameLen * sizeof(WCHAR));
        Event->processName[nameLen] = L'\0';
    }

    /* 时间戳 */
    now.QuadPart = 0;
    KeQuerySystemTime(&now);
    Event->timestamp = now;
}

/*
 * AndunIsSelfProcess - 判断是否为御天自身进程
 *
 * 通过进程映像名判断是否为御天用户态组件，
 * 检查文件名是否以 "andun" 开头（不区分大小写）。
 * 命中后该进程将被加入受保护 PID 列表。
 *
 * 注意：此为简单识别策略，实际项目可根据需要扩展为
 *       数字签名校验或更严格的路径匹配。
 */
static BOOLEAN AndunIsSelfProcess(PCUNICODE_STRING ProcessImage)
{
    WCHAR  nameBuf[260];
    ULONG  chars;
    ULONG  i;
    ULONG  lastSlash = 0;
    PCWSTR prefix = L"andun";

    if (ProcessImage == NULL || ProcessImage->Buffer == NULL || ProcessImage->Length == 0) {
        return FALSE;
    }

    chars = ProcessImage->Length / sizeof(WCHAR);
    if (chars >= 260) {
        chars = 259;
    }
    for (i = 0; i < chars; i++) {
        nameBuf[i] = ProcessImage->Buffer[i];
        if (ProcessImage->Buffer[i] == L'\\' || ProcessImage->Buffer[i] == L'/') {
            lastSlash = i + 1;
        }
    }
    nameBuf[chars] = L'\0';

    /* 不区分大小写比较文件名前缀 */
    for (i = 0; i < 5; i++) {
        WCHAR ch = nameBuf[lastSlash + i];
        WCHAR expected = prefix[i];

        /* 转小写比较 */
        if (ch >= L'A' && ch <= L'Z') {
            ch = (WCHAR)(ch + (L'a' - L'A'));
        }

        if (ch != expected) {
            return FALSE;
        }
    }

    return TRUE;
}

/*
 * AndunCopyUnicodeToWChar - 将 UNICODE_STRING 拷贝到以 NULL 结尾的 WCHAR 数组
 */
static VOID AndunCopyUnicodeToWChar(
    PWSTR            Dst,
    ULONG            DstChars,
    PCUNICODE_STRING Src)
{
    ULONG copyChars;

    if (Dst == NULL || DstChars == 0) {
        return;
    }
    Dst[0] = L'\0';

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return;
    }

    copyChars = Src->Length / sizeof(WCHAR);
    if (copyChars >= DstChars) {
        copyChars = DstChars - 1;
    }

    RtlCopyMemory(Dst, Src->Buffer, copyChars * sizeof(WCHAR));
    Dst[copyChars] = L'\0';
}
