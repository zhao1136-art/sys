/*
 * registry_callback.c - 注册表操作回调
 *
 * 通过 CmRegisterCallbackEx 注册注册表回调，监控注册表键值写入、
 * 键创建与键删除操作，结合规则引擎实现拦截，并将事件推入队列。
 *
 * 调用环境：PASSIVE_LEVEL
 * 兼容性：Windows Vista+（CmRegisterCallbackEx / CmCallbackGetKeyObjectIDEx）
 */

#include "andun.h"

/* ============================================================
 * 全局变量
 * ============================================================ */

/* 注册表回调注册时返回的 Cookie，反注册时使用 */
static LARGE_INTEGER g_RegistryCookie = {0};

/*
 * device_control.c 中定义的全局配置。
 * 注意：device_control.c 中的 g_Config 必须去掉 static 修饰符，
 * 才能在本文件中以 extern 方式引用。
 */
extern ANDUN_CONFIG g_Config;

/* ============================================================
 * 内部辅助函数
 * ============================================================ */

/*
 * AndunGetRegistryPath - 获取注册表键对象的完整路径
 *
 * 通过 CmCallbackGetKeyObjectIDEx 查询键对象的完整路径名，
 * 拷贝到调用者提供的缓冲区中。
 *
 * 参数：
 *   RegistryObject - 注册表键对象指针（来自回调参数中的 Object）
 *   Path           - 接收路径的 UNICODE_STRING（Buffer 由调用者提供）
 *   BufferLen      - Path->Buffer 的字节长度
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 */
static NTSTATUS AndunGetRegistryPath(PVOID RegistryObject, PUNICODE_STRING Path, ULONG BufferLen)
{
    PCUNICODE_STRING keyPath = NULL;
    NTSTATUS status;

    status = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie,
                                        RegistryObject,
                                        NULL,
                                        &keyPath,
                                        0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 拷贝到调用者缓冲区（保留 1 个 WCHAR 用于 NULL 终止符） */
    if (keyPath->Length + sizeof(WCHAR) > BufferLen) {
        CmCallbackReleaseKeyObjectIDEx(keyPath);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Path->Buffer, keyPath->Buffer, keyPath->Length);
    Path->Length = keyPath->Length;
    Path->Buffer[keyPath->Length / sizeof(WCHAR)] = L'\0';

    CmCallbackReleaseKeyObjectIDEx(keyPath);
    return STATUS_SUCCESS;
}

/*
 * AndunFillRegistryEvent - 填充注册表事件结构并推入队列
 *
 * 参数：
 *   EventType - EventRegistrySet 或 EventRegistryDelete
 *   KeyPath   - 注册表键路径（UNICODE_STRING，可能不以 NULL 结尾）
 *   Action    - ActionAllow / ActionBlock
 */
static VOID AndunFillRegistryEvent(ULONG EventType,
                                   PCUNICODE_STRING KeyPath,
                                   ULONG Action)
{
    ANDUN_EVENT event;
    ULONG copyChars;

    RtlZeroMemory(&event, sizeof(event));

    event.eventType = EventType;
    event.pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.action = Action;
    KeQuerySystemTime(&event.timestamp);

    /* 拷贝键路径到事件 targetPath 字段（保证 NULL 结尾） */
    if (KeyPath != NULL && KeyPath->Buffer != NULL && KeyPath->Length > 0) {
        copyChars = KeyPath->Length / sizeof(WCHAR);
        if (copyChars >= 520) {
            copyChars = 520 - 1;
        }
        RtlCopyMemory(event.targetPath,
                      KeyPath->Buffer,
                      copyChars * sizeof(WCHAR));
        event.targetPath[copyChars] = L'\0';
    }

    EventQueuePush(&event);
}

/* ============================================================
 * 回调实现
 * ============================================================ */

/*
 * AndunRegistryCallback - 注册表回调函数
 *
 * 由配置管理器在 PASSIVE_LEVEL 调用，针对以下预操作事件进行处理：
 *   - RegNtPreSetValueKey:  写注册表值
 *   - RegNtPreDeleteKey:    删除注册表键
 *   - RegNtPreCreateKeyEx:  创建注册表键
 *
 * 命中阻断规则时返回 STATUS_ACCESS_DENIED，配置管理器会将其作为
 * 操作失败结果回传给发起方，从而阻止操作继续。
 *
 * 参数：
 *   CallbackContext - 注册时传入的上下文（本驱动为 NULL）
 *   Argument1       - REG_NOTIFY_CLASS 枚举值（转成 ULONG_PTR）
 *   Argument2       - 指向对应通知类型的参数结构
 */
NTSTATUS AndunRegistryCallback(PVOID CallbackContext,
                               PVOID Argument1,
                               PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;

    UNREFERENCED_PARAMETER(CallbackContext);

    /* 1. 全局开关：未启用注册表回调直接放行 */
    if (!g_Config.registryCallbackEnabled) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* 2. 按通知类型分发处理 */
    switch (notifyClass) {

    /* --- 写注册表值 --- */
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info;
        UNICODE_STRING keyPath;
        WCHAR pathBuf[ANDUN_MAX_PATTERN_LEN];
        ULONG action;

        info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL || info->Object == NULL) {
            return STATUS_SUCCESS;
        }

        /* 准备本地缓冲区获取完整路径 */
        RtlZeroMemory(pathBuf, sizeof(pathBuf));
        keyPath.Buffer = pathBuf;
        keyPath.Length = 0;
        keyPath.MaximumLength = sizeof(pathBuf);

        if (!NT_SUCCESS(AndunGetRegistryPath(info->Object,
                                              &keyPath,
                                              sizeof(pathBuf)))) {
            return STATUS_SUCCESS;
        }

        /* 规则匹配 */
        action = RuleMatchRegistry(&keyPath);

        /* 推送事件 */
        AndunFillRegistryEvent(EventRegistrySet, &keyPath, action);

        if (action == ActionBlock) {
            return STATUS_ACCESS_DENIED;
        }
        break;
    }

    /* --- 删除注册表键 --- */
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info;
        UNICODE_STRING keyPath;
        WCHAR pathBuf[ANDUN_MAX_PATTERN_LEN];
        ULONG action;

        info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (info == NULL || info->Object == NULL) {
            return STATUS_SUCCESS;
        }

        RtlZeroMemory(pathBuf, sizeof(pathBuf));
        keyPath.Buffer = pathBuf;
        keyPath.Length = 0;
        keyPath.MaximumLength = sizeof(pathBuf);

        if (!NT_SUCCESS(AndunGetRegistryPath(info->Object,
                                              &keyPath,
                                              sizeof(pathBuf)))) {
            return STATUS_SUCCESS;
        }

        action = RuleMatchRegistry(&keyPath);
        AndunFillRegistryEvent(EventRegistryDelete, &keyPath, action);

        if (action == ActionBlock) {
            return STATUS_ACCESS_DENIED;
        }
        break;
    }

    /* --- 创建注册表键 --- */
    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info;
        UNICODE_STRING keyPath;
        ULONG action;

        info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (info == NULL || info->CompleteName == NULL) {
            return STATUS_SUCCESS;
        }

        /*
         * CreateKey 阶段键对象尚不存在，无法用 CmCallbackGetKeyObjectIDEx
         * 获取路径，直接使用 CompleteName 作为匹配路径。
         */
        keyPath = *info->CompleteName;

        action = RuleMatchRegistry(&keyPath);

        /* 创建键归类为 RegistrySet 事件 */
        AndunFillRegistryEvent(EventRegistrySet, &keyPath, action);

        if (action == ActionBlock) {
            return STATUS_ACCESS_DENIED;
        }
        break;
    }

    default:
        /* 其他操作放行 */
        break;
    }

    return STATUS_SUCCESS;
}

/* ============================================================
 * 初始化与卸载
 * ============================================================ */

/*
 * RegistryCallbackInit - 注册注册表回调
 *
 * 调用 CmRegisterCallbackEx 注册 AndunRegistryCallback。
 * Altitude 需为唯一数字字符串，使用 "321001" 作为本驱动占位值。
 *
 * 参数：
 *   DriverObject - 驱动对象（作为回调上下文/关联对象）
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 */
NTSTATUS RegistryCallbackInit(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    /*
     * CmRegisterCallbackEx 要求 Altitude 为唯一的数字字符串，
     * ANDUN_DEVICE_NAME 含 '\' 不适合作为 Altitude，改用 "321001"。
     */
    RtlInitUnicodeString(&altitude, L"321001");

    status = CmRegisterCallbackEx(AndunRegistryCallback,
                                  &altitude,
                                  DriverObject,
                                  NULL,
                                  &g_RegistryCookie,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] CmRegisterCallbackEx 失败: 0x%08X\n", status);
        g_RegistryCookie.QuadPart = 0;
        return status;
    }

    DbgPrint("[御天驱动] 注册表回调初始化成功\n");
    return STATUS_SUCCESS;
}

/*
 * RegistryCallbackUnload - 反注册注册表回调
 */
VOID RegistryCallbackUnload(VOID)
{
    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
    }

    DbgPrint("[御天驱动] 注册表回调已卸载\n");
}
