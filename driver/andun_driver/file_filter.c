/*
 * file_filter.c - Minifilter 文件系统过滤
 *
 * 使用 FltMgr（Minifilter Framework）注册文件系统过滤，
 * 监控文件创建 / 写入 / 删除 / 重命名操作，根据规则引擎进行匹配，
 * 对命中拦截规则的操作返回 STATUS_ACCESS_DENIED，并填充事件推入队列。
 *
 * 回调运行环境：IRQL <= APC_LEVEL，可安全调用 FltMgr API 与
 * PsGetCurrentProcess / PsGetProcessImageFileName 等系统服务。
 *
 * 注意：
 *   - paging I/O 直接放行，避免死锁与递归
 *   - FltGetFileNameInformation 可能失败（如预打开阶段），需检查返回值
 *   - 文件名信息必须通过 FltReleaseFileNameInformation 释放
 *   - 可能异常的操作使用 __try / __except 包裹
 */

#include "andun.h"

/* g_Config 在 device_control.c 中定义，andun.h 中已 extern 声明 */

/* ============================================================
 * 内部全局变量
 * ============================================================ */

/* Minifilter 句柄，FltRegisterFilter 返回，卸载时用于反注册 */
static PFLT_FILTER g_FilterHandle = NULL;

/* ============================================================
 * 内部函数前置声明
 * ============================================================ */

static FLT_PREOP_CALLBACK_STATUS AndunPreOperationCallback(
    _Inout_  PFLT_CALLBACK_DATA    Data,
    _In_     PFLT_RELATED_OBJECTS   FltObjects,
    _Out_    PVOID                 *CompletionContext);

static NTSTATUS FLTAPI AndunFilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static VOID AndunFillFileEvent(
    _Out_    PANDUN_EVENT               Event,
    _In_     ANDUN_EVENT_TYPE           EventType,
    _In_     ANDUN_ACTION               Action,
    _In_opt_ PCUNICODE_STRING           FilePath,
    _In_     HANDLE                      Pid);

static VOID AndunAnsiToWide(
    _In_opt_ PCSTR Ansi,
    _Out_    PWSTR  Wide,
    _In_     ULONG  WideChars);

static VOID AndunCopyUnicodeToWChar(
    _Out_    PWSTR             Dst,
    _In_     ULONG             DstChars,
    _In_opt_ PCUNICODE_STRING  Src);

/* ============================================================
 * Minifilter 注册结构
 * ============================================================ */

/* 上下文注册：本驱动不使用流 / 流句柄 / 实例上下文 */
static const FLT_CONTEXT_REGISTRATION AndunContextRegistration[] = {
    { FLT_CONTEXT_END }
};

/* 操作回调注册：监听创建、写入、设置信息三类操作 */
static const FLT_OPERATION_REGISTRATION AndunOperationRegistration[] = {
    { IRP_MJ_CREATE,
      0,
      AndunPreOperationCallback,
      NULL },
    { IRP_MJ_WRITE,
      0,
      AndunPreOperationCallback,
      NULL },
    { IRP_MJ_SET_INFORMATION,
      0,
      AndunPreOperationCallback,
      NULL },
    { IRP_MJ_OPERATION_END }
};

/* Minifilter 注册结构 */
static const FLT_REGISTRATION AndunFilterRegistration = {
    sizeof(FLT_REGISTRATION),               /* Size */
    FLT_REGISTRATION_VERSION,               /* Version */
    0,                                      /* Flags */
    AndunContextRegistration,               /* ContextRegistration */
    AndunOperationRegistration,             /* OperationRegistration */
    AndunFilterUnloadCallback,              /* FilterUnloadCallback */
    NULL,                                   /* InstanceSetupCallback */
    NULL,                                   /* InstanceQueryTeardownCallback */
    NULL,                                   /* InstanceTeardownStartCallback */
    NULL,                                   /* InstanceTeardownCompleteCallback */
    NULL,                                   /* GenerateFileNameCallback */
    NULL,                                   /* NormalizeNameComponentCallback */
    NULL                                    /* NormalizeContextCleanupCallback */
};

/* ============================================================
 * 初始化与卸载
 * ============================================================ */

/*
 * FileFilterInit - 注册 Minifilter 并启动过滤
 *
 * 调用 FltRegisterFilter 向 FltMgr 注册本驱动，
 * 随后调用 FltStartFiltering 开始接收文件操作回调。
 *
 * 参数：
 *   DriverObject - 驱动对象
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 */
NTSTATUS FileFilterInit(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    /* 1. 注册 Minifilter */
    status = FltRegisterFilter(DriverObject,
                               &AndunFilterRegistration,
                               &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FltRegisterFilter 失败: 0x%08X\n", status);
        g_FilterHandle = NULL;
        return status;
    }

    /* 2. 启动过滤 */
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FltStartFiltering 失败: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    DbgPrint("[御天驱动] 文件过滤初始化成功\n");
    return STATUS_SUCCESS;
}

/*
 * FileFilterUnload - 反注册 Minifilter
 *
 * 调用 FltUnregisterFilter 完成清理。
 * 注意：FltUnregisterFilter 内部会触发 AndunFilterUnloadCallback。
 */
VOID FileFilterUnload(VOID)
{
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    DbgPrint("[御天驱动] 文件过滤已卸载\n");
}

/*
 * AndunFilterUnloadCallback - FltMgr 卸载回调
 *
 * 当 FltUnregisterFilter 被调用时由 FltMgr 触发，
 * 这里仅返回 STATUS_SUCCESS 表示允许卸载，
 * 真正的清理工作在 FileFilterUnload 中完成，避免递归调用。
 */
static NTSTATUS FLTAPI AndunFilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[御天驱动] Minifilter 卸载回调触发\n");
    return STATUS_SUCCESS;
}

/* ============================================================
 * Pre-operation 回调
 * ============================================================ */

/*
 * AndunPreOperationCallback - 操作前回调
 *
 * 处理 IRP_MJ_CREATE / IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION，
 * 根据规则引擎匹配结果决定放行或拦截：
 *   - ActionBlock: 完成 IO 请求返回 STATUS_ACCESS_DENIED
 *   - ActionAsk  : 记录事件但放行，由用户态决定后续操作
 *   - ActionAllow: 记录事件并放行
 *
 * 返回值：
 *   FLT_PREOP_SUCCESS_NO_CALLBACK - 放行，不需要 post-operation 回调
 *   FLT_PREOP_COMPLETE            - 完成 IO 请求（用于拦截）
 */
static FLT_PREOP_CALLBACK_STATUS AndunPreOperationCallback(
    PFLT_CALLBACK_DATA   Data,
    PFLT_RELATED_OBJECTS FltObjects,
    PVOID               *CompletionContext)
{
    PFLT_IO_PARAMETER_BLOCK    iopb;
    ULONG                      majorFunction;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS                   nameStatus;
    HANDLE                     pid;
    ULONG                      action;
    ANDUN_EVENT_TYPE           eventType;
    BOOLEAN                    needName;
    FLT_PREOP_CALLBACK_STATUS  result;

    UNREFERENCED_PARAMETER(FltObjects);

    /* 输出参数初始化 */
    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    /* 1. 检查全局开关：文件过滤未启用直接放行 */
    if (g_Config.fileFilterEnabled == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    iopb = Data->Iopb;
    majorFunction = iopb->MajorFunction;
    pid = PsGetCurrentProcessId();
    eventType = EventFileCreate;
    needName = FALSE;
    result = FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* 2. 跳过 paging I/O，避免死锁与递归 */
    if (FlagOn(iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 3. 根据操作类型分流，确定事件类型并判断是否需要获取文件名 */
    switch (majorFunction) {

    case IRP_MJ_CREATE:
    {
        ACCESS_MASK desiredAccess;

        eventType = EventFileCreate;

        /* 仅对带有写入 / 删除意图的创建操作进行过滤 */
        desiredAccess = iopb->Parameters.Create.SecurityContext->DesiredAccess;
        if ((desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)) == 0) {
            /* 纯读取打开，跳过 */
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        needName = TRUE;
        break;
    }

    case IRP_MJ_WRITE:
        eventType = EventFileWrite;
        needName = TRUE;
        break;

    case IRP_MJ_SET_INFORMATION:
    {
        FILE_INFORMATION_CLASS infoClass;

        infoClass = iopb->Parameters.SetFileInformation.FileInformationClass;

        /* 只关心删除和重命名操作 */
        if (infoClass != FileDispositionInformation &&
            infoClass != FileRenameInformation &&
            infoClass != FileRenameInformationEx) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        eventType = EventFileDelete;
        needName = TRUE;
        break;
    }

    default:
        /* 不应到达此处，放行 */
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 4. 获取文件名信息 */
    if (needName) {
        __try {
            nameStatus = FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            nameStatus = GetExceptionCode();
        }

        if (!NT_SUCCESS(nameStatus) || nameInfo == NULL) {
            /* 无法获取文件名（如 paging I/O、预打开阶段等），放行 */
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* 5. 调用规则引擎匹配 */
        action = RuleMatchFile(&nameInfo->Name, HandleToULong(pid));

        /* 6. 构造事件并推入队列 */
        {
            ANDUN_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            AndunFillFileEvent(&event,
                                eventType,
                                (ANDUN_ACTION)action,
                                &nameInfo->Name,
                                pid);
            EventQueuePush(&event);
        }

        /* 7. 释放文件名信息 */
        FltReleaseFileNameInformation(nameInfo);
        nameInfo = NULL;

        /* 8. 根据匹配结果决定返回值 */
        if (action == ActionBlock) {
            /* 阻断：完成 IO 请求返回拒绝访问 */
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            result = FLT_PREOP_COMPLETE;
        } else {
            /* ActionAsk / ActionAllow：放行 */
            result = FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    return result;
}

/* ============================================================
 * 辅助函数
 * ============================================================ */

/*
 * AndunFillFileEvent - 填充 ANDUN_EVENT 结构
 *
 * 根据操作类型、动作、文件名信息、PID 填充事件结构，
 * 进程名通过 PsGetProcessImageFileName 获取（ANSI 转 UNICODE）。
 */
static VOID AndunFillFileEvent(
    PANDUN_EVENT       Event,
    ANDUN_EVENT_TYPE   EventType,
    ANDUN_ACTION       Action,
    PCUNICODE_STRING   FilePath,
    HANDLE             Pid)
{
    PEPROCESS process;
    PCSTR     processNameA;
    LARGE_INTEGER now;

    if (Event == NULL) {
        return;
    }

    RtlZeroMemory(Event, sizeof(ANDUN_EVENT));

    Event->eventType = EventType;
    Event->action    = Action;
    Event->pid       = HandleToULong(Pid);

    /* 获取当前进程名（PsGetProcessImageFileName 返回 ANSI 字符串） */
    process = PsGetCurrentProcess();
    if (process != NULL) {
        processNameA = PsGetProcessImageFileName(process);
        if (processNameA != NULL) {
            AndunAnsiToWide(processNameA, Event->processName, 260);
        }
    }

    /* 拷贝目标文件路径 */
    if (FilePath != NULL) {
        AndunCopyUnicodeToWChar(Event->targetPath, 520, FilePath);
    }

    /* 时间戳：KeQuerySystemTime 返回系统时间（UTC） */
    now.QuadPart = 0;
    KeQuerySystemTime(&now);
    Event->timestamp = now;
}

/*
 * AndunAnsiToWide - 将 ANSI 字符串转换为 UNICODE 字符串
 * 仅处理 ASCII 字符，适用于进程名转换
 */
static VOID AndunAnsiToWide(PCSTR Ansi, PWSTR Wide, ULONG WideChars)
{
    ULONG i;

    if (Wide == NULL || WideChars == 0) {
        return;
    }
    Wide[0] = L'\0';

    if (Ansi == NULL) {
        return;
    }

    for (i = 0; i < WideChars - 1 && Ansi[i] != '\0'; i++) {
        Wide[i] = (WCHAR)(UCHAR)Ansi[i];
    }
    Wide[i] = L'\0';
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
