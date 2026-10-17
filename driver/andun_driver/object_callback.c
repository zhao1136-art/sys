/*
 * object_callback.c - 对象句柄回调与受保护进程管理
 *
 * 一、受保护 PID 管理：
 *   维护一个全局数组记录被保护的进程 ID，使用自旋锁保证并发安全，
 *   支持添加/移除/查询操作。用于防止受保护进程被恶意打开危险权限。
 *
 * 二、对象回调：
 *   通过 ObRegisterCallbacks 注册进程/线程对象句柄打开前的回调，
 *   当发起方对受保护进程请求危险权限时（如 PROCESS_TERMINATE、
 *   THREAD_TERMINATE 等），剥离这些权限位并推送事件到队列。
 *
 * 调用环境：PASSIVE_LEVEL
 * 兼容性：Windows Vista+（ObRegisterCallbacks）
 */

#include "andun.h"

/* ============================================================
 * 危险权限位定义
 *
 * WDK 头文件中 PROCESS_* / THREAD_* 权限位定义在 winnt.h 中，
 * 内核态未必可见，这里显式定义避免依赖。
 * ============================================================ */

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE       0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD   0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION    0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE        0x0020
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE        0x0001
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT      0x0010
#endif

/* 进程危险权限掩码：终止 + 写内存 + VM操作 + 创建线程 */
#define ANDUN_PROCESS_DANGEROUS_MASK    (PROCESS_TERMINATE       | \
                                         PROCESS_VM_WRITE        | \
                                         PROCESS_VM_OPERATION    | \
                                         PROCESS_CREATE_THREAD)

/* 线程危险权限掩码：终止 + 设置上下文 */
#define ANDUN_THREAD_DANGEROUS_MASK     (THREAD_TERMINATE | THREAD_SET_CONTEXT)

/* ============================================================
 * 受保护 PID 管理全局变量
 * ============================================================ */

static ULONG       g_ProtectedPids[ANDUN_MAX_PROTECTED_PIDS] = {0};
static KSPIN_LOCK  g_PidLock;
static ULONG       g_PidCount = 0;

/* ============================================================
 * 对象回调全局变量
 * ============================================================ */

static OB_CALLBACK_REGISTRATION   g_ObCallbackReg;
static PVOID                      g_ObRegistrationHandle = NULL;
static OB_OPERATION_REGISTRATION  g_ObOps[2];   /* [0]=进程  [1]=线程 */

/*
 * device_control.c 中定义的全局配置。
 * 注意：device_control.c 中的 g_Config 必须去掉 static 修饰符，
 * 才能在本文件中以 extern 方式引用。
 */
extern ANDUN_CONFIG g_Config;

/* ============================================================
 * 受保护 PID 管理实现
 * ============================================================ */

/*
 * ProtectedPidInit - 初始化受保护 PID 列表
 * 初始化自旋锁，清空 PID 数组与计数
 */
VOID ProtectedPidInit(VOID)
{
    KeInitializeSpinLock(&g_PidLock);
    RtlZeroMemory(g_ProtectedPids, sizeof(g_ProtectedPids));
    g_PidCount = 0;
}

/*
 * ProtectedPidDestroy - 清理受保护 PID 列表
 */
VOID ProtectedPidDestroy(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    RtlZeroMemory(g_ProtectedPids, sizeof(g_ProtectedPids));
    g_PidCount = 0;
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

/*
 * ProtectedPidAdd - 添加受保护 PID
 *
 * 若 PID 已存在则视为成功（幂等）；若数组已满则返回 FALSE。
 * 成功添加时会递增 g_Stats.protectedPids 统计。
 */
BOOLEAN ProtectedPidAdd(ULONG Pid)
{
    KIRQL   oldIrql;
    ULONG   i;
    BOOLEAN added = FALSE;

    if (Pid == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    /* 1. 先检查是否已存在（幂等） */
    for (i = 0; i < g_PidCount; i++) {
        if (g_ProtectedPids[i] == Pid) {
            KeReleaseSpinLock(&g_PidLock, oldIrql);
            return TRUE;
        }
    }

    /* 2. 数组未满则追加 */
    if (g_PidCount < ANDUN_MAX_PROTECTED_PIDS) {
        g_ProtectedPids[g_PidCount] = Pid;
        g_PidCount++;
        added = TRUE;
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);

    /* 3. 更新统计（在统计锁下） */
    if (added) {
        StatsIncrement(&g_Stats.protectedPids);
    }

    return added;
}

/*
 * ProtectedPidRemove - 移除受保护 PID
 *
 * 找到后用后续元素前移填补空位，保持数组紧凑。
 * 成功移除时会递减 g_Stats.protectedPids 统计。
 */
BOOLEAN ProtectedPidRemove(ULONG Pid)
{
    KIRQL   oldIrql;
    ULONG   i;
    ULONG   j;
    BOOLEAN removed = FALSE;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    for (i = 0; i < g_PidCount; i++) {
        if (g_ProtectedPids[i] == Pid) {
            /* 用后续元素前移填补空位 */
            for (j = i; j < g_PidCount - 1; j++) {
                g_ProtectedPids[j] = g_ProtectedPids[j + 1];
            }
            g_ProtectedPids[g_PidCount - 1] = 0;
            g_PidCount--;
            removed = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);

    /* 更新统计：避免锁嵌套，单独获取统计锁 */
    if (removed) {
        KIRQL statIrql;
        KeAcquireSpinLock(&g_StatsLock, &statIrql);
        if (g_Stats.protectedPids > 0) {
            g_Stats.protectedPids--;
        }
        KeReleaseSpinLock(&g_StatsLock, statIrql);
    }

    return removed;
}

/*
 * ProtectedPidIsProtected - 检查 PID 是否在受保护列表中
 */
BOOLEAN ProtectedPidIsProtected(ULONG Pid)
{
    KIRQL   oldIrql;
    ULONG   i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    for (i = 0; i < g_PidCount; i++) {
        if (g_ProtectedPids[i] == Pid) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return found;
}

/* ============================================================
 * 内部辅助函数
 * ============================================================ */

/*
 * AndunFillHandleEvent - 填充句柄打开事件并推入队列
 *
 * 参数：
 *   TargetPid      - 被打开句柄的目标进程 ID
 *   DesiredAccess  - 原始请求权限
 *   StrippedAccess - 被剥离的权限位
 *   Action         - ActionAllow / ActionBlock
 *
 * 字段映射说明：
 *   event.ppid        <- TargetPid（受保护的目标进程）
 *   event.remotePort  <- 被剥离的权限位低 16 位（复用字段记录权限信息）
 */
static VOID AndunFillHandleEvent(ULONG TargetPid,
                                 ULONG DesiredAccess,
                                 ULONG StrippedAccess,
                                 ULONG Action)
{
    ANDUN_EVENT event;

    RtlZeroMemory(&event, sizeof(event));

    event.eventType = EventHandleOpen;
    event.pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.ppid = TargetPid;
    event.remotePort = (USHORT)(StrippedAccess & 0xFFFF);
    event.action = Action;
    KeQuerySystemTime(&event.timestamp);

    EventQueuePush(&event);
}

/* ============================================================
 * 对象回调实现
 * ============================================================ */

/*
 * AndunPreObjectOperation - 对象句柄打开前回调
 *
 * 当发起方打开进程/线程句柄时被调用：
 *   - 进程对象：若目标进程在受保护列表中，且请求了危险权限，
 *     则剥离危险权限位并推送事件。
 *   - 线程对象：若线程所属进程在受保护列表中，且请求了危险权限，
 *     则剥离并推送事件。
 *
 * 注意：OB 回调不能直接拒绝句柄打开（不返回 OB_PREOP_COMPLETE），
 * 只能通过修改 DesiredAccess 削弱权限。
 *
 * 参数：
 *   Context        - 注册时传入的上下文（本驱动为 NULL）
 *   OperationInfo  - 操作信息，包含对象、权限等
 */
OB_PREOP_CALLBACK_STATUS AndunPreObjectOperation(PVOID Context,
                                                 POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    ULONG targetPid;
    ULONG desiredAccess;
    ULONG stripped;

    UNREFERENCED_PARAMETER(Context);

    /* 1. 全局开关：未启用对象回调直接放行 */
    if (!g_Config.objectCallbackEnabled) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInfo == NULL || OperationInfo->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    /* 2. 进程对象处理 */
    if (OperationInfo->ObjectType == *PsProcessType) {
        targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(OperationInfo->Object);
        if (!ProtectedPidIsProtected(targetPid)) {
            return OB_PREOP_SUCCESS;
        }

        /* 取出请求的权限 */
        desiredAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;

        /* 检查是否包含危险权限 */
        if ((desiredAccess & ANDUN_PROCESS_DANGEROUS_MASK) != 0) {
            stripped = desiredAccess & ANDUN_PROCESS_DANGEROUS_MASK;

            /* 剥离危险权限位 */
            OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &=
                ~ANDUN_PROCESS_DANGEROUS_MASK;

            /* 推送事件（动作为 Block，因为已削弱权限） */
            AndunFillHandleEvent(targetPid, desiredAccess, stripped, ActionBlock);
        }

        return OB_PREOP_SUCCESS;
    }

    /* 3. 线程对象处理 */
    if (OperationInfo->ObjectType == *PsThreadType) {
        targetPid = (ULONG)(ULONG_PTR)PsGetThreadProcessId(OperationInfo->Object);
        if (!ProtectedPidIsProtected(targetPid)) {
            return OB_PREOP_SUCCESS;
        }

        desiredAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;

        if ((desiredAccess & ANDUN_THREAD_DANGEROUS_MASK) != 0) {
            stripped = desiredAccess & ANDUN_THREAD_DANGEROUS_MASK;

            OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &=
                ~ANDUN_THREAD_DANGEROUS_MASK;

            AndunFillHandleEvent(targetPid, desiredAccess, stripped, ActionBlock);
        }

        return OB_PREOP_SUCCESS;
    }

    /* 4. 其他对象类型放行 */
    return OB_PREOP_SUCCESS;
}

/* ============================================================
 * 初始化与卸载
 * ============================================================ */

/*
 * ObjectCallbackInit - 注册对象回调
 *
 * 注册进程与线程两类对象的句柄创建/复制 Pre-operation 回调。
 * Altitude 字符串需为唯一值，使用 "321000" 作为本驱动占位值。
 *
 * 参数：
 *   DriverObject - 驱动对象（仅用于关联，本驱动未直接使用）
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 */
NTSTATUS ObjectCallbackInit(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS      status;
    UNICODE_STRING altitude;

    UNREFERENCED_PARAMETER(DriverObject);

    /* 1. 初始化进程对象操作注册项 */
    g_ObOps[0].ObjectType = PsProcessType;
    g_ObOps[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOps[0].PreOperation = AndunPreObjectOperation;
    g_ObOps[0].PostOperation = NULL;

    /* 2. 初始化线程对象操作注册项 */
    g_ObOps[1].ObjectType = PsThreadType;
    g_ObOps[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOps[1].PreOperation = AndunPreObjectOperation;
    g_ObOps[1].PostOperation = NULL;

    /* 3. 填充注册结构 */
    RtlZeroMemory(&g_ObCallbackReg, sizeof(g_ObCallbackReg));
    g_ObCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    g_ObCallbackReg.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&altitude, L"321000");
    g_ObCallbackReg.Altitude = altitude;
    g_ObCallbackReg.Context = NULL;
    g_ObCallbackReg.OperationRegistration = g_ObOps;

    /* 4. 注册回调 */
    status = ObRegisterCallbacks(&g_ObCallbackReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] ObRegisterCallbacks 失败: 0x%08X\n", status);
        g_ObRegistrationHandle = NULL;
        return status;
    }

    DbgPrint("[御天驱动] 对象回调初始化成功\n");
    return STATUS_SUCCESS;
}

/*
 * ObjectCallbackUnload - 反注册对象回调
 */
VOID ObjectCallbackUnload(VOID)
{
    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }

    DbgPrint("[御天驱动] 对象回调已卸载\n");
}
