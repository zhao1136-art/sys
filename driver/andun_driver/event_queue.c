/*
 * event_queue.c - 事件环形队列管理与全局统计
 *
 * 提供内核态事件环形缓冲区，支持各回调模块在不同 IRQL 下并发推送，
 * 并提供用户态批量读取接口。同时定义全局统计变量及辅助函数。
 *
 * 线程安全说明：
 *   - EventQueuePush 可在 DISPATCH_LEVEL 下调用（来自 WFP/微过滤回调）
 *   - EventQueuePop  在 PASSIVE_LEVEL 下调用（IOCTL 处理中）
 *   - 所有共享状态由 KSPIN_LOCK 保护
 */

#include "andun.h"

/* ============================================================
 * 全局统计变量定义（andun.h 中以 extern 声明）
 * ============================================================ */

KSPIN_LOCK g_StatsLock;
ANDUN_STATS g_Stats = {0};

/* ============================================================
 * 事件环形队列内部状态
 * ============================================================ */

static ANDUN_EVENT g_EventQueue[ANDUN_EVENT_QUEUE_SIZE];
static LONG        g_QueueHead;       /* 下一个写入位置 */
static LONG        g_QueueTail;       /* 下一个读取位置 */
static LONG        g_QueueCount;      /* 当前队列中的事件数量 */
static KSPIN_LOCK  g_QueueLock;       /* 保护队列并发访问 */
static BOOLEAN     g_QueueInitialized;/* 队列是否已初始化 */

/* ============================================================
 * 统计辅助函数
 * ============================================================ */

/*
 * StatsIncrement - 原子递增指定计数器
 * 使用 g_StatsLock 保护，保证多回调并发安全
 */
VOID StatsIncrement(ULONG64 *Counter)
{
    KIRQL oldIrql;

    if (Counter == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_StatsLock, &oldIrql);
    (*Counter)++;
    KeReleaseSpinLock(&g_StatsLock, oldIrql);
}

/*
 * StatsEventPushed - 事件入队后更新统计
 * 根据事件类型递增对应分类计数器，并根据动作更新拦截计数
 */
VOID StatsEventPushed(ULONG EventType, ULONG Action)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_StatsLock, &oldIrql);

    g_Stats.totalEvents++;

    if (Action == ActionBlock) {
        g_Stats.blockedEvents++;
    }

    switch (EventType) {
    case EventFileCreate:
    case EventFileWrite:
    case EventFileDelete:
        g_Stats.fileOperations++;
        break;

    case EventProcessCreate:
    case EventProcessTerminate:
        g_Stats.processOperations++;
        break;

    case EventRegistrySet:
    case EventRegistryDelete:
        g_Stats.registryOperations++;
        break;

    case EventNetworkConnect:
        g_Stats.networkOperations++;
        break;

    case EventHandleOpen:
        g_Stats.handleOperations++;
        break;

    default:
        /* EventDriverLoad / EventRootkitDetected 等不计入细分统计 */
        break;
    }

    KeReleaseSpinLock(&g_StatsLock, oldIrql);
}

/* ============================================================
 * 事件队列实现
 * ============================================================ */

/*
 * EventQueueInit - 初始化事件环形队列
 * 初始化自旋锁、清空队列并重置读写指针
 */
VOID EventQueueInit(VOID)
{
    KeInitializeSpinLock(&g_StatsLock);
    KeInitializeSpinLock(&g_QueueLock);

    g_QueueHead = 0;
    g_QueueTail = 0;
    g_QueueCount = 0;
    g_QueueInitialized = TRUE;

    RtlZeroMemory(g_EventQueue, sizeof(g_EventQueue));
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
}

/*
 * EventQueueDestroy - 清理事件队列
 * 标记队列为未初始化并重置状态
 */
VOID EventQueueDestroy(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    g_QueueInitialized = FALSE;
    g_QueueHead = 0;
    g_QueueTail = 0;
    g_QueueCount = 0;
    KeReleaseSpinLock(&g_QueueLock, oldIrql);
}

/*
 * EventQueuePush - 将事件推入环形队列
 *
 * 调用环境：IRQL <= DISPATCH_LEVEL（各回调模块均可调用）
 * 行为：队列满时覆盖最旧事件，并递增 g_Stats.droppedEvents
 */
VOID EventQueuePush(ANDUN_EVENT *Event)
{
    KIRQL   oldIrql;
    BOOLEAN dropped = FALSE;

    if (Event == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_QueueLock, &oldIrql);

    if (!g_QueueInitialized) {
        KeReleaseSpinLock(&g_QueueLock, oldIrql);
        return;
    }

    /* 将事件写入头指针位置 */
    RtlCopyMemory(&g_EventQueue[g_QueueHead], Event, sizeof(ANDUN_EVENT));
    g_QueueHead = (g_QueueHead + 1) % ANDUN_EVENT_QUEUE_SIZE;

    if (g_QueueCount >= ANDUN_EVENT_QUEUE_SIZE) {
        /* 队列已满，覆盖最旧事件，尾指针前移 */
        g_QueueTail = (g_QueueTail + 1) % ANDUN_EVENT_QUEUE_SIZE;
        dropped = TRUE;
    } else {
        g_QueueCount++;
    }

    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    /* 在释放队列锁后更新丢弃计数，避免锁嵌套 */
    if (dropped) {
        StatsIncrement(&g_Stats.droppedEvents);
    }

    /* 更新事件分类统计 */
    StatsEventPushed(Event->eventType, Event->action);
}

/*
 * EventQueuePop - 批量读取事件到调用方缓冲区
 *
 * 调用环境：IRQL = PASSIVE_LEVEL（IOCTL 处理中）
 * 参数：
 *   Buffer   - 接收事件的缓冲区（内核态地址，METHOD_BUFFERED 下由 IO 管理器提供）
 *   MaxCount - 缓冲区最多可容纳的事件数
 * 返回值：实际读取的事件数量
 */
ULONG EventQueuePop(PANDUN_EVENT Buffer, ULONG MaxCount)
{
    KIRQL oldIrql;
    ULONG readCount;
    ULONG i;

    if (Buffer == NULL || MaxCount == 0) {
        return 0;
    }

    KeAcquireSpinLock(&g_QueueLock, &oldIrql);

    if (!g_QueueInitialized) {
        KeReleaseSpinLock(&g_QueueLock, oldIrql);
        return 0;
    }

    /* 计算本次可读取的事件数量 */
    readCount = (ULONG)g_QueueCount;
    if (readCount > MaxCount) {
        readCount = MaxCount;
    }

    /* 从尾指针依次取出事件 */
    for (i = 0; i < readCount; i++) {
        RtlCopyMemory(&Buffer[i],
                       &g_EventQueue[g_QueueTail],
                       sizeof(ANDUN_EVENT));
        g_QueueTail = (g_QueueTail + 1) % ANDUN_EVENT_QUEUE_SIZE;
    }
    g_QueueCount -= (LONG)readCount;

    KeReleaseSpinLock(&g_QueueLock, oldIrql);
    return readCount;
}

/*
 * EventQueueGetCount - 获取当前队列中的事件数量
 */
ULONG EventQueueGetCount(VOID)
{
    KIRQL oldIrql;
    ULONG count;

    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    count = (ULONG)g_QueueCount;
    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    return count;
}
