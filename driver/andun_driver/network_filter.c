/*
 * network_filter.c - WFP (Windows Filtering Platform) 网络过滤模块
 *
 * 通过 WFP 在 ALE 层注册 callout，对 IPv4 出站连接（ALE_AUTH_CONNECT_V4）
 * 与入站连接（ALE_AUTH_RECV_ACCEPT_V4）进行规则匹配，并将网络事件
 * 推入队列供用户态读取决策。
 *
 * 设计说明：
 *   - 通过 andun.h 中 extern 声明的 g_Config 读取 networkFilterEnabled 开关
 *   - WFP callout 注册需要设备对象，创建独立的控制设备对象 \Device\AndunWfp
 *     供 FwpsCalloutRegister0 使用，并在卸载时删除。
 *
 * 线程安全说明：
 *   - AndunNetworkClassify 运行在 IRQL = DISPATCH_LEVEL
 *   - g_Config 读取为原子操作（ULONG 对齐读）
 *   - 初始化/卸载运行在 PASSIVE_LEVEL
 */

#include "andun.h"

/* ============================================================
 * 全局变量
 * ============================================================ */

static HANDLE      g_EngineHandle = NULL;       /* WFP 引擎句柄 */
static UINT32      g_CalloutIdV4 = 0;           /* IPv4 callout ID */
static UINT32      g_CalloutIdV6 = 0;           /* IPv6 callout ID（预留） */
static UINT32      g_FilterIdV4Connect = 0;     /* IPv4 出站连接过滤器 ID */
static UINT32      g_FilterIdV4Accept = 0;      /* IPv4 入站连接过滤器 ID */
static KSPIN_LOCK  g_NetLock;                   /* 保护本地开关的访问 */

/*
 * WFP 专用设备对象（用于 FwpsCalloutRegister0）
 * 由于 device_control.c 中的控制设备对象是 static，无法直接引用，
 * 这里创建独立的控制设备对象供 WFP callout 注册使用。
 */
static PDEVICE_OBJECT g_WfpDeviceObject = NULL;

/* g_Config 在 device_control.c 中定义，通过 andun.h 的 extern 声明引用 */

/* ============================================================
 * 自定义 GUID
 * 直接定义为 const 结构体，避免依赖 initguid.h 实例化
 * ============================================================ */

/* {8A9B3C2D-E4F5-4A1B-9C8D-7E6FA5B4C3D2} - IPv4 callout 标识 */
static const GUID ANDUN_CALLOUT_V4_GUID =
    { 0x8a9b3c2d, 0xe4f5, 0x4a1b, { 0x9c, 0x8d, 0x7e, 0x6f, 0xa5, 0xb4, 0xc3, 0xd2 } };

/* {1A2B3C4D-5E6F-4A5B-8C7D-9E0F1A2B3C4D} - IPv4 出站连接过滤器标识 */
static const GUID ANDUN_FILTER_V4_CONNECT_GUID =
    { 0x1a2b3c4d, 0x5e6f, 0x4a5b, { 0x8c, 0x7d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d } };

/* {2B3C4D5E-6F70-4B5C-9D8E-AF1B2C3D4E5F} - IPv4 入站连接过滤器标识 */
static const GUID ANDUN_FILTER_V4_ACCEPT_GUID =
    { 0x2b3c4d5e, 0x6f70, 0x4b5c, { 0x9d, 0x8e, 0xaf, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f } };

/* ============================================================
 * WFP 回调函数前置声明
 * ============================================================ */

void NTAPI AndunNetworkClassify(
    const FWPS_INCOMING_VALUES0 *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER0 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0 *classifyOut);

NTSTATUS NTAPI AndunNetworkNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID *filterKey,
    const FWPS_FILTER0 *filter);

/* ============================================================
 * 内部辅助函数前置声明
 * ============================================================ */

static VOID AndunIpv4ToStr(UINT32 IpAddr, PWSTR Buffer, ULONG BufferChars);

/* ============================================================
 * 辅助函数实现
 * ============================================================ */

/*
 * AndunIpv4ToStr - 将 IPv4 地址（UINT32，主机字节序）转换为宽字符串
 *
 * WFP 在 ALE 层提供的 IPv4 地址为 FWP_UINT32 类型，主机字节序存储，
 * 最高字节对应地址的第一段。结果格式："a.b.c.d"。
 *
 * 调用环境：任意 IRQL（仅使用栈缓冲区，不依赖分页池函数）
 */
static VOID AndunIpv4ToStr(UINT32 IpAddr, PWSTR Buffer, ULONG BufferChars)
{
    ULONG  b[4];
    ULONG  pos = 0;
    ULONG  i, j;
    WCHAR  tmp[4];
    ULONG  dlen;

    if (Buffer == NULL || BufferChars < 16) {
        return;
    }

    /* 主机字节序：高位为地址首段 */
    b[0] = (IpAddr >> 24) & 0xFF;
    b[1] = (IpAddr >> 16) & 0xFF;
    b[2] = (IpAddr >> 8) & 0xFF;
    b[3] = IpAddr & 0xFF;

    for (i = 0; i < 4; i++) {
        ULONG val = b[i];

        dlen = 0;
        if (val == 0) {
            tmp[0] = L'0';
            dlen = 1;
        } else {
            while (val > 0 && dlen < 4) {
                tmp[dlen] = (WCHAR)(L'0' + (val % 10));
                dlen++;
                val /= 10;
            }
        }

        /* 逆序写入缓冲区 */
        for (j = dlen; j > 0; j--) {
            Buffer[pos++] = tmp[j - 1];
        }

        if (i < 3) {
            Buffer[pos++] = L'.';
        }
    }

    Buffer[pos] = L'\0';
}

/* ============================================================
 * WFP 回调实现
 * ============================================================ */

/*
 * AndunNetworkClassify - WFP 分类回调
 *
 * 在 ALE_AUTH_CONNECT_V4 / ALE_AUTH_RECV_ACCEPT_V4 层被调用，
 * 对每个连接尝试进行规则匹配，根据匹配结果设置允许/阻断动作，
 * 并构造网络事件推入事件队列供用户态读取。
 *
 * 调用环境：IRQL = DISPATCH_LEVEL
 */
void NTAPI AndunNetworkClassify(
    const FWPS_INCOMING_VALUES0 *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER0 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UINT32      remoteIp = 0;
    USHORT      remotePort = 0;
    ULONG       pid = 0;
    WCHAR       ipStr[16];
    ULONG       action;
    ULONG       fieldIdxIp;
    ULONG       fieldIdxPort;
    ANDUN_EVENT event;
    KIRQL       oldIrql;
    BOOLEAN     enabled = FALSE;
    ULONG       i;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /* 1. 校验关键参数 */
    if (inFixedValues == NULL || classifyOut == NULL) {
        return;
    }

    /* 若已被更早的 filter 作出最终决定，直接返回 */
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        return;
    }

    /* 2. 检查网络过滤是否启用（自旋锁保护读取本地开关） */
    KeAcquireSpinLock(&g_NetLock, &oldIrql);
    enabled = g_Config.networkFilterEnabled ? TRUE : FALSE;
    KeReleaseSpinLock(&g_NetLock, oldIrql);

    if (!enabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    /* 3. 根据 layerId 选择对应字段索引（V4 connect / V4 accept 字段索引一致） */
    if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        fieldIdxIp   = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        fieldIdxPort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
    } else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
        fieldIdxIp   = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
        fieldIdxPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
    } else {
        /* 非 IPv4 ALE 层，不处理，放行 */
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    /* 4. 提取远程地址、远程端口 */
    if (inFixedValues->numValues > fieldIdxIp) {
        remoteIp = inFixedValues->incomingValue[fieldIdxIp].value.uint32;
    }
    if (inFixedValues->numValues > fieldIdxPort) {
        remotePort = inFixedValues->incomingValue[fieldIdxPort].value.uint16;
    }

    /* 5. 提取进程 PID（FWPS_METADATA_FIELD_PROCESS_ID 标志存在时才有效） */
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        pid = (ULONG)inMetaValues->processId;
    }

    /* 6. 将 IPv4 地址转换为字符串 */
    AndunIpv4ToStr(remoteIp, ipStr, 16);

    /* 7. 调用规则引擎匹配网络规则 */
    action = RuleMatchNetwork(ipStr, remotePort, pid);

    /* 8. 构造网络事件 */
    RtlZeroMemory(&event, sizeof(event));
    event.eventType  = EventNetworkConnect;
    event.pid        = pid;
    event.ppid       = 0;                       /* WFP 不提供父进程信息 */
    event.remotePort = remotePort;
    event.action     = action;
    KeQuerySystemTime(&event.timestamp);

    /* 拷贝远程地址字符串到事件 */
    for (i = 0; i < 45 && ipStr[i] != L'\0'; i++) {
        event.remoteAddr[i] = ipStr[i];
    }
    event.remoteAddr[i] = L'\0';

    /* 9. 根据匹配结果设置 WFP 动作 */
    switch (action) {
    case ActionBlock:
        /* 阻断连接 */
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        break;

    case ActionAsk:
        /*
         * 询问模式：WFP 无"询问"动作，此处放行连接，
         * 事件以 ActionAsk 推入队列由用户态决策。
         */
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        break;

    case ActionAllow:
    default:
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        break;
    }

    /* 10. 将事件推入队列（EventQueuePush 可在 DISPATCH_LEVEL 调用） */
    EventQueuePush(&event);
}

/*
 * AndunNetworkNotify - WFP 通知回调
 *
 * 当 filter 被添加/删除时由 WFP 调用。本模块不需要处理通知，
 * 简单返回 STATUS_SUCCESS 即可。
 */
NTSTATUS NTAPI AndunNetworkNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID *filterKey,
    const FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

/* ============================================================
 * NetworkFilterInit - 初始化 WFP 网络过滤
 *
 * 执行顺序：
 *   1. 初始化自旋锁与本地开关
 *   2. 创建 WFP 专用设备对象
 *   3. 打开 WFP 引擎
 *   4. 在事务中注册 callout 与 filter
 *   5. 提交事务
 *
 * 失败时按反序回滚已分配的资源。
 * ============================================================ */

NTSTATUS NetworkFilterInit(VOID)
{
    NTSTATUS        status;
    UNICODE_STRING  devName;
    FWPS_CALLOUT0   fwpsCallout;
    FWPM_CALLOUT0   fwpmCallout;
    FWPM_FILTER0    fwpmFilter;
    FWPM_SESSION0   session;
    UINT16          tmpCalloutId = 0;
    UINT64          tmpFilterId = 0;

    /* 1. 初始化自旋锁 */
    KeInitializeSpinLock(&g_NetLock);

    /* 2. 创建 WFP 专用设备对象（用于 FwpsCalloutRegister0） */
    RtlInitUnicodeString(&devName, L"\\Device\\AndunWfp");
    status = IoCreateDevice(
        NULL,                   /* DriverObject - 控制设备可传 NULL */
        0,                      /* DeviceExtensionSize */
        &devName,               /* DeviceName */
        FILE_DEVICE_NETWORK,    /* DeviceType */
        0,                      /* DeviceCharacteristics */
        FALSE,                  /* Exclusive */
        &g_WfpDeviceObject);    /* DeviceObject */
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] WFP IoCreateDevice 失败: 0x%08X\n", status);
        g_WfpDeviceObject = NULL;
        return status;
    }

    /* 3. 打开 WFP 引擎 */
    RtlZeroMemory(&session, sizeof(session));
    status = FwpmEngineOpen0(
        NULL,                   /* serverName - 本地引擎 */
        RPC_C_AUTHN_WINNT,      /* authnService */
        NULL,                   /* authIdentity */
        &session,               /* session 参数 */
        &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpmEngineOpen0 失败: 0x%08X\n", status);
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        g_EngineHandle = NULL;
        return status;
    }

    /* 4. 开始事务（在事务中注册 callout 和 filter，保证原子性） */
    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpmTransactionBegin0 失败: 0x%08X\n", status);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        return status;
    }

    /* 5. 定义 FWPS_CALLOUT0 并注册到内核 callout 驱动 */
    RtlZeroMemory(&fwpsCallout, sizeof(fwpsCallout));
    fwpsCallout.calloutKey     = ANDUN_CALLOUT_V4_GUID;
    fwpsCallout.classifyFn     = AndunNetworkClassify;
    fwpsCallout.notifyFn       = AndunNetworkNotify;
    fwpsCallout.flowDeleteFn   = NULL;

    status = FwpsCalloutRegister0(
        g_WfpDeviceObject,
        &fwpsCallout,
        &tmpCalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpsCalloutRegister0 失败: 0x%08X\n", status);
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        return status;
    }
    g_CalloutIdV4 = (UINT32)tmpCalloutId;

    /* 6. 定义 FWPM_CALLOUT0 并添加到 WFP 引擎（绑定到 ALE_AUTH_CONNECT_V4 层） */
    RtlZeroMemory(&fwpmCallout, sizeof(fwpmCallout));
    fwpmCallout.calloutKey              = ANDUN_CALLOUT_V4_GUID;
    fwpmCallout.displayData.name        = L"御天网络过滤 Callout V4";
    fwpmCallout.displayData.description = L"御天 WFP ALE 层网络连接过滤 Callout";
    fwpmCallout.providerKey             = NULL;
    fwpmCallout.applicableLayer         = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(
        g_EngineHandle,
        NULL,                   /* PSECURITY_DESCRIPTOR */
        &fwpmCallout,
        &tmpCalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpmCalloutAdd0 失败: 0x%08X\n", status);
        FwpsCalloutUnregisterById0((UINT16)g_CalloutIdV4);
        g_CalloutIdV4 = 0;
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        return status;
    }

    /* 7. 添加出站连接过滤器（ALE_AUTH_CONNECT_V4） */
    RtlZeroMemory(&fwpmFilter, sizeof(fwpmFilter));
    fwpmFilter.filterKey              = ANDUN_FILTER_V4_CONNECT_GUID;
    fwpmFilter.displayData.name       = L"御天出站连接过滤 V4";
    fwpmFilter.displayData.description = L"对 IPv4 出站连接调用御天 callout 进行规则匹配";
    fwpmFilter.layerKey               = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    fwpmFilter.subLayerKey            = FWPM_SUBLAYER_UNIVERSAL;
    fwpmFilter.weight.type            = FWP_EMPTY;          /* 默认权重 */
    fwpmFilter.action.type            = FWP_ACTION_CALLOUT_TERMINATING;
    fwpmFilter.action.calloutKey      = ANDUN_CALLOUT_V4_GUID;
    fwpmFilter.filterCondition        = NULL;               /* 无条件，匹配所有 */
    fwpmFilter.numFilterConditions    = 0;

    status = FwpmFilterAdd0(
        g_EngineHandle,
        &fwpmFilter,
        NULL,                   /* PSECURITY_DESCRIPTOR */
        &tmpFilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpmFilterAdd0(Connect) 失败: 0x%08X\n", status);
        FwpsCalloutUnregisterById0((UINT16)g_CalloutIdV4);
        g_CalloutIdV4 = 0;
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        return status;
    }
    g_FilterIdV4Connect = (UINT32)tmpFilterId;

    /* 8. 添加入站连接过滤器（ALE_AUTH_RECV_ACCEPT_V4） */
    RtlZeroMemory(&fwpmFilter, sizeof(fwpmFilter));
    fwpmFilter.filterKey              = ANDUN_FILTER_V4_ACCEPT_GUID;
    fwpmFilter.displayData.name       = L"御天入站连接过滤 V4";
    fwpmFilter.displayData.description = L"对 IPv4 入站连接调用御天 callout 进行规则匹配";
    fwpmFilter.layerKey               = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    fwpmFilter.subLayerKey            = FWPM_SUBLAYER_UNIVERSAL;
    fwpmFilter.weight.type            = FWP_EMPTY;
    fwpmFilter.action.type            = FWP_ACTION_CALLOUT_TERMINATING;
    fwpmFilter.action.calloutKey      = ANDUN_CALLOUT_V4_GUID;
    fwpmFilter.filterCondition        = NULL;
    fwpmFilter.numFilterConditions    = 0;

    status = FwpmFilterAdd0(
        g_EngineHandle,
        &fwpmFilter,
        NULL,
        &tmpFilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpmFilterAdd0(Accept) 失败: 0x%08X\n", status);
        FwpmFilterDeleteById0(g_EngineHandle, (UINT64)g_FilterIdV4Connect);
        g_FilterIdV4Connect = 0;
        FwpsCalloutUnregisterById0((UINT16)g_CalloutIdV4);
        g_CalloutIdV4 = 0;
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        return status;
    }
    g_FilterIdV4Accept = (UINT32)tmpFilterId;

    /* 9. 提交事务 */
    status = FwpmTransactionCommit0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FwpmTransactionCommit0 失败: 0x%08X\n", status);
        FwpmFilterDeleteById0(g_EngineHandle, (UINT64)g_FilterIdV4Accept);
        g_FilterIdV4Accept = 0;
        FwpmFilterDeleteById0(g_EngineHandle, (UINT64)g_FilterIdV4Connect);
        g_FilterIdV4Connect = 0;
        FwpsCalloutUnregisterById0((UINT16)g_CalloutIdV4);
        g_CalloutIdV4 = 0;
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
        return status;
    }

    DbgPrint("[御天驱动] WFP 网络过滤初始化成功\n");
    return STATUS_SUCCESS;
}

/* ============================================================
 * NetworkFilterUnload - 清理 WFP 资源
 *
 * 按注册的反序依次删除：过滤器 -> callout -> 引擎 -> 设备对象
 * ============================================================ */

VOID NetworkFilterUnload(VOID)
{
    /* 1. 删除出站连接过滤器 */
    if (g_EngineHandle != NULL && g_FilterIdV4Connect != 0) {
        FwpmFilterDeleteById0(g_EngineHandle, (UINT64)g_FilterIdV4Connect);
        g_FilterIdV4Connect = 0;
    }

    /* 2. 删除入站连接过滤器 */
    if (g_EngineHandle != NULL && g_FilterIdV4Accept != 0) {
        FwpmFilterDeleteById0(g_EngineHandle, (UINT64)g_FilterIdV4Accept);
        g_FilterIdV4Accept = 0;
    }

    /* 3. 反注册 callout */
    if (g_CalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0((UINT16)g_CalloutIdV4);
        g_CalloutIdV4 = 0;
    }

    /* 4. 关闭 WFP 引擎 */
    if (g_EngineHandle != NULL) {
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    /* 5. 删除 WFP 专用设备对象 */
    if (g_WfpDeviceObject != NULL) {
        IoDeleteDevice(g_WfpDeviceObject);
        g_WfpDeviceObject = NULL;
    }

    DbgPrint("[御天驱动] WFP 网络过滤已卸载\n");
}
