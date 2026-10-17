/*
 * driver_main.c - 御天内核驱动主入口
 *
 * 负责驱动加载/卸载流程，按顺序初始化各子模块，
 * 卸载时按反序清理，保证资源不泄漏。
 *
 * 注意：g_Stats 和 g_StatsLock 在 event_queue.c 中定义，
 *       本文件仅负责初始化它们的值，不重新定义。
 */

#include "andun.h"

/* ============================================================
 * 内部函数前置声明
 * ============================================================ */

static NTSTATUS AndunDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* ============================================================
 * DriverEntry - 驱动入口函数
 *
 * 执行顺序：
 *   1. 初始化全局统计与自旋锁
 *   2. 初始化事件队列
 *   3. 初始化规则引擎
 *   4. 初始化受保护 PID 列表
 *   5. 设置卸载函数
 *   6. 初始化设备控制（设备对象 + 符号链接）
 *   7. 按顺序初始化各子模块（失败时反序回滚）
 *   8. 设置 IRP 分发函数
 *   9. 打印加载成功信息
 *  10. 返回 STATUS_SUCCESS
 * ============================================================ */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* 1. 初始化全局统计 g_Stats 和 g_StatsLock */
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    KeInitializeSpinLock(&g_StatsLock);

    /* 2. 初始化事件队列 */
    EventQueueInit();

    /* 3. 初始化规则引擎 */
    RuleEngineInit();

    /* 4. 初始化受保护 PID 列表 */
    ProtectedPidInit();

    /* 5. 设置卸载函数 */
    DriverObject->DriverUnload = DriverUnload;

    /* 6. 初始化设备控制（创建设备对象和符号链接） */
    status = DeviceControlInit(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] DeviceControlInit 失败: 0x%08X\n", status);
        goto fail_event;
    }

    /* 7. 按顺序初始化各子模块（每个失败时回滚已初始化模块） */

    /* a. Minifilter 文件过滤 */
    status = FileFilterInit(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] FileFilterInit 失败: 0x%08X\n", status);
        goto fail_device;
    }

    /* b. 进程创建回调 */
    status = ProcessCallbackInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] ProcessCallbackInit 失败: 0x%08X\n", status);
        goto fail_file;
    }

    /* c. 注册表回调 */
    status = RegistryCallbackInit(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] RegistryCallbackInit 失败: 0x%08X\n", status);
        goto fail_process;
    }

    /* d. 对象句柄回调 */
    status = ObjectCallbackInit(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] ObjectCallbackInit 失败: 0x%08X\n", status);
        goto fail_registry;
    }

    /* e. WFP 网络过滤 */
    status = NetworkFilterInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] NetworkFilterInit 失败: 0x%08X\n", status);
        goto fail_object;
    }

    /* f. Rootkit 扫描模块（无初始化资源，仅预留） */
    /* g. 自保护模块：默认安装目录为空，由用户态通过 IOCTL 下发 */
    status = SelfProtectInit(NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] SelfProtectInit 失败: 0x%08X\n", status);
        goto fail_network;
    }

    /* 8. 设置各 IRP 分发函数 */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = AndunDispatchCreateClose;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlIoctlDispatch;

    /* 9. 打印加载成功信息 */
    DbgPrint("[御天驱动] 驱动加载成功\n");

    /* 10. 返回成功 */
    return STATUS_SUCCESS;

    /* ===== 反序回滚已初始化的模块 ===== */
fail_network:
    NetworkFilterUnload();
fail_object:
    ObjectCallbackUnload();
fail_registry:
    RegistryCallbackUnload();
fail_process:
    ProcessCallbackUnload();
fail_file:
    FileFilterUnload();
fail_device:
    DeviceControlUnload();
fail_event:
    ProtectedPidDestroy();
    RuleEngineDestroy();
    EventQueueDestroy();

    DbgPrint("[御天驱动] 驱动加载失败: 0x%08X\n", status);
    return status;
}

/* ============================================================
 * DriverUnload - 驱动卸载函数
 *
 * 按加载的反序依次卸载各子模块，确保资源正确释放。
 * ============================================================ */

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* 1. 卸载自保护模块 */
    SelfProtectUnload();

    /* 2. Rootkit 扫描模块清理 */
    RootkitScanUnload();

    /* 3. 卸载 WFP 网络过滤 */
    NetworkFilterUnload();

    /* 2. 卸载对象句柄回调 */
    ObjectCallbackUnload();

    /* 3. 卸载注册表回调 */
    RegistryCallbackUnload();

    /* 4. 卸载进程创建回调 */
    ProcessCallbackUnload();

    /* 5. 卸载 Minifilter 文件过滤 */
    FileFilterUnload();

    /* 6. 卸载设备控制（删除设备对象和符号链接） */
    DeviceControlUnload();

    /* 7. 销毁受保护 PID 列表 */
    ProtectedPidDestroy();

    /* 8. 销毁规则引擎 */
    RuleEngineDestroy();

    /* 9. 销毁事件队列 */
    EventQueueDestroy();

    /* 10. 打印卸载完成信息 */
    DbgPrint("[御天驱动] 驱动卸载完成\n");
}

/* ============================================================
 * AndunDispatchCreateClose
 *   - 处理 IRP_MJ_CREATE / IRP_MJ_CLOSE
 *   - 简单成功返回，不进行额外处理
 * ============================================================ */

static NTSTATUS AndunDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
