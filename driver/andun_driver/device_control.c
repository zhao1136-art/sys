/*
 * device_control.c - 设备对象和 IOCTL 分发
 *
 * 负责创建控制设备对象、符号链接，并处理用户态下发的 IOCTL 请求，
 * 包括事件读取、规则管理、配置读写、PID 保护、统计查询等。
 */

#include "andun.h"

/* ============================================================
 * 全局变量
 * ============================================================ */

/* 控制设备对象指针 */
static PDEVICE_OBJECT g_DeviceObject = NULL;

/* 当前驱动配置：默认启用除 rootkit 扫描外的所有模块
 * 注意：非 static，供其他子模块（file_filter.c / process_callback.c 等）共享访问 */
ANDUN_CONFIG g_Config = { 1, 1, 1, 1, 1, 0 };

/* ============================================================
 * DeviceControlInit - 创建控制设备对象和符号链接
 *
 * 参数：
 *   DriverObject - 驱动对象
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 * ============================================================ */

NTSTATUS DeviceControlInit(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(ANDUN_DEVICE_NAME);
    UNICODE_STRING symlinkName = RTL_CONSTANT_STRING(ANDUN_SYMLINK_NAME);
    PDEVICE_OBJECT deviceObject = NULL;

    /* 1. 创建设备对象 */
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] IoCreateDevice 失败: 0x%08X\n", status);
        return status;
    }

    /* 2. 创建符号链接（供用户态通过 \\\\.\\AndunDriver 访问） */
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[御天驱动] IoCreateSymbolicLink 失败: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    /* 3. 设置设备标志：使用缓冲 IO */
    deviceObject->Flags |= DO_BUFFERED_IO;

    /* 4. 清除 DO_DEVICE_INITIALIZING 标志，使设备可被访问 */
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* 5. 保存到全局变量 */
    g_DeviceObject = deviceObject;

    DbgPrint("[御天驱动] 设备控制初始化成功\n");
    return STATUS_SUCCESS;
}

/* ============================================================
 * DeviceControlUnload - 删除设备对象和符号链接
 * ============================================================ */

VOID DeviceControlUnload(VOID)
{
    UNICODE_STRING symlinkName = RTL_CONSTANT_STRING(ANDUN_SYMLINK_NAME);

    /* 1. 删除符号链接 */
    IoDeleteSymbolicLink(&symlinkName);

    /* 2. 删除设备对象 */
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[御天驱动] 设备控制已卸载\n");
}

/* ============================================================
 * DeviceControlIoctlDispatch - IOCTL 分发函数
 *
 * 根据用户态下发的 IoControlCode 调用对应子模块接口。
 * ============================================================ */

NTSTATUS DeviceControlIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    PIO_STACK_LOCATION ioStack;
    ULONG ioControlCode;
    PVOID systemBuffer;
    ULONG inputLength;
    ULONG outputLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    /* 1. 获取当前 IRP 栈位置 */
    ioStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;

    /* 2. 根据 IoControlCode 分发处理 */
    switch (ioControlCode) {

    /* --- 批量读取事件 --- */
    case IOCTL_ANDUN_GET_EVENTS:
    {
        ULONG maxEvents;
        ULONG eventsRead;

        if (systemBuffer == NULL || outputLength < sizeof(ANDUN_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        /* 最大可读取数量 = OutputBufferLength / sizeof(ANDUN_EVENT) */
        maxEvents = outputLength / sizeof(ANDUN_EVENT);
        eventsRead = EventQueuePop((PANDUN_EVENT)systemBuffer, maxEvents);
        information = (ULONG_PTR)eventsRead * sizeof(ANDUN_EVENT);
        status = STATUS_SUCCESS;
        break;
    }

    /* --- 添加规则 --- */
    case IOCTL_ANDUN_ADD_RULE:
    {
        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = RuleEngineAddRule((PANDUN_RULE)systemBuffer);
        break;
    }

    /* --- 删除规则 --- */
    case IOCTL_ANDUN_DEL_RULE:
    {
        if (systemBuffer == NULL || inputLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = RuleEngineDelRule(*(PULONG)systemBuffer);
        break;
    }

    /* --- 清空所有规则 --- */
    case IOCTL_ANDUN_CLEAR_RULES:
        RuleEngineClearRules();
        status = STATUS_SUCCESS;
        break;

    /* --- 设置配置 --- */
    case IOCTL_ANDUN_SET_CONFIG:
        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&g_Config, systemBuffer, sizeof(ANDUN_CONFIG));
        status = STATUS_SUCCESS;
        break;

    /* --- 获取配置 --- */
    case IOCTL_ANDUN_GET_CONFIG:
        if (systemBuffer == NULL || outputLength < sizeof(ANDUN_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(systemBuffer, &g_Config, sizeof(ANDUN_CONFIG));
        information = sizeof(ANDUN_CONFIG);
        status = STATUS_SUCCESS;
        break;

    /* --- 添加受保护 PID --- */
    case IOCTL_ANDUN_PROTECT_PID:
    {
        PANDUN_PID_REQUEST req;

        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_PID_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PANDUN_PID_REQUEST)systemBuffer;
        ProtectedPidAdd(req->pid);
        status = STATUS_SUCCESS;
        break;
    }

    /* --- 移除受保护 PID --- */
    case IOCTL_ANDUN_UNPROTECT_PID:
    {
        PANDUN_PID_REQUEST req;

        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_PID_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PANDUN_PID_REQUEST)systemBuffer;
        ProtectedPidRemove(req->pid);
        status = STATUS_SUCCESS;
        break;
    }

    /* --- 获取统计信息（用自旋锁保护读取） --- */
    case IOCTL_ANDUN_GET_STATS:
    {
        KIRQL oldIrql;

        if (systemBuffer == NULL || outputLength < sizeof(ANDUN_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&g_StatsLock, &oldIrql);
        RtlCopyMemory(systemBuffer, &g_Stats, sizeof(ANDUN_STATS));
        KeReleaseSpinLock(&g_StatsLock, oldIrql);

        information = sizeof(ANDUN_STATS);
        status = STATUS_SUCCESS;
        break;
    }

    /* --- Rootkit 扫描 --- */
    case IOCTL_ANDUN_ROOTKIT_SCAN:
    {
        if (systemBuffer == NULL || outputLength < sizeof(ANDUN_ROOTKIT_SCAN_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = RootkitScanRun((PANDUN_ROOTKIT_SCAN_RESULT)systemBuffer);
        if (NT_SUCCESS(status)) {
            information = sizeof(ANDUN_ROOTKIT_SCAN_RESULT);
        }
        break;
    }

    /* --- 自保护配置：0=进程 1=文件 2=注册表 3=服务 --- */
    case IOCTL_ANDUN_SELFPROTECT_PROCESS:
    case IOCTL_ANDUN_SELFPROTECT_FILE:
    case IOCTL_ANDUN_SELFPROTECT_REGISTRY:
    case IOCTL_ANDUN_SELFPROTECT_SERVICE:
    {
        ULONG cfgType = 0;
        switch (ioControlCode) {
            case IOCTL_ANDUN_SELFPROTECT_FILE:     cfgType = 1; break;
            case IOCTL_ANDUN_SELFPROTECT_REGISTRY: cfgType = 2; break;
            case IOCTL_ANDUN_SELFPROTECT_SERVICE:  cfgType = 3; break;
            default:                               cfgType = 0; break;
        }
        if (systemBuffer == NULL || inputLength < 8) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SelfProtectSetConfig(cfgType, systemBuffer, inputLength);
        break;
    }

    /* --- 处置响应：终止进程 --- */
    case IOCTL_ANDUN_RESPONSE_KILL_PROCESS:
    {
        PANDUN_RESPONSE_KILL_PROCESS req;
        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_RESPONSE_KILL_PROCESS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PANDUN_RESPONSE_KILL_PROCESS)systemBuffer;
        status = ResponseKillProcess(req->target_pid, req->force != 0);
        break;
    }

    /* --- 处置响应：隔离文件 --- */
    case IOCTL_ANDUN_RESPONSE_QUARANTINE_FILE:
    {
        PANDUN_RESPONSE_QUARANTINE_FILE req;
        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_RESPONSE_QUARANTINE_FILE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PANDUN_RESPONSE_QUARANTINE_FILE)systemBuffer;
        status = ResponseQuarantineFile(req->file_path, req->quarantine_dir);
        break;
    }

    /* --- 处置响应：下发拦截规则 --- */
    case IOCTL_ANDUN_RESPONSE_BLOCK_RULE:
    {
        PANDUN_RESPONSE_BLOCK_RULE req;
        if (systemBuffer == NULL || inputLength < sizeof(ANDUN_RESPONSE_BLOCK_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PANDUN_RESPONSE_BLOCK_RULE)systemBuffer;
        status = ResponseBlockRule(&req->rule, req->auto_remove_sec);
        break;
    }

    /* --- 未知 IOCTL --- */
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    /* 3. 完成 IRP */
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    /* 4. 返回状态 */
    return status;
}
