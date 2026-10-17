/*
 * andun.h - 御天内核驱动公共头文件
 *
 * 定义 IOCTL 控制码、数据结构、函数声明，
 * 供所有驱动子模块共享。
 */

#pragma once

#include <ntddk.h>
#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ndis.h>
#include <ntstrsafe.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

#define ANDUN_DEVICE_NAME       L"\\Device\\AndunDriver"
#define ANDUN_SYMLINK_NAME      L"\\DosDevices\\AndunDriver"
#define ANDUN_USERMODE_PATH     L"\\\\.\\AndunDriver"

#define ANDUN_MAX_RULES         1024
#define ANDUN_EVENT_QUEUE_SIZE  256
#define ANDUN_MAX_PROTECTED_PIDS 64
#define ANDUN_MAX_PATTERN_LEN   520

/* ============================================================
 * IOCTL 控制码
 * ============================================================ */

#define ANDUN_IOCTL_BASE  0x8000

#define IOCTL_ANDUN_GET_EVENTS     CTL_CODE(ANDUN_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_ADD_RULE      CTL_CODE(ANDUN_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_DEL_RULE      CTL_CODE(ANDUN_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_CLEAR_RULES   CTL_CODE(ANDUN_IOCTL_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_SET_CONFIG    CTL_CODE(ANDUN_IOCTL_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_GET_CONFIG    CTL_CODE(ANDUN_IOCTL_BASE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_PROTECT_PID   CTL_CODE(ANDUN_IOCTL_BASE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_UNPROTECT_PID CTL_CODE(ANDUN_IOCTL_BASE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_ROOTKIT_SCAN  CTL_CODE(ANDUN_IOCTL_BASE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_GET_STATS     CTL_CODE(ANDUN_IOCTL_BASE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 自保护 IOCTL（进程/文件/注册表/服务防护） */
#define IOCTL_ANDUN_SELFPROTECT_PROCESS  CTL_CODE(ANDUN_IOCTL_BASE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_SELFPROTECT_FILE     CTL_CODE(ANDUN_IOCTL_BASE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_SELFPROTECT_REGISTRY CTL_CODE(ANDUN_IOCTL_BASE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_SELFPROTECT_SERVICE  CTL_CODE(ANDUN_IOCTL_BASE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 处置响应 IOCTL（终止进程/隔离文件/下发拦截规则） */
#define IOCTL_ANDUN_RESPONSE_KILL_PROCESS   CTL_CODE(ANDUN_IOCTL_BASE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_RESPONSE_QUARANTINE_FILE CTL_CODE(ANDUN_IOCTL_BASE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANDUN_RESPONSE_BLOCK_RULE      CTL_CODE(ANDUN_IOCTL_BASE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ============================================================
 * 事件类型枚举
 * ============================================================ */

typedef enum _ANDUN_EVENT_TYPE {
    EventFileCreate = 1,
    EventFileWrite,
    EventFileDelete,
    EventProcessCreate,
    EventProcessTerminate,
    EventRegistrySet,
    EventRegistryDelete,
    EventNetworkConnect,
    EventHandleOpen,
    EventDriverLoad,
    EventRootkitDetected,
} ANDUN_EVENT_TYPE;

/* ============================================================
 * 动作枚举
 * ============================================================ */

typedef enum _ANDUN_ACTION {
    ActionAllow = 0,
    ActionBlock = 1,
    ActionAsk   = 2,
} ANDUN_ACTION;

/* ============================================================
 * 规则类型枚举
 * ============================================================ */

typedef enum _ANDUN_RULE_TYPE {
    RuleTypeFile     = 0,
    RuleTypeProcess  = 1,
    RuleTypeRegistry = 2,
    RuleTypeNetwork  = 3,
    RuleTypeHandle   = 4,
} ANDUN_RULE_TYPE;

/* ============================================================
 * 驱动事件结构（推送给用户态）
 * ============================================================ */

#pragma pack(push, 1)

typedef struct _ANDUN_EVENT {
    ULONG       eventType;          /* ANDUN_EVENT_TYPE */
    ULONG       pid;
    ULONG       ppid;
    WCHAR       processName[260];   /* 进程名 */
    WCHAR       processPath[520];   /* 进程完整路径 */
    WCHAR       targetPath[520];    /* 目标路径（文件/注册表/设备） */
    WCHAR       remoteAddr[46];     /* 远程地址（网络事件） */
    USHORT      remotePort;         /* 远程端口 */
    ULONG       action;             /* ANDUN_ACTION */
    LARGE_INTEGER timestamp;        /* 时间戳 */
} ANDUN_EVENT, *PANDUN_EVENT;

/* ============================================================
 * 拦截规则结构（用户态下发）
 * ============================================================ */

typedef struct _ANDUN_RULE {
    ULONG       ruleId;             /* 规则ID */
    ULONG       ruleType;           /* ANDUN_RULE_TYPE */
    ULONG       action;             /* ANDUN_ACTION */
    WCHAR       pattern[ANDUN_MAX_PATTERN_LEN]; /* 匹配模式 */
    ULONG       enabled;            /* 是否启用 */
} ANDUN_RULE, *PANDUN_RULE;

/* ============================================================
 * 配置结构
 * ============================================================ */

typedef struct _ANDUN_CONFIG {
    ULONG   fileFilterEnabled;
    ULONG   networkFilterEnabled;
    ULONG   processCallbackEnabled;
    ULONG   registryCallbackEnabled;
    ULONG   objectCallbackEnabled;
    ULONG   rootkitScanEnabled;
} ANDUN_CONFIG, *PANDUN_CONFIG;

/* ============================================================
 * 统计信息结构
 * ============================================================ */

typedef struct _ANDUN_STATS {
    ULONG64 totalEvents;
    ULONG64 blockedEvents;
    ULONG64 fileOperations;
    ULONG64 processOperations;
    ULONG64 registryOperations;
    ULONG64 networkOperations;
    ULONG64 handleOperations;
    ULONG64 droppedEvents;      /* 队列满丢弃的事件数 */
    ULONG   activeRules;
    ULONG   protectedPids;
} ANDUN_STATS, *PANDUN_STATS;

/* ============================================================
 * PID 保护请求
 * ============================================================ */

typedef struct _ANDUN_PID_REQUEST {
    ULONG   pid;
} ANDUN_PID_REQUEST, *PANDUN_PID_REQUEST;

/* ============================================================
 * Rootkit 扫描结果结构
 * ============================================================ */

/* 内核进程条目 */
typedef struct _ANDUN_ROOTKIT_PROC_ENTRY {
    ULONG       pid;
    ULONG       ppid;
    WCHAR       name[260];
    WCHAR       image_path[520];
} ANDUN_ROOTKIT_PROC_ENTRY, *PANDUN_ROOTKIT_PROC_ENTRY;

/* 内核驱动条目 */
typedef struct _ANDUN_ROOTKIT_DRIVER_ENTRY {
    WCHAR       name[260];
    ULONG64     base_address;
    ULONG64     size;
    ULONG       section_unloaded;   /* 1=节区已卸载（无文件驱动） */
} ANDUN_ROOTKIT_DRIVER_ENTRY, *PANDUN_ROOTKIT_DRIVER_ENTRY;

/* 内核钩子条目 */
typedef struct _ANDUN_ROOTKIT_HOOK_ENTRY {
    ULONG       hook_type;          /* 0=SSDT, 1=IRP, 2=Inline */
    WCHAR       function_name[128];
    ULONG64     hook_address;
    UCHAR       original_bytes[16];
    UCHAR       current_bytes[16];
    WCHAR       driver_name[260];   /* 来源驱动 */
    ULONG       severity;           /* 0=info, 1=warn, 2=critical */
} ANDUN_ROOTKIT_HOOK_ENTRY, *PANDUN_ROOTKIT_HOOK_ENTRY;

/* 回调劫持条目 */
typedef struct _ANDUN_ROOTKIT_CALLBACK_ENTRY {
    ULONG       callback_type;      /* 0=Process, 1=Thread, 2=Image, 3=Registry, 4=Object */
    ULONG64     callback_address;
    WCHAR       driver_name[260];   /* 回调所在驱动 */
    ULONG       is_trusted;         /* 是否在可信列表 */
    ULONG       severity;
} ANDUN_ROOTKIT_CALLBACK_ENTRY, *PANDUN_ROOTKIT_CALLBACK_ENTRY;

/* 聚合扫描结果 */
typedef struct _ANDUN_ROOTKIT_SCAN_RESULT {
    ULONG       proc_count;
    ULONG       driver_count;
    ULONG       hook_count;
    ULONG       callback_count;
    ANDUN_ROOTKIT_PROC_ENTRY      procs[256];
    ANDUN_ROOTKIT_DRIVER_ENTRY    drivers[64];
    ANDUN_ROOTKIT_HOOK_ENTRY      hooks[32];
    ANDUN_ROOTKIT_CALLBACK_ENTRY  callbacks[32];
} ANDUN_ROOTKIT_SCAN_RESULT, *PANDUN_ROOTKIT_SCAN_RESULT;

/* ============================================================
 * 自保护/处置响应结构
 * ============================================================ */

/* 自保护进程配置 */
typedef struct _ANDUN_SELFPROTECT_PROCESS_CFG {
    ULONG   agent_pid;             /* agent 自身 PID */
    ULONG   protect_enabled;       /* 1=启用 */
} ANDUN_SELFPROTECT_PROCESS_CFG, *PANDUN_SELFPROTECT_PROCESS_CFG;

/* 自保护文件路径 */
typedef struct _ANDUN_SELFPROTECT_FILE_CFG {
    WCHAR   install_dir[520];      /* 安装目录 */
    ULONG   protect_enabled;
} ANDUN_SELFPROTECT_FILE_CFG, *PANDUN_SELFPROTECT_FILE_CFG;

/* 自保护注册表键 */
typedef struct _ANDUN_SELFPROTECT_REGISTRY_CFG {
    WCHAR   key_path[520];         /* 注册表键路径 */
    ULONG   protect_enabled;
} ANDUN_SELFPROTECT_REGISTRY_CFG, *PANDUN_SELFPROTECT_REGISTRY_CFG;

/* 自保护服务名 */
typedef struct _ANDUN_SELFPROTECT_SERVICE_CFG {
    WCHAR   service_name[260];     /* 服务名 */
    ULONG   protect_enabled;
} ANDUN_SELFPROTECT_SERVICE_CFG, *PANDUN_SELFPROTECT_SERVICE_CFG;

/* 处置响应：终止进程 */
typedef struct _ANDUN_RESPONSE_KILL_PROCESS {
    ULONG   target_pid;
    ULONG   force;                 /* 1=强制终止 */
} ANDUN_RESPONSE_KILL_PROCESS, *PANDUN_RESPONSE_KILL_PROCESS;

/* 处置响应：隔离文件 */
typedef struct _ANDUN_RESPONSE_QUARANTINE_FILE {
    WCHAR   file_path[520];
    WCHAR   quarantine_dir[520];   /* 隔离目录 */
} ANDUN_RESPONSE_QUARANTINE_FILE, *PANDUN_RESPONSE_QUARANTINE_FILE;

/* 处置响应：下发即时拦截规则 */
typedef struct _ANDUN_RESPONSE_BLOCK_RULE {
    ANDUN_RULE  rule;               /* 复用 ANDUN_RULE 结构 */
    ULONG       auto_remove_sec;    /* 0=永久, >0=秒后自动移除 */
} ANDUN_RESPONSE_BLOCK_RULE, *PANDUN_RESPONSE_BLOCK_RULE;

#pragma pack(pop)

/* ============================================================
 * 事件队列接口 (event_queue.c)
 * ============================================================ */

VOID     EventQueueInit(VOID);
VOID     EventQueueDestroy(VOID);
VOID     EventQueuePush(ANDUN_EVENT *Event);
ULONG    EventQueuePop(PANDUN_EVENT Buffer, ULONG MaxCount);
ULONG    EventQueueGetCount(VOID);

/* ============================================================
 * 规则引擎接口 (rule_engine.c)
 * ============================================================ */

VOID     RuleEngineInit(VOID);
VOID     RuleEngineDestroy(VOID);
NTSTATUS RuleEngineAddRule(PANDUN_RULE Rule);
NTSTATUS RuleEngineDelRule(ULONG RuleId);
VOID     RuleEngineClearRules(VOID);
ULONG    RuleEngineGetActiveCount(VOID);

/* 匹配函数：返回匹配的规则动作，无匹配返回 ActionAllow */
ULONG    RuleMatchFile(PCUNICODE_STRING FilePath, ULONG Pid);
ULONG    RuleMatchProcess(PCWSTR ProcessName, ULONG Pid);
ULONG    RuleMatchNetwork(PCWSTR RemoteAddr, USHORT RemotePort, ULONG Pid);
ULONG    RuleMatchRegistry(PCUNICODE_STRING KeyPath);
ULONG    RuleMatchHandle(ULONG TargetPid, ULONG DesiredAccess);

/* 通配符匹配 */
BOOLEAN  WildcardMatch(PCWSTR Pattern, PCWSTR Text);

/* ============================================================
 * 受保护 PID 管理接口 (object_callback.c)
 * ============================================================ */

VOID     ProtectedPidInit(VOID);
VOID     ProtectedPidDestroy(VOID);
BOOLEAN  ProtectedPidAdd(ULONG Pid);
BOOLEAN  ProtectedPidRemove(ULONG Pid);
BOOLEAN  ProtectedPidIsProtected(ULONG Pid);

/* ============================================================
 * 各子模块初始化/清理接口
 * ============================================================ */

/* file_filter.c */
NTSTATUS FileFilterInit(PDRIVER_OBJECT DriverObject);
VOID     FileFilterUnload(VOID);

/* process_callback.c */
NTSTATUS ProcessCallbackInit(VOID);
VOID     ProcessCallbackUnload(VOID);

/* registry_callback.c */
NTSTATUS RegistryCallbackInit(PDRIVER_OBJECT DriverObject);
VOID     RegistryCallbackUnload(VOID);

/* object_callback.c */
NTSTATUS ObjectCallbackInit(PDRIVER_OBJECT DriverObject);
VOID     ObjectCallbackUnload(VOID);

/* network_filter.c */
NTSTATUS NetworkFilterInit(VOID);
VOID     NetworkFilterUnload(VOID);

/* device_control.c */
NTSTATUS DeviceControlInit(PDRIVER_OBJECT DriverObject);
VOID     DeviceControlUnload(VOID);
NTSTATUS DeviceControlIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* ============================================================
 * 全局配置（在 device_control.c 中定义，各子模块共享读取）
 * ============================================================ */

extern ANDUN_CONFIG g_Config;

/* ============================================================
 * Rootkit 扫描接口 (rootkit_scan.c)
 * ============================================================ */

NTSTATUS RootkitScanRun(PANDUN_ROOTKIT_SCAN_RESULT Result);
VOID     RootkitScanUnload(VOID);

/* ============================================================
 * 自保护接口 (self_protect.c)
 * ============================================================ */

NTSTATUS SelfProtectInit(PCWSTR InstallDir);
VOID     SelfProtectUnload(VOID);
NTSTATUS SelfProtectSetConfig(ULONG CfgType, PVOID Buffer, ULONG BufferLen);
NTSTATUS SelfProtectGetConfig(ULONG CfgType, PVOID Buffer, PULONG BufferLen);
BOOLEAN  SelfProtectIsSelfFile(PCUNICODE_STRING FilePath);

/* ============================================================
 * 处置响应接口 (response.c)
 * ============================================================ */

NTSTATUS ResponseKillProcess(ULONG TargetPid, BOOLEAN Force);
NTSTATUS ResponseQuarantineFile(PCWSTR FilePath, PCWSTR QuarantineDir);
NTSTATUS ResponseBlockRule(PANDUN_RULE Rule, ULONG AutoRemoveSec);

/* ============================================================
 * 全局统计
 * ============================================================ */

extern KSPIN_LOCK g_StatsLock;
extern ANDUN_STATS g_Stats;

VOID StatsIncrement(ULONG64 *Counter);
VOID StatsEventPushed(ULONG EventType, ULONG Action);
