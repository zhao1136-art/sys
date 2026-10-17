/*
 * self_protect.c - 安全产品自保护模块
 *
 * 在现有事件回调框架上叠加自保护规则：
 *   1. 进程保护：通过 ObRegisterCallbacks（已实现于 object_callback.c）
 *      + 自动将 agent PID 加入受保护列表（已实现于 process_callback.c）
 *   2. 文件自保护：向规则引擎预置安装目录保护规则，Minifilter 自动拦截
 *   3. 注册表自保护：向规则引擎预置注册表键保护规则，CmCallback 自动拦截
 *   4. 服务自保护：配置存储，由用户态通过 IOCTL 下发
 *
 * 本模块提供配置存储与规则预置接口。
 */

#include "andun.h"

/* ============================================================
 * 自保护配置全局变量
 * ============================================================ */

static ANDUN_SELFPROTECT_PROCESS_CFG    g_SelfProtectProc = {0, 1};
static ANDUN_SELFPROTECT_FILE_CFG       g_SelfProtectFile = {L"", 1};
static ANDUN_SELFPROTECT_REGISTRY_CFG   g_SelfProtectReg  = {L"", 1};
static ANDUN_SELFPROTECT_SERVICE_CFG    g_SelfProtectSvc  = {L"", 1};
static KSPIN_LOCK g_SelfProtectLock;

/* ============================================================
 * 自保护注册表键路径（与用户态一致）
 * ============================================================ */

/* 自启动项 */
#define ANDUN_SELF_REG_RUN     L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Andun*"
/* 服务配置 */
#define ANDUN_SELF_REG_SERVICE L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Andun*"
/* 安全中心排除 */
#define ANDUN_SELF_REG_EXCLUDE L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions*"

/* ============================================================
 * 内部辅助函数
 * ============================================================ */

/*
 * SelfProtectPreloadRules - 向规则引擎预置自保护规则
 *
 * 在驱动初始化时调用，添加文件与注册表自保护规则：
 *   - 安装目录下的 .exe/.dll/.dat 文件禁止外部写/删除
 *   - 自身注册表键禁止外部修改/删除
 *
 * 注意：这些规则不受 g_Config 开关影响，始终启用。
 * 规则 ID 使用 ANDUN_SELFPROTECT_RULE_BASE 起始值避免冲突。
 */
#define ANDUN_SELFPROTECT_RULE_BASE 0xFFF00000

static NTSTATUS SelfProtectPreloadRules(VOID)
{
    NTSTATUS status;
    ANDUN_RULE rule;

    /* 1. 文件保护规则：安装目录 .exe 禁止写/删除 */
    if (g_SelfProtectFile.install_dir[0] != L'\0') {
        RtlZeroMemory(&rule, sizeof(rule));
        rule.ruleId = ANDUN_SELFPROTECT_RULE_BASE + 1;
        rule.ruleType = RuleTypeFile;
        rule.action = ActionBlock;
        swprintf_s(rule.pattern, ANDUN_MAX_PATTERN_LEN,
                   L"%s\\*", g_SelfProtectFile.install_dir);
        rule.enabled = 1;
        status = RuleEngineAddRule(&rule);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[御天驱动] 自保护文件规则添加失败: 0x%08X\n", status);
        }

        /* 安装目录子目录 */
        RtlZeroMemory(&rule, sizeof(rule));
        rule.ruleId = ANDUN_SELFPROTECT_RULE_BASE + 2;
        rule.ruleType = RuleTypeFile;
        rule.action = ActionBlock;
        swprintf_s(rule.pattern, ANDUN_MAX_PATTERN_LEN,
                   L"%s\\*\\*", g_SelfProtectFile.install_dir);
        rule.enabled = 1;
        status = RuleEngineAddRule(&rule);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[御天驱动] 自保护文件子目录规则添加失败: 0x%08X\n", status);
        }
    }

    /* 2. 注册表保护规则 */
    {
        RtlZeroMemory(&rule, sizeof(rule));
        rule.ruleId = ANDUN_SELFPROTECT_RULE_BASE + 3;
        rule.ruleType = RuleTypeRegistry;
        rule.action = ActionBlock;
        wcscpy_s(rule.pattern, ANDUN_MAX_PATTERN_LEN, ANDUN_SELF_REG_RUN);
        rule.enabled = 1;
        status = RuleEngineAddRule(&rule);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[御天驱动] 自保护注册表规则(Run)添加失败: 0x%08X\n", status);
        }

        RtlZeroMemory(&rule, sizeof(rule));
        rule.ruleId = ANDUN_SELFPROTECT_RULE_BASE + 4;
        rule.ruleType = RuleTypeRegistry;
        rule.action = ActionBlock;
        wcscpy_s(rule.pattern, ANDUN_MAX_PATTERN_LEN, ANDUN_SELF_REG_SERVICE);
        rule.enabled = 1;
        status = RuleEngineAddRule(&rule);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[御天驱动] 自保护注册表规则(Service)添加失败: 0x%08X\n", status);
        }

        /* 安全中心排除项只读 */
        RtlZeroMemory(&rule, sizeof(rule));
        rule.ruleId = ANDUN_SELFPROTECT_RULE_BASE + 5;
        rule.ruleType = RuleTypeRegistry;
        rule.action = ActionBlock;
        wcscpy_s(rule.pattern, ANDUN_MAX_PATTERN_LEN, ANDUN_SELF_REG_EXCLUDE);
        rule.enabled = 1;
        status = RuleEngineAddRule(&rule);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[御天驱动] 自保护注册表规则(Exclude)添加失败: 0x%08X\n", status);
        }
    }

    DbgPrint("[御天驱动] 自保护规则预置完成\n");
    return STATUS_SUCCESS;
}

/*
 * SelfProtectRemoveRules - 移除自保护规则
 */
static VOID SelfProtectRemoveRules(VOID)
{
    RuleEngineDelRule(ANDUN_SELFPROTECT_RULE_BASE + 1);
    RuleEngineDelRule(ANDUN_SELFPROTECT_RULE_BASE + 2);
    RuleEngineDelRule(ANDUN_SELFPROTECT_RULE_BASE + 3);
    RuleEngineDelRule(ANDUN_SELFPROTECT_RULE_BASE + 4);
    RuleEngineDelRule(ANDUN_SELFPROTECT_RULE_BASE + 5);
}

/* ============================================================
 * 对外接口
 * ============================================================ */

/*
 * SelfProtectInit - 初始化自保护模块
 *
 * 参数：
 *   InstallDir - 安装目录（可为空，为空时不预置文件保护规则）
 * 返回：
 *   STATUS_SUCCESS
 */
NTSTATUS SelfProtectInit(PCWSTR InstallDir)
{
    KeInitializeSpinLock(&g_SelfProtectLock);

    /* 保存配置 */
    if (InstallDir != NULL) {
        wcscpy_s(g_SelfProtectFile.install_dir, 520, InstallDir);
    }

    /* 服务名默认 */
    wcscpy_s(g_SelfProtectSvc.service_name, 260, L"AndunAgent");

    /* 预置自保护规则 */
    SelfProtectPreloadRules();

    DbgPrint("[御天驱动] 自保护模块初始化完成\n");
    return STATUS_SUCCESS;
}

/*
 * SelfProtectUnload - 卸载自保护
 */
VOID SelfProtectUnload(VOID)
{
    SelfProtectRemoveRules();
    DbgPrint("[御天驱动] 自保护模块已卸载\n");
}

/*
 * SelfProtectSetConfig - 设置自保护配置
 *
 * 根据 cfgType 判断配置类型：
 *   0=进程, 1=文件, 2=注册表, 3=服务
 */
NTSTATUS SelfProtectSetConfig(ULONG cfgType, PVOID Buffer, ULONG BufferLen)
{
    KIRQL oldIrql;

    if (Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_SelfProtectLock, &oldIrql);

    switch (cfgType) {
    case 0: /* 进程 */
        if (BufferLen >= sizeof(ANDUN_SELFPROTECT_PROCESS_CFG)) {
            RtlCopyMemory(&g_SelfProtectProc, Buffer,
                          sizeof(ANDUN_SELFPROTECT_PROCESS_CFG));
        }
        break;
    case 1: /* 文件 */
        if (BufferLen >= sizeof(ANDUN_SELFPROTECT_FILE_CFG)) {
            RtlCopyMemory(&g_SelfProtectFile, Buffer,
                          sizeof(ANDUN_SELFPROTECT_FILE_CFG));
            /* 重新预置文件保护规则 */
            SelfProtectRemoveRules();
            SelfProtectPreloadRules();
        }
        break;
    case 2: /* 注册表 */
        if (BufferLen >= sizeof(ANDUN_SELFPROTECT_REGISTRY_CFG)) {
            RtlCopyMemory(&g_SelfProtectReg, Buffer,
                          sizeof(ANDUN_SELFPROTECT_REGISTRY_CFG));
        }
        break;
    case 3: /* 服务 */
        if (BufferLen >= sizeof(ANDUN_SELFPROTECT_SERVICE_CFG)) {
            RtlCopyMemory(&g_SelfProtectSvc, Buffer,
                          sizeof(ANDUN_SELFPROTECT_SERVICE_CFG));
        }
        break;
    default:
        KeReleaseSpinLock(&g_SelfProtectLock, oldIrql);
        return STATUS_INVALID_PARAMETER;
    }

    KeReleaseSpinLock(&g_SelfProtectLock, oldIrql);
    return STATUS_SUCCESS;
}

/*
 * SelfProtectGetConfig - 读取自保护配置
 */
NTSTATUS SelfProtectGetConfig(ULONG cfgType, PVOID Buffer, PULONG BufferLen)
{
    KIRQL oldIrql;
    ULONG copySize = 0;

    if (Buffer == NULL || BufferLen == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_SelfProtectLock, &oldIrql);

    switch (cfgType) {
    case 0: copySize = sizeof(ANDUN_SELFPROTECT_PROCESS_CFG);
            RtlCopyMemory(Buffer, &g_SelfProtectProc, copySize); break;
    case 1: copySize = sizeof(ANDUN_SELFPROTECT_FILE_CFG);
            RtlCopyMemory(Buffer, &g_SelfProtectFile, copySize); break;
    case 2: copySize = sizeof(ANDUN_SELFPROTECT_REGISTRY_CFG);
            RtlCopyMemory(Buffer, &g_SelfProtectReg, copySize); break;
    case 3: copySize = sizeof(ANDUN_SELFPROTECT_SERVICE_CFG);
            RtlCopyMemory(Buffer, &g_SelfProtectSvc, copySize); break;
    default:
        KeReleaseSpinLock(&g_SelfProtectLock, oldIrql);
        return STATUS_INVALID_PARAMETER;
    }

    *BufferLen = copySize;
    KeReleaseSpinLock(&g_SelfProtectLock, oldIrql);
    return STATUS_SUCCESS;
}

/*
 * SelfProtectIsSelfFile - 检查文件路径是否在自保护目录内
 *
 * 供 Minifilter 回调/用户态备查
 */
BOOLEAN SelfProtectIsSelfFile(PCUNICODE_STRING FilePath)
{
    ULONG installLen;
    KIRQL oldIrql;
    BOOLEAN match = FALSE;

    if (FilePath == NULL || FilePath->Buffer == NULL ||
        g_SelfProtectFile.install_dir[0] == L'\0') {
        return FALSE;
    }

    installLen = (ULONG)wcslen(g_SelfProtectFile.install_dir);

    KeAcquireSpinLock(&g_SelfProtectLock, &oldIrql);

    if (FilePath->Length / sizeof(WCHAR) >= installLen) {
        /* 比较路径前缀是否匹配安装目录 */
        ULONG i;
        BOOLEAN prefixMatch = TRUE;
        for (i = 0; i < installLen; i++) {
            if (i >= FilePath->Length / sizeof(WCHAR)) {
                prefixMatch = FALSE;
                break;
            }
            WCHAR fc = FilePath->Buffer[i];
            WCHAR tc = g_SelfProtectFile.install_dir[i];
            /* 大小写不敏感 */
            if (fc >= L'A' && fc <= L'Z') fc += (L'a' - L'A');
            if (tc >= L'A' && tc <= L'Z') tc += (L'a' - L'A');
            if (fc != tc) {
                prefixMatch = FALSE;
                break;
            }
        }
        match = prefixMatch;
    }

    KeReleaseSpinLock(&g_SelfProtectLock, oldIrql);
    return match;
}