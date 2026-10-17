/*
 * rule_engine.c - 内核态规则匹配引擎
 *
 * 提供规则数组管理与通配符匹配功能，
 * 支持文件/进程/网络/注册表/句柄五类规则的增删查与匹配。
 *
 * 线程安全说明：
 *   - 规则数组由 KSPIN_LOCK 保护
 *   - 管理函数（Add/Del/Clear）在 PASSIVE_LEVEL 下调用（IOCTL 处理中）
 *   - 匹配函数可在 IRQL <= DISPATCH_LEVEL 下调用（各回调模块）
 *   - 使用 KeAcquireSpinLock / KeReleaseSpinLock 保证任意 IRQL 下的安全性
 */

#include "andun.h"

/* ============================================================
 * 规则引擎内部状态
 * ============================================================ */

static ANDUN_RULE  g_RuleArray[ANDUN_MAX_RULES];
static KSPIN_LOCK  g_RuleEngineLock;
static BOOLEAN     g_RuleEngineInitialized;

/* ============================================================
 * 内部辅助函数
 * ============================================================ */

/*
 * AndunToLowerW - 将单个宽字符转换为小写
 * 仅处理 ASCII 大写字母，避免依赖 RtlDowncaseUnicodeString
 */
static WCHAR AndunToLowerW(WCHAR ch)
{
    if (ch >= L'A' && ch <= L'Z') {
        return (WCHAR)(ch + (L'a' - L'A'));
    }
    return ch;
}

/*
 * AndunUnicodeToZStr - 将 UNICODE_STRING 拷贝为以 NULL 结尾的宽字符串
 * 用于将内核 UNICODE_STRING 转换为 WildcardMatch 所需的 PCWSTR 格式
 */
static VOID AndunUnicodeToZStr(PCUNICODE_STRING Us,
                                PWSTR             Dst,
                                ULONG             DstChars)
{
    ULONG copyChars;

    if (Dst == NULL || DstChars == 0) {
        return;
    }
    Dst[0] = L'\0';

    if (Us == NULL || Us->Buffer == NULL) {
        return;
    }

    copyChars = Us->Length / sizeof(WCHAR);
    if (copyChars >= DstChars) {
        copyChars = DstChars - 1;
    }

    RtlCopyMemory(Dst, Us->Buffer, copyChars * sizeof(WCHAR));
    Dst[copyChars] = L'\0';
}

/*
 * AndunUlongToWStr - 将 ULONG 转换为十进制宽字符串
 * 不依赖任何运行库函数，可在任意 IRQL 下调用
 */
static VOID AndunUlongToWStr(ULONG Value, PWSTR Buffer, ULONG BufferChars)
{
    WCHAR  tmp[16];
    ULONG  len = 0;
    ULONG  i;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (Value == 0) {
        Buffer[0] = L'0';
        Buffer[1] = L'\0';
        return;
    }

    while (Value > 0 && len < 15) {
        tmp[len] = (WCHAR)(L'0' + (Value % 10));
        len++;
        Value /= 10;
    }

    for (i = 0; i < len && i < BufferChars - 1; i++) {
        Buffer[i] = tmp[len - 1 - i];
    }
    Buffer[i] = L'\0';
}

/*
 * RuleMatchLocked - 内部通用匹配逻辑
 * 遍历指定类型的所有启用规则，返回第一个匹配规则的动作
 * 调用前必须已持有 g_RuleEngineLock
 */
static ULONG RuleMatchLocked(ULONG RuleType, PCWSTR Text)
{
    ULONG i;

    if (Text == NULL) {
        return ActionAllow;
    }

    for (i = 0; i < ANDUN_MAX_RULES; i++) {
        if (g_RuleArray[i].enabled == 0) {
            continue;
        }
        if (g_RuleArray[i].ruleType != RuleType) {
            continue;
        }
        if (WildcardMatch(g_RuleArray[i].pattern, Text)) {
            return g_RuleArray[i].action;
        }
    }

    return ActionAllow;
}

/*
 * RuleUpdateActiveStats - 更新 g_Stats.activeRules
 * 先在规则锁下统计活跃规则数，再在统计锁下写入
 */
static VOID RuleUpdateActiveStats(VOID)
{
    KIRQL oldIrql;
    ULONG count;
    ULONG i;

    /* 在规则锁保护下统计启用的规则数量 */
    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    count = 0;
    for (i = 0; i < ANDUN_MAX_RULES; i++) {
        if (g_RuleArray[i].enabled != 0) {
            count++;
        }
    }
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    /* 在统计锁保护下更新计数 */
    KeAcquireSpinLock(&g_StatsLock, &oldIrql);
    g_Stats.activeRules = count;
    KeReleaseSpinLock(&g_StatsLock, oldIrql);
}

/* ============================================================
 * 通配符匹配
 * ============================================================ */

/*
 * WildcardMatch - 通配符匹配（支持 * 和 ?，大小写不敏感）
 *
 * 语义：
 *   '*' 匹配任意长度的字符序列（包括空序列）
 *   '?' 匹配单个任意字符
 *
 * 算法：经典双指针回溯法
 *   - 遇到 '*' 记录位置并尝试让其匹配空串
 *   - 匹配失败时回溯，让上一个 '*' 多匹配一个字符
 */
BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR Text)
{
    PCWSTR p     = Pattern;
    PCWSTR t     = Text;
    PCWSTR starP = NULL;   /* 上一个 '*' 在模式中的位置 */
    PCWSTR starT = NULL;   /* 上一个 '*' 在文本中开始匹配的位置 */

    if (Pattern == NULL || Text == NULL) {
        return FALSE;
    }

    while (*t != L'\0') {
        if (*p == L'?' || AndunToLowerW(*p) == AndunToLowerW(*t)) {
            /* 单字符匹配或 '?' 通配 */
            p++;
            t++;
        } else if (*p == L'*') {
            /* 记录 '*' 位置，先尝试匹配空串 */
            starP = p;
            starT = t;
            p++;
        } else if (starP != NULL) {
            /* 回溯：让上一个 '*' 多匹配一个字符 */
            p = starP + 1;
            starT++;
            t = starT;
        } else {
            /* 无 '*' 可回溯，匹配失败 */
            return FALSE;
        }
    }

    /* 跳过模式末尾剩余的 '*' */
    while (*p == L'*') {
        p++;
    }

    return (*p == L'\0');
}

/* ============================================================
 * 规则引擎初始化与清理
 * ============================================================ */

/*
 * RuleEngineInit - 初始化规则数组与自旋锁
 */
VOID RuleEngineInit(VOID)
{
    KeInitializeSpinLock(&g_RuleEngineLock);
    RtlZeroMemory(g_RuleArray, sizeof(g_RuleArray));
    g_RuleEngineInitialized = TRUE;
}

/*
 * RuleEngineDestroy - 清理规则引擎
 */
VOID RuleEngineDestroy(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    g_RuleEngineInitialized = FALSE;
    RtlZeroMemory(g_RuleArray, sizeof(g_RuleArray));
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);
}

/* ============================================================
 * 规则增删查
 * ============================================================ */

/*
 * RuleEngineAddRule - 添加规则到数组
 *
 * 若已存在相同 ruleId 的规则则覆盖更新；否则寻找第一个空闲槽位写入
 * 返回 STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES（数组已满）
 */
NTSTATUS RuleEngineAddRule(PANDUN_RULE Rule)
{
    KIRQL    oldIrql;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG    i;
    BOOLEAN  found = FALSE;

    if (Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);

    if (!g_RuleEngineInitialized) {
        KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);
        return STATUS_DEVICE_NOT_READY;
    }

    /* 第一遍：查找是否已存在相同 ruleId 的规则，存在则覆盖 */
    for (i = 0; i < ANDUN_MAX_RULES; i++) {
        if (g_RuleArray[i].enabled != 0 &&
            g_RuleArray[i].ruleId == Rule->ruleId) {
            RtlCopyMemory(&g_RuleArray[i], Rule, sizeof(ANDUN_RULE));
            /* 确保 pattern 以 NULL 结尾，防止 WildcardMatch 越界 */
            g_RuleArray[i].pattern[ANDUN_MAX_PATTERN_LEN - 1] = L'\0';
            found = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    /* 第二遍：不存在则寻找空闲槽位（enabled == 0） */
    if (!found) {
        for (i = 0; i < ANDUN_MAX_RULES; i++) {
            if (g_RuleArray[i].enabled == 0) {
                RtlCopyMemory(&g_RuleArray[i], Rule, sizeof(ANDUN_RULE));
                g_RuleArray[i].pattern[ANDUN_MAX_PATTERN_LEN - 1] = L'\0';
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    /* 更新活跃规则统计 */
    if (status == STATUS_SUCCESS) {
        RuleUpdateActiveStats();
    }

    return status;
}

/*
 * RuleEngineDelRule - 按 ruleId 删除规则
 * 返回 STATUS_SUCCESS 或 STATUS_NOT_FOUND
 */
NTSTATUS RuleEngineDelRule(ULONG RuleId)
{
    KIRQL    oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG    i;

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);

    if (!g_RuleEngineInitialized) {
        KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);
        return STATUS_DEVICE_NOT_READY;
    }

    for (i = 0; i < ANDUN_MAX_RULES; i++) {
        if (g_RuleArray[i].enabled != 0 &&
            g_RuleArray[i].ruleId == RuleId) {
            RtlZeroMemory(&g_RuleArray[i], sizeof(ANDUN_RULE));
            status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    if (status == STATUS_SUCCESS) {
        RuleUpdateActiveStats();
    }

    return status;
}

/*
 * RuleEngineClearRules - 清空所有规则
 */
VOID RuleEngineClearRules(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);

    if (!g_RuleEngineInitialized) {
        KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);
        return;
    }

    RtlZeroMemory(g_RuleArray, sizeof(g_RuleArray));

    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    /* 清空后活跃规则数为 0 */
    KeAcquireSpinLock(&g_StatsLock, &oldIrql);
    g_Stats.activeRules = 0;
    KeReleaseSpinLock(&g_StatsLock, oldIrql);
}

/*
 * RuleEngineGetActiveCount - 获取当前启用的规则数量
 */
ULONG RuleEngineGetActiveCount(VOID)
{
    KIRQL oldIrql;
    ULONG count = 0;
    ULONG i;

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);

    if (g_RuleEngineInitialized) {
        for (i = 0; i < ANDUN_MAX_RULES; i++) {
            if (g_RuleArray[i].enabled != 0) {
                count++;
            }
        }
    }

    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);
    return count;
}

/* ============================================================
 * 规则匹配函数
 * ============================================================ */

/*
 * RuleMatchFile - 匹配文件规则
 *
 * 参数：
 *   FilePath - 文件完整路径（UNICODE_STRING，可能不以 NULL 结尾）
 *   Pid      - 触发操作的进程 ID（当前未参与匹配，预留给后续扩展）
 * 返回：匹配的规则动作，无匹配返回 ActionAllow
 */
ULONG RuleMatchFile(PCUNICODE_STRING FilePath, ULONG Pid)
{
    KIRQL oldIrql;
    ULONG action;
    WCHAR pathBuf[ANDUN_MAX_PATTERN_LEN];

    UNREFERENCED_PARAMETER(Pid);

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return ActionAllow;
    }

    /* 将 UNICODE_STRING 转换为以 NULL 结尾的宽字符串 */
    AndunUnicodeToZStr(FilePath, pathBuf, ANDUN_MAX_PATTERN_LEN);

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    action = RuleMatchLocked(RuleTypeFile, pathBuf);
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    return action;
}

/*
 * RuleMatchProcess - 匹配进程规则
 *
 * 参数：
 *   ProcessName - 进程名（以 NULL 结尾，如 "cmd.exe"）
 *   Pid         - 进程 ID（当前未参与匹配，预留给后续扩展）
 * 返回：匹配的规则动作，无匹配返回 ActionAllow
 */
ULONG RuleMatchProcess(PCWSTR ProcessName, ULONG Pid)
{
    KIRQL oldIrql;
    ULONG action;

    UNREFERENCED_PARAMETER(Pid);

    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return ActionAllow;
    }

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    action = RuleMatchLocked(RuleTypeProcess, ProcessName);
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    return action;
}

/*
 * RuleMatchNetwork - 匹配网络规则
 *
 * 参数：
 *   RemoteAddr - 远程地址字符串（以 NULL 结尾，如 "192.168.1.1"）
 *   RemotePort - 远程端口
 *   Pid        - 进程 ID（当前未参与匹配，预留给后续扩展）
 *
 * 匹配格式：构造 "地址:端口" 字符串与规则 pattern 进行通配符匹配
 *   例如 pattern "*:443" 匹配所有目标端口为 443 的连接
 * 返回：匹配的规则动作，无匹配返回 ActionAllow
 */
ULONG RuleMatchNetwork(PCWSTR RemoteAddr, USHORT RemotePort, ULONG Pid)
{
    KIRQL   oldIrql;
    ULONG   action;
    WCHAR   netStr[64];
    ULONG   i;
    USHORT  port;
    WCHAR   digits[6];
    ULONG   dlen = 0;
    ULONG   j;

    UNREFERENCED_PARAMETER(Pid);

    if (RemoteAddr == NULL || RemoteAddr[0] == L'\0') {
        return ActionAllow;
    }

    /* 构造 "地址:端口" 字符串 */
    for (i = 0; i < 58 && RemoteAddr[i] != L'\0'; i++) {
        netStr[i] = RemoteAddr[i];
    }
    netStr[i] = L':';
    i++;

    /* 追加端口号（十进制） */
    port = RemotePort;
    if (port == 0) {
        netStr[i] = L'0';
        i++;
    } else {
        while (port > 0 && dlen < 5) {
            digits[dlen] = (WCHAR)(L'0' + (port % 10));
            dlen++;
            port = (USHORT)(port / 10);
        }
        for (j = dlen; j > 0 && i < 63; j--) {
            netStr[i] = digits[j - 1];
            i++;
        }
    }
    netStr[i] = L'\0';

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    action = RuleMatchLocked(RuleTypeNetwork, netStr);
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    return action;
}

/*
 * RuleMatchRegistry - 匹配注册表规则
 *
 * 参数：
 *   KeyPath - 注册表键路径（UNICODE_STRING，可能不以 NULL 结尾）
 * 返回：匹配的规则动作，无匹配返回 ActionAllow
 */
ULONG RuleMatchRegistry(PCUNICODE_STRING KeyPath)
{
    KIRQL oldIrql;
    ULONG action;
    WCHAR keyBuf[ANDUN_MAX_PATTERN_LEN];

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return ActionAllow;
    }

    AndunUnicodeToZStr(KeyPath, keyBuf, ANDUN_MAX_PATTERN_LEN);

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    action = RuleMatchLocked(RuleTypeRegistry, keyBuf);
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    return action;
}

/*
 * RuleMatchHandle - 匹配句柄规则
 *
 * 参数：
 *   TargetPid     - 被打开句柄的目标进程 ID
 *   DesiredAccess - 请求的访问权限（当前未参与匹配，预留给后续扩展）
 *
 * 匹配格式：将 TargetPid 转换为十进制字符串与规则 pattern 匹配
 *   例如 pattern "*" 匹配所有目标进程，pattern "1234" 匹配 PID 1234
 * 返回：匹配的规则动作，无匹配返回 ActionAllow
 */
ULONG RuleMatchHandle(ULONG TargetPid, ULONG DesiredAccess)
{
    KIRQL oldIrql;
    ULONG action;
    WCHAR pidStr[16];

    UNREFERENCED_PARAMETER(DesiredAccess);

    AndunUlongToWStr(TargetPid, pidStr, 16);

    KeAcquireSpinLock(&g_RuleEngineLock, &oldIrql);
    action = RuleMatchLocked(RuleTypeHandle, pidStr);
    KeReleaseSpinLock(&g_RuleEngineLock, oldIrql);

    return action;
}
