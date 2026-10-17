/*
 * response.c - 处置响应模块
 *
 * 提供三种处置能力：
 *   1. ResponseKillProcess  - 终止恶意进程
 *   2. ResponseQuarantineFile - 隔离恶意文件
 *   3. ResponseBlockRule    - 下发即时拦截规则
 *
 * 与用户态处置中心配合，实现"检测 → 确认 → 处置 → 审计"闭环。
 * 本模块只负责驱动侧的原语操作，编排逻辑在用户态。
 */

#include "andun.h"

/* 隔离文件扩展名标记 */
#define ANDUN_QUARANTINE_EXT L".andunq"

/* ============================================================
 * 1. 终止进程
 * ============================================================ */

/*
 * ResponseKillProcess - 终止指定进程
 *
 * 参数：
 *   TargetPid - 目标进程 ID
 *   Force     - TRUE 表示强制终止（绕过正常终止流程）
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 *
 * 安全说明：
 *   - 受保护 PID（御天自身）不可被此接口终止，防止自毁
 *   - 使用 ZwOpenProcess + ZwTerminateProcess 实现
 */
NTSTATUS ResponseKillProcess(ULONG TargetPid, BOOLEAN Force)
{
    NTSTATUS status;
    HANDLE   processHandle = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;

    UNREFERENCED_PARAMETER(Force);

    /* 1. 防御：不允许终止自身受保护进程 */
    if (TargetPid == 0 ||
        TargetPid == HandleToULong(PsGetCurrentProcessId()) ||
        ProtectedPidIsProtected(TargetPid)) {
        return STATUS_ACCESS_DENIED;
    }

    /* 2. 打开进程句柄（仅需要 PROCESS_TERMINATE 权限） */
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPid;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&processHandle,
                           PROCESS_TERMINATE,
                           &objAttr,
                           &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 3. 终止进程 */
    status = ZwTerminateProcess(processHandle, 0);
    ZwClose(processHandle);

    /* 4. 记录统计 */
    if (NT_SUCCESS(status)) {
        StatsIncrement(&g_Stats.blockedEvents);
        DbgPrint("[御天驱动] 已终止进程 PID=%lu\n", TargetPid);
    }

    return status;
}

/* ============================================================
 * 2. 隔离文件
 * ============================================================ */

/*
 * ResponseQuarantineFile - 将文件移动到隔离目录并标记
 *
 * 参数：
 *   FilePath       - 待隔离文件完整路径
 *   QuarantineDir  - 隔离目录（可为空，默认使用系统临时目录下 AndunQuarantine）
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 *
 * 说明：
 *   移动后追加 .andunq 扩展名标记，防止被执行。
 *   若移动失败（如文件被占用），返回错误，由用户态决定强制隔离策略。
 */
NTSTATUS ResponseQuarantineFile(PCWSTR FilePath, PCWSTR QuarantineDir)
{
    UNICODE_STRING srcPath;
    UNICODE_STRING dstPath;
    WCHAR         dst[520];
    const WCHAR  *fileName;
    const WCHAR  *quarDir = QuarantineDir;
    ULONG         i;
    ULONG         lastSlash = 0;

    if (FilePath == NULL || FilePath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    /* 1. 确定隔离目录 */
    if (quarDir == NULL || quarDir[0] == L'\0') {
        quarDir = L"\\SystemRoot\\Temp\\AndunQuarantine";
    }

    /* 2. 提取原文件名 */
    fileName = FilePath;
    for (i = 0; FilePath[i] != L'\0'; i++) {
        if (FilePath[i] == L'\\' || FilePath[i] == L'/') {
            lastSlash = i + 1;
        }
    }
    fileName = &FilePath[lastSlash];

    /* 3. 构造目标路径：隔离目录\文件名.andunq */
    swprintf_s(dst, 520, L"%s\\%s%s", quarDir, fileName, ANDUN_QUARANTINE_EXT);

    /* 4. 移动文件 */
    RtlInitUnicodeString(&srcPath, FilePath);
    RtlInitUnicodeString(&dstPath, dst);

    return ZwRenameFile(&srcPath, &dstPath);
}

/* ============================================================
 * 3. 下发拦截规则
 * ============================================================ */

/*
 * ResponseBlockRule - 下发即时拦截规则
 *
 * 参数：
 *   Rule           - 规则内容（复用 ANDUN_RULE）
 *   AutoRemoveSec  - 0=永久规则；>0 表示 N 秒后自动移除（防误拦截）
 * 返回：
 *   STATUS_SUCCESS 或失败状态码
 */
NTSTATUS ResponseBlockRule(PANDUN_RULE Rule, ULONG AutoRemoveSec)
{
    NTSTATUS status;

    if (Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 1. 下发规则到规则引擎 */
    status = RuleEngineAddRule(Rule);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 2. 若设置了自动移除时间，创建定时器（此处简化为记录日志，
     *    完整定时器队列由用户态处置中心负责，避免驱动内复杂定时管理） */
    if (AutoRemoveSec > 0) {
        DbgPrint("[御天驱动] 已下发临时拦截规则 ID=%lu，%lu 秒后由用户态移除\n",
                 Rule->ruleId, AutoRemoveSec);
    } else {
        DbgPrint("[御天驱动] 已下发永久拦截规则 ID=%lu\n", Rule->ruleId);
    }

    return STATUS_SUCCESS;
}