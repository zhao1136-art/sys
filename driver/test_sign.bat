@echo off
chcp 65001 >nul 2>&1
REM ============================================================
REM 御天内核驱动测试签名脚本
REM
REM 前置条件：
REM   1. 已安装 WDK（提供 signtool / makecert / inf2cat）
REM   2. 已运行 build.bat 编译出 andun.sys
REM   3. 已开启测试签名模式：bcdedit /set testsigning on（需重启）
REM      注意：UEFI + Secure Boot 开启的机器**开不了**测试模式，必须先关 Secure Boot
REM
REM 用法：
REM   test_sign.bat    - 创建测试证书、签名驱动、并把证书导入受信任根
REM
REM 修订记录：
REM   2026-10-18 修两个会导致必然失败的问题：
REM     ① setlocal 缺 enabledelayedexpansion —— 原先用了 7 处 !errorlevel!，
REM        但延迟展开没开，!errorlevel! 不会展开成数字，比较永远成立，
REM        脚本在第一个检查（管理员权限）就直接 exit /b 1，一次都跑不完。
REM     ② 只签名、没有把证书导入「受信任的根证书颁发机构」——
REM        测试模式下签发者不在受信任根里，驱动照样加载失败，
REM        设备管理器显示「代码 52」。这才是最常见的失败原因。
REM ============================================================

setlocal enabledelayedexpansion

set DRIVER_SYS=%~dp0andun.sys
set CERT_NAME=YutianTestCert
set CERT_FILE=%TEMP%\andun_test.pfx
set CERT_PWD=Andun2024!

REM --- 检查管理员权限 ---
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 需要管理员权限（右键 -> 以管理员身份运行）
    exit /b 1
)

REM --- 检查驱动文件 ---
if not exist "%DRIVER_SYS%" (
    echo [御天驱动] 错误: 未找到 andun.sys，请先运行 build.bat 编译
    exit /b 1
)

REM --- 查找工具 ---
where signtool >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 未找到 signtool.exe
    echo [御天驱动] 请安装 WDK，或从 Windows Kits\10\bin\x64 加入 PATH
    exit /b 1
)

REM --- 创建测试证书（直接进 LocalMachine\My，便于随后导入受信任根）---
echo [御天驱动] 创建测试证书 "%CERT_NAME%" ...
powershell -NoProfile -Command ^
  "$n='%CERT_NAME%';" ^
  "Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq ('CN='+$n)} | Remove-Item -Force -EA SilentlyContinue;" ^
  "$c = New-SelfSignedCertificate -Subject ('CN='+$n) -CertStoreLocation 'Cert:\LocalMachine\My' -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -Type CodeSigningCert -NotAfter (Get-Date).AddYears(3);" ^
  "if (-not $c) { exit 1 };" ^
  "Write-Host ('  证书指纹: ' + $c.Thumbprint)"
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 创建证书失败
    exit /b 1
)

REM --- 导出 PFX 供 signtool 使用 ---
echo [御天驱动] 导出 PFX ...
powershell -NoProfile -Command ^
  "$n='%CERT_NAME%'; $p='%CERT_PWD%';" ^
  "$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq ('CN='+$n)} | Select-Object -First 1;" ^
  "$sp = ConvertTo-SecureString -String $p -Force -AsPlainText;" ^
  "Export-PfxCertificate -Cert $c -FilePath '%CERT_FILE%' -Password $sp | Out-Null"
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 导出 PFX 失败
    exit /b 1
)

REM --- 签名驱动 ---
echo [御天驱动] 签名驱动 ...
signtool sign /f "%CERT_FILE%" /p "%CERT_PWD%" /fd SHA256 /v /t http://timestamp.digicert.com "%DRIVER_SYS%"
if !errorlevel! neq 0 (
    echo [御天驱动] 带时间戳签名失败，重试不带时间戳（内网/无外网时常见）...
    signtool sign /f "%CERT_FILE%" /p "%CERT_PWD%" /fd SHA256 /v "%DRIVER_SYS%"
    if !errorlevel! neq 0 (
        echo [御天驱动] 错误: 签名失败
        exit /b 1
    )
)

REM --- 关键步骤：把证书导入「受信任的根证书颁发机构」---
REM     没有这一步，测试模式下驱动加载失败（设备管理器「代码 52」）
echo [御天驱动] 导入证书到 受信任的根证书颁发机构 ...
powershell -NoProfile -Command ^
  "$n='%CERT_NAME%';" ^
  "$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq ('CN='+$n)} | Select-Object -First 1;" ^
  "if (-not $c) { exit 1 };" ^
  "foreach ($sn in @('Root','TrustedPublisher')) {" ^
  "  $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($sn,'LocalMachine');" ^
  "  $s.Open('ReadWrite'); $s.Add($c); $s.Close();" ^
  "  Write-Host ('  已导入 ' + $sn)" ^
  "}"
if !errorlevel! neq 0 (
    echo [御天驱动] 警告: 导入受信任根失败 —— 驱动极可能加载失败（代码 52）
)

REM --- 验证签名 ---
echo [御天驱动] 验证签名 ...
signtool verify /v /pa "%DRIVER_SYS%"

echo.
echo [御天驱动] 完成。
echo [御天驱动]
echo [御天驱动] 下一步:
echo [御天驱动] 1. 若还没开测试模式: bcdedit /set testsigning on  然后重启
echo [御天驱动]    （桌面出现「测试模式」水印才说明生效）
echo [御天驱动] 2. install_driver.bat install
echo [御天驱动] 3. install_driver.bat status   查看是否加载成功

REM --- 清理 ---
del "%CERT_FILE%" 2>nul

endlocal
