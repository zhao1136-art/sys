@echo off
chcp 65001 >nul 2>&1
REM ============================================================
REM 御天内核驱动安装/卸载脚本
REM
REM 用法：
REM   install_driver.bat install   - 安装并启动驱动
REM   install_driver.bat uninstall - 停止并卸载驱动
REM   install_driver.bat status    - 查看驱动状态
REM   install_driver.bat start     - 仅启动驱动
REM   install_driver.bat stop      - 仅停止驱动
REM
REM 注意：需要管理员权限运行
REM ============================================================

setlocal

set DRIVER_NAME=AndunDriver
set DRIVER_SYS=%~dp0andun.sys
set ACTION=%1

if "%ACTION%"=="" set ACTION=install

REM --- 检查管理员权限 ---
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 需要管理员权限
    echo [御天驱动] 请右键 "以管理员身份运行"
    exit /b 1
)

if /i "%ACTION%"=="install" goto :install
if /i "%ACTION%"=="uninstall" goto :uninstall
if /i "%ACTION%"=="status" goto :status
if /i "%ACTION%"=="start" goto :start
if /i "%ACTION%"=="stop" goto :stop
echo [御天驱动] 用法: install_driver.bat [install^|uninstall^|status^|start^|stop]
exit /b 1

:install
echo [御天驱动] 安装驱动...
if not exist "%DRIVER_SYS%" (
    echo [御天驱动] 错误: 未找到 andun.sys，请先运行 build.bat 编译
    exit /b 1
)

REM 检查是否已安装
sc query %DRIVER_NAME% >nul 2>&1
if !errorlevel! equ 0 (
    echo [御天驱动] 驱动已存在，先卸载...
    sc stop %DRIVER_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %DRIVER_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

REM 创建服务
sc create %DRIVER_NAME% type= kernel start= demand binPath= "%DRIVER_SYS%"
if !errorlevel! neq 0 (
    echo [御天驱动] 创建服务失败
    exit /b 1
)

REM 启动服务
sc start %DRIVER_NAME%
if !errorlevel! neq 0 (
    echo [御天驱动] 启动驱动失败
    echo [御天驱动] 可能原因: 驱动未签名，请先运行 test_sign.bat 并开启测试签名模式
    echo [御天驱动] 开启测试签名: bcdedit /set testsigning on (需重启)
    sc delete %DRIVER_NAME% >nul 2>&1
    exit /b 1
)

echo [御天驱动] 驱动安装并启动成功
goto :eof

:uninstall
echo [御天驱动] 卸载驱动...
sc stop %DRIVER_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul
sc delete %DRIVER_NAME% >nul 2>&1
if !errorlevel! equ 0 (
    echo [御天驱动] 驱动已卸载
) else (
    echo [御天驱动] 卸载失败或驱动未安装
)
goto :eof

:status
sc query %DRIVER_NAME%
goto :eof

:start
sc start %DRIVER_NAME%
if !errorlevel! equ 0 (
    echo [御天驱动] 驱动已启动
) else (
    echo [御天驱动] 启动失败
)
goto :eof

:stop
sc stop %DRIVER_NAME%
if !errorlevel! equ 0 (
    echo [御天驱动] 驱动已停止
) else (
    echo [御天驱动] 停止失败
)
goto :eof

endlocal
