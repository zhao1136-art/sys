@echo off
chcp 65001 >nul 2>&1
REM ============================================================
REM 御天内核驱动编译脚本
REM
REM 前置条件：
REM   1. 已安装 WDK (Windows Driver Kit)
REM   2. 已安装 Visual Studio (带 C++ 桌面开发 + 驱动开发)
REM   3. 在 "开发人员命令提示符" 或配置了 WDK 环境的终端中运行
REM
REM 用法：
REM   build.bat            - 编译 Release 版本
REM   build.bat debug      - 编译 Debug 版本
REM ============================================================

setlocal enabledelayedexpansion

set BUILD_CONFIG=%1
if "%BUILD_CONFIG%"=="" set BUILD_CONFIG=release

echo [御天驱动] 开始编译 (%BUILD_CONFIG%)

REM --- 查找 WDK ---
set WDK_FOUND=0

REM 方式1: 使用 WDK 环境变量
if exist "%WindowsSdkDir%Include" (
    set WDK_INC=%WindowsSdkDir%Include
    set WDK_LIB=%WindowsSdkDir%Lib
    set WDK_FOUND=1
    echo [御天驱动] 使用 WindowsSdkDir: %WindowsSdkDir%
)

REM 方式2: 常见安装路径
if "!WDK_FOUND!"=="0" (
    for %%V in (10.0.22621.0 10.0.22000.0 10.0.20348.0 10.0.19041.0 10.0.18362.0) do (
        if exist "C:\Program Files (x86)\Windows Kits\10\Include\%%V\km" (
            set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%%V
            set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%%V
            set WDK_FOUND=1
            echo [御天驱动] 找到 WDK: %%V
            goto :wdk_found
        )
    )
)

:wdk_found
if "!WDK_FOUND!"=="0" (
    echo [御天驱动] 错误: 未找到 WDK，请先安装 Windows Driver Kit
    echo [御天驱动] 下载地址: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

set KM_INC=!WDK_INC!\km
set KM_LIB=!WDK_LIB!\km\x64
set UM_INC=!WDK_INC!\um
set UCRT_INC=!WDK_INC!\ucrt
set SH_INC=!WDK_INC!\shared

REM --- 查找编译器 ---
where cl >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 未找到 cl.exe，请在 "开发人员命令提示符" 中运行
    echo [御天驱动] 或运行: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

REM --- 设置编译参数 ---
set SRC_DIR=%~dp0andun_driver
set OUT_DIR=%~dp0

if "%BUILD_CONFIG%"=="debug" (
    set CFLAGS=/nologo /c /W4 /WX- /D_AMD64_ /D_WIN64 /DDBG /Zi /Od /GS
) else (
    set CFLAGS=/nologo /c /W4 /WX- /D_AMD64_ /D_WIN64 /O2 /GS
)

set INCLUDES=/I"%KM_INC%" /I"%SH_INC%" /I"%UM_INC%" /I"%UCRT_INC%" /I"%SRC_DIR%"

set SOURCES=^
    "%SRC_DIR%\driver_main.c" ^
    "%SRC_DIR%\device_control.c" ^
    "%SRC_DIR%\event_queue.c" ^
    "%SRC_DIR%\rule_engine.c" ^
    "%SRC_DIR%\file_filter.c" ^
    "%SRC_DIR%\process_callback.c" ^
    "%SRC_DIR%\registry_callback.c" ^
    "%SRC_DIR%\object_callback.c" ^
    "%SRC_DIR%\network_filter.c" ^
    "%SRC_DIR%\response.c" ^
    "%SRC_DIR%\rootkit_scan.c" ^
    "%SRC_DIR%\self_protect.c"
REM ↑ 原先只列了 9 个，漏了 response.c / rootkit_scan.c / self_protect.c
REM   （andun_driver\ 下实际有 12 个 .c）。漏掉的文件如果被其它模块引用，
REM   链接阶段会报 unresolved external symbol。

set LIBS=ntoskrnl.lib hal.lib fltMgr.lib wdm.lib fwpkclnt.lib ndis.lib uuid.lib

set LDFLAGS=/nologo /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /MACHINE:X64 /NODEFAULTLIB

if "%BUILD_CONFIG%"=="debug" (
    set LDFLAGS=!LDFLAGS! /DEBUG
) else (
    set LDFLAGS=!LDFLAGS! /RELEASE
)

REM --- 编译 ---
echo [御天驱动] 编译中...
cd /d "%OUT_DIR%"

cl %CFLAGS% %INCLUDES% %SOURCES%
if !errorlevel! neq 0 (
    echo [御天驱动] 编译失败
    exit /b 1
)

REM --- 链接 ---
echo [御天驱动] 链接中...

link %LDFLAGS% /LIBPATH:"%KM_LIB%" %LIBS% /OUT:"%OUT_DIR%andun.sys" *.obj
if !errorlevel! neq 0 (
    echo [御天驱动] 链接失败
    exit /b 1
)

REM --- 清理 ---
del *.obj 2>nul

echo [御天驱动] 编译成功: %OUT_DIR%andun.sys
echo [御天驱动] 请运行 test_sign.bat 进行测试签名
echo [御天驱动] 然后运行 install_driver.bat 安装驱动

endlocal
