<div align="center">

# 御天内核驱动 · Andun Driver

**`andun.sys` —— 一个自己写的 Windows 内核驱动，用 GitHub Actions 云端编译。**

[![Build](https://github.com/zhao1136-art/sys/actions/workflows/build-driver.yml/badge.svg)](https://github.com/zhao1136-art/sys/actions/workflows/build-driver.yml)
[![Type](https://img.shields.io/badge/type-WDM%20kernel%20driver-5C6BC0)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?logo=windows&logoColor=white)](#)
[![Sources](https://img.shields.io/badge/sources-12%20.c%20%2F%20%E7%BA%A6%20170%20KB-2ea44f)](#)
[![License](https://img.shields.io/badge/license-MIT-EA6A00)](LICENSE)

</div>

---

## 这是什么

御天安全套件的**内核态**部分。用户态能看到的东西有限，有些事只有内核层能做：

| 模块 | 干什么 |
|---|---|
| `file_filter.c` | 文件系统过滤（minifilter，依赖 `fltMgr`） |
| `process_callback.c` | 进程创建/退出回调（`PsSetCreateProcessNotifyRoutine*`） |
| `registry_callback.c` | 注册表操作回调（`CmRegisterCallback`） |
| `object_callback.c` | 对象回调，进程/线程句柄访问控制（`ObRegisterCallbacks`） |
| `network_filter.c` | 网络过滤（WFP，依赖 `fwpkclnt`） |
| `rootkit_scan.c` | Rootkit 检测（隐藏进程/驱动/SSDT 钩子等） |
| `self_protect.c` | 自保护（防止本进程/文件被终止或删除） |
| `rule_engine.c` | 内核态规则匹配 |
| `event_queue.c` | 事件队列（内核 → 用户态上报通道） |
| `device_control.c` | 设备与 IOCTL 分发 |
| `response.c` | 处置动作（阻断/隔离请求） |
| `driver_main.c` | `DriverEntry`：按顺序初始化各模块，卸载时反序清理 |

**纯 WDM**，不是 KMDF —— 链接 `ntoskrnl.lib hal.lib fltMgr.lib wdm.lib fwpkclnt.lib ndis.lib`，
`/SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry`。

## 为什么用 GitHub Actions 编

内核驱动**必须**用 WDK + MSVC 编译（MinGW 编不了内核模式）。本地装 WDK 约 1 GB、MSVC 约 4 GB，
而 GitHub 的 Windows runner 自带 MSVC —— 只要补装 WDK，**几分钟就能产出一个 `.sys`**。

这也是绝大多数「GitHub 上能看到 .sys 文件」的项目实际用的办法。

**用法**：打开 [Actions](../../actions/workflows/build-driver.yml) → `Build Driver` → `Run workflow`，
跑完在 run 详情页底部下载 `andun-driver` artifact，里面就是 `andun.sys` + `andun.inf`。

## 本地构建（可选）

```bat
:: 需要：Visual Studio（含 C++ 桌面开发）+ WDK
:: 在「x64 本机工具命令提示」里跑
build.bat release
```

产物：`andun.sys`。

## 测试签名（只能在自家开发机用）

Windows 对内核驱动强制签名。**不想买 EV 证书的话，开发阶段用测试签名模式**：

```bat
:: 1) 开启测试签名模式（需重启；桌面会显示「测试模式」水印）
bcdedit /set testsigning on

:: 2) 生成测试证书 + 签名 + 导入受信任根
test_sign.bat

:: 3) 安装驱动
install_driver.bat install
install_driver.bat status
```

**前提**：UEFI + Secure Boot 开启的机器**开不了**测试模式，得先进 BIOS 关掉 Secure Boot；
内存完整性（HVCI）也要关闭，否则测试签名驱动照样加载失败。

> `test_sign.bat` 除了签名，**还会把证书导入「受信任的根证书颁发机构」** ——
> 少了这一步，测试模式下驱动会加载失败，设备管理器显示**代码 52**。这是最常见的坑。
> 另外证书的 `CN` 不要用中文：`makecert`/`signtool` 在某些代码页下处理中文 CN 会出错，
> 这里已经改成 `YutianTestCert`。

## ⚠️ 当前状态：从未编译成功过

**诚实说明**：这套源码写了 12 个模块约 170 KB，但**一次都没编译过**（仓库里没有成功产出的 `.sys`）。
第一次跑 CI 几乎一定会在编译阶段报一堆错 —— 那是正常的起点，不是失败。

已知需要处理的地方：

- `build.bat` 原先只列了 9 个源文件，漏了 `response.c` / `rootkit_scan.c` / `self_protect.c`（已修）
- `test_sign.bat` 原先有两个必挂的 bug：`setlocal` 缺 `enabledelayedexpansion`（7 处 `!errorlevel!` 不展开）、
  没有把证书导入受信任根（已修）
- 内核 API 在 Windows 10 19045 上的可用性需要逐个核对（尤其是 WFP 与 minifilter 的组合）

## 发布到用户机器的真实门槛

测试模式**只能开发用，绝不能要求用户开**（等于拆掉 Windows 的核心安全边界）。

正式发布需要：

1. **EV 代码签名证书**（约 ¥3000–5000/年）
2. Windows 10 1607+ 起，**新**内核驱动光有 EV 签名装不上，必须过微软：
   - **Attestation signing**（Dev Portal 提交，自动签）
   - 或 **WHQL 认证**（跑 HLK 测试）
3. 每个驱动版本都要重新提交，且要承担蓝屏责任

## 许可证

[MIT](LICENSE)
