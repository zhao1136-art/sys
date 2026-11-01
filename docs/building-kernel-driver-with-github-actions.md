# 用 GitHub Actions 免费编译 Windows 内核驱动

> 不装 WDK、不买证书，从 0 到 andun.sys 的完整过程（含 16 个坑）
> 代码：https://github.com/zhao1136-art/sys

---

## 一、先说被劝退的地方

想学 Windows 驱动开发，第一步就卡死人：

- 装 Visual Studio（勾选「使用 C++ 的桌面开发」）—— 4 GB 起步
- 装 Windows Driver Kit（WDK）—— 再 1 GB，而且必须和 VS 版本匹配
- 装完还得用「x64 本机工具命令提示」打开，普通 cmd 里 `cl.exe` 根本找不到
- 然后编译报一堆错，你都不知道是环境问题还是代码问题

很多人到这一步就放弃了，**连一行驱动代码都没写**。

**但其实编译这件事可以完全丢给云端。**

GitHub 的 `windows-2022` runner 自带 Visual Studio + MSVC，你只要补装一个 WDK，**几分钟就能产出一个 `.sys` 文件**，本地零安装。

这也是绝大多数「GitHub 上能看到 `.sys` 文件」的项目实际采用的做法。

## 二、最小可用工作流

先给能跑起来的完整 YAML（这是我仓库里正在跑的，已经把坑填平了）：

```yaml
name: Build Driver
on:
  workflow_dispatch:
  push:
    paths: ['driver/**']

jobs:
  build-driver:
    runs-on: windows-2022
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@v4

      - name: 安装 WDK
        shell: pwsh
        run: |
          winget install --id Microsoft.WindowsWDK.10.0.22621 `
            --silent --accept-package-agreements --accept-source-agreements `
            --disable-interactivity
          # 装完必须检查 km 头文件真的在
          $found = $false
          Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Include' -EA SilentlyContinue |
            ForEach-Object {
              if (Test-Path (Join-Path $_.FullName 'km')) { $found = $true }
            }
          if (-not $found) { Write-Error "没有 km 头文件，WDK 没装上"; exit 1 }

      - name: 配置 MSVC
        uses: ilammy/msvc-dev-cmd@v1
        with:
          arch: x64          # 必须写！默认是 x86，编 x64 驱动会出怪问题

      - name: 编译
        shell: cmd
        run: |
          cd /d "%GITHUB_WORKSPACE%\driver"
          call build.bat release
          if errorlevel 1 exit /b 1

      - name: 上传产物
        uses: actions/upload-artifact@v4
        with:
          name: my-driver
          path: driver\my_driver.sys
```

跑完在 Actions 那次运行的页面底部 **Artifacts** 里下载，就是一个 `.sys`。

## 三、编译参数（关键就这几行）

```bat
:: 编译（WDK 头文件在 Include\<版本号>\km，别漏版本号）
cl /c /W4 /D_AMD64_ /D_WIN64 /O2 /GS ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\km" ^
   /I"...\Include\10.0.22621.0\shared" ^
   driver_main.c ...

:: 链接
link /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /MACHINE:X64 /NODEFAULTLIB ^
     /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\km\x64" ^
     ntoskrnl.lib hal.lib wdm.lib BufferOverflowK.lib ntstrsafe.lib uuid.lib ^
     /OUT:andun.sys *.obj
```

**注意最后两个 `.lib`**：`BufferOverflowK.lib` 和 `ntstrsafe.lib`。不加它们，链接必挂（原因见下文）。

## 四、16 个坑，按类分

### A 类：WDK 安装（3 个）

**坑 1：官方下载链接返回的不是安装包**

我第一次写的是：

```powershell
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2307229' -OutFile wdksetup.exe
```

看起来对，但那个链接返回的是 **15278 字节的 HTML 落地页**，不是 exe。`Start-Process` 当然失败。

判断方法：下载完检查大小，安装包是 1.3 MB 左右：

```powershell
if ($sz -lt 500000) { throw "下载到的不是安装包（$sz 字节）" }
```

**最终改用 winget** —— 官方包名明确，不用猜 fwlink 编号：

```powershell
winget install --id Microsoft.WindowsWDK.10.0.22621
```

**坑 2：装完不检查就继续，后面一堆 C1083**

WDK 装「成功」不代表 km 头文件在。必须显式检查 `Include\<版本>\km` 目录存在，否则后面 12 个文件全报 `C1083: cannot open ntddk.h`。

**坑 3：不指定 x64，得到的是 x86 工具链**

`ilammy/msvc-dev-cmd@v1` 默认 arch 是 x86。用它编 x64 驱动会出各种怪现象 —— 包括不报明确错误、只返回退出码 255。

```yaml
with:
  arch: x64
```

### B 类：cmd 批处理的坑（4 个，最阴）

这类坑最要命，因为**编译器和代码都没问题，是构建脚本自己被 cmd 解析错了**。

**坑 4：批处理文件必须是 CRLF 行尾**

我用 Python 脚本改 `build.bat` 时写了 `newline=''`，把 CRLF 转成了 LF。结果 cmd 逐行乱解析：

```
'RC_DIR"' is not recognized as an internal or external command
'GS' is not recognized as an internal or external command
```

**批处理只能是 CRLF。** 改完记得验证：

```powershell
python -c "b=open('build.bat','rb').read(); print(b.count(b'\r\n'), b.count(b'\n'))"
# 两个数字必须相等
```

**坑 5：set 的值里有括号，会提前闭合 if 块**

这个坑我在同一个问题上栽了三次。

```bat
if exist "...\Include\%%V\km" (
    set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%%V
)
```

`(x86)` 里那个**右括号**会把外层 `if` 块提前闭合，剩下的 `\Windows Kits\...` 变成一条孤立命令，报：

```
\Windows was unexpected at this time.
```

**正确写法是加引号：**

```bat
set "WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%%V"
```

**坑 6：REM 注释里也不能有括号**

对，注释一样会闭合块。我修完坑 5 之后，自己在块内写了一条解释性注释：

```bat
REM set 的值里含 (x86) —— 那个右括号会闭合块
```

**于是又崩了一次，报错完全一样。**

**坑 7：echo 展开带括号的变量，同样会崩**

```bat
if exist "%WindowsSdkDir%Include" (
    ...
    echo 使用 WindowsSdkDir: %WindowsSdkDir%
)
```

`%WindowsSdkDir%` 的值就是 `C:\Program Files (x86)\Windows Kits\10\` —— 展开后括号闭合块，还是那个 `\Windows was unexpected`。

**改法**：`echo "...%WindowsSdkDir%"` 加引号，或者干脆删掉这行。

> **这一类坑的通用判断**：只要报 `xxx was unexpected at this time`，就是某个块被提前闭合了，去块内找**未加引号的括号**（出现在 `set` 值、`echo`、`REM` 里都算）。
>
> 而且这类问题**本地测不出来** —— 我在本机跑 `build.bat` 一直正常，因为本机没装 WDK，那个 `if` 块根本不执行。是 CI 上条件成立、进了分支才炸的。

### C 类：编译和链接（9 个）

**坑 8：注释里的 `*/` 提前闭合块注释**

```c
 *   - 全局 PASSIVE_LEVEL，可安全调用 Zw*/Mm*/Ps* 接口。
```

`Zw*/` 里的 `*/` 把 `/* ... */` 注释提前结束了，后面的 `Mm*/Ps*` 被当代码解析：

```
error C2143: syntax error: missing '{' before '*'
error C3872: '0xa5': this character is not allowed in an identifier
```

**坑 9：`fltKernel.h` 和 `ndis.h` 不能放同一个编译单元**

我原来把框架头全塞进了公共头文件：

```c
#include <ntddk.h>
#include <fltKernel.h>   // minifilter
#include <fwpsk.h>       // WFP
#include <ndis.h>
```

结果：

```
ntifs.h(85): error C2371: 'PEPROCESS': redefinition; different basic types
ntifs.h(86): error C2371: 'PETHREAD': redefinition
```

**正确做法是按文件拆：**

```c
// andun.h —— 公共头只放 ntddk.h
#include <ntddk.h>
#include <ntstrsafe.h>

// file_filter.c —— 只有它需要 minifilter
#include <fltKernel.h>
#include "andun.h"

// network_filter.c —— 只有它需要 WFP
#include "andun.h"
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
```

**坑 10：`fwpsk.h` 必须定义 NDIS 版本号，否则 102 条错**

这个错得最惨。现象是 `fwpsk.h` 里一片红：

```
fwpsk.h(2763): error C2146: syntax error: missing ')' before identifier 'netBufferList'
fwpsk.h(2741): error C2371: 'FWPS_PACKET_LIST_INFORMATION0': redefinition
fwpsk.h(2740): error C2370: 'UINT32': redefinition; different storage class
```

看起来像一堆问题，**其实根因只有一个**：`NET_BUFFER_LIST` 未定义。后面的 `UINT32` / `BOOLEAN`「重定义」全是解析崩了之后的连锁反应。

原因：`ndis.h` 里的 NDIS6 类型（`NET_BUFFER_LIST`、`NDIS_HANDLE`）只在**定义了 NDIS 版本宏**时才导出。只定义 `NDIS_WDM` 不够，默认会落到 NDIS 5.1。

```c
#define NDIS_WDM 1
#define NDIS630 1
#include <ndis.h>
#include <fwpsk.h>
```

加上这一行，102 条错误全消失。

**坑 11：结构体成员名记错**

```
error C2039: 'Context': is not a member of '_OB_CALLBACK_REGISTRATION'
```

正确字段是 `RegistrationContext`，不是 `Context`。

**坑 12：函数先用后定义**

```
error C2065: 'DriverUnload': undeclared identifier
```

C 要求先声明后使用。`DriverUnload` 定义在文件末尾，`DriverEntry` 里先用到了 —— 补个前置声明就行。

**坑 13：WDK 没导出你想用的符号**

```
error C2065: 'PsLoadedModuleList': undeclared identifier
error C2065: 'PLDR_DATA_TABLE_ENTRY': undeclared identifier
error C2065: 'PROCESS_TERMINATE': undeclared identifier
```

这些在 `ntifs.h` 里「理论上」有，实际这个 WDK 版本没导出。只能自己声明：

```c
extern PLIST_ENTRY PsLoadedModuleList;

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

// LDR_DATA_TABLE_ENTRY 按公开布局自己定义（x64 偏移）
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;            // 0x00
    LIST_ENTRY     InMemoryOrderLinks;          // 0x10
    LIST_ENTRY     InInitializationOrderLinks;  // 0x20
    PVOID          DllBase;                     // 0x30
    PVOID          EntryPoint;                  // 0x38
    ULONG          SizeOfImage;                 // 0x40
    UNICODE_STRING FullDllName;                 // 0x48
    UNICODE_STRING BaseDllName;                 // 0x58
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;
```

**坑 14：API 签名不合**

```
error C2039: 'numValues': is not a member of 'FWPS_INCOMING_VALUES0_'
error C2197: 'FwpmTransactionCommit0(HANDLE)': too many arguments for call
```

`FWPS_INCOMING_VALUES0` 的字段是 `valueCount` 不是 `numValues`；`FwpmTransactionCommit0` 只收一个参数。这类只能靠编译报错一个个改。

**坑 15：`/GS` 的运行时库**

```
error LNK2001: unresolved external symbol __security_check_cookie
error LNK2001: unresolved external symbol __security_cookie
error LNK2001: unresolved external symbol __report_rangecheckfailure
```

用了 `/GS`（缓冲区安全检查）就要链 **`BufferOverflowK.lib`** —— 这是 WDK 专门给内核驱动提供的。

**坑 16：用户态函数不能在内核里用**

```
error LNK2019: unresolved external symbol __stdio_common_vswprintf_s
```

`swprintf_s` 是 UCRT 的函数，内核里没有。换成 `RtlStringCchPrintfW` 还不行，因为 `ntstrsafe.h` 默认用内联实现，内部还是要调 `vswprintf`。

**解法**：定义 `NTSTRSAFE_LIB` 走库版本，并链 `ntstrsafe.lib`：

```c
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
```

同类的还有 `ZwRenameFile` —— 它**不是**内核导出符号。改名要用：

```c
ZwOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &iosb, ...);
// 填 FILE_RENAME_INFORMATION
ZwSetInformationFile(hFile, &iosb, &rinfo, sizeof(rinfo), FileRenameInformation);
ZwClose(hFile);
```

## 五、CI 编译错误看不到怎么办

这个问题很现实：CI 失败了，你要看报错。

- GitHub 网页上能看，但一次几百行，翻起来痛苦
- API 拿日志要 token，匿名访问有配额（我撞过 403）
- 有些报错不在最后，在中间

我用的办法是：**失败时把 `build.log` 提交回仓库**，然后本地 `git pull` 就能看全文。

```yaml
- name: 失败时回传编译日志
  if: failure()
  shell: pwsh
  run: |
    git config user.name 'ci-bot'
    git config user.email 'ci-bot@users.noreply.github.com'
    git add -f driver/build.log
    git commit -m "ci: 编译失败日志 [skip ci]" --allow-empty
    git push origin HEAD:main
```

两个细节：

- 提交信息带 `[skip ci]`，防止无限触发
- 用 `git push origin HEAD:main`，不要用 `git push` —— checkout 出来可能是 detached HEAD，直接 push 会报 "not currently in a branch"

## 六、编出来 ≠ 能装

这是必须强调的一点。`.sys` 文件产出成功，只证明**能编译**，不证明**能加载**。

Windows 对内核驱动强制签名。开发阶段可以用**测试签名模式**：

```bat
bcdedit /set testsigning on
:: 重启，桌面会显示「测试模式」水印
test_sign.bat    :: 自签证书 + 签名 + 证书导入受信任根
install_driver.bat install
```

两个容易踩的点：

- **证书必须导入「受信任的根证书颁发机构」** —— 只签名不导根证书，测试模式下照样加载失败，设备管理器显示「代码 52」
- **UEFI + Secure Boot 开着就开不了测试模式**，得先进 BIOS 关 Secure Boot；内存完整性（HVCI）也要关

**而且：加载失败是蓝屏。** 建议先在虚拟机里试。

## 七、给用户发布的真实门槛

测试模式只能自己开发用，**绝不能要求用户开** —— 那是把 Windows 的核心安全边界拆掉。

正式发布需要：

| 要求 | 说明 |
|---|---|
| EV 代码签名证书 | 约 ¥3000–5000/年 |
| 微软签名服务 | Win10 1607+ 起，新驱动光有 EV 签名装不上，必须过 Attestation signing 或 WHQL 认证 |
| 每个版本重新提交 | 驱动一改就要重新签 |
| 蓝屏责任 | 内核崩溃是整机崩，不是进程崩 |

这就是为什么很多「个人安全软件」没有驱动 —— **不是不想做，是成本不划算**。

## 八、一些数字

我这个驱动（御天 `andun.sys`）：

- 12 个 `.c` 模块，约 170 KB 源码
- minifilter + WFP + 进程/注册表/对象回调 + Rootkit 扫描 + 自保护
- **CI 跑了 15 次才编出来**
- 最终产物 41,472 字节，`Subsystem = 1 (NATIVE)`，`Machine = 0x8664 (AMD64)`

## 九、项目地址

**https://github.com/zhao1136-art/sys**

里面有：

- 完整的 `.github/workflows/build-driver.yml`（就是本文第二、五节那些）
- 12 个模块的驱动源码
- `build.bat` / `test_sign.bat` / `install_driver.bat`
- README 里写清了当前状态（**编出来了，但还没在真机上加载过**）

许可：**禁止商业使用**（PolyForm Noncommercial 1.0.0）。

## 十、最后

写这篇的原因很简单：我在这个过程中被坑了 15 次，其中一半是「网上搜不到答案、只能自己读报错推」的。

本文列的所有坑都是真实的，包括我自己的失误（把 HTML 落地页当安装包、Python 脚本把 CRLF 改成 LF、修完坑 5 又在注释里重犯一次）。**写出来是为了以后查这个的人不用再踩。**

如果这篇帮你省下了装 WDK 的时间，那它就没白写。

有问题欢迎留言，也欢迎指正 —— 尤其是那个 `NDIS630` 的坑，我到现在也没完全搞清楚 WDK 的版本宏规则，只知道这样能过。
