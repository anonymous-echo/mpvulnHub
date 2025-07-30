#  PowerShell 漏洞 — 现代 APT 及其恶意脚本策略   
hai dragon  安全狗的自我修养   2025-02-18 23:19  
  
介绍图片 （我非常不擅长编辑图片 ^_^ ）  
  
你好在本博客中，我们将从 PowerShell 简介开始，解释为什么它是 Red Teamer 最喜欢的工具。从那里，我们将探索它的内存加载功能并详细研究 AMSI（反恶意软件扫描接口），包括它如何深入运行。然后，我将通过三个简单而有效的 PowerShell 命令行（脚本小子会非常高兴，尤其是在这部分）向您详细介绍绕过 AMSI 的方法。  
  
接下来，我们将介绍如何**滥用 .NET 功能来运行 PowerShell 命令，而无需实际使用 PowerShell**  
 本身，以及如何**使用 Invoke-Obfuscation 等工具逃避检测**  
。C ^_^ **语言中 AMSI 内存修补**  
的一些示例。我们还将了解高级持续性威胁 **（APT） 如何创建自定义混淆器以成功规避技术。**  
  
此外，我们还将讨论鲜**为人知的 CLSID 劫持**  
等技术，探索**有效但未得到充分利用的 LOLBins**  
，最后介绍 **PowerLoad3r 等高级工具**  
的真实示例。  
  
我希望您发现本指南内容丰富且引人入胜，其中包含大量实用见解，可以增强您的红队工作，你猜怎么着？**我们将进行的所有旁路和测试都将针对卡巴斯基 EDR**  
 :)并希望它可以加快或帮助您参与红队。  
# - 什么是 PowerShell？  
  
PowerShell 是 Microsoft 面向系统管理员和高级用户的瑞士军刀。它诞生于 2006 年，是一种基于类固醇的命令行 shell 和脚本语言。  
  
以下是 PowerShell 的特别之处：  
- **它是面向对象的，**  
PowerShell 不仅使用文本，还**处理结构化数据**  
。这意味着您可以轻松地在命令之间作和传递复杂信息。  
  
- **它基于 .NET 构建**  
：这使 PowerShell 能够深入访问 Windows 内部，并使其在系统管理方面非常强大。  
  
- PowerShell 最初仅适用于 Windows，现在**也可以在 Linux 和 macOS 上运行**  
。  
  
无论您是管理单台笔记本电脑还是一组云服务器，PowerShell 都能为您提供更快、更高效地完成工作的工具。它是任何认真对待 Windows 管理或 DevOps 的人的首选工具。  
# - 为什么 Red Teamers 和 Penetration Testers 喜欢 PowerShell  
  
PowerShell 牢固地确立了自己作为红队和渗透测试的基石。原因如下：  
- 它预装在 Windows 上，因此攻击者不需要添加额外的工具，因此更难被发现。  
  
- 它可以利用 Windows 的核心系统和 .NET，让攻击者执行诸如窃取凭据、跨网络移动或提取数据等作。  
  
- 从查找目标到维护访问权限，PowerShell 会处理攻击的每一步。  
  
- 脚本可以隐藏或打乱，使防御者难以捕捉它们。  
  
- 它与 Azure 和 AWS 等云平台配合使用，非常适合现代攻击。  
  
**PowerShell 不仅仅是一个工具**  
，它是导航现代攻击面不可或缺的盟友。  
# PowerShell 及其内存中加载功能  
  
PowerShell 的内存执行是红队成员的梦想工具。原因如下：  
- **代码直接在 RAM 中运行**  
，不会在磁盘上留下任何痕迹。这使得防病毒和安全工具难以检测到。  
  
- 攻击者可以**动态地动态生成、修改和混淆代码**  
。这允许快速适应不同的环境并规避安全措施。  
  
- 整个框架和**复杂工具都可以加载到内存中**  
，从而为攻击者提供一整套功能，而无需安装软件。  
  
- 靠土地生活  
  
- **一旦进入系统，内存中执行就有助于从凭证收集到横向移动的所有作，同时保持低调**  
。  
  
# Invoke-Expression cmdlet — 启用内存中执行  
  
Invoke-Expression（IEX） 允许在当前会话中将字符串作为 PowerShell 命令执行。它是内存中执行的关键工具。  
```
```  
  
此命令运行 “Get-Process” 并返回活动进程的列表。 与其他 cmdlet 或 .NET 方法结合使用时，功能会更加强大，从而支持复杂的内存中命令执行。Invoke-Expression  
# 使用 IEX 进行内存中加载和执行  
  
当与 from the class 结合使用时，可以完全在内存中下载和运行脚本。.DownloadStringWebClientIEX  
```
```  
- New-Object Net.WebClient创建用于检索资源的实例。WebClient  
- .DownloadString('URL')从提供的 URL 下载脚本。  
- IEX在内存中执行下载的脚本。  
此方法允许秘密执行，绕过磁盘存储并使检测更加困难。  
## 一旦你尝试执行它 “BOOM”  
  
  
  
但是，现代 Windows 版本使用反恶意软件扫描接口 （AMSI） 加强了防御措施，以抵御此类脚本下载和执行尝试。AMSI 集成到 Windows 10 安全措施中，旨在检测和防止基于脚本的规避技术，挫败绕过传统防病毒解决方案的努力。AMSI 是一种强大的防御机制，可抵御潜在的恶意脚本执行，包括那些利用 PowerShell 的内存加载功能。  
# AMSI 如何运作  
  
反恶意软件扫描接口 （AMSI） 代表深度集成到 Windows作系统中的复杂安全框架。该分析深入研究了其错综复杂的作机制、高级功能和不断发展的功能。  
  
**核心架构**  
  
AMSI 利用组件对象模型 （COM） 接口实现 Windows、应用程序和防病毒解决方案之间的顺畅交互。这些接口有助于无缝通信和集成，以实现有效的恶意软件检测。AMSI 架构的关键组件包括：  
- **amsi.dll**  
是便于扫描作的中央 AMSI 库  
  
- **AmsiScanBuffer**  
 和 **AmsiScanString**  
是分别负责扫描内存数据缓冲区和字符串以查找潜在威胁的函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFxZZnl9cd3HFgbeGMSic3Rh5saIoLZNFT4S9Mr0l3pyHPrib2MZsPIZicXMkLDVatkhY72ictEbvhsnw/640?wx_fmt=png&from=appmsg "")  
  
  
实际上 AmsiScanString 只是使用 AmsiScanBuffer :)  
- **IAntimalwareProvider**  
：防病毒软件用于与 AMSI 集成的接口，允许第三方安全解决方案在 AMSI 框架内进行威胁检测。  
  
AMSI 拱门  
  
**初始化和注册过程**  
  
系统启动时，反恶意软件扫描接口 （AMSI） 将进行结构化初始化，以便与 Windows 应用程序和防病毒解决方案无缝集成：  
1. AMSI 服务在引导过程的早期初始化，确保扫描框架已准备好处理来自应用程序和服务的请求。  
  
1. 防病毒解决方案通过界面向 AMSI 注册。此注册允许防病毒产品与 AMSI 集成，使其能够参与扫描过程。IAntimalwareProvider  
1. 识别 AMSI 的应用程序（如 PowerShell 和 Microsoft Office）会加载该库。此动态链接库 （DLL） 对于 AMSI 执行的扫描作至关重要。amsi.dll  
1. 这些应用程序使用以下函数配置其扫描上下文：AmsiInitialize  
```
```  
- 此功能为每个应用程序创建唯一的上下文，从而允许使用特定于应用程序的扫描策略。该参数指定应用程序的名称，该参数是指向将在后续 AMSI API 调用中使用的句柄的指针。appNameamsiContext  
**内存扫描功能**  
  
AMSI 执行内存中扫描的能力是检测直接在系统内存内运行的复杂无文件恶意软件的关键功能，从而规避了传统的基于磁盘的检测方法。  
  
该功能是此功能的核心：AmsiScanBuffer  
```
```  
  
此功能使 AMSI 能够检查原始内存缓冲区，从而有助于检测高级威胁，例如：  
- 直接在内存中加载和执行的脚本，绕过磁盘存储和传统的基于文件的扫描。  
  
- 尝试直接从内存中执行代码的恶意软件，通常通过反射 DLL 注入等技术。  
  
**情境感知扫描**  
  
AMSI 利用基于会话的扫描来维护多次扫描的上下文，从而实现更准确的风险评估。  
  
该函数用于在现有 AMSI 上下文中创建会话：AmsiOpenSession  
```
```  
- amsiContextAMSI 上下文的句柄，从 获取。AmsiInitialize  
- amsiSession：指向将表示新会话的句柄的指针。  
此函数在成功时返回，如果失败，则返回 HRESULT 错误代码。S_OK  
  
通过打开会话，应用程序可以对多个扫描请求进行分组，从而允许 AMSI 跟踪执行流并做出更明智的决策。  
  
检查 powershell  
  
**判决确定**  
  
AMSI 收集所有提供商的回复，并使用加权评分系统确定最终裁决：  
1. 每个提供程序返回从 AMSI_RESULT_CLEAN 到 AMSI_RESULT_MALWARE 的结果。  
  
1. AMSI 汇总了这些结果，并根据提供商的声誉和置信度对其进行加权。  
  
1. 最终判决将决定作：  
  
- 允许执行  
  
- 阻止执行并通知应用程序  
  
- 触发其他日志记录、警报或辅助扫描  
  
> **下载 Mimikatz 的挑战：**  
  
> 当您尝试使用直接 IEX 方法下载并执行 Mimikatz 时，AMSI 会在执行脚本内容之前拦截脚本内容。鉴于 Mimikatz 臭名昭著的声誉及其可识别的恶意模式，AMSI 很可能会识别并随后阻止其执行。  
  
  
  
AMSI 检测到了它  
  
这种 AMSI 干预使得像 Mimikatz 这样臭名昭著的脚本的直接下载和内存执行变得非常成问题。规避或绕过 AMSI 对于此类脚本的运行至关重要。  
> **为什么直接下载 Mimikatz 有问题：**  
  
  
当您尝试使用 IEX 方法直接下载并执行 Mimikatz 脚本时，AMSI 会在执行脚本内容之前捕获脚本内容。鉴于 Mimikatz 已知恶意模式，AMSI 可能会标记并阻止执行。  
  
这使得直接下载和内存中执行 Mimikatz 等知名脚本具有挑战性，而无需首先绕过或规避 AMSI。  
  
**所以**  
PowerShell 的强大内存作功能无疑是强大的。然而，Microsoft 的内置安全措施，尤其是 AMSI，对直接的恶意活动构成了重大障碍。网络安全机制和规避策略之间的这种不断发展和相互作用体现了该领域的动态性质，需要不断学习和适应。  
# 使用 Import-Module 加载 Mimikatz  
  
将 Mimikatz 加载到 PowerShell 会话中的另一种方法是使用 Import-Module cmdlet：  
```
```  
  
**什么是 Import-Module？**  
Import-Module cmdlet 是一个内置的 PowerShell 命令，用于将一个或多个模块添加到当前会话。在 PowerShell 的上下文中，模块是包含 PowerShell 成员（包括 cmdlet、提供程序、函数、变量等）的包。  
  
**Import-Module 的工作原理：**  
1. 首先，PowerShell 在当前目录中搜索指定的模块，在本例中为 .\Invoke-Mimikatz.ps1。如果在那里找不到，PowerShell 会检查预定义的模块路径。  
  
1. 接下来，如果模块清单文件 （.psd1） 存在，PowerShell 会读取该文件以确定模块的属性、依赖项和任何必需的程序集。在此之后，任何必要的 .NET 程序集都将加载到 PowerShell 进程中。  
  
1. 找到脚本文件 （Invoke-Mimikatz.ps1） 后，它将在单独的范围内执行。此执行定义模块中包含的所有函数、变量和别名。只有显式导出的项或所有项（如果未设置限制）才可用于当前会话。  
  
1. 然后，导出的项目将集成到会话的函数和变量表中，这允许直接访问它们，就像它们是本机命令一样。为了提高性能，该模块被缓存在内存中，以便在后续导入期间更快地访问。  
  
1. 如果模块依赖于其他模块或脚本，PowerShell 也会以递归方式导入它们。此外，在执行模块中的任何代码之前，PowerShell 会检查系统的执行策略，以确保允许运行模块。  
  
1. 最后，重要的是要注意，模块中定义的内部变量与当前会话中的内部变量保持隔离。这种隔离可以防止模块变量和现有会话变量之间发生冲突，从而确保平稳运行并降低出错的风险。  
  
值得注意的是，即使您从磁盘导入模块，如果执行模块的任何部分，AMSI 仍然可以扫描并可能阻止其内容。  
# - 混淆和绕过AMSI（概述）  
  
模糊处理是一种使代码难以理解的方法。这就像写一条只有你懂得阅读的秘密信息。当我们谈论 AMSI 时，经常使用混淆来尝试欺骗它。  
  
以下是大多数混淆对 AMSI 的工作原理：  
1. 隐藏 Obfuscation → 的真正含义会改变代码的外观，而不会改变它的功能。例如，您可以编写 “H” + “e” + “l” + “l” + “o”，而不是写 “Hello”。它仍然是 “Hello” 的意思，但看起来不同。  
  
1. 使内容变得混乱 - > 混淆会添加额外的内容，这些内容不会执行任何重要作。这就像在句子中添加随机单词以混淆阅读它的人。  
  
1. 使用奇怪的名称，而不是为代码中的事物使用明确的名称，混淆使用随机或误导性的名称。这使得 AMSI 更难猜测代码在做什么。  
  
1. 使用编码例如，当以 Base64 编码时，“Hello” 可能会变为 “SGVsbG8=”。AMSI 可能不会立即意识到这一点。  
  
# - Invoke-Obfuscation（第一个技巧）  
  
Invoke-Obfuscation 由 Daniel Bohannon 创建，是一种用于对 PowerShell 脚本进行模糊处理以避免检测的工具，通常用于 Red Team 参与。  
  
要更深入地了解 Invoke-Obfuscation 及其应用程序，您可能会发现以下视频很有启发性：  
https://www.youtube.com/watch?v=uE8IAxM_BhE  
  
在给定的脚本中，正在执行反向 shell 有效负载，概述如下 ->   
Github — Payload All The Things — Powershell Reverse Shell  
 ：  
```
```  
  
在启动混淆后，payload 会经历一次变形，变得模糊，同时保留其核心功能，如下所示：  
  
> **“我已经在 Windows Defender 上测试了该工具，在某些情况下，还针对卡巴斯基进行了测试，它成功地避开了它们，没有任何问题。这就是我将其添加到博客中的原因。:)”**  
  
# - PowerShell 中的 3 种简单有效的 AMSI 绕过技术  
  
基于反射的旁路 此方法使用 .NET 反射通过将其内部 amsiInitFailed 标志设置为 true 来禁用 AMSI。  
```
```  
- 它访问 System.Management.Automation 程序集中的 AmsiUtils 类。  
  
- 它将 amsiInitFailed 字段设置为 true，强制 AMSI 初始化失败  
  
- 字符串被拆分 （'System.Manage'+'ment.Automa'+'tion.AmsiUtils'） 来逃避静态检测。  
  
> Base64 + ASCII 混淆该方法使用 Base64 和 ASCII 编码对关键字符串进行混淆，以避免被发现。  
  
```
```  
- 从 Base64 解码“System.Management.Automation.AmsiUtils”。  
  
- 将 'amsiInitFailed' 从 ASCII 字节值转换。  
  
- 使用反射来禁用 AMSI。  
  
> Minimal Reflection Bypass（最小反射旁通）：这是基于反射的旁通的更简洁版本。  
  
```
```  
# - C 语言中的 AMSI 修补技术  
  
本节深入探讨了使用 C 编程修补反恶意软件扫描接口 （AMSI） 的各种方法。详细解释了每种技术，包括其基本原理、实现和潜在影响。  
  
**使用 WriteProcessMemory 进行函数修补**  
  
该技术涉及直接覆盖内存中 AMSI 函数的代码。  
```
```  
> - LoadLibraryA("amsi.dll")将 AMSI DLL 加载到进程内存中- 检索函数的内存地址 - 数组包含机器代码指令：： MOV EAX （将值移动到 EAX 寄存器）： 值 0x80070057 （E_INVALIDARG十六进制）： RET（从函数返回）- 用我们的补丁覆盖原始函数代码。- 此修补程序有效地使始终返回E_INVALIDARG，绕过扫描。GetProcAddress()AmsiScanBufferpatch0xB80x57, 0x00, 0x07, 0x800xC3WriteProcessMemory()AmsiScanBuffer  
  
  
**内存保护修改**  
  
该方法临时更改目标函数的内存保护以允许修改。  
```
```  
> - 我们像以前一样定位函数 - 用于将内存保护更改为 PAGE_EXECUTE_READWRITE- 用（JE/JZ 指令）覆盖函数的第一个字节 - 我们恢复原来的内存保护AmsiScanBufferVirtualProtect()memcpy()0x74  
  
  
**汇编级函数修补**  
  
该技术涉及注入特定的汇编指令来改变函数行为。  
```
```  
> - 我们找到函数- 包含 ，这是无条件短跳转的作码 - 我们用这个跳转指令覆盖函数的第一个字节AmsiScanBufferjumpPatch0xEB  
  
  
**指令覆盖**  
  
此方法用简单的中和指令覆盖函数 start。  
```
```  
> - 包含指令（机器代码中的 48 31 C0）- 此指令清除 RAX 寄存器，该寄存器通常用于 x64 调用约定中的返回值- 通过清除 RAX，我们确保函数始终返回 0，表示成功并绕过扫描nopPatchXOR RAX, RAX  
  
  
**远程进程注入**  
  
此技术允许在不同的进程中修补 AMSI。  
```
```  
> - OpenProcess（） 获取目标进程的句柄 - 我们在 AMSI DLL中找到函数 - 数组包含指令- WriteProcessMemory（） 将此代码注入目标进程的内存空间- 我们关闭进程句柄以清理资源AmsiOpenSessionbypassXOR RAX, RAX  
  
  
**函数挂钩**  
  
此方法涉及将 AMSI 函数重定向到自定义实现。  
```
```  
> - 我们找到函数- 数组包含 ，这是 x86/x64 程序集中近跳转的作码 - 这是 5 字节跳转指令的第一个字节 - 实现将涉及计算和写入跳转偏移量以重定向到自定义函数AmsiScanBufferhook0xE9  
  
# - 高级威胁行为者和高级持续性威胁 （APT）  
  
APT 通常会创建自定义混淆工具，而不是使用公共工具。这些定制工具通过安全系统未知、利用特定弱点和频繁更新来逃避检测。他们结合了多种技术，使用零日漏洞，并适应他们的环境，使 APT 能够保持对受感染系统的长期访问。  
  
**为了强调这一点，让我们向 0xNinjacCyclone 创建的令人难以置信的 Ruby 脚本大喊大叫：**  
  
  
**这个怎么运作？**  
  
**此 Ruby 脚本是一种概念验证 （PoC），旨在通过随机重命名函数、变量和参数来混淆 PowerShell 脚本（如 Invoke-Mimikatz.ps1）。它旨在使分析复杂化，使安全工具更难检测或分析脚本，这对于红队作或渗透测试很有用。**  
  
该脚本包括一组要进行模糊处理的 PowerShell 命令 （INVOCATIONS），例如常见命令，如 and（此脚本无法修改这些命令，因为更改这些值需要修改二进制文件本身;该脚本仅对函数名称和参数进行模糊处理）。coffeesekurlsa::logonpasswords  
  
主要的混淆过程的工作原理是生成随机字母数字字符串（最长 8 个字符）来替换函数、参数和变量的名称。这种随机化可确保没有两个混淆是相同的。将检查每个生成的名称，以确保它尚未被使用，从而防止重复。  
  
对于函数，obfuscate_funcs 方法会扫描脚本中的函数定义，将其名称替换为随机字符串，并存储经过混淆处理的名称以供以后使用。同样，obfuscate_args 方法处理参数的混淆，而 obfuscate_vars 侧重于变量名称。  
  
该脚本使用 remove_comments 方法从 PowerShell 脚本中删除所有注释。这消除了单行 （#） 和多行 （<#...#>） 注释，使脚本更难阅读。  
  
混淆完成后，脚本将打印转换后的命令，显示原始命令的更改方式。它还输出经过混淆的函数、参数和变量数的计数。最后，它将修改后的脚本保存到具有随机名称的新文件中。  
  
  
**实际应用和检测测试**  
：  
- 这种混淆方法会显著改变 PowerShell 脚本，使安全工具更难根据已知模式和签名进行检测。  
  
主要工具的检测没有任何混淆：  
- 该脚本针对卡巴斯基安全软件进行了测试，以证明其有效性。这些图像显示了在没有任何混淆的情况下对主工具的检测，以及混淆后降低的检测率。  
  
运行脚本时未从 Kaserpsky 检测到蜂鸣  
> **注意**  
：“在实际场景中，我们不能简单地通过混淆器运行像 Mimikatz 这样的工具，并期望它们无法被检测到。Mimikatz 等工具具有**众所周知的签名**  
，许多 **YARA 规则**  
可以根据它们的不同模式来识别它们。因此，仅依靠自动混淆工具可能是不够的。为了在使用此类工具时有效地绕过检测，我们还必须采用手动混淆技术。但请试一试！  
  
  
  
混淆后 Virus-Total 的检测率  
  
  
对抗 Windows Defender  
# - 使用 powerpick 绕过控件 ？？  
> PowerPick 是红队成员和渗透测试人员武器库中的关键工具，旨在秘密执行 PowerShell 脚本。这种创新工具绕过了对传统二进制的需求 ，而二进制是安全监控系统的常见关注点。PowerPick 的方法通常称为“非托管 PowerShell”，它使脚本能够直接通过 PowerShell 引擎执行。此方法显著降低了 PowerShell 活动的可见性，使 PowerPick 成为谨慎作的首选。powershell.exe  
  
# - 增强 PowerPick 的规避性：在没有 PowerShell 的情况下使用 powershell  
> PowerPick 支持在不生成 powershell.exe的情况下执行 PowerShell 脚本，使用 .NET 程序集实现更隐蔽的方法。  
  
  
**修改 PowerPick 以实现 Stealthier Execution 的示例**  
  
在此示例中，我们将演示如何修改 C# .NET 应用程序以通过 .NET 程序集加载和执行 PowerShell 代码，并了解它在后台的工作原理  
```
```  
  
**它到底是如何工作的？**  
- 对象是使用 创建的。这会在 .NET 运行时中分配一个专用的执行环境，而运行空间是处理 PowerShell 脚本执行的单独线程RunspaceRunspaceFactory.CreateRunspace()  
- 在运行空间内创建一个对象，该对象处理命令的顺序执行。当您添加命令（如 ）时，它会被编译成中间形式并传递给管道，在那里执行PipelineGet-Process  
- 添加到管道中的每个命令都会转换为 a，后者将脚本转换为字节码以供执行。这发生在运行空间内，避免了对外部进程的需求，例如CommandProcessor powershell.exe  
- PowerShell 对象创建为 .NET 对象（如），这些对象由 .NET 的垃圾回收器，但 PowerShell 的内部内存管理确保在运行空间关闭时正确处理它们PSObject  
# - 劫持和滥用鲜为人知的 CLSID  
  
那么什么是 CLSID？  
- CLSID （类标识符） 是 128 位 GUID （例如，） ，用于唯一标识 Windows 中的 COM 对象，使应用程序能够查找系统或第三方组件（如设备管理器或 UI 处理程序）并与之交互。{374DE290-123F-4565-9164-39C4925E467B}  
- 它们映射在 Windows 注册表中的 下，其中子项定义对象的可执行文件 （DLL/EXE）、线程模型和权限的路径。HKEY_CLASSES_ROOT\CLSID  
- 应用程序使用 CLSID 等 API 来实例化 COM 对象，这对于文件资源管理器的旧式搜索框 （） 或 Office 应用程序等功能至关重要。CoCreateInstance{bc32b5-4eec-4de7-972d-bd8bd0324537}  
- 攻击者通过覆盖 （用户级别） 中的合法注册表项来劫持 CLSID，以将受信任的进程 （例如 ） 重定向到没有管理员权限的恶意负载。HKCU\Software\Classes\CLSIDexplorer.exe  
- 被劫持的 CLSID 会悄悄地执行，通常会在重新启动后持续存在，并通过模拟磁盘清理 （） 等合法系统任务来绕过检测。vssadmin delete shadows  
- 缓解措施包括监视注册表更改、强制实施对 CLSID 密钥的最低特权访问、通过 AppLocker 将受信任的 COM 对象列入白名单，以及验证引用的二进制文件的数字签名。  
  
- 开发人员必须确保正确的 CLSID 注册（例如，使用 ）并匹配 32/64 位架构，以避免出现 .regsvr320x80040154  
那么，现在关于滥用它们的令人兴奋的部分是：  
  
ShellWindows COM （效果： ★★★★ ☆）  
```
```  
  
ShellBrowserWindow （有效性：★★★★★）  
```
```  
  
Excel 4.0 宏 （效果： ★★★★ ☆）  
```
```  
  
XMLDOM 远程 Scriptlet（有效性：★★★★★）  
```
```  
  
MMC20 的。应用 （效果： ★★★ ☆☆）  
```
```  
  
Verclsid.exe 代理 （效果： ★★★★ ☆）  
```
```  
# - 滥用（鲜为人知的）Windows 二进制文件执行 Stealth Payload  
  
Windows 具有攻击者喜欢的内置工具，这些受信任的二进制文件每天都在使用，但稍加改变，它们就会成为保持安全蒙眼的有效**载荷发射器**  
  
**MSHTA**  
 直接在内存中执行 VBScript 或 JavaScript，没有文件，没有跟踪  
```
```  
  
**Conhost**  
 在后台安静地运行 payloade44s 无头，而不会产生噪音  
```
```  
  
**Forfiles**  
 静默循环并执行有效负载没有人会多看这个工具  
```
```  
  
**Regsvr32**  
 通过 COM 对象加载 scriptlet，绕过大多数防御（这被很好地检测到）  
```
```  
  
**BITSAdmin**  
 （后台传输服务） 谨慎下载有效负载  
```
```  
  
**InstallUtil**  
（.NET 实用程序）在安装过程中运行恶意 .NET 程序集  
```
```  
  
**Rasautou**  
：是的，您忘记存在的远程访问工具像幽灵一样静默地执行有效负载  
```
```  
# - PowerLoad3r 概述  
  
**如何修改它以运行您想要的内容（如果您想了解它的功能和作用，请先转到本节下的下一部分！**  
  
听说过 PowerLoad3r （  
https://github.com/0xNinjaCyclone/PowerLoad3r  
） 吗？不？好吧，让我告诉你，它是一个旨在运行 PowerShell 脚本的工具，这个工具有一些动作！它充满了先进的闪避技术，你猜怎么着？它的一些魔力是纯粹的组装和 C. 令人兴奋，对吧？  
  
但是等等，还有更多！准备好升级了吗？让我们深入了解如何将 PowerLoad3r 与您选择的任何 C2 集成。  
  
那么，您知道 WriteToPipes 函数吗？这就是魔法开始的地方。你需要修改它的调用来记下 shellcode，默认情况下它使用 IEX 加载和执行第 622 行的 Mimikatz，所以我们在这里修改代码。首先，仅根据 shellcode 计算 base64 编码文本的字符数大小。然后，计算这些 base64 字符的总和，并在顶部添加一个樱桃：额外的 8。是的，你听到了，添加 8 个（base64 字符 + 8），这就是你将作为参数赠送的大小。  
  
以下是一个小小的先睹为快：  
```
```  
  
规避卡巴斯基 PoC：与 CobaltStrike C2 集成：  
  
  
Empire C2（视频）：演示将很快上传。  
  
  
使用 Empire C2  
> **猜猜接下来发生了什么？我们完全躲避并搞砸了卡巴斯基安全软件！**  
  
# PowerLoad3r 是如何工作的？  
  
**在博客的这一部分不要觉得奇怪，我将在故事中解释这个神奇的工具 :)）**  
  
从这里检查工具 =>   
https://github.com/0xNinjaCyclone/PowerLoad3r  
  
**子 Process Caper**  
  
故事始于 PowerLoad3r 在内存中的 PowerShell 欺骗实例上创建，该技术旨在绕过应用程序控制并作为 Sysmon/事件日志的早期分散注意力，确保进程创建的实际指令不可见。然后，PowerLoad3r 将特定策略应用于子进程，从而防止将任何未签名的 Microsoft DLL 加载到子进程中。此策略旨在阻止 EDR 系统可能依赖的基于 DLL 的检测方法。  
  
他们计划的主要部分涉及父进程和子进程之间的秘密通信，名为 “**pwsh.exe**  
”。使用“匿名管道”创建了一个隐藏通道，允许父进程将 PowerShell 命令发送到子进程，而无需将它们作为参数传递。这种巧妙的策略帮助 PowerLoad3r 避免了被 EDR 系统检测到。  
  
不过，父进程并没有坐以待毙。它密切关注子进程，从 EDR 的安全机制中寻找任何注入的钩子。如果发现任何情况，PowerLoad3r 会迅速删除它们，从而保护子进程并保持作的隐蔽性。此外，父进程还修补了子进程中的 AMSI（反恶意软件扫描接口）和 ETW（Windows 事件跟踪）等关键安全功能，使 EDR 更难检测到活动。  
  
**父进程策略**  
  
随着故事的继续，焦点转移到了 PowerLoad3r，即父进程，它已准备好执行自己的技巧。第一步是使用动态加载对 API 进行混淆处理。这是避免导入地址表 （IAT） 的聪明策略，使 API 调用对 EDR 系统不可见。  
  
**动态加载如何帮助绕过导入地址表 （IAT）？**  
  
**=>**IAT 是程序可执行文件的一部分，其中列出了程序所需的 DLL（动态链接库）中的外部函数的地址。当程序启动时，作系统会用这些函数的实际内存地址填充 IAT。但是，动态加载的工作原理是在运行时解析函数的地址，而不是在 IAT 中列出它们。这种方法允许程序绕过 IAT，使安全系统更难检测到可能隐藏在 IAT 中的恶意活动。  
  
PowerLoad3r 更进一步，对 GetModuleHandle 和 GetProcAddress 等函数使用自定义程序集代码。通过利用 HellsGate、HalosGate 和 Veles' Reeks 等高级技术，PowerLoad3r 能够直接进行系统调用。这种强大的方法绕过了 EDR 的监控，使 PowerLoad3r 能够在不被注意的情况下执行其作，使 EDR 系统陷入混乱，因为它们无法跟踪其运动。  
  
**解钩技术与 HellsGate、HalosGate 和 Veles' Reeks 相结合，如何有助于执行直接系统调用以规避安全机制？**  
  
**=>**当与 HellsGate、HalosGate 和 Veles' Reeks 结合使用时，解钩技术可以更隐蔽地执行直接系统调用，从而有助于规避安全机制。HellsGate、HalosGate 和 Veles' Reeks 是解钩规避技术，可促进间接系统调用的执行，这些系统调用是低级系统作，绕过了可能由安全软件监控的通常 API 调用。解除挂钩是指删除或禁用安全解决方案放置的挂钩以监控系统行为的过程。通过与这些框架一起使用 unhooking，恶意代码可以通过确保安全监控钩子被抵消来逃避检测，同时绕过更高级别的 API 的直接系统调用与系统交互，从而减少被安全软件检测到的机会。  
  
对钩子引擎检测点的叙述进行了修改，避免了扫描钩子引擎 DLL 的误解。PowerLoad3r 阐明了钩子本身是焦点。如果发现诱捕过程的钩子，父母会准备好进行解钩，将孩子从潜在的危险手中解放出来，这是一个巧妙的举动，以确保他们的越轨行为毫发无损。  
  
正如 PowerLoad3r 和 PowerShell 的字节大小编年史所总结的那样，他们留下了一大群令人困惑的 EDR 哨兵、修补的进程和刻在数字传说编年史上的规避遗产。他们的冒险揭开了一个关于技术实力和颠覆性战略的故事，这些故事将在未来的周期中被代码制作者和二进制吟游诗人解析和思考。当他们重新融入代码宇宙时，他们的玩笑和快乐的短途旅行故事等待着在 Evasion 的编年史中一字节一字节、一点一点地重述。  
  
  
  
其它相关课程  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW4Nlt9pZBgFYgFxfVZFxu83EQnESej7ydiblH1UfHqKX3hBfcm76JiaSA/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg "")  
#   
# 新课  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFxZZnl9cd3HFgbeGMSic3Rhnz8cu7Ah6aD3IpvbdsDGtr1vNPgraqtoWFylFteGYksl2OjCcP08JQ/640?wx_fmt=png&from=appmsg "")  
#   
# 详细目录  
# mac/ios安全视频  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFbBn3mydWukVkxb7u4ibpOneTvEKRymYhW9KMlUWP1RnaXLuZibvPMdGmrdWVV3AMJya9dNxszgOeA/640?wx_fmt=png&from=appmsg "")  
# QT开发底层原理与安全逆向视频教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLfUhNeUCnH7x8VtPq0Q2zxZBdhjqiaibsx0rIbaYWMuIibmk5QtNPzsOSw/640?wx_fmt=png&from=appmsg "")  
  
linux文件系统存储与文件过滤安全开发视频教程(2024最新)  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHSM6Wk8NAEmbHHUS2brkROr9JOj6WZCwGz4gE4MlibULVefmhRw2dvJd8ZeYnDpRIm0AV1TmIsuEQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux高级usb安全开发与源码分析视频教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHCd9Qic4AAIQfFFD7Rabvry4pqowTdAw6HyVbkibwH5NjRTU4Mibeo4JbMRD3XplqCRzg4Kiaib3jchSw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**linux程序设计与安全开发**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGoVibbKav1DpliaTJ9icDrosqXeWyaMRJdCVWEG0VYLDibSMwUP1L5r9XmLibGkEkSZnXjPD6mWgkib9lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEH4eXCW471pNuHpGPzUKCkbyticiayoQ5gxMtoR1AX0QS7JJ2v1Miaibv1lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- #   
  
-   
- w  
i  
n  
d  
o  
w  
s  
网  
络  
安  
全  
防  
火  
墙  
与  
虚  
拟  
网  
卡  
（  
更  
新  
完  
成  
）  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERE5qcRgQueCyt3U01ySnOUp2wOmiaFhcXibibk6kjPoUhTeftn9aOHJjO6mZIIHRCBqIZ1ok5UjibLMRA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
o  
w  
s  
文  
件  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmvkF91T2mwk3lSlbG5CELC5qbib3qMOgHvow2cvl6ibicVH4KguzibAQOQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- U  
S  
B  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHv0vyWxLx9Sb68ssCJQwXngPmKDw2HNnvkrcle2picUraHyrTG2sSK7A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 游  
戏  
安  
全  
(  
更  
新  
中  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHzEAlXtdkXShqbkibJUKumsvo65lnP6lXVR7nr5hq4PmDZdTIoky8mCg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- i  
o  
s  
逆  
向  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmjrTM3epTpceRpaWpibzMicNtpMIacEWvJMLpKKkwmA97XsDia4StFr1Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
b  
g  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibv9VNhRI73qFehic91I5dsr3Jkh6EkHIRTPGibESZicD7IeA5ocHjexHhw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 还  
有  
很  
多  
免  
费  
教  
程  
(  
限  
学  
员  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHDvveGEwLYBVsps1sH6rGrSnNZtjD2pzCk4EwhH3yeVNibMMSxsW5jkg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibR2Viaxgog8I2gicVHoXJODoqtq7tTVGybA8W0rTYaAkLcp8e2ByCd1QQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibDwwqQLTNPnzDQxtQUF6JjxyxDoNGsr6XoNLicwxOeYfFia0whaxu6VXA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREEHMPaJ2RMX7CPES3mic42r1Wub102J6lAmEwKIicDfADiajsEReibfvSCbmiaRlGRCQibqfJJia0iak421Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- **windows恶意软件开发与对抗视频教程**  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFPap5AiahwlmRC2MGPDXSULNssTzKQk8b4K3pttYKPjVL4xPVu1WHTmddAZialrGo8nQB3dJfJvlZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-    
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
