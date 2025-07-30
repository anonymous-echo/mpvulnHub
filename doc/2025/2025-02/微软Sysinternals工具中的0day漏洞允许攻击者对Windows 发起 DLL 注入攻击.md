#  微软Sysinternals工具中的0day漏洞允许攻击者对Windows 发起 DLL 注入攻击   
会杀毒的单反狗  军哥网络安全读报   2025-02-07 01:00  
  
**导****读**  
  
  
  
几乎所有 Microsoft Sysinternals 工具中都发现一个严重的 0-Day 漏洞，这对依赖这些实用程序进行系统分析和故障排除的 IT 管理员和开发人员构成了重大风险。  
  
  
该漏洞概述了攻击者如何利用DLL 注入技术执行恶意代码，已在详细的视频演示中进行了细致的研究、验证和演示。  
  
  
尽管 90 多天前已向微软披露，但该漏洞仍未解决。  
  
  
Sysinternals 工具由 Microsoft 开发，是一套广泛使用的实用程序，旨在深入了解 Windows 系统的进程、服务和配置。该系列中的热门工具包括Process Explorer、Autoruns和Bginfo。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGDMttlnBTje7VZiamyeDmdLVUnU9UwIQRkgQoZBPJiaawW0FV3YraR9E2wWPicJ7Fyic82337Rz6an3g/640?wx_fmt=png&from=appmsg "")  
  
  
虽然这些工具对于 IT 管理和恶意软件分析来说是必不可少的，但它们缺乏与 Windows 更新系统的集成，带来了独特的挑战。  
  
  
工具的安全补丁和更新必须由管理员手动管理，当出现漏洞时，会留下潜在风险。  
  
### 漏洞详情：DLL 注入漏洞  
###   
  
发现的漏洞源于 Sysinternals 工具加载 DLL 文件的方式。具体来说，许多此类应用程序在加载 DLL 时会优先考虑不受信任的路径（例如当前工作目录 (CWD) 或网络路径），而不是安全的系统目录。  
  
  
这种疏忽使得攻击者能够用恶意 DLL 替换合法的 DLL，从而执行任意代码。  
  
  
攻击机制相对简单：  
- 攻击者制作恶意 DLL，例如cryptbase.dll或TextShaping.dll，嵌入有害负载。  
- 恶意 DLL 被放置在与合法     Sysinternals 可执行文件相同的目录中（例如Bginfo.exe）。  
- 当用户从该目录执行应用程序时，将加载恶意     DLL，而不是受信任的系统 DLL。  
- 攻击者的代码在用户权限下执行，可能会导致整个系统受到损害。  
###   
### 真实案例：通过 Bginfo 部署木马  
###   
  
该漏洞的实际影响通过 Bginfo 工具得到演示，该工具经常部署在企业环境中，用于在用户桌面上显示系统信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGDMttlnBTje7VZiamyeDmdLJDiaHYwT9rJVaPiaP2OTTicTYegM5tfKsmAEtTJ9QGxxLmiaQ2S6mOy1mQ/640?wx_fmt=png&from=appmsg "")  
  
  
在模拟攻击场景中，攻击者将恶意 DLL 文件放置在与合法Bginfo.exe.  
  
在系统启动期间，启动脚本Bginfo直接从此共享网络位置执行该工具。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGDMttlnBTje7VZiamyeDmdLRe6KkpqWL114SmcfRolkxo1AXmauRKJDDuVS7AQof9OB6tYUdGCGZg/640?wx_fmt=png&from=appmsg "")  
  
  
结果，该工具会无意中加载恶意 DLL 而不是受信任的 DLL，从而能够在多个客户端系统上自动部署木马或其他恶意软件。  
  
  
“但是，如果网络路径带有准备好的 DLL，则每个客户端在启动过程中都会自动受到攻击。在这种情况下，Bginfo 工具会从网络驱动器加载，而 Meterpreter 则会从 DLL 加载并启动”，Research在其技术文章中指出。  
  
  
此示例强调了此漏洞带来的严重风险，特别是在依赖于从基于网络的路径执行 Sysinternals 工具的环境中。  
  
  
该漏洞影响广泛的 Sysinternals 应用程序，包括但不限于：  
  
进程浏览器（procexp.exe，procexp64.exe）  
  
自动运行（autoruns.exe，autoruns64.exe）  
  
背景信息( bginfo.exe, bginfo64.exe)  
  
  
研究人员提供的相关测试表提供了易受攻击的工具的完整列表。  
  
  
该漏洞于 2024 年 10 月 28 日按照行业标准惯例负责任地向 Microsoft 披露。然而，Microsoft 将该问题归类为“纵深防御”增强功能，而不是严重漏洞。  
  
  
这种分类意味着问题是在应用程序的安全使用最佳实践中解决的，而不是作为根本的安全漏洞。  
  
  
微软的观点侧重于从本地程序目录运行的可执行文件，而研究人员则强调了使用网络驱动器的危险，其中网络位置充当应用程序的 CWD。  
  
  
研究人员指出，微软根据其自身处理 DLL 漏洞的指导方针，立场存在不一致。  
  
  
截至 2024 年 12 月 Sysinternals 博客的最新更新，该漏洞仍未修补，用户只能依赖变通方法来降低风险。  
  
  
在 Microsoft 解决此漏洞之前，管理员和用户可以采取一些预防措施来减少受到这些攻击的风险：  
- 避免从网络位置运行工具：执行前始终将     Sysinternals 可执行文件复制到本地路径。  
- 验证 DLL     完整性：采用安全解决方案仅加载受信任的 DLL。  
- 审核您的环境：使用提供的测试表来识别易受     DLL 注入的工具并采取必要的保护措施。  
Sysinternals 工具通常用于恶意软件分析。诸如Process Explorer之类的工具有助于识别应用程序加载的潜在恶意 DLL。  
  
  
技术报告：  
  
https://www.foto-video-it.de/2025/allgemein/disclosure-sysinternals/  
  
  
新闻链接：  
  
https://cybersecuritynews.com/0-day-vulnerabilities-in-microsoft-sysinternals-tools/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
