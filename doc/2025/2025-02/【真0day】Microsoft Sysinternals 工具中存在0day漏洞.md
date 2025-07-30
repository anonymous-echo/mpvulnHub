#  【真0day】Microsoft Sysinternals 工具中存在0day漏洞   
 独眼情报   2025-02-06 06:48  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFWpYAZDJibvp8d9wEbgAmteibYCdnkSCQJpB6Lo5jyeY9qOdzfdwl77vA/640?wx_fmt=jpeg&from=appmsg "")  
  
我发现了几乎所有Sysinternals工具中的关键漏洞，并在视频中详细展示了这些漏洞的背景及攻击过程。关于这些漏洞的总结和视频链接可以在我的博客文章中找到。  
  
这些工具由Microsoft开发，广泛应用于IT管理中，常用于系统分析和故障排查。视频中展示的漏洞涉及工具套件中的多个应用程序，攻击者可以通过DLL注入将恶意代码植入并执行。  
  
自从向Microsoft首次报告该漏洞以来，已经过去超过90天，现在是时候讨论这个问题了。  
### 观看视频：https://youtu.be/Hg81N0HAgCg  
## 什么是Sysinternals工具？  
  
Sysinternals工具是一套有用的工具集，帮助IT管理员和开发人员分析Windows系统。它包括**Process Explorer**、**Autoruns**、**Bginfo**等工具。这些工具可以深入了解Windows系统中的进程、服务和配置。然而，这些工具无法通过Windows更新功能自动更新，这带来了显著的风险——如果出现安全漏洞，工具需要手动检查和更新。  
## Sysinternals工具与恶意软件  
  
许多文章将Sysinternals工具描述为在恶意软件分析中支持的工具。例如，Process Explorer可以显示程序文件加载的所有DLL，并识别潜在的恶意DLL。然而，具有一定讽刺意味的是，Sysinternals工具本身存在DLL处理漏洞，可能成为攻击的目标……  
## 0day  
  
我发现的漏洞涉及Sysinternals工具加载DLL文件的方式。许多应用程序会首先搜索当前工作目录（CWD）或其他指定路径，然后才会访问受信任的系统路径。这使得攻击者能够将恶意DLL文件放置在与可执行文件相同的目录中，并且这些DLL可以不被察觉地被加载。  
  
在我的研究中，除了“Process Explorer”和“Listdlls”应用程序外，我还使用了“systeminformer”工具。  
  
以下是如何通过“Listdlls”查看进程中加载的DLL文件的示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFLGxVSVOiaLSOEYN5xmUC5u7nsHkdupCjXz9TyiaGbOG4icGFssrFjK4XA/640?wx_fmt=png&from=appmsg "")  
## 示例：如何利用这个漏洞  
  
攻击者可以将恶意DLL文件与合法应用程序（如**Bginfo.exe**）一起放置在网络共享（如\\server1\share2\）上。当用户从该目录启动应用程序时，恶意DLL将被加载，攻击者的代码将在应用程序中执行，从而可能完全控制系统。  
  
**攻击流程：**  
1. 攻击者创建一个恶意DLL（如cryptbase.dll或TextShaping.dll），利用应用程序中的漏洞。  
  
1. 将该DLL复制到与合法可执行文件相同的目录中。  
  
1. 用户执行该应用程序，导致恶意DLL而非原始DLL被加载。  
  
1. 恶意DLL的代码以用户的权限执行。  
  
DLL文件和应用程序在同一目录中的位置：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFTp9zDqJ9YoM48AiclqrVpianDBVXb5a7EL7mhn2jvSPOLc8oNb8SDibgQ/640?wx_fmt=png&from=appmsg "")  
  
应用程序启动并加载DLL（这里的DLL功能：“计算器”成功执行 -> 成功进行代码执行）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFQGl3EYWMzFO13OPdyW0UVkibQj5Yuq6d782EWjsbL33iamOibCdJ9dMpw/640?wx_fmt=png&from=appmsg "")  
  
我的安全分析表明，并非所有DLL都以不安全的方式进行处理。下文中我将列出成功测试过的DLL的概况。  
## 与Microsoft的沟通  
  
该漏洞已于2024年10月28日按规定报告给Microsoft，但尽管进行了沟通，问题仍未得到解决。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFJb5ib9TV9jUBPvlsfExAkicrVZsEK5pgXSic5D1MicWQEnycfeNNQnJiahA/640?wx_fmt=png&from=appmsg "")  
  
Microsoft将该漏洞分类为“防御深度”问题，而非关键问题。在我的视频中，我详细讨论了这次沟通，并展示了为什么这种分类存在问题。Microsoft讨论的是程序目录，但我也在讨论网络共享的情况。在这些情况下，网络共享成为了应用程序的当前工作目录。  
  
Microsoft曾在**这里**(https://msrc.microsoft.com/blog/2018/04/triaging-a-dll-planting-vulnerability/)发布过一篇关于DLL漏洞分类的旧文章，详细讨论了这一问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFr7Yg1ibBSvcINR5kH0Lz1PxX492DMib5KrlOAl82wKdfYUtCxpIJknzg/640?wx_fmt=png&from=appmsg "")  
  
根据Microsoft自己的指导方针，从共享文件夹加载的DLL作为CWD处理是一个严重的安全风险。  
## 安全加固措施  
  
由于Microsoft在更新工具后（见Sysinternals博客链接(https://techcommunity.microsoft.com/category/windows/blog/sysinternals-blog)）仍未修复这些安全漏洞，目前只能采取一些缓解措施。  
  
为了保护免受该漏洞攻击，管理员和用户可以采取以下预防措施：  
1. **避免直接从网络存储运行工具**：将可执行文件复制到本地路径。  
  
1. **确保应用程序完整性**：使用安全解决方案，确保只加载受信任的DLL。  
  
1. **检查环境中是否有受影响的工具**：使用提供的测试表格识别易受攻击的应用程序。  
  
这里查看测试表格(https://www.foto-video-it.de/wp-content/uploads/2025/01/sysinternals-zero-day-testsheet.pdf)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFXWnpSdPhibFMvVEYEgtZE9xKwQqyP1S7ztEuKa9xg4WFZzY6BdYefJg/640?wx_fmt=png&from=appmsg "")  
## 演示与测试表格  
  
在视频中，我现场演示了如何利用**Process Explorer**和**Bginfo**工具中的漏洞。此外，我还提供了一个全面的测试表格，列出了哪些工具易受到DLL注入的攻击。以下是一些受影响的工具：  
- **Process Explorer**（procexp.exe, procexp64.exe）  
  
- **Autoruns**（autoruns.exe, autoruns64.exe）  
  
- **Bginfo**（bginfo.exe, bginfo64.exe）  
  
- 更多工具可以在测试表格中找到（几乎所有其他工具……）  
  
**总结来说，几乎所有Sysinternals工具都容易受到DLL注入漏洞的攻击。**  
## 现实案例：通过Bginfo传播木马  
  
在我的视频中，我特别展示了**Bginfo**工具的一个关键示例。该工具常用于企业环境中，在桌面上显示系统信息。视频中展示了如何通过恶意DLL文件利用**Bginfo**工具启动木马。在这个例子中，我通过PowerShell启动Bginfo。  
  
Bginfo的调用可以在启动脚本中进行，例如：  
  
<网络路径>/Bginfo.exe /timer=0  
  
这时，Bginfo工具将从网络路径启动。命令timer=0会抑制配置对话框，网络存储上的DLL将直接加载并执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFaWGl4Z5sJMvcPomrSRcT6eTMlhnIrNMjDtO3icrJVNA2ydKaU3dfXvQ/640?wx_fmt=png&from=appmsg "")  
  
如果网络路径中有经过精心准备的DLL文件，那么每个客户端在启动时都可能会被自动感染。此时，Bginfo工具将从网络共享加载，Meterpreter将从DLL中加载并启动：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnROAM4ZCLQjRagHtiaM7nReFIiaAPnJcLJCopkRMhxI8rD7YtQsX9c6P8A7g52C4dviaeIy8qMQUp89g/640?wx_fmt=png&from=appmsg "")  
## 总结  
  
这次揭露的零日漏洞展示了在信任的工具中也不容忽视安全性的重要性。Sysinternals工具是强大的工具，但它们在DLL注入攻击中的脆弱性使它们成为攻击者的目标。  
  
  
原文详情：https://www.foto-video-it.de/2025/allgemein/disclosure-sysinternals/  
  
  
