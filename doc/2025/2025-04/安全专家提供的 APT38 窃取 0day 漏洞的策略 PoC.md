#  安全专家提供的 APT38 窃取 0day 漏洞的策略 PoC   
 Ots安全   2025-04-28 08:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
- 一个自动化 APT38 技术的程序，该技术已被用于针对网络安全研究人员专家  
  
- Lazarus 是一个受朝鲜政府支持的组织，其针对网络安全研究人员的攻击记录屡见不鲜。在其众多引人注目的技术中，有一种因其能够有效欺骗众多网络安全专家而尤为突出。  
  
- 攻击者创建多个 Twitter 和其他社交媒体账户来建立信誉。他们通过社会工程学手段，诱骗安全研究人员使用 Microsoft Visual Studio Project 进行协作研究，该项目的 vcxproj 文件包含恶意代码。因此，当研究人员尝试构建该项目时，嵌入其中的恶意代码就会被执行。  
  
技术细节  
  
此项分析基于Google 威胁分析小组和安全研究员Joel Eriksson分享的信息，他们记录了此次攻击的经历。他们的推文强调了有效的防护措施：  
  
初步方法  
- 在社交平台上创建可信的安全研究员角色，并通过技术对话建立信任  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegriaPf0WgffjVib7rew92yyoX0e0lmw0ibJRo7M32C9DqABrTU4HlMibbvvwzMuh8QhBpbuCJe6Lopw/640?wx_fmt=png&from=appmsg "")  
  
- 通过直接消息瞄准实际的安全研究人员并提供“概念验证”项目的合作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegriaPf0WgffjVib7rew92yywiaOP1rVw2WeBibNOBgHLHZWcrdetcQHzRLTibEzA9pHn32q9y4qnq82w/640?wx_fmt=png&from=appmsg "")  
  
交付机制  
- 发送包含 Visual Studio 项目的加密 ZIP 文件，并声称这些项目存在有趣的漏洞，提及加密以显示安全意识  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegriaPf0WgffjVib7rew92yyVxAcgsCvibu61ZuctL68Mxo1V6pyGGrItJ7icRyv4k0EtAsaJ7EENQYw/640?wx_fmt=png&from=appmsg "")  
  
使用较小的文件大小（452.13KB）来使其看起来像合法的代码项目  
  
执行方法  
  
在 Visual Studio 项目文件中隐藏恶意 PowerShell 命令，powerShell 命令使用绕过的执行策略和隐藏的窗口执行，包括验证以下内容的操作系统检查：  
- Windows 10 正在运行（osversion.version.major -eq 10）  
  
- 系统是 64 位 (is64bitoperatingsystem)  
  
- 存在特定路径（Test-Path x64\Debug\Browse.VC.db）  
  
关键技术：使用rundll32从伪装成Visual Studio数据库文件的文件中加载恶意代码，并调用特定的导出函数ENGINE_get_RAND，该函数带有两个参数：一个看起来像密钥/标识符的16个字符的字符串：6bt7cJNGEb3Bx9yK 一个数值：2907  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegriaPf0WgffjVib7rew92yyicxoic1vhBJQJNMgnoOuKjOyd503psLowChaP3DnIbUn29s5J6oEfDzA/640?wx_fmt=png&from=appmsg "")  
  
APT38-0day-Stealer技术细节  
- 在 Visual Studio 项目目录中执行后，该程序会通过注入自定义代码感染所有 vcxproj 文件。这些代码会在用户尝试构建项目时执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegriaPf0WgffjVib7rew92yyOdWbicRoVzO8eI37wH1WR44k6qVNmzibzIKMz028cuKF8vE4N6BNFjtg/640?wx_fmt=png&from=appmsg "")  
  
攻击场景：开发者环境供应链攻击  
  
攻击者向开发人员发送恶意的 Visual Studio 项目，开发人员打开该项目，看起来像是一个合法的代码示例，首次构建时，该程序会感染开发人员系统上的所有 Visual Studio 项目  
  
受感染的开发人员继续正常工作，修改并与同事共享项目，每个共享项目都会将感染传播到新的开发人员机器上，当同事打开并构建这些项目时，他们的环境就会受到感染，感染会继续在整个开发团队中蔓延  
  
影响  
  
在成功的活动中，这将对整个开发生态系统造成灾难性的损害。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegriaPf0WgffjVib7rew92yyibjktHemPliccuQgl3hZMI6OeHEQpCEJxjic26hzrmo71gnX2WGdRfkeQ/640?wx_fmt=png&from=appmsg "")  
  
演示  
  
  
  
项目  
  
https://github.com/ZeroMemoryEx/APT38-0day-Stealer?tab=readme-ov-file  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
