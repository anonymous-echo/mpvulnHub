#  Windows 任务计划程序漏洞允许提升权限和篡改日志   
 Ots安全   2025-04-20 06:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tado6aEFCZDSvapes2FSkyQVtFFoMiaCaibkkGmFO6HCUCbg7QYQu709mQYngCxbP9WekYbgEB30XkMg/640?wx_fmt=webp&from=appmsg "")  
  
Windows 的核心组件之一——任务计划程序——中发现了四个新漏洞，这些漏洞可导致本地权限提升攻击。研究表明，攻击者不仅可以获取管理权限，还可以通过篡改事件日志来抹去其活动痕迹。  
  
这些漏洞主要围绕二进制文件“schtasks.exe”展开，该文件用于本地和远程管理任务。专家发现其运行中存在严重漏洞，可能允许攻击者绕过包括用户帐户控制 (UAC) 在内的标准保护机制。  
  
据Cymulate称，其中一个漏洞允许以 SYSTEM 帐户启动进程，而无需用户确认。这是通过使用批量登录方法创建任务来实现的——该方法使用密码而非交互式令牌进行身份验证。此类任务以最高权限运行，使其成为执行恶意脚本的理想选择。  
  
然而，利用该漏洞的关键前提是拥有目标帐户的有效密码。例如，可以通过在 SMB 身份验证期间拦截和解密 NTLMv2 哈希，或者利用其他漏洞（例如 CVE-2023-21726）来获取该密码。  
  
只要有有效的密码，即使是低权限帐户也可以冒充管理员、备份操作员或性能日志用户。这可以通过使用带有 /ru 和 /rp 标志的标准 Windows 实用程序来指定用户名和密码凭据来实现。  
  
研究人员特别关注了混淆痕迹的技术。研究人员演示了如何使用 XML 任务文件来构造超过 3,500 个字符的作者姓名，从而导致日志描述溢出，最终有效地擦除之前的活动记录。另一种技术针对位于 C:\Windows\System32\winevt\logs\Security.evtx 的安全事件日志数据库，使其遭到破坏并销毁关键的审计记录。  
  
因此，任务计划程序不再仅仅是一个任务自动化工具，而是一个能够授予最高级别访问权限的强大攻击向量。它可供所有用户使用，并由以 SYSTEM 权限运行的服务控制，为操纵权限、进程完整性和模拟机制提供了大量的机会。  
  
这项研究凸显了在更广泛的安全领域中，内置系统实用程序是多么容易被低估。一个看似无害的命令行工具也可能成为后门，绕过访问控制、提升权限并抹去数字足迹。  
  
尽管报告中概述了该漏洞的技术深度和重大风险，但微软尚未承认提交给 MSRC 的任何发现是官方漏洞。因此，目前尚未计划针对“schtasks.exe”推出任何更新或缓解措施，这使得上述技术仍然可能在本地被利用。  
  
广告  
  
[](https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247529175&idx=1&sn=e81fc82c778809f8b728b880e0097a35&scene=21#wechat_redirect)  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
