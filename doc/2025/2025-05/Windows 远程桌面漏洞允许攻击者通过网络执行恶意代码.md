#  Windows 远程桌面漏洞允许攻击者通过网络执行恶意代码   
邑安科技  邑安全   2025-05-14 09:31  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v7T54TklESlCO3EibopMCruRE4jZN6hibWjGlJ9OD4GAKoro3sC7OhonyjpPTXXgJCBlNxrVwIH93Q/640?wx_fmt=png&from=appmsg "")  
  
Microsoft 的 2025 年 5 月补丁星期二解决了 Windows 远程桌面服务中的几个关键漏洞，这些漏洞可能允许攻击者远程执行恶意代码。安全专家敦促用户立即应用这些补丁，以保护他们的系统免受潜在漏洞的攻击。  
  
在本月安全更新中修复的 72 个缺陷中，有两个关键的远程桌面漏洞特别令人担忧。CVE-2025-29966 和 CVE-2025-29967 分别涉及远程桌面客户端和网关服务中基于堆的缓冲区溢出漏洞，允许未经授权的攻击者通过网络执行任意代码。  
  
“在远程桌面连接的情况下，当受害者使用易受攻击的远程桌面客户端连接到攻击者的服务器时，控制远程桌面服务器的攻击者可以在 RDP 客户端计算机上触发远程代码执行，”Microsoft 在其安全公告中解释说。  
  
这些漏洞获得了“严重”严重等级和较高的 CVSS 分数，表明它们对受影响系统的潜在影响。这些缺陷专门利用了 CWE-122 分类的弱点：基于堆的缓冲区溢出，允许攻击者以支持代码执行的方式破坏内存。  
  
受影响的系统范围广泛  
  
这些漏洞会影响使用远程桌面服务的多个版本的 Windows作系统。虽然 Microsoft 尚未报告这些特定缺陷的积极利用情况，但该公司目前已将其归类为“利用可能性较低”评估。  
  
“尽管这些特定的漏洞尚未被利用，但类似的远程桌面漏洞过去一直是攻击者的主要目标，”一位熟悉此事的网络安全研究人员说。“未经身份验证的攻击者获得远程代码执行的可能性使这些漏洞特别危险。”  
  
这些远程桌面漏洞是 Microsoft 5 月补丁星期二中解决的 72 个缺陷之一，该补丁还修复了 5 个被积极利用的零日漏洞，包括 Windows DWM 核心库、Windows 通用日志文件系统驱动程序和 WinSock 的 Windows 辅助函数驱动程序中的问题。  
  
安全专家建议组织和个人用户立即应用这些补丁。当用户连接到恶意的远程桌面服务器时，可能会利用此漏洞，使客户端计算机面临完全系统受损的风险。  
  
对于无法立即修补的系统，专家建议将远程桌面连接限制为仅受信任的服务器，并实施额外的网络安全措施来限制潜在的攻击媒介。  
  
2025 年 5 月的安全更新可通过 Windows 更新、Windows Server Update Services （WSUS） 和 Microsoft Update Catalog 获得。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/windows-remote-desktop-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
