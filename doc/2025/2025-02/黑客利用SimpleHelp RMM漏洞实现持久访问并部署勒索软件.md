#  黑客利用SimpleHelp RMM漏洞实现持久访问并部署勒索软件   
邑安科技  邑安全   2025-02-08 02:36  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8uq7wicvNWT2nUMybaZgghIGUWoVXyXPL1m1ptO6foNqqJ6iaSPeTlLReicCJicks9ZOMdtfC7mee0nBA/640?wx_fmt=png&from=appmsg "")  
  
据观察，威胁行为者利用 SimpleHelp 远程监控和管理 （RMM） 软件中最近披露的安全漏洞作为似乎是勒索软件攻击的前兆。  
  
某网络安全公司的在新闻报道中表示，此次入侵利用了现已修复的漏洞，初步获取了对某个未公开目标网络的访问权限，并维持了持久的远程访问。  
  
安全研究人员表示：“此次攻击涉及快速且有计划地执行多种攻击后战术、技术和程序（TTPs），包括网络和系统发现、管理员账户创建以及持久化机制的建立，这些行为可能导致勒索软件的部署。”  
  
相关漏洞（CVE-2024-57726、CVE-2024-57727和CVE-2024-57728）由Horizon3.ai于上个月披露。成功利用这些漏洞可能导致信息泄露、权限提升和远程代码执行。SimpleHelp已在2025年1月8日和13日发布的5.3.9、5.4.10和5.5.8版本中修复了这些漏洞。  
  
仅仅几周后，Arctic Wolf表示观察到一场攻击活动，涉及通过SimpleHelp远程桌面软件获取未经授权的设备访问权限，作为初始攻击途径。虽然当时尚不清楚这些漏洞是否被利用，但Field Effect的最新发现几乎证实了它们正被积极武器化，成为勒索软件攻击链的一部分。  
  
在这家加拿大网络安全公司分析的事件中，攻击者通过位于爱沙尼亚的一个存在漏洞的SimpleHelp RMM实例（“194.76.227[.]171”）获得了对目标端点的初始访问权限。在建立远程连接后，威胁行为者被观察到执行了一系列攻击后操作，包括侦察和发现活动，并创建了一个名为“sqladmin”的管理员账户，以促进开源Sliver框架的部署。  
  
随后，攻击者滥用Sliver提供的持久化功能在网络上横向移动，在域控制器（DC）和存在漏洞的SimpleHelp RMM客户端之间建立连接，并最终安装了一个Cloudflare隧道，通过该网络基础设施公司的设施将流量隐秘地路由到攻击者控制的服务器。  
  
Field Effect表示，攻击在此阶段被检测到，阻止了隧道的执行，并将系统与网络隔离以确保进一步的危害不会发生。如果该事件未被标记，Cloudflare隧道可能被用作获取额外有效载荷（包括勒索软件）的渠道。该公司表示，这些战术与2023年5月报告的Akira勒索软件攻击有重叠之处，但其他威胁行为者也可能采用了类似手法。  
  
研究人员表示：“此次攻击活动展示了威胁行为者如何积极利用SimpleHelp RMM漏洞获取对目标网络的未经授权的持久访问权限。暴露于这些漏洞的组织必须尽快更新其RMM客户端，并考虑采用网络安全解决方案以防御此类威胁。”  
  
与此同时，Silent Push透露，其观察到攻击者在防弹主机上使用ScreenConnect RMM软件的情况有所增加，以此作为获取访问权限并控制受害者端点的手段。该公司表示：“潜在攻击者一直在利用社交工程诱骗受害者安装配置为在攻击者控制下运行的合法软件副本。一旦安装，攻击者会使用修改后的安装程序快速访问受害者的文件。”  
  
原文来自:   
thehackernews.com  
  
原文链接: https://thehackernews.com/2025/02/hackers-exploit-simplehelp-rmm-flaws.html  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
