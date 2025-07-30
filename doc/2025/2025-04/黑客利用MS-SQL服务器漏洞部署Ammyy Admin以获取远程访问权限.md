#  黑客利用MS-SQL服务器漏洞部署Ammyy Admin以获取远程访问权限   
邑安科技  邑安全   2025-04-27 03:29  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v4TWNX2h42Wqr4VEqehAyt7jTPpJBwbtezg7a7mha3DWlSg9PqEZoTtRCKMgdS59gxXUxp7G0uwA/640?wx_fmt=png&from=appmsg "")  
  
已发现一个针对易受攻击的 Microsoft SQL Server 的复杂网络攻击活动，旨在部署远程访问工具和权限提升恶意软件。  
  
安全研究人员已经发现，威胁行为者专门利用安全性不佳的 MS-SQL 实例来安装 Ammyy Admin，这是一种合法的远程桌面软件，可以被滥用于未经授权的访问，以及一种称为 PetitPotato 的权限提升工具。  
  
攻击者利用这些受感染的服务器建立对受害者网络的持续访问，从而可能实现数据盗窃和组织基础设施内的横向移动。  
  
攻击从识别具有弱安全配置（包括默认凭据或公开的管理端口）的 MS-SQL 服务器开始。  
  
一旦获得访问权限，威胁行为者就会执行一系列命令来收集系统信息，从而允许他们根据目标环境定制方法。  
  
然后，攻击者利用命令行实用程序下载和部署他们的恶意负载，展示了令人担忧的作复杂程度，并表明了一个组织良好的威胁组织。  
  
Broadcom 研究人员发现，自 2025 年 4 月初以来，这些攻击的频率一直在增加，目标涵盖多个行业，包括金融、医疗保健和制造业。  
  
研究人员指出，该活动与之前归因于出于经济动机的威胁行为者的攻击有相似之处，尽管确定归因仍然具有挑战性。  
  
持久性机制  
  
此活动特别令人担忧的方面是攻击者保持访问权限的方法。  
  
在最初入侵后，威胁行为者会在受感染的服务器上启用远程桌面协议 （RDP） 服务，从而在发现其主要入口点时允许他们使用替代访问方法。  
  
此外，他们还创建具有管理权限的新用户帐户，从而有效地建立后门，即使检测到并删除了初始恶意软件，这些后门也可以持续存在。  
  
这种多层持久性策略展示了活动的复杂性，并强调了超越简单恶意软件检测的全面安全监控的重要性。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/hackers-exploiting-ms-sql-servers-deploy-ammyy/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
