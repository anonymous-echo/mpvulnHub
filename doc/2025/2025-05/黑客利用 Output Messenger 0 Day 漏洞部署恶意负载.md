#  黑客利用 Output Messenger 0 Day 漏洞部署恶意负载   
邑安科技  邑安全   2025-05-13 05:24  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tzFbKQRxa94xpNBC3ibmYnU5IiavyDvdr6gj9rh2PTtvwtTXCXadQiac527C1CgFwneGunPOvl9GbJw/640?wx_fmt=png&from=appmsg "")  
  
Microsoft 威胁情报已确定针对伊拉克库尔德军事实体的复杂网络间谍活动。自 2024 年 4 月以来，被称为 Marbled Dust 的威胁行为者一直在利用 Output Messenger 中的零日漏洞来收集敏感的用户数据并在受害者网络中部署恶意负载。  
  
Output Messenger 是组织用于内部通信的多平台聊天软件，包含一个目录遍历漏洞 （CVE-2025-27920），允许经过身份验证的用户将恶意文件上传到服务器的启动目录。  
  
发现此漏洞后，Microsoft 通知了 Output Messenger 的开发商 Srimax，后者立即发布了补丁来解决此问题。  
  
据 Microsoft 的研究人员称，Marbled Dust 一直专门针对与伊拉克库尔德军事行动相关的用户。这与该组织历史上的目标重点一致，因为他们之前一直专注于代表土耳其政府反利益的实体。  
  
输出 Messenger 0 Day 漏洞  
  
“零日漏洞的成功使用表明技术复杂性的增加，可能表明 Marbled Dust 的目标优先级已经升级，或者他们的运营目标变得更加紧迫，”Microsoft 在他们最近的安全博客中表示。  
  
Microsoft 评估 Marbled Dust 是否会进行侦察，以确定潜在目标在发动攻击之前是否使用 Output Messenger。  
  
虽然获取初始身份验证凭证的确切方法尚不清楚，但研究人员认为，该组织利用 DNS 劫持或拼写错误抢注的域来拦截和重复使用合法凭证。  
  
一旦 Marbled Dust 获得对 Output Messenger Server Manager 的身份验证访问权限，攻击链就开始了。他们利用目录遍历漏洞将恶意文件（包括 OMServerService.vbs 和 OM.vbs）上传到服务器的启动文件夹，并将OMServerService.exe上传到 Users/public/videos 目录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tzFbKQRxa94xpNBC3ibmYnUADCQVoiatEOGJxxEK8icia72dMtWDiavkODKmoMteaVL9BybdhQylYiamBA/640?wx_fmt=png&from=appmsg "")  
  
这些文件协同工作以建立连接到命令和控制域 （api.wordinfos[.]com） 获取进一步说明和数据泄露。  
  
在客户端计算机上，另一个名为 OMClientService.exe 的后门程序与合法的 Output Messenger 应用程序一起安装。该恶意软件与相同的命令和控制基础设施进行通信，发送有关受害者的身份信息并执行从攻击者那里收到的命令。  
  
在至少一个观察到的案例中，攻击者使用 PuTTY 的命令行版本 （plink） 来泄露 RAR 档案中收集的数据。  
  
“一旦 Marbled Dust 获得了对 Output Messenger 服务器的访问权限，他们就可以利用系统架构不分青红皂白地访问每个用户的通信，窃取敏感数据并冒充用户，”Microsoft 安全研究人员解释说。  
  
Microsoft 已将 Marbled Dust 确定为土耳其附属的间谍组织，该组织与其他安全供应商跟踪的活动重叠，如 Sea Turtle 和 UNC1326。  
  
该集团主要针对欧洲和中东的实体，专注于政府机构、电信和信息技术行业。  
  
为了减轻威胁，Microsoft 建议将 Output Messenger 更新到 Windows 客户端的 2.0.63 版和服务器的 2.0.62 版。  
  
此外，组织应在其防病毒产品中启用云提供的保护，为关键应用程序实施防网络钓鱼身份验证，并部署 Microsoft Defender 漏洞管理以识别其环境中的漏洞。  
  
Microsoft 将继续监控这种不断演变的威胁，并发布了详细的检测指南，以帮助安全团队识别潜在的危害。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/output-messenger-0-day-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
