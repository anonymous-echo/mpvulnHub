> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247524896&idx=2&sn=2c69b2922642df8b30a2b9228811d615

#  APT36 黑客在复杂的网络钓鱼攻击中攻击印度国防人员  
邑安科技  邑安全   2025-06-24 03:23  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8vg7HicFlibrPicJSP0yRGf62sbvvFw2V3KMeusmrdj6PQmYd7UhDtaVHMBKUfca0uXkcIHjlIG9pB0Q/640?wx_fmt=png&from=appmsg "")  
  
一个名为 APT36 或 Transparent Tribe 的巴基斯坦网络间谍组织发起了一项针对印度国防人员的高度复杂的网络钓鱼活动，利用凭据窃取恶意软件在敏感的军事网络中建立长期渗透。  
  
该活动代表了民族国家网络威胁的显著升级，它采用了先进的社会工程技术，利用了政府官方通信中固有的信任。  
  
攻击媒介依赖于精心设计的网络钓鱼电子邮件，其中包含模仿合法政府文件的恶意 PDF 附件。  
  
当收件人打开这些 PDF 时，他们会遇到一个故意模糊的背景，旨在创造真实性，并附有一条消息，说明文档受到保护，需要用户交互才能访问内容。  
  
CYFIRMA 分析师发现，单击突出显示的“单击以查看文档”按钮会将用户重定向到模仿国家信息学中心 （NIC） 登录界面的欺诈 URL，最终启动包含伪装恶意软件的 ZIP 存档的下载。  
  
该活动的影响不仅限于直接的凭据盗窃，因为恶意软件会在目标系统中建立持久访问机制。  
  
此次行动展示了 APT36 在印度国防基础设施中保持长期存在的战略目标，凸显了当前网络安全协议中的关键漏洞。  
  
涉及的恶意域于 2024 年 10 月 23 日注册，到期日期为 2025 年 10 月 23 日，这表明这是一种经过深思熟虑的短期部署策略。  
  
技术感染机制和规避策略  
  
恶意软件的感染机制揭示了旨在逃避检测和分析的复杂技术能力。  
  
名为 “PO-003443125.pdf.exe” 的可执行文件采用了多种反分析技术，包括 Windows API 函数来检测调试环境。IsDebuggerPresent  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8vg7HicFlibrPicJSP0yRGf62sSp6EYSN0w5T6uLuj71h80pUAOI7F5s5XlHZ1OLMIZqVY2WWtOGfMibw/640?wx_fmt=png&from=appmsg "")  
  
假 PDF  
  
在检测到 x64dbg、WinDbg 或 OllyDbg 等分析工具后，恶意软件会在终止执行之前显示一条关键消息，指出“这是第三方编译的脚本”。  
  
此外，该恶意软件还用于识别在 64 位系统上运行的 32 位进程，这是虚拟化或分析环境的常见指标。IsWow64Process  
  
该恶意软件的资源加载机制用于定位嵌入式脚本资源，然后通过 COM 或 ActiveScript 接口执行，从而实现绕过传统检测方法的无文件执行。FindResourceExW  
  
这种多层方法展示了 APT36 在开发专门针对高价值国防部门目标的抗检测恶意软件方面不断发展的复杂性。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/apt36-hackers-attacking-indian-defense-personnel/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
