#  Erlang/OTP SSH远程代码执行漏洞的概念验证（PoC）利用代码已公开   
邑安科技  邑安全   2025-04-18 03:24  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tvINqC7vPe1PJ99Mlvk6g2bZQjpecZzfDFQ0QlD8ncckI4JCIOIe4NTq1ybVicv0tic6EZRdMSLcRQ/640?wx_fmt=png&from=appmsg "")  
  
在研究人员确认开发了概念验证漏洞后，Erlang/OTP 的 SSH 实施中存在一个关键的远程代码执行漏洞，安全团队争先恐后地修补受影响的系统。  
  
该漏洞被跟踪为 CVE-2025-32433，并被分配了最高可能的 CVSS 分数 10.0，它允许攻击者在未经身份验证的情况下执行任意代码，从而可能导致系统完全受损。  
  
一个安全研究人员团队于 2025 年 4 月公开披露了该漏洞。该漏洞存在于 SSH 协议消息处理机制中，使得攻击者能够在身份验证完成之前发送连接协议消息。  
  
该问题是由 SSH 协议消息处理中的缺陷引起的，允许攻击者在身份验证之前发送连接协议消息。此漏洞会影响运行 SSH 服务器组件的所有 Erlang/OTP 版本，无论底层版本如何。  
  
Horizon3 攻击团队的安全研究人员已经复制了该漏洞并开发了一个概念验证漏洞。在一个令人担忧的开发中，他们将该漏洞描述为“非常容易”利用。  
  
刚刚完成了 CVE-2025-32433 的重现并快速整合了一个 PoC 漏洞，非常简单。如果公共 PoC 很快开始下降，也不会感到震惊。如果您正在跟踪这一点，现在是采取行动的时候了，Horizon3 在社交媒体上发布了帖子。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tvINqC7vPe1PJ99Mlvk6g2K9bZpabiaMwHvd6WjQ6vNpR5ggO0lgWniadSENkreH7edrhucrLSuXSA/640?wx_fmt=png&from=appmsg "")  
  
利用的便利性引起了安全专业人员的警惕，他们担心一旦公共漏洞可用，广泛的攻击可能会迅速出现。  
  
一位匿名安全研究人员在 Pastebin 上发布了 CVE-2025-32433 的概念验证代码。  
  
此漏洞特别危险，因为 Erlang 广泛部署在关键基础设施中，包括来自主要供应商的电信设备，以及 IoT 和运营技术 （OT） 环境。  
  
安全专家将该漏洞描述为“极其严重”，并警告说它可能允许威胁行为者执行安装勒索软件或窃取敏感数据等作。  
  
通过利用漏洞执行的任何命令都将使用与 SSH 守护程序相同的权限运行。由于这些守护程序通常以 root 身份运行，因此成功的攻击可能导致完全接管系统。  
  
缓解步骤  
  
Erlang/OTP 团队已经发布了受影响版本的补丁。组织应立即升级到以下修补版本：  
- OTP-27.3.3 （适用于运行 OTP-27.x 的系统）  
  
- OTP-26.2.5.11（适用于运行 OTP-26.x 的系统）  
  
- OTP-25.3.2.20（适用于运行 OTP-25.x 的系统）  
  
对于无法立即更新的系统，安全专家建议实施以下解决方法：  
- 使用防火墙规则限制对 SSH 端口的访问  
  
- 禁用 Erlang/OTP SSH 服务器（如果不是必要的）  
  
- 将 SSH 访问限制为仅受信任的 IP 地址  
  
此漏洞允许对运行 Erlang/OTP SSH 服务器的主机具有网络访问权限的恶意行为者执行未经身份验证的远程代码。漏洞的严重性和对有效漏洞的确认使得立即采取行动变得至关重要。  
  
敦促组织识别运行 Erlang/OTP SSH 服务的所有系统并确定修补的优先级。  
  
在确认漏洞很容易被利用并且公开漏洞利用的可能性即将出现后，对于暴露了易受攻击系统的组织来说，补救窗口正在迅速关闭。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/erlang-otp-ssh-rce-poc/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
