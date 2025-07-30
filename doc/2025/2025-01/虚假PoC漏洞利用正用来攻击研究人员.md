#  虚假PoC漏洞利用正用来攻击研究人员   
AI小蜜蜂  FreeBuf   2025-01-31 02:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
根据Trend Micro的最新研究，针对CVE-2024-49113这个曾经存在于Microsoft的Windows轻量级目录访问协议(LDAP)中的拒绝服务(DoS)漏洞，识别出了一种名为“LDAPNightmare”的虚假漏洞利用方式。这两个漏洞最初由Safebreach团队发现。  
  
  
攻击者创建了一个恶意存储库，并在其中放置了虚假的PoC，以此窃取敏感的计算机和网络信息。这种攻击被称为LDAPNightmare，其目的是引诱安全研究人员下载并执行窃取信息的恶意软件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73AbSkaiaf5kGfc66YicKgBMdtcW3oJUrKfGzkZam8pMgsGuomcXAMXclXg/640?wx_fmt=jpeg&from=appmsg "")  
  
存放“poc.exe”的存储库（via Trendmicro）  
  
  
当不知情的研究人员下载/执行这段看似无害的代码时，他们无意中释放出一种窃取信息的恶意软件。此恶意软件在被感染的计算机上悄然地收集敏感数据，包括计算机信息、运行进程、网络详细信息和已安装更新。然后，它将这些被窃取的数据发送到攻击者控制的远程服务器。  
  
  
攻击者采用了一种高级技术来传递此恶意软件。恶意存储库看起来像是一个合法存储库的衍生版本，不容易立即识别为恶意。  
  
  
存储库中真实的Python文件已被替换为恶意可执行文件，该文件在被执行时会释放并执行一个PowerShell脚本。该脚本然后创建一个计划任务，从Pastebin下载并执行另一个恶意脚本。最终的脚本会收集受害者的公共IP地址，并将窃取的数据传输到外部FTP服务器。  
  
  
值得注意的是，这个漏洞已在Microsoft于2024年12月发布的"补丁星期二"中得到修复，此次发布还修复了LDAP中的其他两个关键性漏洞。其中第一个漏洞是CVE-2024-49112，这是一个远程代码执行漏洞，攻击者可以通过发送特制的LDAP请求来利用它。第二个漏洞是CVE-2024-49113，这是一个DoS漏洞，攻击者可以利用它来使LDAP服务崩溃，导致服务中断。  
  
  
需要注意的是，PoC漏洞利用通常是一种无害的攻击方式，用于揭示软件安全漏洞，帮助公司修补漏洞。然而，如果使用不当，PoC漏洞利用可能会为攻击者提供对系统的攻击蓝图，使用户在安装修补程序之前就可能受到危害。  
  
  
正如Trendmicro的报告所述，尽管这种攻击方式并不完全新颖，但仍然对网络安全社区构成威胁，因为攻击者通过利用一个备受关注的漏洞和针对安全研究人员进行攻击，这些研究人员通常对安全威胁非常敏感，攻击者可以获取有价值的情报并潜在地危害关键性的安全系统。  
  
  
因此，安全研究人员在下载和执行来自在线存储库的代码时应谨慎行事。他们应优先考虑官方来源，审查存储库中是否存在可疑内容，并验证存储库的真实性。  
  
  
此外，还应该考虑对于活动较少的存储库的社区反馈，并查找存储库中可能预示潜在安全风险的红旗。这将帮助他们远离潜在的威胁，并确保他们的安全。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
   
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
