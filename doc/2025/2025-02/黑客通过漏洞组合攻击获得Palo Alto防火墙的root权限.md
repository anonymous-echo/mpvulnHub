#  黑客通过漏洞组合攻击获得Palo Alto防火墙的root权限   
AI小蜜蜂  FreeBuf   2025-02-20 11:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
Palo Alto Networks PAN-OS软件中一个上周刚修补的高严重性认证绕过漏洞，目前正被威胁攻击者积极利用，以获得受影响防火墙系统的root级别访问权限。  
  
  
![Palo Alto Networks](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39hzegxXibGx7eXYBm2V82YGEoZ0w1ib92GP7CjUjdWCS3s4D0yVkuvauPblGxvDk3wGFK3uVAbUCibA/640?wx_fmt=jpeg&from=appmsg "")  
  
图片来源：Ken Wolter / Shutterstock  
  
  
该漏洞被追踪为CVE-2025-0108，允许未经认证的攻击者通过网络访问PAN-OS管理网页界面，绕过认证要求。漏洞的严重性评分为CVSS 8.8（满分10分），但仅当允许从互联网上的外部IP地址访问管理网页界面时成立。如果将该访问限制在指定的IP地址，评分则会显著降至5.9，成为一种有效的变通措施。  
  
  
Palo Alto在安全公告中表示，此绕过漏洞使攻击者能够调用某些PHP脚本，虽然这些脚本可能无法实现远程代码执行，但会“对PAN-OS的完整性和保密性产生负面影响”。  
  
  
**结合旧漏洞实现root权限提升**  
  
  
  
攻击行为涉及将CVE-2025-0108与两个旧漏洞结合在一起，其中一个漏洞之前已被积极利用，允许在受影响的系统上进行权限提升和认证文件读取。  
  
  
根据公告更新，“Palo Alto Networks已观察到攻击者试图在未修补且未受保护的PAN-OS网页管理界面上，将CVE-2025-0108与CVE-2024-9474和CVE-2025-0111结合在一起进行利用。”  
  
  
CVE-2025-0108的发现源于对CVE-2024-9474的补丁后分析。CVE-2024-9474是一个中等严重性漏洞（CVSS 6.9/10），去年11月已被积极利用。当时，攻击者将CVE-2024-9474与另一个影响PAN-OS的关键认证绕过漏洞（CVE-2024-0012）结合在一起，从而允许在受感染的系统上远程执行代码。  
  
  
现在，威胁攻击者将CVE-2025-0108和CVE-2024-9474与一个高严重性漏洞（CVE-2025-0111）结合在一起，用于未经授权的root级别访问，可能允许提取敏感配置数据和用户凭证。  
  
  
**建议立即修补系统**  
  
  
  
所有这三个漏洞均影响PAN-OS 10.1、10.2、11.1和11.2版本，且已分别发布修补程序。Palo Alto Networks确认其Cloud NGFW和Prisma Access服务未受影响。  
  
  
作为一种变通方法，建议管理员仅允许受信任的内部IP地址访问管理网页界面。即便如此，未修补的系统仍可能面临风险，只是风险有所降低。此外，公告补充道，拥有威胁预防订阅的客户可以通过启用威胁ID 510000和510001来阻止试图利用CVE-2025-0108和CVE-2025-0111的攻击尝试。  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
