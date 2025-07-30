#  研究人员警告称，Apache Struts 2 关键漏洞可能遭利用   
会杀毒的单反狗  军哥网络安全读报   2024-12-21 01:01  
  
**导****读**  
  
  
  
研究人员警告说，在 Apache Struts 2 中的一个严重漏洞首次披露和修补几天后，攻击者就正在积极利用该漏洞。  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaE8jgaibPKYUDalMTcm8Y2jgpic8rfXOqXQiaEo2xd9I9v2icnxc2NxpTbq0vl0uyOjLibsfTdLYibbPMvg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
根据 Apache 的公告，该漏洞编号为CVE-2024-53677，涉及文件上传逻辑缺陷。该漏洞的CVSS评分为 9.5（满分 10 分），表明风险级别为严重。  
  
  
攻击者可以操纵文件上传参数以实现路径遍历。Apache 敦促用户升级到 Struts 6.4.0 或更高版本并使用 Action File Upload Interceptor。 安全研究人员警告称，该漏洞可能允许攻击者进行恶意操作。  
  
  
SANS 技术研究所研究主任Johannes Ullrich通过电子邮件表示：“由于 Struts 2 上传功能存在漏洞，攻击者可以将文件上传到服务器上的限制区域，然后利用这些文件执行代码。”  
  
  
Ullrich 表示，在典型的攻击场景中，黑客会上传一个 Web shell，这为他们提供了一个简单的界面来在服务器上执行命令并发起进一步的攻击。  
  
  
Sonatype 在周五的博客文章中表示，来自 Maven Central 的数据显示，自 12 月 11 日首次发布修复程序以来，易受攻击的组件已被下载近 40,000 次。  
  
  
据 Sonatype 称，过去一周内，有漏洞的组件版本占 Struts 2 下载量的 90% 左右。Sonatype 官员表示，这表明风险非常高，时间紧迫。  
  
  
研究人员警告称，该漏洞建立在与先前漏洞（列为CVE-2023-50164）相关的问题之上。这种联系导致一些研究人员担心补丁不完整。  
  
  
Sonatype 联合创始人兼首席技术官 Brian Fox表示，升级并不能完全解决该漏洞，而利用不同的文件上传拦截器所需的潜在代码更改会使缓解步骤变得更加复杂。  
  
  
Rapid7 首席安全研究员Stephen Fewer对主动攻击的真实性和程度提出了质疑，并补充说，人们的担忧源于对针对蜜罐系统的公开概念验证攻击的观察。  
  
  
Fewer  
  
周五通过电子邮件表示：“目前还不清楚是否有针对任何可行目标系统的成功攻击。”  
  
  
Fewer 表示，公开的概念验证漏洞可能需要进行修改，才能成功利用任何目标 Web 应用程序。  
  
  
官方安全公告：  
  
https://cwiki.apache.org/confluence/display/WW/S2-067  
  
  
sonatype博客：  
  
https://www.sonatype.com/blog/cve-2024-53677-a-critical-file-upload-vulnerability-in-apache-struts2  
  
  
新闻链接：  
  
https://www.cybersecuritydive.com/news/active-exploitation-apache-struts-2-flaw/736199/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
