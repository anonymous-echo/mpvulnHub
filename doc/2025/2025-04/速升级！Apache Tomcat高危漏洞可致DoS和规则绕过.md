#  速升级！Apache Tomcat高危漏洞可致DoS和规则绕过   
看雪学苑  看雪学苑   2025-04-29 09:59  
  
近期，Apache 软件基金会披露了 Apache Tomcat 的一项重大安全漏洞 ——CVE-2025-31650。该漏洞属于高危漏洞，其 CVSS 3.1 评分为 7.5，攻击者可利用漏洞绕过安全规则并触发拒绝服务（DoS）条件，对使用该 Java 应用服务器的组织构成严重威胁。  
  
  
该漏洞源于 Apache Tomcat 对 HTTP 优先级标头的处理存在不当输入验证问题，其错误处理部分无效的 HTTP 优先级标头，致使失败请求未得到充分清理，进而产生内存泄漏。一旦攻击者大量发送包含无效 HTTP 优先级标头的恶意请求，就会触发 OutOfMemoryException，最终导致拒绝服务，使应用无法正常运行。HTTP 优先级标头在正常情况下，用于表明客户端对响应交付顺序的优先级偏好，如今却被攻击者利用来实施攻击。  
  
  
此漏洞影响到 Apache Tomcat 的多个版本，具体包括 Apache Tomcat 9.0.76 至 9.0.102、10.1.10 至 10.1.39 以及 11.0.0-M2 至 11.0.5。其风险因素主要体现在，攻击者无需身份验证，只需向目标服务器发送大量带有无效 HTTP 优先级标头的 HTTP 请求，就有可能成功实施攻击，导致服务器因内存耗尽而停止服务。  
  
  
Apache 软件基金会在官方安全公告中给出了以下缓解措施：  
  
  * 升级至 Apache Tomcat 11.0.6 或更高版本。  
  
  * 升级至 Apache Tomcat 10.1.40 或更高版本。  
  
  * 升级至 Apache Tomcat 9.0.104 或更高版本。  
  
  
值得一提的是，Apache Tomcat 9.0.103 虽然包含修复该问题的补丁，但因该版本的发布投票未能通过，所以并不在官方建议的升级范围之内。此次漏洞曝光并非 Apache Tomcat 首次遭遇安全危机，早在 2025 年 3 月，就曾曝出过 CVE-2025-24813 远程代码执行漏洞，其 CVSS 评分为 9.8，攻击者可借此漏洞掌控易受攻击的服务器。  
  
  
鉴于此漏洞的严重性以及可能对 Web 应用造成的完全瘫痪风险，建议相关用户和企业引起高度重视，尽快采取官方推荐的升级措施，以保障系统的安全性与稳定性。  
  
  
  
资讯来源：  
cybersecuritynews  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
