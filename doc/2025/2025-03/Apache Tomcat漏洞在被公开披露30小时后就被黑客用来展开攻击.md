#  Apache Tomcat漏洞在被公开披露30小时后就被黑客用来展开攻击   
看雪学苑  看雪学苑   2025-03-18 18:00  
  
近期，老牌服务器软件 Apache Tomcat 被曝出严重的远程代码执行漏洞（CVE-2025-24813），然而该漏洞在被公开披露后仅仅 30 小时，就迅速遭到黑客的利用，全球众多使用 Apache Tomcat 的企业服务器面临严峻的安全威胁。  
  
  
此次漏洞影响范围广泛，涉及 Apache Tomcat 多个版本，包括 11.0.0-M1 至 11.0.2、10.1.0-M1 至 10.1.34 以及 9.0.0-M1 至 9.0.98 版本。黑客利用该漏洞，可以通过特定的 HTTP PUT 请求上传恶意的序列化 Java 会话文件，随后通过发送带有恶意会话 ID 的 GET 请求触发反序列化，从而在目标服务器上执行任意代码，甚至植入恶意脚本或后门程序，严重威胁服务器的安全性和稳定性。  
  
  
更令人担忧的是，该漏洞的利用难度极低，无需进行身份验证，只要 Apache Tomcat 使用基于文件的会话存储，攻击者就能够轻松发起攻击。而且，随着攻击者策略的不断演变，未来可能会出现上传恶意 JSP 文件、修改配置文件等更复杂的攻击手段，进一步扩大攻击面，给服务器带来更大的安全隐患。  
  
  
目前，Apache 官方已经紧急发布新版本修复了这一漏洞，分别是 9.0.99、10.1.35 和 11.0.3 版本。然而，由于许多企业用户可能并未及时关注到漏洞信息并进行版本升级，导致大量服务器依然处于风险之中。  
  
  
  
资讯来源：  
thehackernews  
  
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
  
