#  从披露到被利用仅4小时！WordPress插件漏洞使黑客肆意创建管理员账户   
看雪学苑  看雪学苑   2025-04-15 18:01  
  
4月10日，WordPress插件SureTriggers被曝出存在一个严重的身份验证绕过漏洞（CVE-2025-3102），该漏洞在公开披露后仅4小时内就被黑客积极利用，全球超过10万个使用该插件的网站面临巨大安全威胁。  
  
  
**漏洞详情**  
  
SureTriggers是一款拥有超过10万安装量的WordPress自动化平台插件，旨在帮助用户在不同网站、应用程序和其他WordPress插件之间创建自动化流程。然而，该插件在1.0.78及之前所有版本中，由于`autheticate_user`函数未对`secret_key`值进行空值检查，存在认证绕过漏洞。  
  
  
当插件已安装激活但未配置API密钥时，未经认证的攻击者即可利用该漏洞在目标网站上创建管理员账户，从而完全控制WordPress网站。攻击者一旦获得管理员权限，可以上传恶意插件、篡改内容、传播恶意软件或垃圾信息，并将访问者重定向至恶意网站。  
  
  
**攻击情况**  
  
安全监测发现，多个IP地址发起了针对该漏洞的利用尝试，包括IPv6地址2a01:e5c0:3167::2和2602:ffc8:2:105:216:3cff:fe96:129f，以及IPv4地址89.169.15.201和107.173.63.224。攻击者主要通过创建管理员账户来建立持久访问权限，且为了增加检测难度，他们随机化了用于创建账户的用户名、密码和电子邮件别名。  
  
  
**应对措施**  
  
网站管理员应立即采取以下措施：  
  
  
-更新插件：立即将SureTriggers插件更新至最新版本（1.0.79或更高版本），以修复漏洞。  
  
-临时禁用插件：如果无法立即更新，应暂时禁用该插件，直到能够应用更新。  
  
-审计用户账户：检查自4月10日以来创建的任何可疑管理员级用户，并删除这些账户。  
  
-检查最近安装的插件和主题：查看是否有未经授权的插件或主题被安装。  
  
-审查服务器日志：查找针对漏洞端点的请求，以确定是否有攻击尝试。  
  
-部署Web应用防火墙：考虑实施Web应用防火墙以提供额外的保护。  
  
  
此外，Wordfence Premium、Wordfence Care和Wordfence Response用户在4月1日就收到了防火墙规则，以保护其免受针对该漏洞的攻击。而使用免费版本的Wordfence用户将在5月1日获得同样的保护。  
  
  
  
  
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
  
