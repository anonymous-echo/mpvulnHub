#  速修复！Joomla 漏洞可导致RCE攻击   
Bill Toulas  代码卫士   2024-02-22 18:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Joomla 内容管理系统中存在5个漏洞，可被用于在易受攻击网站上执行任意代码。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRoCrCAgkmRiaThl4MMrLrHkWc5uPK9MxEhgYBWua1x8gwkRwnO0YDTgfNSS6kc14t887MYrOeotIQ/640?wx_fmt=png&from=appmsg "")  
  
  
这些漏洞影响多个 Joomla 版本，已在 5.0.3和4.4.3 中修复。这些漏洞概述如下：  
  
- CVE-2024-21722：当用户的MFA方法被修改后，MFA管理特性并未正确终止已有的用户会话。  
  
- CVE-2024-21723：对URL的不当解析可导致开放重定向后果。  
  
- CVE-2024-21724：对媒体选择字段的输入验证不当可导致在多个扩展中的XSS漏洞。  
  
- CVE-2024-21725：邮件地址的不当逃逸可导致多个组件中的XSS漏洞。  
  
- CVE-2024-21726：在过滤器代码中的内容过滤不当可导致多个XSS漏洞。  
  
  
  
Joomla 在安全公告中提到，CVE-2024-21725造成的风险最为严重，可利用性也较高。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oJZWTpJpiae8ZGUA6NJ0gIsbyqibEkC9QDCZHjfRibssuBH9licy1tTj3Zicicasrf5VfyHIwErz6OFFbJAhow5x2tjQ/640?wx_fmt=png "")  
  
**远程代码执行风险**  
  
  
CVE-2024-21726影响 Joomla的核心过滤器组件，严重性和可利用性均为中等，然而Sonar公司的漏洞研究员 Stefan Schiller 提醒称它可导致远程代码执行后果。  
  
Shiller 提到，“攻击者可利用该漏洞，诱骗管理员点击恶意链接，从而获得远程代码执行权限。”XSS漏洞可导致攻击者将恶意脚本注入向其它用户发送的内容中，一般可导致通过受害者浏览器执行不安全的代码。  
  
利用该漏洞要求用户交互。攻击者需要诱骗具有管理员权限的用户点击恶意链接。尽管用户交互降低了该漏洞的严重性，但攻击者可提出正确诱饵，他们可以发动所谓的“spray-and-pray”攻击，即更多受众被暴露给恶意链接，寄望于某些用户会点击这些链接。  
  
Sonar 公司并未分享该漏洞的详情以及利用详情，从而可使更多的 Joomla 管理员能够应用可用的安全更新。Shiller 表示，“虽然我们目前并未披露技术详情，但我们希望强调立即采取措施缓解该风险的重要性。”他强调称所有 Joomla 用户均应升级至最新版本。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源内容管理系统 Joomla 数据遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493286&idx=2&sn=4f641ce315534da4703946e0114eafb9&chksm=ea94d7ccdde35eda9119c9c7c2dd461aa526a18606adeb87169cd2e77335704700679902434d&scene=21#wechat_redirect)  
  
  
[Joomla 3.x 被曝易遭利用的RCE 0day漏洞（含多种利用方式详情）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491044&idx=1&sn=4661e1e02f9606f86c1f8d17a5d499b9&chksm=ea972c8edde0a598c5cd624909a7071a974de82850c1cf52db9bb6d2d611aebddb64735c8144&scene=21#wechat_redirect)  
  
  
[Joomla修复严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485617&idx=3&sn=9b8b7dd11b2c143e64741dc203a83d1a&chksm=ea9739dbdde0b0cda16eb76f422d688f61ca4031d96cdc3fc3b137297c8bc9806dc4a42cbb08&scene=21#wechat_redirect)  
  
  
[PHPFusion 开源 CMS 中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=2&sn=7f19eccf19674dfcdf5f6515082f6989&chksm=ea94b4e8dde33dfedce31e414840f4579284cf9589c84909a1efa2bda3cb52dea3b0de2e1433&scene=21#wechat_redirect)  
  
  
[开源CMS TYPO3中存在XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513988&idx=2&sn=d8e2aa2199ecfa383521908c1073c29b&chksm=ea9486eedde30ff81f3dd92049688847d298f700e6c02f09be03797789e7985c8a14915576a5&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/joomla-fixes-xss-flaws-that-could-expose-sites-to-rce-attacks/  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
