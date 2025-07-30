#  Salesforce 邮件服务0day用于钓鱼攻击活动   
THN  代码卫士   2023-08-03 18:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Guardio Labs的研究员 Oleg Zaytsev 和 Nati Tal 发布报告提到，一起复杂的 Facebook 钓鱼攻击活动利用 Salesforce 邮件服务0day漏洞，通过该公司的域名和基础设施构造目标钓鱼信息。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQSp5Y3MYDgeCN4GKOhy9E8avtC0d8Tv6ibzdB8FVjM7LlfNFUG1gtErYw2sdlBOyGwDibb6s2451uw/640?wx_fmt=gif "")  
  
  
研究人员提到，“显而易见，这些钓鱼活动通过组合利用 Salesforce 漏洞和 Facebook Web Games 平台中的遗留问题躲避检测方法。”  
  
邮件信息假装源自 Meta，同时从域为 @salesforce.com 的邮件地址发送，目的是诱骗收件人点击链接，说辞是因为“怀疑参与假冒活动”，因此正在“全面调查”收件人的 Facebook 账号，目的就是将用户指向恶意登录页，而该页面的目的是捕获受害者的账号凭据和双因素认证码。该钓鱼包被托管为域名为 apps.facebook[.]com的 Facebook apps 平台下的游戏。  
  
研究人员解释称，“难怪我们会看到这份邮件避开了传统的反垃圾邮件和反钓鱼机制。它包含facebook.com的合法链接，而且是从全球顶级CRM提供商之一、合法的邮件地址（@salesforce.com）发送的。”值得一提的是，Meta 在2020年7月弃用 Web Games 特性，尽管很有可能在弃用前开发了对遗留游戏的支持。  
  
虽然通过 salesforce.com 发送邮件涉及验证步骤，但研究人员提到钓鱼攻击配置了使用 salesforce.com域的 Email-to-Case 站内路由邮件地址并将其设置为组织机构内的邮件地址，狡猾地绕过了这些防御措施。  
  
研究人员指出，“它触发了验证流，将邮件发送到该路由地址，从而成为系统中的新任务。”这就导致只要点击添加受控地址请求所附加的链接，就能验证 salesforce.com 邮件地址。  
  
他们还指出，“从此处开始能够制造任何类型的钓鱼方案，甚至通过这类邮件直接攻击 Salesforce 客户。而这最终到达受害者的收件箱，绕过反垃圾邮件和反钓鱼机制，甚至被谷歌标记为‘重要’。”  
  
研究人员在2023年6月28日将问题告知 Salesforce 公司，后者在7月28日修复该0day，增加检查，阻止使用 @salesforce.com域的邮件地址。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Salesforce 社区可泄露业务敏感信息](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506912&idx=2&sn=7b9ef1d121650f3c20b844ed435ca2ad&chksm=ea94ea8adde3639c0ca0c81f5220f0d77fc5a9801a8eae66dc2df868978342542caf42676d2d&scene=21#wechat_redirect)  
  
  
[默认数据库脚本部署提升 Salesforce 所有用户权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489980&idx=1&sn=64190d35361b97a9fac8c92e96183de9&chksm=ea9728d6dde0a1c06555787f9d005ac1ebd5e15485f81f64e80c0c04d5c3efbe9491e9a76f5a&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/08/phishers-exploit-salesforces-email.html  
  
  
题图：Pixabay License  
  
  
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
  
