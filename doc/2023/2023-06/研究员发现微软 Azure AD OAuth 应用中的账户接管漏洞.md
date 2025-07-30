#  研究员发现微软 Azure AD OAuth 应用中的账户接管漏洞   
Ryan Naraine  代码卫士   2023-06-21 16:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
安全创业公司 Descope 的安全研究员在微软 Azure AD OAuth 应用中发现了一个严重的配置不当问题。任何使用“通过微软登录”的企业可被暴露到完全账户接管风险中。  
  
  
该漏洞被称为 “nOAuth”，是一个认证实现漏洞，影响微软 Azure AD 多租户OAuth 应用。  
  
Descope 公司在安全公告中提到，恶意人员可修改微软 Azure AD 账户中的邮件属性，并通过他们想要假冒的任何受害者的邮件地址利用一次点击“通过微软登录”特性。  
  
公告中解释称，“在常见的 OAuth 和 OpenID Connect 实现中，应用将用户邮件地址作为唯一标识符。然而，在微软 Azure AD中，返回的‘邮件’断言是易变的且未验证的，因此是不可信的。”该公司表示，这一影响导致创建 Azure AD 租户的攻击者，通过易受攻击的应用和特殊构造的受害者用户使用‘通过微软登录’特性，造成账户遭完全接管。Descope 发布演示视频，展示了潜在利用非常简单。  
  
Descope 在今年早些时候将该问题告知微软并与微软共同推出新的缓解措施，保护企业免受提权攻击。  
  
微软将该漏洞描述为“用于 Azure AD (AAD) 应用中的不安全的反模式”，使用访问令牌中的邮件断言进行授权，会导致提权后果。微软证实称，“攻击者可伪造发给应用的令牌中的邮件断言。另外，如果应用使用此类断言进行邮件查询，则存在数据泄露威胁。微软建议在授权时不得使用邮件断言。如应用使用这些邮件断言进行授权或用于主要用户识别，则可遭受账户和提权攻击。”  
  
微软督促开发人员审计应用的授权业务逻辑，并按照文档指南保护应用程序遭越权访问。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[微软 Azure Bastion 和 Container Registry 中存在两个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516737&idx=1&sn=c4b5adfcf7e55915ef943fcfd4fd9a56&chksm=ea94b32bdde33a3d834b36d01e90e0a897698720411c56832829d175a4722dd94ba823e665d5&scene=21#wechat_redirect)  
  
  
[研究员在微软 Azure API 管理服务中发现3个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=3&sn=f563d9d06d17140943a9006f9816fecd&chksm=ea94b182dde33894747c1e2aa9ddbd52a923d8f1cc8ec0edd712caa946b58d97a9ac1bda8ecf&scene=21#wechat_redirect)  
  
  
[微软Azure新漏洞可导致RCE，研究员获3万美元奖励](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515363&idx=2&sn=36927e449388a6dc1fcc5e7ccbf92a2e&chksm=ea948d89dde3049ffbff2cf56bcfbaa5d4e844e193a9391619d310ac4f075848d0fc66a2cf00&scene=21#wechat_redirect)  
  
  
[四款微软Azure服务存在漏洞，可导致云资源遭越权访问](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515363&idx=3&sn=6c939ad71b9754325cf5e804212ce38e&chksm=ea948d89dde3049f9674c7caff6a7a10ad9243925974600a40bc322cfba7198f6d8f4e045dbf&scene=21#wechat_redirect)  
  
  
[微软悄悄修复Azure跨租户数据访问高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515121&idx=1&sn=a174aa208e22a8d97fae0aa69a4777b2&chksm=ea948a9bdde3038d87dd9ce4fd4207e50cee5c030640d32b5ae879eac287877c6505152caf15&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/researchers-flag-account-takeover-flaw-in-microsoft-azure-ad-oauth-apps/  
  
  
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
  
