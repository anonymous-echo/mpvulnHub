#  GhostToken 漏洞导致恶意应用隐藏在谷歌云平台中   
Ravie Lakshmanan  代码卫士   2023-04-23 16:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT1iczUBQV6SRZYmH2cZ9Ls54iccaZePZAibgO7UQ38iaklxnLeiaIzzh8AkzbOBr95KUH513icliaKr5eTQ/640?wx_fmt=gif "")  
  
**网络安全研究员披露了谷歌云平台 (GCP) 中一个已修复 0day 的详情。该漏洞可导致攻击者在受害者的谷歌账户中披露不可删除的恶意应用程序。以色列安全公司Astrix Security 将该漏洞称为 “GhostToken”。**  
  
该漏洞影响所有谷歌账户，包括专注于企业的 Workspace 账户。研究人员在2022年6月19日发现并报告了该漏洞，9个多月后，谷歌在2023年4月7日发布全局补丁。  
  
Astrix 公司在报告中指出，“该漏洞可导致攻击者通过将已授权的第三方应用转换为恶意木马应用的方式，获得对受害者谷歌账户不可删除的访问权限，从而导致受害者的个人数据永远遭暴露。”简言之，该漏洞可导致攻击者从受害者的谷歌账户应用管理页面隐藏恶意应用，从而阻止用户删除其访问权限。  
  
攻击者可删除与越权 OAuth 应用程序关联的 GCP 项目，导致其处于“即将删除”的状态。攻击者通过这种能力恢复该项目使恶意应用程序可用，并通过访问令牌获取受害者的数据并再次使其不可用。Astrix 公司指出，“换句话说，攻击者具有对受害者账户的‘幽灵’令牌”。  
  
可被访问的这类数据取决于该 app 给出的权限，而攻击者可利用这一点从 Google Drive 删除文件、代表受害者编写邮件执行社工攻击、追踪位置并从谷歌Calendar、Drive、Photos 和其它应用中提取敏感数据。报告提到，“受害者可能在不知情的情况下，从谷歌 Marketplace 或其他很多网络工具安装看似无害的 app并获得对它的访问权限。一旦该恶意 app 获得授权，攻击者即可利用该漏洞绕过谷歌的 ‘具有访问账户权限的Apps’管理特性，而这是谷歌用户可查看与其账户相关联的第三方应用的唯一地方。”  
  
谷歌发布补丁修复该漏洞，并在第三方访问页面展示正处于被删除状态的应用，使用户可撤销对这类应用的权限。  
  
谷歌云不久前修复了位于 Cloud Asset Inventory API 中的提权漏洞，该漏洞可用于窃取由用户管理的 Service Account 私钥并获得对有价值数据的访问权限。该漏洞是由 SADA 公司在二月初发现的，在3月14日已得到修复。更早时候，云事件响应公司 Mitiga 披露称攻击者可利用对GCP“不充分的”取证可见性提取敏感数据。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌修复今年的第二个已遭利用 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516282&idx=1&sn=52eb5c1094115b783391abfa147ff39a&chksm=ea94b110dde3380674f5e90137e75fac973293e981e63b279fe6617e8a82bd25e2a2d066eccf&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复2023年第一个已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516252&idx=1&sn=8371d9c05433cba2f5df47f101e8ad05&chksm=ea94b136dde33820c0033b8827312e06fe8bf7770075580020919000bdd6049133fc97d2a49e&scene=21#wechat_redirect)  
  
  
[谷歌发布网络安全新举措，提升漏洞管理生态系统](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516244&idx=1&sn=1c27f381699a62f0244ae6abc30289de&chksm=ea94b13edde338281fda8c3088916195d7c19374a957c0a274987a7bdc6c1e3cfb393df14a9c&scene=21#wechat_redirect)  
  
  
[谷歌Pixel手机漏洞可导致打码信息被复原](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515986&idx=2&sn=1c561af50d4d74f92b929c576d1b61c0&chksm=ea948e38dde3072e6ac1c0f86b5c40dae78e7e6ffb50ef855789ba8a438c415a8d85657b29d3&scene=21#wechat_redirect)  
  
  
[谷歌在三星Exynos 芯片集中发现18个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515956&idx=1&sn=01fe340192b1659e658210ae4b02ac97&chksm=ea948e5edde30748775821e1c9ed1b389b2c0dd119e01cd78b9292d859542e3f209300000e4c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/04/ghosttoken-flaw-could-let-attackers.html  
  
  
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
  
