#  严重的 TootRoot 漏洞可导致Mastodon 服务器遭劫持   
Bill Toulas  代码卫士   2023-07-10 18:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**免费开源的去中心化社交网络平台 Mastodon 修复了四个漏洞，其中一个严重漏洞可导致黑客在使用特殊构造的媒体文件的服务器上创建任意文件。**  
  
Mastodon 拥有约880万名用户，分布在由志愿者托管的1.3万个单独服务器（实例）上，以支持独特且互联的社区。所有这些漏洞都是由渗透测试服务公司 Cure53 的独立审计人员发现的。这些审计人员应 Mozilla 公司的要求对 Mastodon 的代码进行了审计。  
  
其中最严重的漏洞是CVE-2023-36460，被称为 “TootRoot”，可使攻击者攻陷目标服务器。该漏洞位于 Mastodon 的媒体处理代码中，可导致攻击者在 toot （相当于推文）上使用媒体文件触发一系列问题，如拒绝服务、任意远程代码执行等。  
  
尽管 Mastodon 发布的安全通告很简短，但安全研究员 Kevin Beaumont 强调了与 TootRoot 相关联的风险，表示toot可被用于在向 Mastodon 用户交付内容的服务器上植入后门。如此攻陷可导致攻击者无限控制服务器及其所托管和管理的数据，并延伸至用户的敏感信息。  
  
第二个严重漏洞是CVE-2023-36459，它是位于 oEmbed 预览卡中的 XSS 漏洞，可导致攻击者绕过目标浏览器上的 HTML 清理机制。攻击者可借此劫持账户、模拟用户或访问敏感数据。  
  
另外两个漏洞是CVE-2023-36461（通过 HTTP 缓慢响应导致的高危 DoS 漏洞）和CVE-2023-36462（高危，可导致攻击者以欺骗方式构造经验证的资料链接，发动钓鱼攻击）。  
  
这四个漏洞影响 Mastodon 3.5.0及后续所有版本，已在版本3.5.9、4.0.5和4.1.3中修复。  
  
这些补丁是服务器安全更新，需要管理员应用以清除为社区带来的风险。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Mastodon 用户易受密码窃取攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514671&idx=2&sn=01488cff40e9435d1ee584d20970714d&chksm=ea948b45dde302533009ce4b9a55ae959c7e279f6c448ff79b402c6c7c1e161a108d6a3d835f&scene=21#wechat_redirect)  
  
[vCenter 服务器漏洞可导致代码执行和认证绕过](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=1&sn=1088fe2b36f5e1648053d9005c87f2ca&chksm=ea94b3f8dde33aee090d8160c827cb19fdabb2041da6ed2e472b13cf421105f734ea2276b4d6&scene=21#wechat_redirect)  
  
  
[十几个NPM恶意包劫持 Discord 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509639&idx=3&sn=b58d39a8a6f2a90572cf41a281824e84&chksm=ea9497eddde31efb2a093085e8dc7d5dd10083227ad6aae0e8f1a10630c0393723d534c85134&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/critical-tootroot-bug-lets-attackers-hijack-mastodon-servers/  
  
  
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
  
