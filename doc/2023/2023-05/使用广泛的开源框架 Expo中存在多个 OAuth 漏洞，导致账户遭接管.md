#  使用广泛的开源框架 Expo中存在多个 OAuth 漏洞，导致账户遭接管   
Eduard Kovacs  代码卫士   2023-05-25 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**API安全公司 Salt Security 指出，广为使用的应用开发框架 Expo 中存在多个与 OAuth 相关的漏洞，可被用于控制用户账户。**  
  
  
  
  
Expo 是一款开源平台，用于为移动设备和 web 开发通用的原生 app。该公司表示其产品被超过60万名开发人员所使用，其中不乏多个大型企业。  
  
研究人员分析 OAuth 功能后发现，它可使开发人员通过第三方服务如 Facebook 和 Google 启用用户认证。他们分析后发现了多个漏洞，攻击者诱骗目标用户点击特殊构造的链接后即可利用这些漏洞。攻击者可利用这种攻击方法劫持会话并完全控制用户的账户，从而暴露敏感信息、实施金融欺诈或盗取身份。在某些情况下，攻击者还可利用这种 exploit 以目标用户的名义在 Facebook、Goolge 或 Twitter 平台上执行操作。  
  
这些漏洞被统称为 CVE-2023-28131，在2月中旬被告知 Expo 开发人员并快速得到修复。Expo 发布文章，详述了阻止利用的多个步骤。目前尚未发现攻陷或恶意利用的证据。  
  
Expo 公司解释称，“该漏洞本可导致潜在攻击者诱骗用户访问恶意链接、登录至第三方认证提供商并暴露其第三方认证凭据。这是因为用于存储应用回调 URL 的 auth.expo.io在用户之前明确证实信任回调URL。发布热修复方案后，auth.expo.io 目前要求用户证实信任未经验证的回调URL。”  
  
Salt Security 公司提到，仅有使用 Expo 社交登录组件 AuthSession Proxy 的实现才受影响。研究人员发现数百种潜在受影响的服务，包括Codecademy 等，研究人员在这些平台上演示了该 exploit 如何控制账户。  
  
就在几个月前，Salt Security 公司称发现多个 OAuth 实现漏洞，可被用于入侵 Booking.com 账户。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌 OAuth客户端库（Java版）中存在高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511856&idx=2&sn=8af051f10bbd30805bce19d5ee116756&chksm=ea949e5adde3174c36f981c8ee950fcc91f0843043f87bf24e5070783d7c9039471df24668cb&scene=21#wechat_redirect)  
  
  
[GitHub：攻击者正在利用被盗 OAuth 令牌攻击数十家组织机构](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511412&idx=3&sn=e1ae2051f86fd59769f851a34b74a6d8&chksm=ea949c1edde31508e64bd8a4cfd379c97ace6c1e7b27fca2a187950cb327637742b57a7fac03&scene=21#wechat_redirect)  
  
  
[Waydev 客户的GitHub 和 GitLab OAuth 令牌被盗，源代码遭访问](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494297&idx=3&sn=27fda07292065fa04502dbd149008f38&chksm=ea94dbf3dde352e53ac806ff0dbee5d9e2f4348a390f01e87d90b3d9d16acb55d9980c78c41f&scene=21#wechat_redirect)  
  
  
[我找到一个价值5.5万美元的 Facebook OAuth账户劫持漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492504&idx=1&sn=1e98065997577058249ef0c61f64a205&chksm=ea94d2f2dde35be4dcd134619c10586e3fafdbf8df55b7febac5d06b25ce5dc809f2a2f659ff&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/oauth-vulnerabilities-in-widely-used-expo-framework-allowed-account-takeovers/  
  
  
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
  
