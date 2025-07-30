#  Chromium 漏洞可用于绕过安卓设备上的安全特性   
Ben Dickson  代码卫士   2023-02-28 17:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**最近，Chromium 项目中修复了一个漏洞，它本可导致恶意人员绕过保护安卓浏览器上敏感cookie的安全特性SameSite。**  
  
  
  
SameSite 设置可使开发人员限制对cookie的访问。例如，通过设置 SameSite=strict，当用户通过其它网站发出的链接或重定向请求导航到该网站时，它可阻止cookie 出现在 HTTP 响应中。  
  
  
**0****1**  
  
**通过Intent 请求绕过SameSite**  
  
  
安全研究员 Axel Chong 发现，如果使用intent scheme 导航到目标网站，则可绕过SameSite 防护措施。Intents是一种外部协议句柄，允许安卓应用打开其它应用，如从浏览器跳转到 Maps 应用或者从SMS跳转到浏览器。  
  
他提到，“我在读到关于intents上的有趣bug (Issue 1249962) 时，发现了这个bug。因为intent URL 可指向同样的app（本案例中是Chrome）并创建一个新的浏览上下文，因此我后来在思考intent URL 很可能绕过哪种安全措施。”  
  
Intent URL 可被视作外部来源并受SameSite 限制。但Chong 用Python 创建的PoC 显示，当web服务器通过intent URL 启动重定向时，设置了 SameSite=strict 的cookie 会遗留下来。  
  
该scheme 还会绕过 Sec-Fetch-Site 标头，判断请求源自何处并可使网站从外部来源控制对资源的访问权限。Chong 表示，“两者都用于防御CSRF攻击，因此造成的影响就是绕过这些防护措施。”  
  
  
**0****2**  
  
**一般重定向也受影响**  
  
  
进一步调查发现，在没有 intent 协议的情况下，SameSite cookie也会通过简单的重定向请求而遗留下来。  
  
虽然该问题已在 Chrome 的一个早期版本中修复，但由于它会破坏变更，因此随后被禁用。  
  
该试验性 cookie 特性标记 (chrome://flags/#enable-experimental-cookie-features) 将恢复安全行为并阻止在普通的请求中发送SameSite cookie。该标记并不会影响intent 重定向的不安全行为。Chong 还提到该标记并不影响 Sec-Fetch-Site 行为，后者应该单独修复。  
  
  
**03**  
  
**修复不易**  
  
  
修复该漏洞并不简单，因为开发人员必须为包括浏览器在内的可信应用的判断担责。  
  
最终的修复方案决定不信任intents，理由有二。一是，设备上的其它应用可能不值得信任；二是网站可使用Intent URL/重定向反射到Chrome 并可能借此绕过SameSite 的限制。”  
  
该漏洞告诉我们，鉴于应用和浏览器通信可达到的复杂性，开发人员应当在应用上使用多个安全层。Chong 建议，“这种浏览器安全机制（如SameSite cookie、Fetch 元数据）的目的是仅仅实现纵深防御。你应该使用它们但不应将它们作为唯一的防御方式。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌决定不修复这个Chromium浏览器XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514671&idx=1&sn=61fcdf93bfac81f15a8003972cd54cfd&chksm=ea948b45dde3025344d546821417c7d84002e20f4ce07d501debfcd2eb37b63ca343e65307ca&scene=21#wechat_redirect)  
  
  
[Chromium 原型污染漏洞导致Sanitizer API 被绕过](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514074&idx=2&sn=69d12874944c58027b021bc2110113e1&chksm=ea9486b0dde30fa679fa1c66c7721ecea6485a6a51d6238c008ca0a4d85e28eb1181d83d6e7d&scene=21#wechat_redirect)  
  
  
[补丁延迟导致数百万台安卓设备易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514727&idx=2&sn=248651ac7d2ceefc9c0c049af0961e9b&chksm=ea948b0ddde3021b4df5688ce372eaee65c7f35e447bcbd7e81112b03f9383d6f6127a80b6b0&scene=21#wechat_redirect)  
  
  
[亚马逊悄悄修复安卓相册 app 中的高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512652&idx=3&sn=2b4e8e13ba0800dd1fc7f8468b6a0829&chksm=ea948326dde30a308994628b3b2468662db78d6469ed717a69fd91089fce0e26e5820559f664&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://portswigger.net/daily-swig/chromium-bug-allowed-samesite-cookie-bypass-on-android-devices  
  
  
题图：Pexels License  
  
  
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
  
