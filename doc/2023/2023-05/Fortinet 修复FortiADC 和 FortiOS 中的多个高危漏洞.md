#  Fortinet 修复FortiADC 和 FortiOS 中的多个高危漏洞   
Ionut Arghire  代码卫士   2023-05-06 16:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**本周，Fortinet 月度安全更新修复了位于多款产品中的九个漏洞，其中两个是位于 FortiADC、FortiOS 和 FortiProxy 中的高危漏洞。**  
  
  
  
CVE-2023-27999最为严重，影响  FortiADC 应用交付控制器，是命令注入漏洞，可导致攻击者执行越权命令。攻击者需认证后才能利用该漏洞。该漏洞影响 FortiADC 7.2.0、7.1.1和7.1.0，已在FortiADC 版本7.2.1和7.1.2中修复。  
  
第二个高危漏洞CVE-2023-22640是位于 FortiOS 和 FortiProxy 的 sslvpnd 组件中的界外写漏洞。认证攻击者可发送特殊构造的请求实现任意代码执行。该漏洞影响 FortiOS 7.2.x、7.0.x、6.4.x、6.2.x 和 6.0.x 以及 FortiProxy 7.2.x、7.0.x、2.0.x 和1.x.x。该漏洞已在 FortiOS 7.4.0、7.2.4、7.0.11、6.4.12和6.2.14以及 FortiProxy 7.2.2和7.0.8中修复。  
  
本周，Fortinet 公司还修复了位于 FortiNAC 和 FortiADC 中的多个中危漏洞，如硬编码凭据、输入中和不当、路径遍历和弱认证等问题。另外还修复了位于 FortiNAC 中的多个低危漏洞。  
  
可从 Fortinet 公司的 PSIRT 公告中获取更多漏洞信息。虽然 Fortinet 公司并未提到这些漏洞是否已遭恶意利用，不过未修复的 Fortinet 产品漏洞历来会被利用，因此建议客户尽快应用安全更新。  
  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Fortinet 修复数据分析解决方案中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516234&idx=2&sn=8b8cbd3bbef796e7781c52396c37618f&chksm=ea94b120dde33836274567a92fa01a00f6e40b1b29565d989648c9eeada3ac326405a7a9e7d9&scene=21#wechat_redirect)  
  
  
[Fortinet FortiOS漏洞被用于攻击政府实体](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515912&idx=1&sn=0d48724c08d4d63949a7142683b6fdd7&chksm=ea948e62dde30774b504e3a089bab575daf337854bba663d40f81014b5672260b74230a007a3&scene=21#wechat_redirect)  
  
  
[Fortinet：注意这个严重的未认证RCE漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515862&idx=1&sn=d2ef6b5ab51eba3e97af531d1a8b212b&chksm=ea948fbcdde306aa2d71b31b492175fc0c01a69233601e35fc9fee73fbfbae62668f3aaaffb2&scene=21#wechat_redirect)  
  
  
[Fortinet修复两个严重的RCE漏洞，其中一个两年前就发现？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=1&sn=b8f00a46755a56f7d9aed5ae56c1b4e4&chksm=ea948c95dde305837c4ef5d418e236f9718061ffd9b877fde4fc8a267a7bf0b9910d885f6ea4&scene=21#wechat_redirect)  
  
  
[Fortinet 两款产品FortiTester和FortiADC中存在高危命令注入漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515203&idx=1&sn=0154c72722b8b2c44432c3c779bc5ce6&chksm=ea948d29dde3043f88a8f390467e5fe9417ffdbb15210cc62b5ca63cb1bb7d11d80897439b47&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/fortinet-patches-high-severity-vulnerabilities-in-fortiadc-fortios/  
  
  
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
  
