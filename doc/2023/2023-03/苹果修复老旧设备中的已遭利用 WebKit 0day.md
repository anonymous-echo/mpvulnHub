#  苹果修复老旧设备中的已遭利用 WebKit 0day   
Sergiu Gatlan  代码卫士   2023-03-28 19:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ8wujiaicZ3m2DgID1dCtK0l0cwpcFYKVQCxDD8iaxJmGXlrLS0hyr77a8yqevrOj1zMiclWpribSDpWQ/640?wx_fmt=png "")  
  
  
**苹果发布安全更新，向后兼容上周发布的补丁，修复老旧 iPhone 和 iPad 中的已遭利用的0day 漏洞CVE-2023-23529。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ8wujiaicZ3m2DgID1dCtK0lpV0uRvHy419pZ2xX5T3860AphSsOsZLfo82195qkaYguWjXCbQAjyw/640?wx_fmt=png "")  
  
  
  
该漏洞是位于 WebKit 中的类型混淆漏洞，苹果已于今年2月13日在更新版本 iPhone 和 iPad中修复。潜在攻击者可利用该漏洞触发操作系统崩溃并获得受陷 iOS 和 iPadOS 设备的代码执行权限。之后，攻击者诱骗受害者打开恶意网页，在目标 iPhone 和 iPad 上执行任意代码。  
  
苹果对该0day 的描述为，“处理恶意构造的 web 内容可能导致任意代码执行后果。苹果已注意到有一份报告称该漏洞可能已遭活跃利用。”苹果还通过增强检查在 iOS 15.7.4 和 iPad 15.7.4 中修复该漏洞。受影响设备包括 iPhone 6s（所有机型）、iPhone 7（所有机型）、iPhone SE（第一代）、iPad Air 2、iPad mini（第四代）和iPod touch（第七代）。  
  
****  
**今年修复的首个遭在野利用的 0day**  
  
  
****  
尽管苹果公司注意到有报告称该漏洞已用于攻击中，但尚未发布相关事件详情。不过这是苹果关于在野利用漏洞的标准披露流程，目的是让尽可能多的用户修复设备并拖慢攻击者开发并部署额外exploit 的进程。  
  
虽然 CVE-2023-23529 漏洞可能仅用于针对性攻击中，但强烈建议尽快安装苹果刚发布的安全更新，阻止潜在攻击尝试，保护老旧版本 iPhone 和 iPad 设备的安全。  
  
今年1月份，苹果曾为远程可利用0day (CVE-2022-42856) 向后兼容补丁。  
  
  
****  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515546&idx=1&sn=f9311f04f319e12385edbfcd698fa495&chksm=ea948cf0dde305e697564ae3c0b973831eece5c572326a20990546b6bacf3bef67450345d514&scene=21#wechat_redirect)  
  
[恶意广告活动利用 WebKit 0day 实施欺诈](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501505&idx=1&sn=6917322af83746724a04f13e0606594e&chksm=ea94f7abdde37ebdba3ce3f283afddf218d44832d06a7cd49e3f21e9404a85d57a74c24333e1&scene=21#wechat_redirect)  
  
  
[开源的WebKit 浏览器引擎受多个漏洞影响，可导致 RCE 后果](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247498263&idx=3&sn=572eec6f8e037c450f78e70fdf18d9ad&chksm=ea94cb7ddde3426bd4d121cfbabe12d01a371187750311db26295606e6137b5e5c5264c0ff13&scene=21#wechat_redirect)  
  
  
[这个 WebKit 漏洞助力 Pwn2Own 冠军斩获5.5万美元赏金（详细分析）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491760&idx=1&sn=395390c544cf809aa50317a4fd88621b&chksm=ea94d1dadde358ccb3ddc1fdcc609348544b3c97b76aa6f2656c391e947b965626f82e76fea8&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/apple/apple-fixes-recently-disclosed-webkit-zero-day-on-older-iphones/  
  
  
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
  
