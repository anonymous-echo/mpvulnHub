#  苹果紧急修复已遭利用的 0day   
Sergiu Gatlan  代码卫士   2023-07-11 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**苹果发布新一轮快速安全响应 (RSR) 更新，修复了一个已遭利用的 0day (CVE-2023-37450)，影响完全打补丁的 iPhone、Mac 和 iPad。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ8OLcVKNUhFpja75tYZbo4Hlaoh1TXesHNiaCxzWOgxQwNJLtGibCu6TlzLMArZEH4TCuVY8FXXG9w/640?wx_fmt=gif "")  
  
  
  
苹果在 iOS 和 macOS 安全通告中指出，该漏洞由一名匿名研究员发现并报告，“苹果公司注意到一份报告提到该漏洞可能已遭活跃利用。”  
  
苹果公司提醒安装了RSR补丁的系统称，“该快速安全响应提供了重要的安全修复方案并建议所有用户应用。”  
  
RSR 补丁作为影响更新推出，旨在解决位于 iPhone、iPad 和 Mac 平台上的安全问题，目的是解决主要软件更新之间引发的安全问题。另外，一些带外安全更新也用于已遭活跃利用的漏洞。如果用户关闭自动更新或未安装RSR，则设备会作为未来软件更新的一部分得以修复。  
  
今天发布的紧急更新包括：  
  
- macOS Ventura 13.4.1 (a)  
  
- iOS 16.5.1 (a)  
  
- iPadOS 16.5.1 (a)  
  
- Safari 16.5.2  
  
  
  
这些漏洞位于由苹果开发的 WebKit 浏览器引擎中，可使攻击者通过诱骗目标打开包含恶意构造内容的网页，在目标设备上获得任意代码执行权限。苹果公司改进了相关检查以缓解利用尝试，修复了该安全弱点。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ8OLcVKNUhFpja75tYZbo4Hlaoh1TXesHNiaCxzWOgxQwNJLtGibCu6TlzLMArZEH4TCuVY8FXXG9w/640?wx_fmt=gif "")  
  
  
**2023年修复的第10个0day**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
自2023年开始，苹果已修复了用户攻击 iPhone、Mac 或 iPad 的10个0day 漏洞。  
  
本月初，苹果修复了三个0day（CVE-2023-32434、CVE-2023-32435和CVE-2023-32439）。它们被用于通过 iMessage 零点击利用在 iPhone 上部署 Triangulation 监控软件。  
  
5月份，苹果公司修复了三个0day（CVE-2023-32409、CVE-2023-28204和CVE-2023-32373），第一个漏洞由 Amnesty International 安全实验室和谷歌威胁分析团队发现，可能被用于安装恶意监控软件。  
  
4月份，苹果修复了其它两个0day（CVE-2023-28206和CVE-2023-28205），它是利用链的一部分。该利用链结合安卓、iOS 和 Chrome 0day以及 nday 漏洞在高风险设备上部署监控软件。  
  
2月份，苹果修复了另外一个 WebKit 0day (CVE-2023-23529)，在易受攻击的 iPhone、iPad 和 Mac 上获得代码执行权限。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[苹果修复3个已遭利用的新 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516531&idx=1&sn=71b3e940c482c53d52c592cdfe3992db&chksm=ea94b019dde3390fb1ecf3bd947eb8852a1f27e29e28f9c88b97d9bb2087840f62be6d882d4b&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个已遭利用的 0day，影响 iPhone 和 Mac设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516192&idx=2&sn=5c3e3733fceb0ec8d172ac2df805b47d&chksm=ea94b14adde3385c3f37236533daf5e7d38ba6c37d81d396c80446e2d37a13b2fd254a3b2904&scene=21#wechat_redirect)  
  
  
[苹果修复老旧设备中的已遭利用 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=2&sn=3b952d583d720b24a32bea4b8840959e&chksm=ea948ecadde307dcb7d589b06a0bed588220bc1bcb179f9c53db7692f79bdbf1e2514b8bea61&scene=21#wechat_redirect)  
  
  
[苹果修复已遭利用的第10个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515027&idx=1&sn=93ebe9404e1ead6aa5f784abf7fab31a&chksm=ea948af9dde303ef597a5e12dd8faab95e3127a6e8214fe9cdfba93dbcd4e59095001090e30f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/apple/apple-releases-emergency-update-to-fix-zero-day-exploited-in-attacks/  
  
  
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
  
