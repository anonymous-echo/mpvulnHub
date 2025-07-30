#  苹果修复3个已遭利用的新 0day   
Sergiu Gatlan  代码卫士   2023-05-19 15:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
****  
****  
**苹果修复了用于攻击 iPhone、Mac 和 iPad 的三个新0day。**  
  
  
苹果公司在安全公告中指出，“苹果已注意到该漏洞可能遭活跃利用的报告。”这三个漏洞均位于多平台的 WebKit 浏览器引擎中，编号为CVE-2023-32409、CVE-2023-28204和CVE-2023-32373。  
  
CVE-2023-32409是一个沙箱逃逸漏洞，可导致远程攻击者攻破 Web Content 沙箱。其它两个漏洞是界外读漏洞，一个有助于攻击者获得访问敏感信息的权限，一个是可导致在受陷设备上实现任意代码执行的释放后使用漏洞，这两个漏洞均要求目标加载恶意构造的网页（web 内容）。  
  
苹果已在 macOS Ventura 13.4、iOS 和 iPadOS 16.5、tvOS 16.5、watchOS 9.5和 Safari 16.5 改进边界检查、输入验证和内存管理，修复了这三个漏洞。  
  
由于影响新老机型，因此受影响设备数量庞大，包括：  
  
- iPhone 6s（所有机型）、iPhone 7（所有机型）、iPhone SE（第一代）、iPad Air 2、iPad mini（第4代）、iPod touch（第7代）以及iPhone 8 及后续版本。  
  
- iPad Pro（所有机型）、iPad Air 第3代及后续版本、iPad 第5代及后续版本以及 iPad mini 第5代及后续版本。  
  
- 运行 macOS Big Sur、Monterey 和 Ventura 的 Mac 设备  
  
- Apple Watch 系列4及后续版本  
  
- Apple TV 4K（所有机型）及 Apple TV HD  
  
  
  
苹果公司还表示，CVE-2023-28204和CVE-2023-32373（由匿名研究员报送）在5月1日通过为 iOS 16.41和 macOS 13.3.1 设备发布快速安全响应 (RSR) 补丁的方式修复。  
  
苹果公司发言人并未回复5月份的RSR 更新所修复漏洞的更多详情。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTViclYLURlxUSBVDaJZ8vLOKVPJUn5AAYnyFGH95XgyibliakM8xicQicVr3PEMn6DyNRE2B6nUYib6TmQ/640?wx_fmt=png "")  
  
  
**2023年以来修复6个0day**  
  
  
  
虽然苹果公司表示已意识到这三个 0day 已遭利用，但并未分享任何相关信息。不过今天发布的安全公告显示，CVE-2023-32409由谷歌威胁分析团队研究员 Clément Lecigne 和 Amnesty International 公司安全实验室的研究员 Donncha Ó Cearbhaill 发现并报告。这两家公司定期披露关于国家黑客组织在政客、记者、异见人士等人群的智能手机和计算机上部署恶意软件。  
  
4月份，苹果修复了两个0day漏洞CVE-2023-28206和CVE-2023-28205。这两个漏洞是由安卓、iOS 和 Chrome 0day 和 nday 漏洞组成的在野利用链的一部分，被用于在高危目标设备上安装商业间谍软件。2月份，苹果公司修复了 WebKit 0day 漏洞CVE-2023-23529，该漏洞被用于在易受攻击的 iPhone、iPad 和 Mac 设备上执行代码。  
  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个已遭利用的 0day，影响 iPhone 和 Mac设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516192&idx=2&sn=5c3e3733fceb0ec8d172ac2df805b47d&chksm=ea94b14adde3385c3f37236533daf5e7d38ba6c37d81d396c80446e2d37a13b2fd254a3b2904&scene=21#wechat_redirect)  
  
  
[苹果修复老旧设备中的已遭利用 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=2&sn=3b952d583d720b24a32bea4b8840959e&chksm=ea948ecadde307dcb7d589b06a0bed588220bc1bcb179f9c53db7692f79bdbf1e2514b8bea61&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515546&idx=1&sn=f9311f04f319e12385edbfcd698fa495&chksm=ea948cf0dde305e697564ae3c0b973831eece5c572326a20990546b6bacf3bef67450345d514&scene=21#wechat_redirect)  
  
  
[苹果修复已遭利用的第10个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515027&idx=1&sn=93ebe9404e1ead6aa5f784abf7fab31a&chksm=ea948af9dde303ef597a5e12dd8faab95e3127a6e8214fe9cdfba93dbcd4e59095001090e30f&scene=21#wechat_redirect)  
  
  
[苹果修复已遭利用的第9枚0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514319&idx=1&sn=10f6c5afa8be65b7ccac62c9ab73645c&chksm=ea9489a5dde300b312a93ec52a321f835baed001465326883dd6cdbbe70fecd5b94b1b8000c7&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/apple/apple-fixes-three-new-zero-days-exploited-to-hack-iphones-macs/  
  
  
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
  
