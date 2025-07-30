#  新Windows?! 苹果再修复已遭利用的新0day   
Sergiu Gatlan  代码卫士   2023-07-26 08:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**苹果公司发布安全更新，修复了已被用于攻击 iPhone、Mac 和 iPad 的 0day 漏洞。这是今年以来苹果修复的第11个0day。**  
  
  
  
本月初，苹果公司在关于新一轮快速安全响应 (RSR) 更新中所修复CVE-2023-37450的安全公告中指出，“苹果公司注意到报告称该漏洞可能已遭活跃利用。”  
  
今天修复的另外一个 0day 是一个新的 Kernel 漏洞CVE-2023-38606，已被用于攻击运行老旧 iOS 版本的设备。苹果公司提到，“苹果注意到一份报告称该漏洞可能已被用于攻击 iOS 15.7.1之前的 iOS 版本。”  
  
攻击者可利用该漏洞在未修复设备上修改敏感的内核状态。苹果公司通过提升检查和状态管理修复了这两个漏洞。  
  
卡巴斯基 GReAT 首席安全研究员 Boris Larin 提到，CVE-2023-38606是攻击者通过 iMessage 利用在iPhone 尚部署 Triangulation 监控软件所使用的零点击利用链的一部分。  
  
苹果公司还向将5月份所修复0day (CVE-2023-32409) 的补丁向后兼容到运行 tvOS 16.6和watchOS 9.6的设备上。  
  
今天修复的这两个漏洞影响范围广，包括大量 iPhone 和 iPad 机型以及运行 macOS Big Sur、Monterey 和 Ventura 的 Mac 设备。  
  
  
**今年以来修复的第11个 0day**  
  
  
  
自今年年初开始，苹果已修复了被用于攻击运行 iOS、macOS 和 iPadOS 设备的11个0day漏洞。  
  
本月早些时候，苹果发布带外 RSR 更新，修复影响已打补丁的 iPhone、Mac 和 iPad 设备的漏洞CVE-2023-37450。  
  
之后不久，苹果公司证实RSR更新破坏了某些网站上的 web 浏览并在两天后发布对有问题补丁的修复版本。  
  
在此之前，苹果公司还修复了如下漏洞：  
  
- 6月修复3个0day（CVE-2023-32434、CVE-2023-32435和CVE-2023-32439）  
  
- 5月修复3个0day（CVE-2023-32409, CVE-2023-28204, and CVE-2023-32373）  
  
- 4月修复2个0day（CVE-2023-28206 和 CVE-2023-28205）  
  
- 2月修复1个WebKit 0day (CVE-2023-23529)  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[苹果员工在CTF大赛发现谷歌0day秘而不报 $10000赏金由他人获得](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517155&idx=1&sn=9af2d4f8742d395b46b7d44e219d9b05&chksm=ea94b289dde33b9f559073d1207e8437f82e8b6acf046825ee7f690fcbe59f72977119ba7dae&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516996&idx=1&sn=99077b8f872c126bf4abbae8c76123fc&chksm=ea94b22edde33b3872fa9d5e8336be03c61f1dbca04bd5821d460d5e0fcd1915fb4c2e9163a3&scene=21#wechat_redirect)  
  
  
[苹果修复3个已遭利用的新 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516531&idx=1&sn=71b3e940c482c53d52c592cdfe3992db&chksm=ea94b019dde3390fb1ecf3bd947eb8852a1f27e29e28f9c88b97d9bb2087840f62be6d882d4b&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个已遭利用的 0day，影响 iPhone 和 Mac设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516192&idx=2&sn=5c3e3733fceb0ec8d172ac2df805b47d&chksm=ea94b14adde3385c3f37236533daf5e7d38ba6c37d81d396c80446e2d37a13b2fd254a3b2904&scene=21#wechat_redirect)  
  
  
[苹果修复老旧设备中的已遭利用 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=2&sn=3b952d583d720b24a32bea4b8840959e&chksm=ea948ecadde307dcb7d589b06a0bed588220bc1bcb179f9c53db7692f79bdbf1e2514b8bea61&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/apple/apple-fixes-new-zero-day-used-in-attacks-against-iphones-macs/  
  
  
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
  
