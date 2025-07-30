#  苹果紧急修复两个已遭利用的 0day，影响 iPhone 和 Mac设备   
Sergiu Gatlan  代码卫士   2023-04-10 17:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**苹果发布紧急安全更新，修复了被用于攻陷 iPhone、Mac 和 iPad 的两个0day 漏洞。**  
  
苹果公司在上周五发布的安全公告中指出，“苹果收到关于该漏洞可能已遭活跃利用的一份报告。”  
  
第一个漏洞是CVE-2023-28206，是 IOSurfaceAccelerator 界外写漏洞，可导致数据损坏、崩溃或代码执行后果。成功利用该漏洞可导致攻击者使用恶意构造的 app 在目标设备上以内核权限执行任意代码。  
  
第二个漏洞是CVE-2023-28205，是一个 WebKit 释放后使用漏洞，可导致在复用已释放内存时数据损坏或任意代码执行后果。攻击者可诱骗目标加载受攻击者控制的恶意网页，利用该漏洞在受陷系统上执行代码。  
  
这两个漏洞已通过改进输入验证和内存管理的方式，在 iOS 16.4.1、iPadOS 16.4.1、macOS Ventura 13.3.1和Safari 16.4.1 中修复。  
  
苹果指出，这两个漏洞影响的设备范围非常广泛，包括：  
  
- iPhone 8 以后续版本  
  
- iPad Pro（所有型号）  
  
- iPad Air 第3代及后续版本  
  
- iPad 第5代及后续版本  
  
- iPad mini 第5代及后续版本  
  
- 运行 macOS Ventura 的Mac  
  
  
  
  
**今年以来修复的第三个 0day**  
  
  
尽管苹果公司表示发现在野利用报告，但尚未发布相关攻击信息。  
  
苹果安全公告指出，这两个漏洞是由谷歌威胁分析团队 (TAG) 的研究员 Clément Lecigne 和 Amnesty International 公司安全实验室研究员 Donncha Ó Cearbhaill 发现的，两人发现这两个漏洞已遭活跃利用。  
  
这两名研究员所在公司都在定期披露遭受政府支持的黑客组织利用的0day 漏洞情况。这些组织在全球政客、记者、异见人士和其他高风险个人所使用的智能手机和计算机上部署商业监控软件。  
  
上周，谷歌 TAG 和 Amnesty International 公司暴露了两起攻击活动，它们利用由安卓、iOS 和Chrome 0day以及 nday 漏洞部署监控软件。虽然今天修复的这两个 0day 很可能仅用于高针对性攻击活动中，但强烈建议用户尽快安装这些紧急更新，以防遭攻击。  
  
2月份，谷歌修复了另外一个已遭利用的WebKit 0day (CVE-2023-23539)。该漏洞可导致操作系统崩溃并在易受攻击的 iPhone、iPad 和 Mac 设备上获得代码执行的权限。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[苹果修复老旧设备中的已遭利用 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=2&sn=3b952d583d720b24a32bea4b8840959e&chksm=ea948ecadde307dcb7d589b06a0bed588220bc1bcb179f9c53db7692f79bdbf1e2514b8bea61&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的 WebKit 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515546&idx=1&sn=f9311f04f319e12385edbfcd698fa495&chksm=ea948cf0dde305e697564ae3c0b973831eece5c572326a20990546b6bacf3bef67450345d514&scene=21#wechat_redirect)  
  
  
[苹果修复已遭利用的第10个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515027&idx=1&sn=93ebe9404e1ead6aa5f784abf7fab31a&chksm=ea948af9dde303ef597a5e12dd8faab95e3127a6e8214fe9cdfba93dbcd4e59095001090e30f&scene=21#wechat_redirect)  
  
  
[苹果修复已遭利用的第9枚0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514319&idx=1&sn=10f6c5afa8be65b7ccac62c9ab73645c&chksm=ea9489a5dde300b312a93ec52a321f835baed001465326883dd6cdbbe70fecd5b94b1b8000c7&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/apple/apple-fixes-two-zero-days-exploited-to-hack-iphones-and-macs/  
  
  
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
  
