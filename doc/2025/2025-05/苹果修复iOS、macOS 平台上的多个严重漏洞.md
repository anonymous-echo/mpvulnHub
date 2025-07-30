#  苹果修复iOS、macOS 平台上的多个严重漏洞   
Ryan Naraine  代码卫士   2025-05-13 10:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周一，苹果修复了 macOS、iPhone 和 iPad 软件栈中的多个漏洞，提醒称只需打开一个特殊构造的图片、视频或网站，就能触发这些代码执行漏洞。**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMT2jXU8n39gJvH7gK28Yz6BGfNrbOmzuPsOoDv5S9Qb4sk7yRwvWIckMFdibtpUChCxYicJfyULvibGg/640?wx_fmt=png&from=appmsg "")  
  
  
**iOS 18.5更新与 iPadOS 补丁一起推出，涵盖 AppleJPEG 和 CoreMedia 中的多个严重漏洞。苹果公司提到攻击者可构造恶意媒体文件，以目标 app 的权限运行任意代码。**  
  
**苹果公司还提到了在 CoreAudio、CoreGraphics 和 ImageIO 中修复的多个严重的文件解析漏洞。如打开受陷内容，则攻击者可利用这些漏洞导致 app 崩溃或数据泄露。**  
  
**iOS 18.5更新还修复了至少9个 WebKit 漏洞，其中一些严重漏洞可导致恶意网站执行代码或使 Safari 浏览器引擎崩溃。苹果公司还修复了 FaceTime 中的一个严重的“静音按钮”漏洞，即使在麦克风被静音后仍可暴露音频会话。苹果公司还提到，iOS 18.5 修复了内核中的两个内核损坏漏洞和libexpat 库中的影响大量软件项目的漏洞 (CVE-2024-8176)。**  
  
**其它值得关注的漏洞包括 Baseband 中的CVE-2025-31214，它可导致位于权限网络中的攻击者拦截iPhone 16e系列上的流量；mDNSResponder 中的提权漏洞CVE-2025-31222；位于Notes 中漏洞可导致iPhone锁屏下数据遭泄露；以及FrontBoard、iCloud Document Sharing 和 Mail Addressing 中的多个漏洞。**  
  
**苹果并未提及这些漏洞是否已遭在野利用。**  
  
**iOS 18.5 更新适用于 iPhone XS及后续版本；iPadOS 发布涵盖了 iPad Pro（2018及后续版本）、iPad Air 3、iPad 7、iPad mini5 及后续机型。苹果还为 macOS Sequoia、macOS Sonoma、macOS Ventura、WatchOS、tvOS 和 visionOS 发布重大更新。**  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果 “AirBorne” 漏洞可导致零点击 AirPlay RCE 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522916&idx=2&sn=1292db15893e34108514b0dc4437e9f7&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的两个0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522769&idx=1&sn=665091a9de4302af67ecf646d9c5bb79&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522462&idx=1&sn=c051df72b6c28d0692307dd16d721ac3&scene=21#wechat_redirect)  
  
  
[苹果紧急修复被用于“极其复杂”攻击中的0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522200&idx=2&sn=a8084137286ce6cbebda935ab8c0d5c2&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的两个0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521533&idx=1&sn=1ab7c5da3e583e48ee67d6f50fd4d97e&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/apple-patches-major-security-flaws-in-ios-macos-platforms/  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
