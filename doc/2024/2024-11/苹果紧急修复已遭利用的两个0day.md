#  苹果紧急修复已遭利用的两个0day   
 代码卫士   2024-11-20 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
作者**：****Lawrence Abrams**  
  
**编译：代码卫士**  
  
**苹果紧急修复了两个0day 漏洞，它们被用于针对基于 Intel 的 Mac 系统攻击活动中。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQUGTh0CgZJIkREAI2aEYCXFG8QhwyD3czSVjAsh0LibUkf17hZVFJtGCRusxXm1PaqpxiaTdm0EQcQ/640?wx_fmt=gif&from=appmsg "")  
  
  
这两个0day漏洞位于 macOS Sequoia JavaScriptCore (CVE-2024-44308) 和 macOS 的 WebKit (CVE-2024-44309) 组件中。前一个漏洞可导致攻击者通过恶意构造的 web 内容实现远程代码执行后果，后一个漏洞跨站点脚本 (XSS) 攻击。  
  
苹果表示已在 macOS Sequoia 15.1.1 版本中修复这两个漏洞。由于一些组件也用于苹果的其它操作系统中，因此该漏洞也在 Ios 17.7.2和 iPadOS 17.7.2、iOS 18.1.1和 iPadOS 18.1.1 和visionOS 2.1.1中修复。这两个漏洞由谷歌威胁分析团队成员 Clément Lecigne 和 Benoît Sevens 发现，不过苹果和谷歌均未提供更多关于漏洞如何遭利用的详情。  
  
加上这两个漏洞，苹果自2024年开始已修复6个0day漏洞，这个情况相比2023年修复的20个0day而言要好得多。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果紧急修复已遭利用的两个新 iOS 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519003&idx=1&sn=87b2f80deede9f2cb8e1092e9732820f&chksm=ea94ba71dde333675f4150799bb36ccc5360912e77c0af8aef77e7426b9b0c244aabb76833e4&scene=21#wechat_redirect)  
  
  
[苹果修复2024年遭利用的第1个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518729&idx=1&sn=022dec20b1d19ed71466fd78c5c9b7c1&chksm=ea94bb63dde33275e80731ce7aa70dbb77566e3599abe9f927ae24a32dc66aff5a1acd09f3d5&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个 iOS 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518251&idx=1&sn=b501407684b48f59fb89d2d77570a27c&chksm=ea94b941dde3305715701eacd7c1a39f8de6430adaf0c7c820423a0694a1ffdbf0ff60504574&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的3个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517726&idx=1&sn=6812214f8fc21189da02ba2731b87720&chksm=ea94b774dde33e62737863151185ae158018de3e7f683d689e2a466982db356c57f6d7c1de92&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/apple-fixes-two-zero-days-used-in-attacks-on-intel-based-macs/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
