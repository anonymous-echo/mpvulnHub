#  苹果紧急修复已遭利用的3个0day漏洞   
Sergiu Gatlan  代码卫士   2023-09-22 17:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**苹果紧急修复了已用于攻击 iPhone 和 Mac 用户的三个新0day，将今年已修复的 0day 漏洞拉升至16个。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTuPwxnxpmkCJBDvQdgXGE5mTiczNFTAEC0GdNqSP1r4iaicRN8eee05yUhf6YOzBLulH1ia9Qg2LRuvg/640?wx_fmt=png "")  
  
  
在这3个新 0day 漏洞中，其中2个位于 WebKit 浏览器引擎 (CVE-2023-41993) 和 Security 框架 (CVE-2023-41991)中，可导致攻击者通过恶意应用绕过签名验证或者通过恶意构造的网页获得任意代码执行权限。  
  
第三个漏洞位于 Kernel 框架中。该框架为内核扩展和内核设备驻留驱动提供 API 和支持。本地攻击者可利用该漏洞 (CVE-2023-41992) 提升权限。  
  
苹果通过修复一个证书验证问题和通过改进检查，修复了位于 macOS 12.7/13.6、iOS 16.7/17.0.1、iPad 16.7/17.0.1和watchOS 9.6.3/10.0.1中的这三个0day 漏洞。受影响设备横跨老旧和新近发布的设备型号，包括：  
  
- iPhone 8 及后续版本  
  
- iPad mini 第5代及后续版本  
  
- 运行 macOS Monterey 和更新版本的 Mac 设备  
  
- Apple Watch Series 4及后续版本  
  
  
  
所有这三个0day 均由多伦多大学公民实验室研究员 Bill Marczak 和谷歌威胁分析团队的研究员 Maddie Stone 发现并报送。  
  
虽然苹果尚未发布关于这些漏洞在野利用的更多详情，但公民实验室和谷歌研究人员经常披露遭面向高风险个体的针对性监控软件利用的0day。公民实验室之前披露了两个0day（CVE-2023-41061和CVE-2023-41064）且已由苹果公司在本月初修复，它们被用于一个零点击利用链中，目的是通过 NSO Group 的 Pegasus 商用监控软件感染完全修复的 iPhone。  
  
从年初开始，苹果公司已修复如下0day：  
  
- 7月修复两个0day（CVE-2023-37450 和 CVE-2023-38606）  
  
- 6月修复3个0day（CVE-2023-32434、CVE-2023-32435和CVE-2023-32439）  
  
- 5月修复3个0day（CVE-2023-32409、CVE-2023-28204和CVE-2023-32373）  
  
- 4月修复2个0day（CVE-2023-28206和CVE-2023-28205）  
  
- 2月修复1个WebKit 0day (CVE-2023-23529)  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果紧急修复两个已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517599&idx=1&sn=f4c64820b9383523f48091354491d150&chksm=ea94b4f5dde33de3f2f7c7d26b6bc5178d7deb13b62b5e3b5220b9ad188751bce855b427f00b&scene=21#wechat_redirect)  
  
  
[新Windows?! 苹果再修复已遭利用的新0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=2&sn=cfa4e9c7c012a88ff6a1ca8ada75564c&chksm=ea94b543dde33c556be2fcb984ebb556ca8d5f6654c7938d9996636b045518ace000eb82f2b6&scene=21#wechat_redirect)  
  
  
[苹果员工在CTF大赛发现谷歌0day秘而不报 $10000赏金由他人获得](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517155&idx=1&sn=9af2d4f8742d395b46b7d44e219d9b05&chksm=ea94b289dde33b9f559073d1207e8437f82e8b6acf046825ee7f690fcbe59f72977119ba7dae&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516996&idx=1&sn=99077b8f872c126bf4abbae8c76123fc&chksm=ea94b22edde33b3872fa9d5e8336be03c61f1dbca04bd5821d460d5e0fcd1915fb4c2e9163a3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/apple/apple-emergency-updates-fix-3-new-zero-days-exploited-in-attacks/  
  
  
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
  
