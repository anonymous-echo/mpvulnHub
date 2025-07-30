#  Chrome 131 更新修复高危内存安全漏洞，其中1个获奖5.5万美元   
Ionut Arghire  代码卫士   2024-12-20 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周三，谷歌发布Chrome 浏览器更新，修复了5个漏洞，其中4个是由外部研究员报送的高危内存安全漏洞。**  
  
  
  
由外部研究员报送的第一个漏洞是位于Chrome 浏览器V8 JavaScript 引擎中的类型混淆漏洞CVE-2024-12692，研究员因此获得5.5万美元的赏金。虽然谷歌并未发布该漏洞的详情，但赏金数额大的漏洞一般可导致远程代码执行 (RCE) 后果。类型混淆问题再缺少内存安全机制的编程语言中普遍存在，成功利用Chrome V8 引擎中的此类漏洞可导致威胁行动者泄露敏感信息或可能攻陷受害者系统。  
  
第二个漏洞也是位于V8引擎中的内存安全漏洞，编号为CVE-2024-12693。它是一个界外内存访问漏洞，研究员为此获得2万美元的赏金。  
  
谷歌还修复了位于 Compositing 中的高危释放后适用漏洞CVE-2023-12694以及位于V8引擎中的界外写漏洞CVE-2023-12695。谷歌尚未公布为这两个漏洞颁发的赏金。  
  
本次Chrome 版本更新已在131.0.6778.204/.205（Windows 和 macOS）和131.0.6778.204 (Linux) zhong 发布。谷歌并未提及这些漏洞是否已遭在野利用。  
  
几年来，谷歌一直致力于采取多种措施，使威胁行动者更难以利用 Chrome 中的内存安全缺陷，同时致力于消除代码库中的此类漏洞，如使用被认为是内存安全的编程语言 Rust。过去五年来，在安卓系统中使用Rust已促使安全内存漏洞大幅减少，谷歌将在Chrome 浏览器中也采用该语言，寄望于获得类似改进。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[【在野利用】Google Chrome V8 类型混淆漏洞(CVE-2024-5274)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519584&idx=2&sn=dab52360076996946ff35b2afa4a9f72&scene=21#wechat_redirect)  
  
  
[Google Chrome V8 类型混淆漏洞 (CVE-2023-3079) 安全风险通告](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516688&idx=1&sn=6978d8fa7462da7ef65701cf3c8b0bb0&scene=21#wechat_redirect)  
  
  
[谷歌Chrome紧急修复已遭利用的 V8类型混淆0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514366&idx=2&sn=20f6b5becbcb5bccca826614a71fbb52&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭在野利用的高危 V8 0day (CVE-2021-4102)](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509684&idx=1&sn=ed1ab96dd9c16cc0ecac28f77ddc289d&scene=21#wechat_redirect)  
  
  
[详细分析 Chrome V8 JIT 漏洞 CVE-2021-21220](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503429&idx=1&sn=9b79f640ab0bb75274a22c3d03bcdc18&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/chrome-131-update-patches-high-severity-memory-safety-bugs/  
  
  
题图：  
Pexels   
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
  
