> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523414&idx=1&sn=af483917f833027e64a5dc3b05e6f56a

#  谷歌紧急修复已遭利用的 Chrome 0day漏洞  
Ddos  代码卫士   2025-07-01 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**谷歌紧急发布Chrome 稳定版更新，修复了一个已遭在野利用的高危0day漏洞CVE-2025-6554。该漏洞是位于 V8 JavaScript 引擎中的一个类型混淆漏洞，给 Windows、macOS 和 Linux 平台的用户造成严重风险。**  
  
谷歌提醒称，“谷歌发现 CVE-2025-6554已出现在野利用。” CVE-2025-6554是位于Chrome 渲染引擎核心的 JavaScript 引擎 V8 中的一个类型混淆漏洞，由谷歌威胁分析团队 (TAG) 的研究员 Clément Lecigne 在2025年6月25日发现，可导致远程攻击者诱骗浏览器错误解释内存类型，执行任意代码，这种方式常用于实现远程代码执行 (RCE) 后果。  
  
0day漏洞，尤其是影响 Chrome 等浏览器的 0day漏洞是国家行动者的、高阶持续威胁 (APTs) 和受经济利益驱动的网络犯罪分子的主要目标。V8 中的类型混淆漏洞此前用于路过式下载攻击、沙箱逃逸和经由看似无害的网站传播恶意 payload。  
  
该漏洞的补丁已在138.0.7204.96/.97（Windows）、138.0.7204.92/.93 (Mac) 和 138.0.7204.96 (Linux) 中发布，并将在未来几天和几周内推出。鉴于该漏洞的敏感性质及其潜在影响，完整详情将在大多数用户受到保护后发布。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌悄悄紧急修复已遭利用的 Chrome 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523177&idx=1&sn=6ead40fb0a70735a161f4ecd984a3f01&scene=21#wechat_redirect)  
  
  
[Chrome修复已遭活跃利用的0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523031&idx=1&sn=40bc8fad7dc229f984420d3f6109a0b9&scene=21#wechat_redirect)  
  
  
[Firefox 存在严重漏洞，类似于 Chrome 已遭利用0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522612&idx=2&sn=50c7ad88e87b485a09c7ae916f9d9677&scene=21#wechat_redirect)  
  
  
[谷歌修复今年第五个 Chrome 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519462&idx=1&sn=1f7824cfd17d3489bc4ba1b37c5d974c&scene=21#wechat_redirect)  
  
  
[谷歌修复 Pwn2Own 2024大赛发现的两个 Chrome 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519170&idx=1&sn=31612ff9461ff59184a818b76f04c198&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://securityonline.info/google-patches-actively-exploited-chrome-zero-day-cve-2025-6554/  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
