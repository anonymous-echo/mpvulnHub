#  谷歌紧急修复2023年第一个已遭利用的 Chrome 0day   
Sergiu Gatlan  代码卫士   2023-04-17 17:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**谷歌发布紧急Chrome 安全更新，修复今年第一个已遭利用的 0day 漏洞CVE-2023-2033。**  
  
  
  
谷歌在安全公告中指出，“谷歌发现 CVE-2023-2033 的 exploit 在野存在。”谷歌已发布适用于 Windows、Mac 和 Linux 系统的新版本，将在未来几天或几周时间内推向所有用户。用户应尽快升级至 112.0.5615.121版本，解决该问题。Chrome 浏览器也将自动查看新版本，无需用户交互，用户设备重启后即安装。  
  
  
**攻击详情未披露**  
  
  
该高危 0day 漏洞 (CVE-2023-2033) 是因为 Chrome V8 JavaScript 引擎中存在高危的类型混淆弱电造成的。该漏洞是由谷歌威胁分析团队 (TAG) 的研究员 Clement Lecigne 发现的。  
  
TAG 经常发现并报告受政府支持威胁行动者发动的高针对性攻击，这些攻击者的目的是在高风险个人如记者、反对党派和异见人士的设备上安装监控软件。  
  
尽管类型混淆漏洞通常可导致攻击者触发浏览器崩溃，但也可被用于在受陷设备上执行任意代码。虽然谷歌表示已了解用于攻击中的 CVE-2023-2033 0day exploit，但尚未共享更多详情。谷歌指出，“访问漏洞详情和链接在大多数用户更新安装修复方案前会得以限制。如果漏洞所在的第三方库是其它项目的依赖但这些项目并未修复，则我们将继续保持限制状态。”如此，谷歌 Chrome 用户可在技术细节发布前，升级浏览器并拦截攻击尝试。  
  
  
****  
****  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌在三星Exynos 芯片集中发现18个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515956&idx=1&sn=01fe340192b1659e658210ae4b02ac97&chksm=ea948e5edde30748775821e1c9ed1b389b2c0dd119e01cd78b9292d859542e3f209300000e4c&scene=21#wechat_redirect)  
  
  
[谷歌：国家黑客组织仍然在利用IE 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514941&idx=1&sn=390b6ed3a46683d9754beb89046fc737&chksm=ea948a57dde30341cf07a0fea29375488e12cc048bfd1a9c43f89d68692073c180d36e9b180e&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复今年已遭利用的第9个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514887&idx=1&sn=7a847e96a21c6cc06818980f855c1cc5&chksm=ea948a6ddde3037b673a148848634d0acbb2f968051fa0ab8a8cda49528d3d0ff7fe2522465e&scene=21#wechat_redirect)  
  
  
[谷歌Chrome紧急修复已遭利用的 V8类型混淆0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514366&idx=2&sn=20f6b5becbcb5bccca826614a71fbb52&chksm=ea948994dde30082201cbb54dca1eb125118589807350c3075bde26c8dc15963db2ff45ae2b0&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/google-chrome-emergency-update-fixes-first-zero-day-of-2023/  
  
  
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
  
