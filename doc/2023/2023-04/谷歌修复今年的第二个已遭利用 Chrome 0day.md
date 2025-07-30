#  谷歌修复今年的第二个已遭利用 Chrome 0day   
Bill Toulas  代码卫士   2023-04-20 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRmrEP8anhIPvpAeojUfsic68gkoibqBJt2pUfn0ficNwiaTiafcdIicNRu9afONoYttthcKsSOib58SKsVg/640?wx_fmt=png "")  
  
  
**谷歌发布 Chrome 安全更新，修复了今年以来已遭利用的第二个 0day 漏洞CVE-2023-2136。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRmrEP8anhIPvpAeojUfsic6kO6KurWiabtCO4kgCKmbDmkPHVnUDa2GnFktno2zo3mgpAT8iaDwc0TA/640?wx_fmt=png "")  
  
  
谷歌在安全公告中指出，“谷歌已发现在野的CVE-2023-2136 exploit。”本次发布的Chrome 版本是112.0.5615.137，共修复了8个漏洞。稳定版仅供 Windows 和 Mac 用户使用，Linux版本将于不久后发布。  
  
用户可通过Chrome设置目录，选择“帮助-关于 Google Chrome”来手动修复；或者谷歌在用户下次启动浏览器时将自动安装更新，无需用户交互，之后用户重启浏览器即可完成更新流程。  
  
  
**无利用详情**  
  
  
  
CVE-2023-2136是位于用C++编写的开源多平台2D图形库 Skia 中的一个高危整数溢出漏洞。Skia 为 Chrome 提供了一系列 API，可用于渲染图形、文本、形状、图像和动画，它被视作Chrome 渲染管道的一个关键组件。  
  
当操作导致值超过既定整数类型的最大值时，就会触发整数溢出漏洞，通常或导致异常的软件行为或造成其它安全后果。在Skia 的案例中，该漏洞可能导致不正确的渲染、内存损坏和可导致越权系统访问的任意代码执行后果。该漏洞是由谷歌威胁分析团队 (TAG) 的研究员Clément Lecigne在本月初发现并报告的。  
  
和往常一样，谷歌并未披露关于 CVE-2023-2136遭活跃利用的很多详情，引发很多人对于利用方法和相关风险的推测。  
  
上周五，谷歌紧急修复了另外一个 0day 漏洞CVE-2023-2033，它是2023年以来Chrome 中存在的第一个已遭活跃利用的漏洞。  
  
这类漏洞一般会遭高阶威胁行动者利用，很多时候这些组织受国家支持，他们一般会攻击位于政府、媒体或其它重要组织机构中的高级别个人。因此，建议所有 Chrome 用户尽快应用这些安全更新。  
  
  
  
****  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复2023年第一个已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516252&idx=1&sn=8371d9c05433cba2f5df47f101e8ad05&chksm=ea94b136dde33820c0033b8827312e06fe8bf7770075580020919000bdd6049133fc97d2a49e&scene=21#wechat_redirect)  
  
  
[谷歌在三星Exynos 芯片集中发现18个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515956&idx=1&sn=01fe340192b1659e658210ae4b02ac97&chksm=ea948e5edde30748775821e1c9ed1b389b2c0dd119e01cd78b9292d859542e3f209300000e4c&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复今年已遭利用的第9个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514887&idx=1&sn=7a847e96a21c6cc06818980f855c1cc5&chksm=ea948a6ddde3037b673a148848634d0acbb2f968051fa0ab8a8cda49528d3d0ff7fe2522465e&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭利用的Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514771&idx=2&sn=82231141505568820fbd6a3f66546680&chksm=ea948bf9dde302ef5d8114281a47daf92a67743ea8eba6632472a813a8d656b261c788586d1e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/google-patches-another-actively-exploited-chrome-zero-day/  
  
  
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
  
