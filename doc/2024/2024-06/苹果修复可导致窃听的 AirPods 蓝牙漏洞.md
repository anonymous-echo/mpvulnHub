#  苹果修复可导致窃听的 AirPods 蓝牙漏洞   
THN  代码卫士   2024-06-27 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSb6T5fbYxqW618g18YcsvIA1UFAf6g7hYCRadgLyTXkwr1N5XSnWMcUA7Wgueiafhq8tsu498S8lw/640?wx_fmt=gif&from=appmsg "")  
  
**苹果为 AirPods 发布固件更新，修复了其中的认证漏洞 (CVE-2024-27867)。该漏洞可导致恶意人员以越权方式获得对耳机的访问权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSb6T5fbYxqW618g18YcsvIwIbmbD1icQ4MFGxEDTQzqcPDDd5vmwsEu6xQqs8VaeW6VVcSp0DuIhQ/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞影响 AirPods（第2代及后续版本）、AirPods Pro（所有机型）、AirPods Max、Powerbeats Pro 和 Beats FitPro。苹果公司在周二发布的安全公告中提到，“当你的耳机在寻找与此前配对设备的连接请求时，位于蓝牙范围内的攻击者可能能够欺骗预期源设备并获得对耳机的访问权限。”换句话说，位于物理范围的攻击者可利用该漏洞窃听私密会话。苹果表示已通过改进状态管理的方式修复该问题。  
  
该漏洞是由 Jonas Dreßler 发现并报送的，已作为 AirPods Firmware Update 6A326、AirPods Firmware Update 6F8和Beats Firmware Update 6F8的一部分得到修复。  
  
两周前，苹果推出 visionOS（版本1.2）的更新，修复了21个漏洞，其中7个位于 WebKit 浏览器引擎中。其中一个问题与逻辑缺陷 (CVE-2024-27812)有关，在处理 web 内容时可导致拒绝服务后果。该问题已通过改进文件处理的方式修复。该漏洞由安全研究员 Ryan Pickren 报送，他将该漏洞称为“世界上的首个空间计算入侵”，可被武器化于“绕过所有告警并强制以任意数量的动画3D对象填满空间”，而无需任何用户交互。  
  
该漏洞利用的是苹果未能在使用 ARKit Quick Look 特性时将许可模型应用到受害者空间中以攻击3D对象。更糟糕的是，由于这些动画对象由另外一款应用处理，因此即使退出 safari 之后，它们仍将持久。  
  
Pickren 表示，“此外，它甚至不需要人‘点击’这个 anchor 标签。因此编程式 JavaScript 点击（即 document.querySelector('a').click()）也能运作。这意味着我们在无需用户交互的情况下可启动任意数量的3D、动画的、创造声音的对象。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果紧急修复已遭利用的两个新 iOS 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519003&idx=1&sn=87b2f80deede9f2cb8e1092e9732820f&chksm=ea94ba71dde333675f4150799bb36ccc5360912e77c0af8aef77e7426b9b0c244aabb76833e4&scene=21#wechat_redirect)  
  
  
[苹果 Shortcuts 零点击漏洞可导致数据被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518905&idx=2&sn=89ec572b50147fe28714126b1d8bcb55&chksm=ea94bbd3dde332c507d0bd517efb3a88849ef91c65ed3b863479408bd332068071f546a9914c&scene=21#wechat_redirect)  
  
  
[苹果 Vision Pro 首发即被黑，内核漏洞触发崩溃](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518831&idx=1&sn=91fdd7a64e5019377ad958272beed267&chksm=ea94bb05dde3321343a784cc3b05ff1f50bca0fe764b046fc5e40d5ebb5195c774c40f83503d&scene=21#wechat_redirect)  
  
  
[苹果修复2024年遭利用的第1个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518729&idx=1&sn=022dec20b1d19ed71466fd78c5c9b7c1&chksm=ea94bb63dde33275e80731ce7aa70dbb77566e3599abe9f927ae24a32dc66aff5a1acd09f3d5&scene=21#wechat_redirect)  
  
  
[iPhone Triangulation 攻击滥用未记录的苹果硬件特性](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518533&idx=2&sn=39036eac661bc92b03daf7ee26b0ef41&chksm=ea94b82fdde33139e787792ebd270d191c64a469be7031d95b49732b3eea99b09d0de8a2a661&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/06/apple-patches-airpods-bluetooth.html  
  
  
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
  
