#  Fortinet 修复数据分析解决方案中的严重漏洞   
Ionut Arghire  代码卫士   2023-04-13 17:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周，网络安全解决方案提供商 Fortinet 宣布发布多款产品的安全更新，包括针对 FortiPresence 中的一个严重漏洞。**  
  
FortiPresence 是一款数据分析解决方案，提供分析、热力图和报告服务，可作为托管的云服务或虚拟机使用。本周，Fortinet 表示，位于 FortiPresence 基础设施服务器中的一个严重的认证缺失漏洞可用于访问 Redis 和 MongoDB 实例。  
  
该漏洞的编号是CVE-2022-41331（CVSS评分9.3），可遭远程未认证攻击者通过构造的认证请求利用。该漏洞影响 FortiPresence 版本1.0、1.1和1.2，已在 FortiPresence 版本2.0.0 中修复。  
  
Fortinet 公司在四月漏洞安全公告中还修复了位于其它产品中的多个中危漏洞，包括FortiOS、FortiProxy、FortiSandbox、FortiDeceptor、FortiWeb、FortiClient for Windows and macOS、FortiSOAR、FortiADC、FortiDDoS、FortiDDoS-F、FortiAnalyzer以及FortiManager。这些漏洞可导致XSS攻击、越权API调用、命令执行、任意代码执行、任意文件创建、提权、信息泄露、任意文件检索以及中间人攻击等。  
  
另外，Fortinet 公司还发布安全公告，详述了用于 FortiAuthenticator、FortiProxy 和 FortiSIEM 中Linux 内核中的一个漏洞，可导致低权限攻击者写入页面缓存并在系统上提权。该漏洞编号是CVE-2022-0847，也被称为“脏管道”漏洞，在 Linux 内核版本5.8 中引入，已在 Linux 5.16.11、5.15.25 和5.10.102 中修复。  
  
另外，该公司还修复了影响 FortiNAC、FortiOS、FortiProxy、FortiADC、FortiGate 和 FortiAuthenticator 中的多个中危和低危漏洞。  
  
建议客户尽快更新设备。尽管该公司并未提到这些漏洞遭利用的情况，但未修复的 Fortinet 产品一直是恶意攻击的目标。更多信息可参照 Fortinet 公司发布的 PSIRT 安全公告页面。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Fortinet FortiOS漏洞被用于攻击政府实体](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515912&idx=1&sn=0d48724c08d4d63949a7142683b6fdd7&chksm=ea948e62dde30774b504e3a089bab575daf337854bba663d40f81014b5672260b74230a007a3&scene=21#wechat_redirect)  
  
  
[Fortinet：注意这个严重的未认证RCE漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515862&idx=1&sn=d2ef6b5ab51eba3e97af531d1a8b212b&chksm=ea948fbcdde306aa2d71b31b492175fc0c01a69233601e35fc9fee73fbfbae62668f3aaaffb2&scene=21#wechat_redirect)  
  
  
[Fortinet修复两个严重的RCE漏洞，其中一个两年前就发现？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=1&sn=b8f00a46755a56f7d9aed5ae56c1b4e4&chksm=ea948c95dde305837c4ef5d418e236f9718061ffd9b877fde4fc8a267a7bf0b9910d885f6ea4&scene=21#wechat_redirect)  
  
  
[Fortinet 紧急修复已遭利用的VPN漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514989&idx=1&sn=d69be3f378da5be4993977d510a35a5b&chksm=ea948a07dde303111a95aab98531af127bcaa9ad279aa46a8fbf4f7e56f0053a9bc6ba7c4ac8&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/fortinet-patches-critical-vulnerability-in-data-analytics-solution/  
  
  
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
  
