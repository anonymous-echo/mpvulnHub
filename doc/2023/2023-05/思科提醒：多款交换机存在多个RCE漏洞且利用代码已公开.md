#  思科提醒：多款交换机存在多个RCE漏洞且利用代码已公开   
Sergiu Gatlan  代码卫士   2023-05-18 16:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**今天，思科提醒客户称，多款 Small Business 系列交换机中存在四个严重的远程代码执行漏洞，且利用代码已遭公开。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRHfm8vWJdpibTYFqHIYGKV2XXdT7qxzzGWGws0kGhlFQrZmfunCeJsdxZ73e2z1eCOop9pIypbhPA/640?wx_fmt=png "")  
  
  
这四个漏洞的 CVSS 评分为9.8分，如遭成功利用可导致未认证的攻击者以根权限在受攻陷设备上执行任意代码。这些漏洞的CVE漏洞编号是CVE-2023-20159、CVE-2023-20160、CVE-2023-20161和CVE-2023-20189，均由对目标交换机 web 接口发送的请求验证不当引发。  
  
攻击者可在复杂度低下的攻击中，利用目标设备 web 用户接口发送特殊构造的请求，利用这些漏洞。思科解释称，“这些漏洞之间不存在相互依赖关系。利用其中一个漏洞时无需利用其它漏洞。另外，受其中一个漏洞影响的软件发布可能不会受其它漏洞的影响。”  
  
受影响的思科交换机包括：  
  
- 250 Series Smart Switches、350 Series Managed Switches、350X Series Stackable Managed Switches和550X Series Stackable Managed Switches （已在固件版本2.5.9.16中修复）  
  
- Business 250 Series Smart Switches 和 Business 350 Series Managed Switches（已在固件版本3.3.0.16中修复）  
  
- Small Business 200 Series Smart Switches、Small Business 300 Series Managed Switches、Small Business 500 Series Stackable Managed Switches（无补丁）  
  
  
  
思科表示，200、300以及500系列的 Small Business 交换机固件将不会得到补丁，因为这些设备已经进入生命周期末期。  
  
思科产品安全事件响应团队 (PSIRT) 还披露称，这些漏洞的 PoC 代码已存在，可导致攻击者活跃利用。本周三，思科提醒称，PSIRT发现这些漏洞的“PoC 利用代码已存在”，可导致攻击者攻击暴露到远程访问的易受攻击设备。不过，幸运的是，思科尚未发现漏洞遭利用的迹象。  
  
思科还在着手修复位于 Prime Collaboration Deployment (PCD) 服务器管理工具中的一个 XSS 漏洞。该漏洞由北约网络安全中心研究员 Pierre Vivegnis 发现。  
  
美国、英国和思科公司最近联合发布安全公告提醒称，俄罗斯军队黑客组织 APT28 已在思科 IOS 路由器上部署自定义 “Jaguar Tooth（美洲虎牙齿）”，获得对受陷设备的未认证访问权限。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[思科电话适配器易受 RCE 攻击，目前无修复方案](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=2&sn=30f06254fcca6feb3228b78389c85056&chksm=ea94b182dde338944d1c48c872c538f5333e8de4ceb4594aede8579d82c069df184557fca031&scene=21#wechat_redirect)  
  
  
[思科服务器管理工具中存在 XSS 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516356&idx=1&sn=3a870e38244c8f43090fe23f54c81fa7&chksm=ea94b1aedde338b8242499091a2cb37dec7924bffa0bde2f1dc62c5d42e10242fb0125850d86&scene=21#wechat_redirect)  
  
  
[思科企业路由器受高危DoS漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515885&idx=1&sn=8bd8588f210b0b78430ead9ac6d5eeb1&chksm=ea948f87dde30691621e2aadd60a0a45bf17ed8880497e1c1b6489d2b57c7f52806f896318c4&scene=21#wechat_redirect)  
  
  
[思科多款IP电话存在严重的Web UI RCE漏洞，有一个将不修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515804&idx=1&sn=3584a336f62d0ca3a0fde7fe3f9bd5dd&chksm=ea948ff6dde306e0cd113b8566d71e3afaca9efd2a9a141cc0a9126b8e84380d067a6405ab9f&scene=21#wechat_redirect)  
  
  
[思科开源杀软ClamAV中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=2&sn=704411c89c34c85e52e2ad18ff0fb77c&chksm=ea948c95dde305838410d09bd123fd529f7be43231802fc228e4300929816f4adb5d4f72007e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/cisco-warns-of-critical-switch-bugs-with-public-exploit-code/  
  
  
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
  
