#  CISA提醒修复严重的Chrome 和 D-Link漏洞   
Bill Toulas  代码卫士   2024-05-20 17:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**美国网络安全和基础设施局 (CISA) 将三个漏洞添加至必修清单，其中一个影响谷歌 Chrome 浏览器，另外两个影响某些D-Link 路由器。**  
  
  
  
CISA 提醒联邦机构和企业这些漏洞正遭利用，应部署安全更新或缓解措施。联邦机构应在6月6日前替换受影响设备或执行防御措施，降低或消减攻击风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTBvibQLiaOydVnsqNvLatP1HGnD0fun5bERPMxFKqyA7Q2MRfR5jzsk4WIUywAAViahq99oUPVkklag/640?wx_fmt=gif&from=appmsg "")  
  
**遭活跃利用的缺陷**  
  
  
  
  
  
Chrome 中的漏洞是CVE-2024-4761，虽然谷歌已在5月13日证实称遭活跃利用，但目前尚不存在公开可用的技术详情。它是位于 Chrome V8 JavaScript 引擎中的一个界外写漏洞，它在 Chrome 浏览器中执行JS代码且其评级为高危漏洞。  
  
就在谷歌披露CVE-2024-4761两天后，又称V8中的另外一个漏洞CVE-2024-4947也遭在野利用，不过CISA尚未将其增加至必修清单。CISA还提醒称，一个已存在10年的影响D-Link DIR-600 路由器的漏洞正在遭利用。该漏洞是CVE-2014-100005，是跨站请求伪造 (CSRF) 漏洞。它可导致攻击者将管理员认证请求劫持到设备的 web 管理面板，创建自己的管理员账户，修改配置并控制改设备。  
  
尽管在该漏洞被披露的四年前，D-Link DIR-600 路由器已达生命周期，但D-Link 还是在固件版本 2.17b02 中发布了修复方案，并发布了包含缓解建议的安全通告。  
  
另外一个影响D-Link 产品的漏洞也被加入必修清单，编号是CVE-2021-40655，影响自2015年起就不再受支持的D-Link DIR-605路由器。该漏洞的利用已遭公开。攻击者可通过发送至 /getcfg.php 页面的特殊构造的请求，在无需认证的前提下提取管理员的用户名和密码。  
  
CISA 并未提供关于这两个D-Link 漏洞的任何背景信息，目前尚不清楚利用者的身份或该机构合适观察到攻击。一般来说老旧漏洞会被僵尸网络恶意软件纳入可利用漏洞清单中，不管设备类型或漏洞的年限。建议 D-Link 600 和605用户将设备替代为更新的机型，获得厂商在性能和安全更新方面的支持。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA提出的安全设计承诺无实际约束力吗？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519473&idx=1&sn=76719fb046d517becc70a14d000736b0&chksm=ea94bd9bdde3348d282aac5f585cddc037e1177a9c37e2da65884e0b494c5e32fed91221d3be&scene=21#wechat_redirect)  
  
  
[CISA的KEV清单加快漏洞修复速度了吗？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519427&idx=2&sn=952e60354283e3d7df02f25ba52d112d&chksm=ea94bda9dde334bfdb20afde43208f87f3735f6e17a2969217271e4641c5537ab0fd6b0689be&scene=21#wechat_redirect)  
  
  
[谷歌修复今年第五个 Chrome 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519462&idx=1&sn=1f7824cfd17d3489bc4ba1b37c5d974c&chksm=ea94bd8cdde3349a09b38fe57ced58ecc0d6aa9cd8270a10e3ef522071c83b0a7ae0fc2e14a6&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复周内第3个已遭利用的0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519506&idx=1&sn=6a998af125698c3afd195f3d1eb96981&chksm=ea94bc78dde3356e58d441d5787adcdb360f70675c569aa3b7e5d7d549868bea76393657c2bd&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-exploiting-chrome-eol-d-link-bugs/  
  
  
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
  
