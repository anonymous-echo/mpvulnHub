> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523537&idx=2&sn=5d168afda91b79b08357b3c4cc3f579d

#  Splunk 修复 SOAR 版本中的第三方包漏洞  
Guru Baran  代码卫士   2025-07-10 10:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Splunk 发布关键安全更新，修复了位于 SOAR 版本6.4.0和6.4中第三方程序包中的多个漏洞。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQFibs0E6lyUrmFsXJM5ichgrrPab0GKvqGzskBhiaZnkug5cvfiakSlEqWrhCB8mr4gb4xqPVJEwDqxw/640?wx_fmt=png&from=appmsg "")  
  
  
该更新发布于2025年7月7日，修复了从中危到严重等级不一的CVE漏洞。这些漏洞影响多个组件，如 git、Django、密码库以及 JavaScript 包，要求安全管理员立即管理 Splunk SOAR 部署。  
  
  
**修复多个严重漏洞**  
  
  
该安全公告提到多个严重漏洞，为 SOAR 环境造成严重风险。  
  
CVE-2024-32002是影响 git 包的严重漏洞，位于 Splunk SOAR 6.4.0和6.4.1，已通过升级至 git 2.48.1的方式予以修复。该严重等级表明该漏洞可造成严重的安全风险，并要求系统管理员立即采取行动。  
  
CVE-2024-48949是另外一个严重漏洞，专门针对 @babel/traverse 包。Splunk SOAR 6.4.0已通过将包升级至7.26.7的方式修复该漏洞。不过在随后的SOAR 6.4.1版本中，Splunk 采取更果断的方式，删除 @babel/traverse 包，完全清除该漏洞。  
  
  
**高危漏洞**  
  
  
高危漏洞包括 CVE-2024-45230 (Django)、CVE-2024-21538 (cross-spawn)、CVE-2024-52804 (tornado)、CVE-2022-35583 (wkhtml)、CVE-2024-6345 (Setuptools)、CVE-2024-39338（Axios JavaScript 库）和CVE-2024-49767（Werkzeug WSGI 工具库）。  
  
这些漏洞可导致在SOAR环境中实施越权访问、代码执行或数据操纵。组织机构必须立即升级至 Splunk SOAR 6.4.1或更高版本，修复所有已识别出的漏洞。这些漏洞影响所有低于6.4.1的SOAR 6.4版本，因此升级到最新版至关重要。鉴于存在多个严重和高危漏洞，系统管理员应当优先部署这些更新。组织机构应当立即安排维护日期，部署关键安全补丁，并保护SOAR 免受潜在攻击。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[第三方依赖关系的风险：利用数十个易受攻击的 NuGet包瞄准 .NET 平台](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506255&idx=1&sn=5dff2ef15506b4ba509e43afdb2a22d8&scene=21#wechat_redirect)  
  
  
[或因第三方数据遭泄露，诺基亚源代码被盗](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521416&idx=2&sn=af708336e0629a268e35f7a6fb2a263b&scene=21#wechat_redirect)  
  
  
[Splunk 修复企业产品中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519961&idx=2&sn=8bd333df15de255db874f15d0653517b&scene=21#wechat_redirect)  
  
  
[Splunk 修复 Enterprise 和 IT Service Intelligence 中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517521&idx=1&sn=4ba48f444fa6833ef1644afc64166e6d&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://cybersecuritynews.com/splunk-third-party-packages-soar-versions/  
  
  
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
  
