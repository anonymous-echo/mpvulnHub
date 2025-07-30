#  SolarWinds 平台修复两个高危漏洞   
Ionut Arghire  代码卫士   2023-04-25 17:45  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSRtDKZD2DPg2tOPibwqu30841uPyXsxqHibwlz2iat9HysZEYeXsd8SBaZWBejjjSjBmpplJh7GyB3Q/640?wx_fmt=gif "")  
  
**SolarWinds 平台修复了两个高危漏洞，它们可分别导致命令执行和权限提升后果。**  
  
其中较为严重的是CVE-2022-36963（CVSS评分8.8），是位于 SolarWinds 的基础设施监控和管理解决方案中的命令注入漏洞。该漏洞可被远程用于执行任意命令。成功利用该漏洞要求攻击者持有合法 SolarWinds 平台管理员账户的凭据。  
  
第二个高危漏洞CVE-2022-47505（CVSS评分7.8）是本地提权漏洞，可导致拥有合法系统用户账户的本地攻击者提升权限。  
  
这两个漏洞都是由趋势科技 ZDI 项目研究员报告的，且均已在 SolarWinds Platform 版本2023.2中修复。  
  
该版本还修复了中危漏洞CVE-2022-47509，它是不正确的输入中和漏洞，可被远程用于附加 URL 参数以注入HTML代码。利用该漏洞要求具有合法账户。  
  
SolarWinds 公司还修复了位于 Database Performance Analyzer 中的两个中危漏洞，一个可导致信息泄露，另一个可导致用户枚举至不同的服务器文件夹中。Database Performance Analyzer 版本2023.2同时修复了这两个漏洞。  
  
SolarWinds 公司并未提到这些漏洞是否遭利用。该公司在安全公告页面提供了更多漏洞详情。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[SolarWinds 称将在2月底修复多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=3&sn=e5d9ae1f0396aaa5c5eb758484fb760b&chksm=ea948c95dde3058339a2b4d43a851fdc2441afec55b15919595ce8d9f6b98ea46b38a0e06ae3&scene=21#wechat_redirect)  
  
  
[SolarWinds 公司：Web Help Desk 实例正遭攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510991&idx=4&sn=90944cad89a7c454178edd41a21c5652&chksm=ea949aa5dde313b3d6c2c7960809d44226a88ed78a7ae795f0ffd4835a5357e4d93d64e6012c&scene=21#wechat_redirect)  
  
  
[微软：攻击者利用SolarWinds Serv-U 0day发动 Log4j 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510233&idx=2&sn=26931bdef44b8579be16fb59abe06f2e&chksm=ea9499b3dde310a5384a230a39a6732eeb2d9db56ce3bef75f12a3c9921af7a27b64fb660e1e&scene=21#wechat_redirect)  
  
  
[SolarWinds 攻击者再次发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509600&idx=2&sn=e35fa9cf222ea6289fbccd1276d3424f&chksm=ea94970adde31e1ccd97458f9208293b83ea8d920841d400774f42afaf7ce252be14ea51ec35&scene=21#wechat_redirect)  
  
  
[SolarWinds 攻击者开发的新后门 FoggyWeb](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508212&idx=2&sn=033b041e06fdec143179b94da5acbeb4&chksm=ea94919edde318882ededf13e579c0dfa333c361d4ec29c20f61af77d2c3a1d72a877d4cf23a&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/solarwinds-platform-update-patches-high-severity-vulnerabilities/  
  
  
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
  
