#  思科企业路由器受高危DoS漏洞影响   
Ionut Arghire  代码卫士   2023-03-10 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSETROYJryuoTIGLozibBpYdqnOY0kFYI6355vzpI9XjLVCCzziclkduic2CfgYXic8mcA7sjDJbTn9rA/640?wx_fmt=png "")  
  
  
本周，思科发布补丁，修复了位于ASR 9000、ASR 9902和ASR 9903系列企业路由器的 IOS XR软件中的高危DoS漏洞 (CVE-2023-20049)。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSETROYJryuoTIGLozibBpYdSkTB8nLENXmia3FE3hjdmGXQEd4fFAYxNZV4OhwHCViarUbibUYgIK72A/640?wx_fmt=png "")  
  
  
该漏洞的CVSS评分为8.6，影响该平台的双向转发检测 (BFD) 硬件卸载特性，无需认证即可遭远程利用。  
  
在启用BFD硬件卸载特性的易受攻击的设备上，异常BFD 数据包被不正确地处理，导致攻击者向已配置的 IPv4 地址发送构造的IPv4 BFD数据包，触发该漏洞。  
  
思科在安全公告中解释称，“成功的exploit可导致攻击者引起线卡异常或硬重置，导致线卡重新加载时该线卡上的流量丢失。”思科建议禁用BFD硬件卸载特性作为应变措施，即删除所有的 hw-module bfw-hw-offload enable命令并重置线卡。  
  
该漏洞影响安装了Lightspeed 或基于Lightspeed-Plus的线卡的 ASR 9000系列聚合服务路由器、ASR 9902和ASR 9903紧凑型高性能路由器。该漏洞的补丁已包含在IOS XR软件版本 7.5.3、7.6.2和7.7.1。  
  
本周，思科修复了IOS XR软件GRUB中的信息泄露漏洞CVE-2023-20064，具有物理访问设备权限的未认证攻击者利用。思科指出，尚未发现漏洞遭在野利用的迹象。更多详情可参考思科的产品安全页面。****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[思科多款IP电话存在严重的Web UI RCE漏洞，有一个将不修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515804&idx=1&sn=3584a336f62d0ca3a0fde7fe3f9bd5dd&chksm=ea948ff6dde306e0cd113b8566d71e3afaca9efd2a9a141cc0a9126b8e84380d067a6405ab9f&scene=21#wechat_redirect)  
  
  
[思科开源杀软ClamAV中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=2&sn=704411c89c34c85e52e2ad18ff0fb77c&chksm=ea948c95dde305838410d09bd123fd529f7be43231802fc228e4300929816f4adb5d4f72007e&scene=21#wechat_redirect)  
  
  
[命令注入漏洞可导致思科设备遭接管，引发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515439&idx=1&sn=bb8d8abcbaaf7e2be431ab9cd0712617&chksm=ea948c45dde30553179da977f93800b8c57d85c6185257361358931ab913191be82c3079d54c&scene=21#wechat_redirect)  
  
  
[思科提醒：很多严重漏洞已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515090&idx=1&sn=331cbd89b5964aa09cd03b9468ba13a5&chksm=ea948ab8dde303ae69139bb78ecfe2cb40235baf8d8e9fbffac6b7eebb2340100e8e16c3dd86&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/vulnerability-exposes-cisco-enterprise-routers-to-disruptive-attacks/  
  
  
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
  
