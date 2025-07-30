#  施耐德电气 UPS 软件中存在严重的未认证 RCE 漏洞   
Bill Toulas  代码卫士   2023-04-25 17:45  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSRtDKZD2DPg2tOPibwqu30841uPyXsxqHibwlz2iat9HysZEYeXsd8SBaZWBejjjSjBmpplJh7GyB3Q/640?wx_fmt=gif "")  
  
**施耐德电气公司旗下的 Easy UPS 在线监控软件易受未认证任意远程代码执行漏洞影响，可导致黑客接管设备；在最糟糕情况下可禁用其功能。**  
  
不间断电源供应 (UPS) 设备在保护数据中心、服务器机房和更小的网络基础设施中发挥着重要作用，负责保护电源不稳定或断电时的无缝运营。而施耐德旗下的 APC 是最热门的 UPS 品牌之一。其产品广泛部署在消费者和企业市场，包括政府、医疗、工业、IT和零售基础设施等。  
  
本月初，施耐德电气公司发布安全通知，提醒客户注意如下三个缺陷：  
  
- CVE-2023-29411：缺少对关键函数的认证，可导致攻击者更改管理员凭据并在 Java rmi 接口上执行任意代码（CVSS v3.1评分9.8,“严重”级别漏洞）。  
  
- CVE-2023-29412：对大小写敏感性的处理不当，当通过 Java RMI 接口操纵内部方法时，可导致攻击者运行任意代码（CVSS v3.1评分9.8,“严重”级别漏洞）。  
  
- CVE-2023-29413：缺少对关键函数的认证，可导致未认证攻击者触发拒绝服务条件（CVSS v3.1评分7.5，“高危”级别漏洞）。  
  
  
  
虽然一般而言拒绝服务漏洞通常不是特别危险，因为很多 UPS 设备都位于数据中心，因此此类断电后果会被放大，因为它会拦截对设备的远程管理。  
  
如上漏洞影响：  
  
- APC Easy UPS 在线监控软件 v2.5-GA-01-22320和之前版本  
  
- 施耐德电气 Easy UPS 在线监控软件 v2.5-GA-01-22320和之前版本  
  
  
  
这些漏洞影响所有 Windows 版本，包括10、11以及 Windows Server 2016、2019和2022。建议用户升级至 V2.5-GS-01-23026 或后续版本。目前，可直接访问 Easy UPS 单元的客户可采取的唯一缓解措施是，在所有受 Easy UPS Online 保护的服务器上升级至 PCSS 软件套件。  
  
施耐德电气公司提供的通用安全建议包括通过防火墙保护任务关键的联网设备、使用VPN 进行远程访问、执行严格的物理访问控制以及避免将设备处于“程序”模式。  
  
最新关于 APC 产品的研究发现了一系列危险漏洞且被称为 “TLStorm”，它们可导致黑客控制易受攻击和遭暴露的 UPS 设备。TLStorm 漏洞公布后，CISA 提醒注意针对联网 UPS 设备的攻击，督促用户立即采取措施拦截攻击并保护其设备。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[多个漏洞可导致施耐德电气继电器遭重启或设备遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510739&idx=4&sn=96c3f57363e08e0b1c5d095730bfa726&chksm=ea949bb9dde312af587e75893133c374d03e6ce9268f83822f1587cd82fa05439ba63437fe65&scene=21#wechat_redirect)  
  
  
[工控2月补丁星期二：西门子、施耐德电气修复近50个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510474&idx=2&sn=87818e92c87a947611eea0423026cf83&chksm=ea9498a0dde311b68937435a613ba0af82df0b65e38a1b9c0b21a08820f9abc23d5820d955c0&scene=21#wechat_redirect)  
  
  
[工控补丁星期二：西门子、施耐德电气修复40个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510120&idx=3&sn=10fcfe44fd89efa7da7cbfc4f511bf60&chksm=ea949902dde31014585298b57b592dd4d60f0c3ab245333bd71e6fe3f2880b1ed79f84747e7d&scene=21#wechat_redirect)  
  
  
[施耐德电气的 Modicon PLC 中被曝严重漏洞，已有缓解措施](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506364&idx=2&sn=dbdf16103d755f102f297ad3ff40368a&chksm=ea94e8d6dde361c09a922f2a8f78043c4207cdb0680525bc4082bfd4e83184c213af8da6464c&scene=21#wechat_redirect)  
  
  
[施耐德电气修复2个严重的电能表漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502220&idx=2&sn=fc3d9b50ac1b77cf4fa954b62939bb36&chksm=ea94f8e6dde371f09aad1c9c3fd321879145750fe2df865253c385b83ad7fcd7f737615d4248&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/apc-warns-of-critical-unauthenticated-rce-flaws-in-ups-software/  
  
  
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
  
