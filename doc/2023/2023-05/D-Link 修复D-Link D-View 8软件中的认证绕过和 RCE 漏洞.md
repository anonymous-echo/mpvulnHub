#  D-Link 修复D-Link D-View 8软件中的认证绕过和 RCE 漏洞   
Bill Toulas  代码卫士   2023-05-26 17:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**D-Link 修复了位于 D-View 8 网络管理套件中的两个严重漏洞，它们可导致远程攻击者绕过认证并执行任意代码。**  
  
  
  
  
D-View 是由D-Link 公司开发的网络管理套件，用于规模不一的企业中，用于监控性能、控制设备配置、创建网络地图并使网络管理和管理员工作更为有效和节约时间。  
  
参加ZDI项目的安全研究员去年晚些时候发现了6个影响 D-View 的漏洞并在2022年12月23日告知D-Link 公司。其中两个漏洞是严重级别（CVSS 9.8），可导致未认证攻击者利用受影响程序。第一个漏洞CVE-2023-32165是一个远程代码执行缺陷，是因为在文件操作中使用由用户提供的路径时缺乏正确验证导致的。攻击者可利用该漏洞以系统权限执行代码，从而在 Windows系统上以最高权限运行，可能导致系统遭完全接管。  
  
第二个严重漏洞CVE-2023-32169是认证绕过漏洞，是因为软件的 TokenUtils 类上的硬编码加密密钥导致的。如遭利用，该漏洞可导致权限提升、越权访问信息、更改软件配置和设置、甚至安装后门和恶意软件。  
  
D-Link 已为所有六个漏洞发布安全公告。它们影响 D-View 8版本2.0.1.27及以下版本。管理员应升级至2023年5月17日发布的已修复版本2.0.1.28。  
  
D-Link 安全通告指出，“D-Link 收到安全问题报告后，立即启动调查并开始开发安全补丁。”尽管D-Link 公司“强烈建议”所有用户安装安全更新，但也提醒称该补丁是“测试软件或热修复方案发布”，仍然处于最终测试阶段。这意味着升级至2.0.1.28可能引发问题或导致D-View 不稳定，但这些漏洞的严重性可能超越了任何潜在的性能问题。  
  
D-Link 还建议用户在下载相应的固件更新前检查底面标签或web配置面板，验证产品的硬件修订版本。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[D-Link 修复多个硬编码密码漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506450&idx=3&sn=e93472d0452c2f5615ef9f11c0f4cb71&chksm=ea94eb78dde3626e9370f9fdd70b4dc576638d8253da74e5bd0a3e1371cf537b4869f1577713&scene=21#wechat_redirect)  
  
  
[D-Link 修复VPN路由器中的多个远程命令注入漏洞，还有一个未修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247498584&idx=6&sn=ae761df7a81ed6965f4a2dcde6755e2e&chksm=ea94ca32dde34324055e8c5d633658bc3a97ad1c2ca770d0cd2d85b8c0ddc932b97aa69691d3&scene=21#wechat_redirect)  
  
  
[D-Link 不止暴露固件镜像密钥，还被曝5个严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494275&idx=1&sn=4ef4e6ac706709f704551718f80bba03&chksm=ea94dbe9dde352ffc1eb0a4c086a5df64ad6ed267624f2319095a0ccbd95b45f081397abad92&scene=21#wechat_redirect)  
  
  
[D-Link 老款路由器被曝多个高危漏洞，未完全修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493529&idx=1&sn=cfc7d888829b44a3984d2fae72f8a8c0&chksm=ea94d6f3dde35fe5f802376b058dc9a8132607f531c9741e44d25973e36c2370a69c0eac42d9&scene=21#wechat_redirect)  
  
  
[多款 D-Link 路由器受多个 RCE 漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492059&idx=1&sn=78141a1114ac7f6f0713bc6c9b0f98b5&chksm=ea94d0b1dde359a780689a3261ed3aaa37237f3d9ae820b104ae3fb0dead70d14f65d1a4dc67&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/d-link-fixes-auth-bypass-and-rce-flaws-in-d-view-8-software/  
  
  
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
  
