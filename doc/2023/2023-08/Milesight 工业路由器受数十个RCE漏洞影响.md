#  Milesight 工业路由器受数十个RCE漏洞影响   
Ionut Arghire  代码卫士   2023-08-04 17:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**思科 Talos 安全研究人员提醒称，数十个漏洞影响Milesight UR32L 工业路由器，可被用于执行任意代码或命令。**  
  
  
  
UR32L 是一款高性价比解决方案，提供 WCDMA 和 4G LTE 支持、以太网端口和远程设备管理能力，适用于大量 M2M/IoT 应用程序。在调查 UR32L 路由器和远程访问解决方案 MilesightVPN 的过程中，Talos 团队提交了20多份漏洞报告，结果获得69个CVE编号，其中63个影响 Milesight UR32L。  
  
在这些漏洞中，最严重的是CVE-2023-23902（CVSS评分9.8），它是位于路由器 HTTP 服务器登录功能中的缓冲溢出漏洞，可导致通过网络请求的远程代码执行后果。  
  
Talos 团队指出，“这是最严重的漏洞，是一个预认证远程栈缓冲区溢出漏洞。能够和HTTP服务器通信的未认证攻击者将能够开展远程命令执行。”  
  
除两个漏洞外，其余漏洞均为高危漏洞，多数可导致任意代码执行或命令执行后果。这些漏洞影响MilesightVPN 应用程序，可被用于执行命令、读取任意文件、绕过认证并注入任意 Javascript 代码。  
  
MilesightVPN 用作确保 UR32L 路由器未暴露到互联网，因此减少攻击面。然而，Talos 团队指出，攻击者可利用VPN软件中的认证绕过漏洞 (CVE-2023-22319)，利用CVE-2023-23902在设备上执行任意代码。  
  
Talos 团队还提到，在2023年2月将漏洞告知厂商，但厂商尚未发布软件更新进行修复。  
  
Milesight 路由器漏洞研究只是Talos 团队SOHO 路由器漏洞研究的一部分，该团队在五年的研究过程中发现了289个漏洞。自2018年发现 VPNFilter 恶意软件开始，这项研究还从华硕、D-Link、InHand Network、Linksys、Netgear、Robustel、Sierra Wireless、Siretta、Synology、TCL、TP-Link、ZTE、OpenWrt、FreshTomato、Asuswrt和 NetUSB.ko 中发现了问题。不过除了Milesight 工业路由器漏洞以外，其它路由器中的漏洞已在2018年至2022年期间公开披露。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[InHand工业路由器中存在多个漏洞，导致OT网络易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515321&idx=2&sn=21b3cad712a7f1267e677ed2354c90e9&chksm=ea948dd3dde304c5320dac4c1f977dc1871ae5bfa1be6fe37d8cad7f7662c9d4936faa0df6c6&scene=21#wechat_redirect)  
  
  
[NetComm 工业路由器存在多个严重漏洞 可导致设备遭远程攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487828&idx=3&sn=8446024dfc31b0ff8edcb4a6490a174a&chksm=ea97203edde0a9282983bc4b1dad7c86d1cfdeb257a33adff5db7c072dcd4e1a01bd4de67a8e&scene=21#wechat_redirect)  
  
  
[思科工业路由器中出现严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485559&idx=2&sn=f36bb934c0122acbe0b58c1a14c4b2bd&chksm=ea97391ddde0b00b1b296b2b8e79e4d03029d1ff4a99e483d9a306344aead7793fd12102753f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/dozens-of-rce-vulnerabilities-impact-milesight-industrial-router/  
  
  
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
  
