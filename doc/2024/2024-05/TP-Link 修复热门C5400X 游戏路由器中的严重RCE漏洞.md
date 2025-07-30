#  TP-Link 修复热门C5400X 游戏路由器中的严重RCE漏洞   
BILL TOULAS  代码卫士   2024-05-28 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**TP-Link Archer C5400X 游戏路由器易受多个漏洞影响，可导致未认证的远程攻击者在设备上执行命令。**  
  
  
  
TP-Link Archer C5400X是一款高端的三频带游戏路由器，旨在为游戏和其它需求较高的应用程序；基于产品在网络商店上的用户评论数量情况，它似乎很受游戏人员欢迎。  
  
路由器上的任意命令执行可导致劫持路由器、数据拦截、修改DNS设置以及攻陷内网。  
  
  
**漏洞概述**  
  
  
  
  
  
该漏洞的编号是CVE-2024-5035（CVSS评分10，“严重”级别），是OneKey公司的分析师通过二进制静态分析找到的。  
  
研究人员发现二进制 “rftest” 暴露了TCP端口8888、8889和8890上易受命令注入和缓冲区溢出影响的网络服务。该 “rftest” 服务在这些端口上运行网络监听器，执行无线接口自评和相关任务。使用shell元字符的攻击者可向这些端口发送特殊构造的消息，可能以提升后的权限实现任意代码执行。Shell 元字符是特殊字符如用于更好地在命令行shell上进行控制的分号、&号和管道符号。然而，当用户输入未被正确清理阻止越权操作时，这些元字符可被滥用于执行命令。  
  
  
**修复方案已发布**  
  
  
  
  
  
由于上述端口是开放的且由 “rftest” 服务活跃应用于路由器的默认配置中，因此它影响所有使用易受攻击固件版本（1.1.1.6及以前）的设备用户。  
  
OneKey 公司的分析师在2024年2月6日将漏洞报送给 TP-Link 的 PSIRT 团队，后者已在2024年4月10日发布测试版补丁，而最终补丁在上周即5月24日发布。Archer C5400X(EU)_V1_1.1.7 Build 20240510 修复了该漏洞。  
  
已执行的修复方案将丢弃包含 shell 元字符的任何命令，因此所有进站信息都被过滤。建议用户从 TP-Link 的官方下载门户下载该固件更新，或者使用路由器管理员面板执行该更新。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[TP-Link 和 NetComm 路由器中存在多个远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515346&idx=1&sn=3d1acdb97283a7d9606c441b9ca5eb27&chksm=ea948db8dde304aea15c93964eceaeb7328f9d6fd59ebe7ea979943fac2a6e48c8fd1b9087c2&scene=21#wechat_redirect)  
  
  
[TP-Link 路由器被曝严重漏洞：无需密码即可登录](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491921&idx=1&sn=ff747109c1daa0e227fdebb93dfb47bd&chksm=ea94d03bdde3592d75c69d82c32070566c30aaa67321a6bd8b613cfd525ae38688db073d635c&scene=21#wechat_redirect)  
  
  
[TP-Link WiFi 扩展器被曝存在严重的 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490231&idx=2&sn=a755875c26dbf80ca944a86a6034cbeb&chksm=ea972bdddde0a2cb3ce9b4c573a5767fb550f59a45fad7ff5da4179dc757810ec7a3d443e01f&scene=21#wechat_redirect)  
  
  
[TP-Link 修复 SOHO 路由器中的远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488569&idx=3&sn=b629d305a12b7d97c3af6139f9face62&chksm=ea972553dde0ac45f6e6d3a3ed4427c1f71adcddbc89d333f83d2f88e32e89d1164d0eece89e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/tp-link-fixes-critical-rce-bug-in-popular-c5400x-gaming-router/  
  
  
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
  
