#  思科修复IMC 高危根提权漏洞   
Sergiu Gatlan  代码卫士   2024-04-18 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**思科修复了一个位于集成管理控制器 (IMC) 中的高危漏洞，可导致本地攻击者提权至 root，其利用代码已被公开。**  
  
  
  
思科 IMC 是一款主板管理控制器，用于通过多个接口如 XML API、web (WebUI) 和命令行 (CLI) 接口等管理 UCS C-Series Rack 和 UCS S-Series Storage 服务。  
  
思科解释称，“思科IMC的CLI 中的漏洞可导致认证的本地攻击者在底层操作系统上执行命令注入攻击并将权限提升至 root。要利用该漏洞，攻击者必须在受影响设备上拥有只读或更高权限。”  
  
该漏洞的编号是CVE-2024-20295，由对用户提供输入的验证不足引发，可在复杂度较低的攻击中使用构造的CLI 命令遭利用。该漏洞影响默认配置下，运行易受攻击IMC版本的如下思科设备：  
  
- 5000 Series Enterprise Network Compute Systems (ENCS)  
  
- Catalyst 8300 Series Edge uCPE  
  
- UCS C-Series Rack Servers in standalone mode  
  
- UCS E-Series Servers  
  
  
  
不过，思科还披露称如果其它产品配置为可访问易受攻击的思科 IMC CLI，则也受攻击。思科的产品安全事件响应团队 (PSIRT) 还提醒称，该漏洞的 PoC 利用代码已可用，不过幸运的是尚未遭利用。  
  
去年10月份，思科发布两个0day漏洞的补丁，这些漏洞可用于在一周内攻陷5万多台 IOS XE设备。攻击者还在去年利用了第二个IOS和IOS XE 0day，它们可用于通过远程代码执行劫持易受攻击的设备。  
  
最近，思科提醒注意针对思科、CheckPoint、Fortinet、SonicWall 和Ubiquiti 设备上VPN和SSH 服务的大规模且正在进行的凭据暴力攻击。而在此之前，思科督促客户缓解针对在思科 Secure Firewall 设备上配置RAVPN服务的密码喷射攻击。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科提醒注意Small Business路由器中的XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519231&idx=2&sn=b7b32d73cbe2046719780c03304729ce&chksm=ea94ba95dde333834c93da6e263ab3af72ce14f2a171799c65802dab992336cd0c1a96492159&scene=21#wechat_redirect)  
  
  
[思科IOS 漏洞可导致未认证的远程DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519204&idx=2&sn=6fc646b9575f6837ef0f55d569c11709&chksm=ea94ba8edde33398e567236352d40e34414aa12c9e4bd4d838bff320754289021c2fafcc02b8&scene=21#wechat_redirect)  
  
  
[思科修复 Data Center OS 中的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518970&idx=1&sn=6962ea177a62fac9410b186624a2cd9a&chksm=ea94bb90dde332865540fed5893fa0fe3b2438bba6108c0ec68ea0e789667b29c274b976ec73&scene=21#wechat_redirect)  
  
  
[思科提醒注意通信软件中的严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518760&idx=2&sn=d82d599134c7b2a410f4ccfe05d73d96&chksm=ea94bb42dde33254d6f854bc5b194c69fc4038bdbac099637195d80d4e0b19bd6ede6758ace6&scene=21#wechat_redirect)  
  
  
[思科称严重的 Unity Connection 漏洞可导致攻击者获得root权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518649&idx=1&sn=21ff8ab835664822aef75af18b5178a8&chksm=ea94b8d3dde331c5c49a02303ecda17deb3b8897d8bee8be24590ef862f6d2be63c6f37b66cd&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/cisco-discloses-root-escalation-flaw-with-public-exploit-code/  
  
  
题图：  
Pexels  
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
  
