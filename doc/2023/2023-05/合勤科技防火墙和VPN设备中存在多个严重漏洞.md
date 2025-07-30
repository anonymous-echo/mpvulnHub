#  合勤科技防火墙和VPN设备中存在多个严重漏洞   
Bill Toulas  代码卫士   2023-05-26 17:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**合勤科技公司提醒用户称，多款防火墙和VPN产品中存在两个严重漏洞，攻击者无需认证即可利用。**  
  
  
  
  
这两个漏洞都是缓冲区溢出漏洞，可导致拒绝服务和远程代码执行后果。合勤科技指出，“合勤科技已发布补丁，修复受多个缓冲区溢出漏洞影响的固件。建议用户安装补丁进行防御。”  
  
缓冲区溢出漏洞可导致内存操控后果，使攻击者在所分配部分之外写数据，一般会导致系统崩溃后果，但在一些情况下可导致代码执行后果。  
  
合勤科技修复的漏洞包括：  
  
（1）CVE-2023-33009：位于某些合勤产品通知功能中的缓冲区溢出漏洞，可导致未认证攻击者执行远程代码或者触发拒绝服务条件（严重程度评分9.8）。  
  
（2）CVE-2023-33010：位于某些合勤产品ID处理功能中的缓冲区溢出漏洞，可导致未认证攻击者执行远程代码或者触发拒绝服务条件（严重性评分9.8）  
  
该公司表示这些易受攻击的设备运行如下固件：  
  
- Zyxel ATP 固件版本ZLD V4.32 至 V5.36 Patch 1（已在ZLD V5.36 Patch 2中修复）  
  
- Zyxel USG FLEX 固件版本 ZLD V4.50 至 V5.36 Patch 1（已在ZLD V5.36 Patch 2中修复）  
  
- Zyxel USG FLEX50(W) / USG20(W)-VPN 固件版本 ZLD V4.25 至 V5.36 Patch 1 （已在ZLD V5.36 Patch 2中修复）  
  
- Zyxel VPN 固件版本 ZLD V4.30 至 V5.36 Patch 1（已在ZLD V5.36 Patch 2中修复）  
  
- Zyxel ZyWALL/USG 固件版本 ZLD V4.25 至V4.73 Patch 1（已在ZLD V4.73 Patch 2中修复）  
  
  
  
合勤科技公司建议受影响用户尽快应用最新的安全更新，消除漏洞利用影响。运行以上易受攻击版本的设备用于中小企业，保护网络安全并使远程或在家办公用户使用安全的网络访问 (VPN)。威胁者密切关注这类设备中的严重漏洞，以便轻松访问企业网络。  
  
上周，网络安全研究员 Kevin Beaumont 称，合勤科技4月份修复的一个命令注入漏洞已遭活跃利用，且它影响与受这两个漏洞影响的同样的防火墙和VPN产品。去年，CISA发布警报称，黑客正在利用合勤科技防火墙和VPN设备中的一个远程代码执行漏洞，督促系统管理员尽快应用固件补丁。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[刚刚，合勤科技发布NAS新固件，修复严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513843&idx=2&sn=8542b0597bb31128891e9f651a8afc17&chksm=ea948799dde30e8fec2983d236de83edbc94c48dc8271c57d4c59d10286c37ff6d303542a054&scene=21#wechat_redirect)  
  
  
[合勤科技修复四个高危漏洞，影响AP、API控制器和防火墙设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512001&idx=3&sn=e25d8213ca24152e4fe49ee900f53295&chksm=ea949eabdde317bdbdb50c88bc48a6238c3d4eb1a57347b38b9cfba3db4a24295bf78c1d8951&scene=21#wechat_redirect)  
  
  
[合勤科技称企业防火墙和VPN设备遭复杂攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506015&idx=2&sn=0f9526d0ee1779ec004d5b2eeabd6a1d&chksm=ea94e935dde360235b0955a9b0143d20560258e44f96dc4a2023d86ba3a34b836e6068a3e766&scene=21#wechat_redirect)  
  
  
[10万+合勤科技防火墙和 VPN 网关被曝秘密后门](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499934&idx=2&sn=a370ec84c6da47a9b94ccab3a8e78b50&chksm=ea94f1f4dde378e22118864dc9ffe43574f156308485b517eef58b5e7514a53f5c44b11e45c1&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/zyxel-warns-of-critical-vulnerabilities-in-firewall-and-vpn-devices/  
  
  
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
  
