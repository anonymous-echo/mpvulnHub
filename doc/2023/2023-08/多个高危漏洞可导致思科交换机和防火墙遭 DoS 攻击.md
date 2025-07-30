#  多个高危漏洞可导致思科交换机和防火墙遭 DoS 攻击   
Ionut Arghire  代码卫士   2023-08-25 17:45  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**本周三，思科宣布修复产品中的六个漏洞，其中三个是位于 NX-OS 和 FXOS 软件中的高危漏洞，可被用于触发拒绝服务条件。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS8Ds6nFbo9GlibvnRLWiareCKC0oLaNRsV0tGHjdiaRviaSahdsfdpCTrZr9TOp15nRtzOMzrFY6iaxiaQ/640?wx_fmt=png "")  
  
  
在这些影响Firepower 4100 和 Firepower 9300 安全设备和 UCS 6300 系列互联结构的 FXOS 软件漏洞中，其中最严重的是CVE-2023-20200，它是对特定 SNMP 请求处理不当漏洞。  
  
该漏洞可使认证的远程攻击者将构造的 SNMP 请求发送给受影响设备并使其重新加载，从而导致 DoS 条件。  
  
思科解释称，“该漏洞影响所有受支持的 SNMP 版本。要通过 SNMPv2c 或更早版本利用该漏洞，攻击者必须了解在受影响设备上配置的 SNMP 社区字符串。要通过 SNMPv3 利用该漏洞，攻击者必须具有在受影响设备上配置的 SNMP 用户的合法凭据。”  
  
第二个高危漏洞CVE-2023-20169影响独立 NX-OS 模式下 Nexus 3000 和 Nexus 9000 系列路由器的 NX-OS 软件，被描述为中间系统对中建系统 (IS-IS) 协议的输入验证不充分漏洞。  
  
该漏洞可导致未认证的 Layer 2 邻近攻击者将构造的 IS-IS 数据包发送给受影响设备，导致 IS-IS 进程重启，从而导致设备重新加载，引发DoS 条件。  
  
思科还修复了位于NX-OS软件的TACACS+ 和 RADIUS 远程认证中的高危漏洞CVE-2023-20168。该漏洞是一个不正确的输入验证漏洞，可导致未认证的本地攻击者在登录时输入构造字符串并引发 DoS 条件。该漏洞影响多款 Nexus 系列交换机、MDS 9000系列交换机和VMware vSphere的 Nexus 1000虚边，仅可通过 Telnet 或控制台管理连接进行利用。  
  
这三个漏洞已在思科的2023年8月半年度安全公告中修复，该公告还修复了可导致文件覆写的两个中危漏洞。  
  
周三，思科还宣布修复位于 APIC 中的一个中危漏洞，它“可导致认证的远程攻击者读取、修改或删除由与受影响系统上不同安全域名关联的用户所创建的非租户策略”。  
  
思科表示并未发现这些漏洞遭恶意利用的证据。其它信息可参加思科的产品安全页面。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[严重的思科 SD-WAN 漏洞可导致信息泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517089&idx=2&sn=d00e1d0fe24db8bf16d2d2b13ca24261&chksm=ea94b2cbdde33bdd104cf70c1e39dc9aa9a50a4a440cfb4040c51ffb19d02aa65883822b0e90&scene=21#wechat_redirect)  
  
  
[高危无补丁0day影响思科数据中心交换机，可导致加密流量遭篡改](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516974&idx=2&sn=179eead740cfb91b376bafa02e4fcb99&chksm=ea94b244dde33b524d84c5fad51227142548b6794645504ad026ef59442f37d9388673b96ff7&scene=21#wechat_redirect)  
  
  
[思科修复企业协作解决方案中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516704&idx=1&sn=6a051f71c4415e8ad5f9be754927a9e7&chksm=ea94b34adde33a5c62b6fd4ed5257ace796ceae62afe7d61ca91d818c2973aaa40cfbe68ff91&scene=21#wechat_redirect)  
  
  
[思科提醒：多款交换机存在多个RCE漏洞且利用代码已公开](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516520&idx=1&sn=b218e43205e7038adc4f452ffee4c6e2&chksm=ea94b002dde339147f0499b209d253c186277b9ecf0af4a44153ac18705dffd978ecbe379083&scene=21#wechat_redirect)  
  
  
[思科电话适配器易受 RCE 攻击，目前无修复方案](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=2&sn=30f06254fcca6feb3228b78389c85056&chksm=ea94b182dde338944d1c48c872c538f5333e8de4ceb4594aede8579d82c069df184557fca031&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/cisco-patches-vulnerabilities-exposing-switches-firewalls-to-dos-attacks/  
  
  
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
  
