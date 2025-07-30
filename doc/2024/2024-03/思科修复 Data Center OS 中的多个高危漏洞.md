#  思科修复 Data Center OS 中的多个高危漏洞   
Ionut Arghire  代码卫士   2024-03-01 17:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**本周三，技术巨头思科发布半年度 FXOS和NX-OS 安全通告，与四个漏洞相关，其中两个是位于 NX-OS 软件中的高危漏洞。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT4ecvicWDAxFv5YWN6UwicQmtOEeSxruyNEqFGUnR3y6YGmWGSkeQJpTNx8cac9OhnaxMjwkm8WLYA/640?wx_fmt=gif&from=appmsg "")  
  
  
第一个高危漏洞CVE-2024-20321是因为External Boarder Gateway Protocol (eBGP) 流量“被映射到一个共享硬件速率限制队列”可导致未认证的远程攻击者发送大量流量并引发拒绝服务条件。  
  
思科指出，在某些条件下，该漏洞影响 Nexus 3600 系列交换机和 Nexus 9500 R系列显卡，包括如下产品ID：N3K-C36180YC-R、N3K-C3636C-R、N9K-X9624D-R2、N9K-X9636C-R、N9K-X9636C-RX、N9K-X9636Q-R和N9K-X96136YC-R。  
  
第二个漏洞CVE-2024-20267存在的原因在于处理入口的 MPLS 框架缺少正确的错误检查。未认证的远程攻击者可在 MPLS 框架中封装一个构造的 IPv6 数据包并将其发送到一个易受攻击的设备，触发 DoS 条件。该漏洞影响 配置了 MPLS 的Nexus 3000、Nexus 5500、Nexus 5600、Nexus 6000、Nexus 7000和Nexus 9000系列的交换机。  
  
NX-OS 软件版本 9.3 (12)、10.2 (6)和10.3 (4a) 已修复了这些漏洞。  
  
本周三，思科还宣布修复了影响 FXOS和NX-OS软件的软件的两个中危漏洞。第一个漏洞影响对“连接层发现协议 (LLDP)”框架中特定字段的处理，并可导致攻击者破坏受影响设备上的 LLDP 服务。第二个漏洞位于独立的NX-OS模式下Nexus 3000和9000系列交换机的端口信道子界面访问控制列表编程中，可在无需认证的情况下被远程用于绕过ACL防护。  
  
周三还修复了第五个漏洞，它影响Intersight Managed Mode (IMM)中 UCS6400和6500系列的互联系统。它也是中危漏洞，可被未认证的远程攻击者用于触发 DoS 条件。  
  
思科表示这些漏洞并未遭在野利用。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科提醒注意通信软件中的严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518760&idx=2&sn=d82d599134c7b2a410f4ccfe05d73d96&chksm=ea94bb42dde33254d6f854bc5b194c69fc4038bdbac099637195d80d4e0b19bd6ede6758ace6&scene=21#wechat_redirect)  
  
  
[思科称严重的 Unity Connection 漏洞可导致攻击者获得root权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518649&idx=1&sn=21ff8ab835664822aef75af18b5178a8&chksm=ea94b8d3dde331c5c49a02303ecda17deb3b8897d8bee8be24590ef862f6d2be63c6f37b66cd&scene=21#wechat_redirect)  
  
  
[罗克韦尔自动化称 Stratix 交换机受思科0day影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517980&idx=1&sn=ffc848776d7e9915b3d800a23587fda9&chksm=ea94b676dde33f6029a679ed808213cb1d41ffd5a8ca6b04cf84a414175c08db3c21817c5f49&scene=21#wechat_redirect)  
  
  
[思科新0day 被用于在数千台设备上植入恶意后门 Lua](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517960&idx=1&sn=a77de274fb21796ddac20805028ec8b0&chksm=ea94b662dde33f74645e70725b4ffb565280e526d7c94ee2cbd1c5177a6c3330dc1b383922b3&scene=21#wechat_redirect)  
  
  
[思科披露称严重的 IOS XE 认证绕过0day已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517910&idx=1&sn=8fb7babd282149838a933250b863edc8&chksm=ea94b7bcdde33eaa96070746c3597032b223e499e281eb14ab47149dc366af11b935031b6706&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/cisco-patches-high-severity-vulnerabilities-in-data-center-os/  
  
  
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
  
