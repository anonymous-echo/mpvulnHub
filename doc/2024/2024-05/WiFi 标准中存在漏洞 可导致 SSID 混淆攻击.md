#  WiFi 标准中存在漏洞 可导致 SSID 混淆攻击   
Jai Vijayan  代码卫士   2024-05-17 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
  
**比利时鲁汶大学的研究人员在 IEEE 802.11 WiFi 标准中发现了一个设计缺陷，可导致攻击者诱骗受害者连接到安全性弱的无线网络而非原来的预期网络。**  
  
  
  
VPN 审计网站 Top10VPN 和鲁汶大学的研究人员提到，这类攻击可导致受害者面临更高的流量拦截和操纵风险，漏洞详情已发布。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMR1C4vV9gtrO2Fm0xib5KeOOfpGmibyvuTsgIR9SooFTI07ODEb9xmwibcaJERFPbPuNPPkHv3t0YHMQ/640?wx_fmt=gif&from=appmsg "")  
  
**设计缺陷**  
  
  
  
  
  
该缺陷的编号是CVE-2023-52424，影响所有操作系统的所有WiFi客户端。受影响的 WiFi 网络包括基于广为部署的 WPA3 协议、WEP和802.11X/EAP的网络。研究人员已发布WiFi标准更新以及个人和组织机构可用于缓解风险的方法。  
  
鲁汶大学的研究人员 Héloïse Gollier 和Mathy Vanhoef在论文中提到，“在本论文中，我们证明了客户端可被诱骗连接到不同的受保护 WiFi 网络而非既定网络。也就是说客户端的用户界面将显示不同的SSID而非实际连接的网络SSID。”  
  
Vanhoef同时是鲁汶大学的一名教授，他此前曾发现了多个著名的WiFi漏洞和利用，如WPA3 中的Dragonblood、涉及WPA2的Krack 密钥重装攻击以及 VPN 客户端中的 TunnelCrack 漏洞。  
  
该设计缺陷的根因在于IEEE 802.11 标准并不总是要求网络的SSID 进行连接认证。SSID 识别唯一的无线访问点和网络，因此与临近区域的其它网络有所不同。研究人员表示，“现代WiFi网络依赖于4个方向握手来认证自身和客户端，并谈判密钥以加密连接。该4个方向的握手采用共享的 PMK，而PMK可根据WiFi版本和所使用的特定认证协议进行不同衍生。”  
  
问题在于，IEEE 802.11 标准并不强制要求SSID包含在密钥衍生流程中。换句话说，SSID并不总是客户端设备连接到SSID时认证流程的一部分。在这些实现中，攻击者有机会设置恶意访问点、嗅探可信网络的SSID，并利用它将受害者降级到可信度更低的网络中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMR1C4vV9gtrO2Fm0xib5KeOOfpGmibyvuTsgIR9SooFTI07ODEb9xmwibcaJERFPbPuNPPkHv3t0YHMQ/640?wx_fmt=gif&from=appmsg "")  
  
**利用条件**  
  
  
  
  
  
攻击者利用该弱点需要满足特定的条件。它仅在组织机构可能拥有凭据共享的两个WiFi网络时才起作用。例如，当环境的网络是2.4 GHz 和另外一个 5 GHz 宽带，每个网络的SSID不同但使用的认证凭据相同。一般而言，客户端设备将连接到更安全的5 GHz 网络。但距离目标网络更近可发动中间人攻击的攻击者可将恶意访问点的SSID绑定到5 GHz，之后通过恶意访问点来接收并将所有的认证框架转发到更弱的 2.4 GHz 访问带你，并将客户端设备转而连接到另外一个网络。  
  
这类降级可导致攻击者易受风险更高的攻击如 Krack 和其它威胁。更重要的是，在某些情况下，它可中和VPN防护措施。研究人员表示，“很多VPN如Cloudflare 的 Warp、hide.me 和 Windscribe 可在连接到可信的 WiFi 网络时自动禁用VPN。”这么做的原因是VPN 基于SSID识别到了该WiFi 网络。建立这类多频道中间人可适用于所有现有的WiFi实现。  
  
Top10VPN 给出了应对这些SSID混淆攻击的三种防御措施。其中一个是更新 IEEE 802.11 标准，使 SSID 认证变为强制性。另外一种方法是更好地保护可定期传输访问点的信号，这样当SSID改变时，可检测到连接的客户端。第三种方法是避免在不同的SSID中复用凭据。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[WiFi 协议漏洞可用于劫持网络流量](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516076&idx=2&sn=7aa0709e9df4a0d8c797ce6c54547971&chksm=ea948ec6dde307d069669905324ed5495a07a93a3b8b7382f3bd7a98c0ca31d2a53d56e329c5&scene=21#wechat_redirect)  
  
  
[CISA提醒：严重的 Ruckus 漏洞被用于感染 WiFi 接入点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516487&idx=2&sn=a0bd3a1e5ae0747b856ff42a50636fa1&chksm=ea94b02ddde3393b8a0a1ef90ddb1b3ee7f686b99ca6be0fbe36815c0c1d139cd46fda753f61&scene=21#wechat_redirect)  
  
  
[Flipper Zero WiFi 钓鱼攻击可解锁和开走特斯拉](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519025&idx=1&sn=767127cd1ed21591b30ff37097d63531&chksm=ea94ba5bdde3334dc67e99c8a398ba118bb96444b8a37f7c9b77069103eedf9b1e2fdcb2edaa&scene=21#wechat_redirect)  
  
  
[WiFi漏洞导致安卓和Linux设备易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518892&idx=2&sn=21e7796662495b4b807b3393dafd9890&chksm=ea94bbc6dde332d07356a2e54be40ffbdc88a3cac47f21912107d477815155335555fe2c827d&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/endpoint-security/flaw-in-wi-fi-standard-can-enable-ssid-confusion-attacks  
  
  
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
  
