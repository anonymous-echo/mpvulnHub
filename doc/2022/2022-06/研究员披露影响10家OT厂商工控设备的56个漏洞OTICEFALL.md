#  研究员披露影响10家OT厂商工控设备的56个漏洞OT:ICEFALL   
Ravie Lakshmanan  代码卫士   2022-06-22 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSBmc3icyTShU82ic2p4Sny1lfwia8sLmGfBq4S2toJ9A14TNn5XpfhfiaMpDHqIS2xupyYFcfVU5wia6A/640?wx_fmt=png "")  
  
研究人员从10家运营技术 (OT) 厂商设备中发现了56个漏洞，并表示是由“设计不安全的实践”造成的。  
  
  
  
Forescout 公司将这些漏洞统称为 “OT:ICEFALL“，设计10家OT公司的25款设备，这些厂商包括 Bently Nevada、艾默生、霍尼韦尔、JTEKT、摩托罗拉、欧姆龙、Phoenix Contact、西门子和Yokogawa等。  
  
  
**主要漏洞类型**  
  
  
  
Forescout 公司在技术报告中指出，“具有目标设备网络访问权限的攻击者可利用这些漏洞远程执行代码，更改OT设备的逻辑、文件或固件，绕过认证，攻陷凭据，引发拒绝服务或造成多种运营影响。“  
  
  
**影响广泛且危害大**  
  
  
  
鉴于受影响设备广泛部署于关键基础设施行业如油气、化学、核武器、发电和配电、制造业、水处理和配水、挖矿和自动化构建等，因此这些漏洞本可造成灾难性后果。  
  
在这56个漏洞中，其中38%的漏洞可导致凭据攻陷、21%的漏洞可导致固件操控、14%的漏洞可导致远程代码执行以及8%的漏洞可导致配置信息遭篡改。  
  
除了可能使攻击者提供任意代码并对固件进行越权修改外，这些漏洞还可被用于使设备宕机并绕过现有认证功能，调用目标上的任意功能。更重要的是，在这56个缺陷中，其中22个可破坏认证机制如绕过、使用具有风险的加密协议以及硬编码和明文凭据，暗示了实现过程中的“欠佳的安全控制“。  
  
在假设的真实场景中，这些缺陷可用于攻击天然气管道、风力涡轮机或分离制造业流水线破坏天然气传输、覆写安全设置、削弱增压站的能力并修改可编程逻辑控制器的功能。但实际上这些威胁不仅仅存在于理论中。影响欧姆龙 NJ/NX 控制器的远程代码执行漏洞 (CVE-2022-31206)已被国家黑客组织 CHERNOVITE 用于开发复杂的恶意软件PIPEDREAM。  
  
使风险管理更复杂的还有IT和OT网络之间不断增强的互联性，再加上很多OT系统的不透明和专有性质，更不用说CVE编号缺乏的情况，使得这些悬而未决的问题仍然使不可见的，并在长时间内还存在如此设计不安全的特性。  
  
  
**缓解建议**  
  
  
  
要缓解OT:ICEFALL，建议发现并给易受攻击的设备设立清单，对OT资产进行分类，监控异常活动的网络流量并采购设计安全的产品来增强供应链安全。  
  
研究人员指出，“近期感染关键基础设施的恶意软件开发如 Industroyer2、Triton和INCONTROLLER 等表明威胁行动者意识到了运营技术的不安全设计本至并且准备好利用它实施破坏。尽管标准驱动的安全加固措施在OT安全中发挥着重要作用，但具有设计不安全特性以及很容易崩溃的安全控制的产品仍然获得认证。“  
  
具体技术详情可见：  
  
https://www.forescout.com/research-labs/ot-icefall/  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[横河电机修复多个工控产品漏洞，可用于破坏和操纵物理进程](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511248&idx=3&sn=6d653ec642fb58f61ba4c4e0e27b2c7b&chksm=ea949dbadde314ac1addd5c17fe3e64fac564986bf43f33a7ed4826d02cf47e4210f2518fcba&scene=21#wechat_redirect)  
  
  
[工控2月补丁星期二：西门子、施耐德电气修复近50个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510474&idx=2&sn=87818e92c87a947611eea0423026cf83&chksm=ea9498a0dde311b68937435a613ba0af82df0b65e38a1b9c0b21a08820f9abc23d5820d955c0&scene=21#wechat_redirect)  
  
  
[很多工控产品都在用的 CODESYS 软件中被曝10个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505442&idx=1&sn=645ef4a67cc6372f43f130a8137ab64b&chksm=ea94e748dde36e5e6a22fd7095c3617ac52b1376100a574a8020f04cef31b81c971ae57ad756&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/researchers-disclose-56-vulnerabilities.html  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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
