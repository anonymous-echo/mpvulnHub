#  vCenter 服务器漏洞可导致代码执行和认证绕过   
Sergiu Gatlan  代码卫士   2023-06-25 17:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**VMware 修复了位于 vCenter Server 中的多个高危漏洞，可导致攻击者获得代码执行权限并绕过未修复系统上的认证。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRhKmAekLpadfATw9IOQlnwiabZmyr8o4VibLCoT9KKafiaAaiaic9Ov84R8zsHVGCK2AtfjDoqHl41XaA/640?wx_fmt=png "")  
  
  
vCenter Server 是VMware 的 vSphere 套件控制中心，也是一款服务器管理解决方案，帮助管理员管理和监控虚拟化基础设施。这些漏洞位于 vCenter Server 使用的 DCE/RPC 协议实现中。该协议可通过创建虚拟的统一计算环境在多个系统实施无缝操作。  
  
VMware 已为四个高危漏洞发布安全更新，包括堆溢出漏洞 (CVE-2023-20892)、释放后使用漏洞 (CVE-2023-20893)、界外读 (CVE-2023-20895)和界外读 (CVE-2023-20894)。  
  
前两个漏洞（CVE-2023-20892和CVE-2023-20893）可被具有网络访问权限的未认证攻击者用于在高度复杂攻击中获取代码执行权限，导致机密性、完整性和可用性完全丢失。  
  
VMware 公司指出，“因在 DCERPC 协议中使用未初始化的内存，因此 vCenter Server 中包含一个堆溢出漏洞。对 vCenter Server 具有网络访问权限的恶意人员可利用该漏洞在托管 vCenter Server 的底层操作系统执行任意代码。”  
  
利用CVE-2023-20895的威胁行动者可触发界外读和内存损坏，从而绕过未修复 vCenter Server 设备上的认证。  
  
VMware 还修复了另外一个 vCenter Server 界外读漏洞CVE-2023-20896，可被用于对目标主机上多种 VMware 服务的远程拒绝服务攻击中。所有这些漏洞均由思科 Talos 安全研究人员 Dimitrios Tatsis 和 Aleksandar Nikolic 发现并报告。  
  
上周，VMware 修复了已遭利用的 ESXi 0day 漏洞，并提醒客户称 Aria Operations for Networks 分析工具中的一个严重漏洞遭活跃利用。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[这个VMware vCenter Server漏洞去年就已发现，至今仍未修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514181&idx=2&sn=50c62919f4f010b5579d19ba752c7ba5&chksm=ea94892fdde30039043be2fb51e549c347507a0846cf9ad231e6e720f7794502b4dc46dd319c&scene=21#wechat_redirect)  
  
  
[8个月后，VMware 终于开始修复这个 vCenter 服务器缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512863&idx=5&sn=1938d972de69614433bcc5f0a48a1213&chksm=ea948275dde30b631a6e7cdfc7519c716dc206f0bbdeee592dbeb111a91fdc0c0c728a6b46bb&scene=21#wechat_redirect)  
  
  
[速修复！VMware vCenter Server 所有版本受严重的 RCE 漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504397&idx=1&sn=4736799052c59070bcb3fe62304da5cb&chksm=ea94e367dde36a710eb39e9ed751e13acb2e009f8503076fb312212384b4e2135e1868a46d1a&scene=21#wechat_redirect)  
  
  
[谈谈我们如何发现 VMware vCenter 的越权 RCE](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501665&idx=1&sn=8fc16a9ed2e40bcad4be0c0f674d9b07&chksm=ea94f60bdde37f1dce831c3c209c2f85d06ab46da3736f4967d00e1bb4868ae61c0c1b2e0672&scene=21#wechat_redirect)  
  
  
[VMware 修复 vCenter 服务器中的严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501629&idx=1&sn=900516d323f0e188600549ae47c7baf4&chksm=ea94f657dde37f4140d649034e02fe85624dd670253119f1fe3ecb8a8d0330ba80e7f05c230b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/vmware-fixes-vcenter-server-bugs-allowing-code-execution-auth-bypass/  
  
  
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
  
