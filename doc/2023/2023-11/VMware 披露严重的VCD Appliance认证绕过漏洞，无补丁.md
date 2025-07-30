#  VMware 披露严重的VCD Appliance认证绕过漏洞，无补丁   
Sergiu Gatlan  代码卫士   2023-11-15 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**VMware 披露了影响 Cloud Director 设备部署中的一个认证绕过 0day 漏洞 (CVE-2023-34060)。**  
  
  
  
Cloud Director 可使 VMware 管理员管理虚拟数据中心 (VDC) 中组织机构的云服务。该认证绕过漏洞仅运行从之前旧版本升级到 VCD Appliance 10.5 的设备。VMware 公司还指出，该漏洞并不影响新的 VCD Appliance 10.5 版本、Linux 部署以及其它设备。  
  
未认证攻击者可在无需用户交互的复杂度较低的攻击活动中远程利用该漏洞。VMware 公司解释称，“在 VMware Cloud Director Appliance 10.5 升级版本中，具有对设备进行网络访问的恶意人员可在端口22 (ssh) 或端口 5480 （设备管理面板）上进行认证时绕过登录限制。该绕过并未出现在端口443（VCD提供商和租户登录）。在VMware Cloud Director Appliance 10.5 的新版本中，该绕过并不存在。”  
  
  
**0****1**  
  
**无补丁，仅有缓解措施**  
  
  
  
虽然 VMware 并未发布对该严重认证绕过漏洞的补丁，但为管理员提供了临时缓解措施。  
  
VMware 在另一份安全公告中提到，“VMware 发布了 VMware 安全公告 VMSA-2023-0026，帮助客户了解该漏洞以及哪种升级路径可修复。”缓解措施仅适用于受影响的 VCD Appliance 10.5.0版本，要求下载自定义脚本并在被暴露的版本中使用。  
  
VMware 公司提到，该缓解措施并不会造成任何功能性破坏，无需重启服务或重启电脑。  
  
6月份，VMware 公司还修复了一个 ESXi 0day 漏洞。10月份，该公司修复了严重的 vCenter Server 漏洞 (CVE-2023-34048)，它可导致RCE攻击。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[VMware 发现34个Windows 驱动易受设备完全接管攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518061&idx=3&sn=d4a64266b93ecf83c41d5c0c3914555f&chksm=ea94b607dde33f115aa5272499ee1b24c6ed4deaf860e06465531de74905247f9b9f11dd84db&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的 vCenter Server 代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517985&idx=2&sn=bf96d48a8e813b54efe7b49e1d451d91&chksm=ea94b64bdde33f5d32a676ffb901bafbd88a9925b05af28720a33389cee0066b41f2b27046cb&scene=21#wechat_redirect)  
  
  
[VMware 修复网络监控产品中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517495&idx=2&sn=f20e793a89665c09e42c6341755a3e88&chksm=ea94b45ddde33d4bec3d0c06c238e806e9061130fc138a24354059fe0f857cafc9054fe04e3c&scene=21#wechat_redirect)  
  
  
[戴尔 Compellent 硬编码密钥暴露 VMware vCenter 管理员凭据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517384&idx=1&sn=265b6987345cae72c67305983ab23dd1&chksm=ea94b5a2dde33cb401636bf5a0c1f1029d2a1c8369d20258285b7dfd15d85f6fa83e963936e9&scene=21#wechat_redirect)  
  
  
[VMware 修复 vRealize 网络分析工具中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516696&idx=2&sn=f9d50b8697f67622344d6400a4246a35&chksm=ea94b372dde33a64677eb42039df16b745cc37313484a52d2b714d5b8c2fad89b1bc71258855&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/vmware-discloses-critical-vcd-appliance-auth-bypass-with-no-patch/  
  
  
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
  
