#  VMware 修复Workstation 和 Fusion 产品中的多个漏洞   
THN  代码卫士   2024-05-16 11:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**VMware Workstation 和 Fusion 产品中存在多个漏洞，可被威胁行动者用于访问敏感信息、触发拒绝服务条件并在某些条件下执行代码。**  
  
  
  
这四个漏洞影响 Workstation 17.x 和 Fusion 13.x，修复方案已分别在17.5.2和13.5.2中发布。这四个漏洞的简述如下：  
  
- CVE-2024-22267：CVSS 9.3，是位于 Bluetooth 设备中的一个释放后使用漏洞，在虚拟机上具有本地管理员权限的恶意人员可作为在主机上运行的虚拟机 VMX 进程执行代码。  
  
- CVE-2024-22268：CVSS 7.1，是位于 Shader 功能中的一个堆缓冲区溢出。对启用了3D图形的虚拟机具有非管理员访问权限的恶意人员可利用该漏洞创造DoS条件。  
  
- CVE-2024-22269：CVSS 7.1，是位于 Bluetooth 设备中的一个信息泄露漏洞。在虚拟机上拥有本地管理员权限的恶意人员可从虚拟机读取管理程序内存中的权限信息。  
  
- CVE-2024-22270：CVSS 7.1，是位于 HGFS 功能中的一个信息泄露漏洞。在虚拟机上拥有本地管理员权限的恶意人员可从虚拟机读取管理程序内存中的权限信息。  
  
  
  
VMware 还提供了部署补丁前可采用的临时应变措施。该公司建议用户关闭虚拟机上的蓝牙支持功能并禁用3D加速特性。对于CVE-2024-22270漏洞而言并不存在任何缓解措施，只能更新至最新版本。  
  
值得注意的是，CVE-2024-22267、CVE-2024-22269和CVE-2024-22270最初由 STAR Labs SG 和 Theori 在今年3月温哥华举行的 Pwn2Own 黑客大赛上进行了演示。  
  
两个多月前，VMware 公司发布补丁，修复了影响 ESXi、Workstation和 Fusion 中的四个漏洞，其中两个严重漏洞CVE-2024-22252和CVE-2024-22253的评分为9.3/8.4，可导致代码执行后果。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[VMware修复多个严重的ESXi 沙箱逃逸漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519003&idx=2&sn=c494f1df6adfe5a6b91c813d2d236c8c&chksm=ea94ba71dde3336793921a1d4a9852067a51546a77a39e5c25ed0836ffe1f6e0706fb9618530&scene=21#wechat_redirect)  
  
  
[VMware督促管理员删除易受攻击的认证插件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518869&idx=2&sn=accd15841c79ae4dc71415f736248c4a&chksm=ea94bbffdde332e9e7711a1bdb39f702a4a132456726e5e95a074e4055c5280db304ea16187d&scene=21#wechat_redirect)  
  
  
[VMware 披露严重的VCD Appliance认证绕过漏洞，无补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518139&idx=2&sn=4951a6280d077d8cd04309f6629182e3&chksm=ea94b6d1dde33fc71b53f7879454b257d922f83689acde6d310a195b1857f38098ca7685fcca&scene=21#wechat_redirect)  
  
  
[VMware 发现34个Windows 驱动易受设备完全接管攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518061&idx=3&sn=d4a64266b93ecf83c41d5c0c3914555f&chksm=ea94b607dde33f115aa5272499ee1b24c6ed4deaf860e06465531de74905247f9b9f11dd84db&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的 vCenter Server 代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517985&idx=2&sn=bf96d48a8e813b54efe7b49e1d451d91&chksm=ea94b64bdde33f5d32a676ffb901bafbd88a9925b05af28720a33389cee0066b41f2b27046cb&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/05/vmware-patches-severe-security-flaws-in.html  
  
  
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
  
