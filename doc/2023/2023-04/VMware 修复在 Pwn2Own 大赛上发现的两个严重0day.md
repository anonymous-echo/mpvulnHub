#  VMware 修复在 Pwn2Own 大赛上发现的两个严重0day   
Sergiu Gatlan  代码卫士   2023-04-26 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**VMware 发布安全更新，修复了两个0day 漏洞。攻击者可组合利用这些漏洞，在运行未修复 Workstation 和 Fusion 软件管理程序的版本上获得代码执行权限。**  
  
STAR Labs 研究人员曾在一个月前的温哥华 Pwn2Own 大赛上演示了含这两个漏洞的利用链。  
  
第一个漏洞是位于蓝牙设备共享功能中的栈缓冲区溢出漏洞，CVE-2023-20869，可导致本地攻击者以在主机上运行的虚拟机VMX进程的身份执行代码。第二个漏洞CVE-2023-20870是位于与虚拟机共享主机蓝牙设备功能中的信息泄露漏洞，可导致恶意人员读取包含在虚拟机管理程序中的权限信息。  
  
VMware 还分享了临时缓解措施，供无法立即部署补丁的管理员使用。  
  
如需删除攻击向量，用户可取消勾选受影响设备上的“与虚拟机共享蓝牙设备”选项，关闭虚拟机上的蓝牙支持。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT01Op6m7ufib1jSxtwyykBjTtatDpicVVAaZXcUlgYp9Q05u58OmKAW5Wkic0icVu5mx9Y28WibXmWH7A/640?wx_fmt=gif "")  
  
**修复其它两个漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT01Op6m7ufib1jSxtwyykBjicx26Plo9t9ZIgFUhvjcKb0oibGeNUfzdp1yjayrLEdTfP9f6v9tHnSA/640?wx_fmt=gif "")  
  
  
  
VMware 还修复了影响VMware Workstation 和 Fusion 托管管理程序中的另外两个漏洞。  
  
CVE-2023-20871是位于 VMware Fusion Raw Disk 中的高危提权漏洞，可被对主机操作系统具有读写权限的攻击者用于提升权限并获得对主机操作系统的根访问权限。  
  
第四个漏洞是CVE-2023-20872，是位于 SCSI/DVD 设备模拟中的“界外读/写漏洞”，同时影响 Workstation 和 Fusion 产品。该漏洞可被用于在虚拟机管理程序上获得代码执行权限。该漏洞的临时缓解措施要求管理员“从虚拟机上删除 CD/DVD 设备或者配置虚拟机不使用虚拟的 SCSI 控制器。”  
  
上周，VMware 还修复了一个严重的 vRealize Log Insight 漏洞，它可被未认证攻击者获得易受攻击设备的远程执行权限。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的 vRealize 反序列化漏洞，可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516298&idx=2&sn=1625888e8762acc4a48a665717933497&chksm=ea94b1e0dde338f62127926fd478fb71059387a0ae20c0fd3e0d9c2f4c6405f946351edeb454&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的Carbon Black App Control漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515674&idx=1&sn=a2545f99534c8c181bb5022bbc3989e1&chksm=ea948f70dde306661e8a7532ffad9fe411f3cd1cbcb74c5ae58c6e4f394d04247cb807e3ce08&scene=21#wechat_redirect)  
  
  
[VMware Workstation中存在高危的提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515478&idx=3&sn=6fb6defbf6e53fa69b775f37bed7bbfd&chksm=ea948c3cdde3052a630422bf457d44f24d36236b6ca666929b3ab6ce6cf3774fc646a1dde7ca&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的ESXi和vRealize 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515027&idx=2&sn=d86995b203eb6824e5179dc7d57b8bce&chksm=ea948af9dde303ef8f28410ce0027472253b95bbd9447f1a2c538a07bda78c61567e5252f1e7&scene=21#wechat_redirect)  
  
  
[VMware：速修复这三个严重的 Workspace ONE Assist 软件漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514441&idx=2&sn=a6a4722590de8e046966eacff21ccc02&chksm=ea948823dde301350f7cab83e012dd91120da7da9ed74b0e8ad2b487f5358c0361971fe016a4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/vmware-fixes-critical-zero-day-exploit-chain-used-at-pwn2own/  
  
  
题图：Pixabay License  
  
  
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
  
