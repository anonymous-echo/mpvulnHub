> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523333&idx=2&sn=23cefe4214956d3fbac95c79c5396243

#  udisks 漏洞可用于获得Linux 主要发行版本的root权限  
Sergiu Gatlan  代码卫士   2025-06-19 10:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**攻击者可利用两个本地提权漏洞在运行 Linux 主要发行版本的系统上获得根权限。**  
  
第一个漏洞  
CVE-2025-6018  
位于  
 openSUSE Leap 15   
和  
 SUSE Linux Enterprise 15  
的可插拔认证模块  
 (PAM)   
框架中，可导致本地攻击者获得对  
 “allow_active”   
用户的权限。  
  
第二个漏洞  
CVE-2025-6019  
位于  
 libblockdev  
中，可导致  
 “allow_active”   
用户通过  
udisks   
守护进程（在多数  
Linux   
发行版本中默认运行的存储管理服务）获得根权限。  
  
虽然作为“本地到根”利用链的一部分，这两个漏洞的利用可导致攻击者迅速获得根权限并完全接管  
SUSE  
系统，但  
 libblockdev/udisks   
漏洞本身仍然极其危险。  
Qualys   
公司威胁研究部的高级经理  
 Saeed Abbasi   
表示，“尽管它名义上要求具有‘  
allow_active  
’特权，但几乎所有  
 Linux   
发行版本默认都交付  
 udisks  
，因此几乎任何系统都易受攻击。获得  
 ‘allow_active’   
的权限，包括这里披露的  
 PAM   
问题，进一步清除了这一障碍。组合利用这些漏洞，通过最小的投入即可获得根权限。”  
  
Qualys   
公司发现并报送了这两个漏洞，并开发了  
 PoC   
利用，成功利用  
CVE-2025-6019  
在  
 Ubuntu  
、  
Debian  
、  
Fedora   
和  
 openSUSE Leap 15   
系统上获得根权限。  
  
  
**立即修复**  
  
  
  
Qualys   
公司的安全公告团队已发布更多技术详情并提供了补丁链接。  
  
Abbasi   
表示，“根访问权限可导致篡改、持久化和横向移动，因此未修复的服务器威胁整个系统的安全。应修复所有位置的  
 PAM   
和  
 libblockdev/udisks   
漏洞来删除这一路径。鉴于  
 udisks   
的唯一性以及该利用的简单性，组织机构必须将其视作一个严重且普遍的风险，并立即部署补丁。”  
  
近年来，  
Qualys   
公司的研究人员发现了多个  
 Linux   
漏洞，它们可导致攻击者劫持未修复  
 Linux   
系统，甚至在默认配置情况下也不例外。研究人员发现的其它相关漏洞包括  
 Polkit pkexec   
组件中的漏洞 “  
PwnKit  
”、  
glibc ld.so   
动态加载器中的漏洞  
 “Looney Tunables”  
、  
Kernel   
文件系统层中的漏洞  
 “Sequoia”  
以及  
 Sudo Unix   
程序中的漏洞  
 “Baron Samedit”  
。  
  
“Looney Tunables”   
漏洞披露不久后，就有  
 PoC   
利用公开出现。一个月之后，攻击者开始利用该漏洞通过恶意软件  
 Kinsing   
窃取云服务提供商的凭据。最近该公司还修复了  
Ubuntu Linux 21.04  
及后续版本默认使用的  
 needrestart   
工具中的五个本地提权漏洞，它们已存在十年之久。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[看我如何通过 OpenAI o3 挖到 Linux 内核远程 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523149&idx=1&sn=0298267a08369cc3ea9bdbdec81eb788&scene=21#wechat_redirect)  
  
  
[恶意Go模块在高阶供应链攻击中传播 Linux 恶意软件擦除磁盘](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522922&idx=1&sn=1d2c75c455f1b47d5561919e7802db6e&scene=21#wechat_redirect)  
  
  
[Linux “io_uring” 安全盲点可导致隐秘的 rootkit 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522855&idx=2&sn=bd3476047b68eecaea9f3fd7914003b9&scene=21#wechat_redirect)  
  
  
[首款能感染 Linux 系统 boot 进程的恶意软件现身](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521662&idx=2&sn=c4ed3ee2f3d46bda404068445f0b9abe&scene=21#wechat_redirect)  
  
  
[这个 root 漏洞已存在10+年之久，影响Ubuntu Linux](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521546&idx=1&sn=deaef16f3522dccfad4051c26652ad09&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/linux/new-linux-udisks-flaw-lets-attackers-get-root-on-major-linux-distros/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
