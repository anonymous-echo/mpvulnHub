> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523602&idx=1&sn=3ec9fd59b332276a13eb21d88cdd9217

#  Vmware 修复 Pwn2Own 柏林大赛上遭利用的四个 ESXi 0day漏洞  
Lawrence Abrams  代码卫士   2025-07-18 10:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**VMware 修复了位于 VMware ESXi、Workstation、Fusion 和 Tools 中的四个 0day漏洞，它们在2025年5月举行的柏林Pwn2Own 大赛上曾被成功利用。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRuqupibSSLZFWiacExROLJicCraFnJRQzIf3t7Wf5NqYic6z6saibAzuu4xz2WzZZ2BmxKwgqIGovwung/640?wx_fmt=png&from=appmsg "")  
  
  
其中三个漏洞的严重性评级为9.3分，可导致在 guest 虚拟机中运行的程序在主机上执行命令，它们是CVE-2025-41236、CVE-2025-41237和CVE-2025-41238。  
  
这些漏洞概述如下：  
  
- CVE-2025-41236：VMware ESXi、Workstation和Fusion 的 VMXNET3虚拟网络适配器中存在一个整数溢出漏洞。STARLabs SG 公司的研究员 Nguyen Hoang Thach 在Pwn2Own 大赛上利用了该漏洞。  
  
- CVE-2025-41237：VMware ESXi、Workstation和Fusion 的 VMCI（虚拟机通信界面）中包含一个整数下溢漏洞，可导致越界写问题，由 Reverse Tactics 公司的研究员 Corentin BAYET 在 Pwn2Own 大赛上利用。  
  
- CVE-2025-41238：VMware ESXi、Workstation和Fusion 的 VMCI（虚拟机通信界面）控制器中包含一个整数下溢漏洞，可导致越界写。在虚拟机上拥有本地管理员权限的恶意人员可利用该漏洞，在虚拟机VMX 流程在主机上运行时，执行代码。Synacktiv 团队成员 Thomas Bouzerar 和 Etienne Helluy-Lafont曾在 Pwn2Own 大赛上利用该漏洞。  
  
  
  
第四个漏洞CVE-2025-41239是评分为7.1的信息泄露漏洞，也是由 Reverse Tactics 公司的研究员 Corentin BAYET 发现的，他在Pwn2Own 大赛上组合CVE-2025-41237实施利用。  
  
VMware 公司并未提供任何应变措施，因此唯一的修复方案是安装软件新版本。值得注意的是，CVE-2025-41239影响 Windows 版的 VMware Tools，因此需要不同的升级流程。这些漏洞均在2025年柏林 Pwn2Own 大赛上展示，研究人员在本次黑客大赛上共发现29个唯一0day 并获得1078750美元的赏金。  
  
  
开源  
卫士试用地址：  
https://oss.qianxin.com/#/login  
  
  
代码卫士试用地址：https://sast.qianxin.com/#/login  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[VMware 紧急修复多个漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523082&idx=1&sn=1ddbeb4f3e454706eafa9900777eed09&scene=21#wechat_redirect)  
  
  
[供应链攻击：通过Vmware 工具RVTools传播Bumblebee 恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523052&idx=2&sn=f996a017b72f7d810caca56e8042083b&scene=21#wechat_redirect)  
  
  
[火狐修复Pwn2Own大会上利用的2个0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523071&idx=1&sn=8d8429be1cebb442aaca091ca13012be&scene=21#wechat_redirect)  
  
  
[2025 Pwn2Own 柏林黑客大赛落下帷幕 Master of Pwn 诞生](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523052&idx=1&sn=4df3d545b249e2eb91adcbfd5893330b&scene=21#wechat_redirect)  
  
  
[2025年Pwn2Own柏林大赛奖金和目标公布](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522389&idx=1&sn=6ae18cd3962e778a6a16fb1f74a1b7aa&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/vmware-fixes-four-esxi-zero-day-bugs-exploited-at-pwn2own-berlin/  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
