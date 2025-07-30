#  微软发现绕过苹果 SIP 根限制的 macOS 漏洞   
Sergiu Gatlan  代码卫士   2023-05-31 17:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**苹果最近修复了一个漏洞，可导致具有 root 权限的攻击者绕过系统完整性防护 (SIP)，安装“无法删除的”恶意软件并绕过透明度同意和管控 (TCC) 安全检查访问受害者的私密数据。**  
  
  
  
  
该漏洞的编号是CVE-2023-32369，由微软安全研究团队发现并报告给苹果公司。苹果已在5月18日发布的 macOS Ventura 13.4、macOS Monterey 12.6.6和macOS Big Sur 11.7.7 安全更新中修复了该漏洞。  
  
SIP又被称为 “rootless”，它是一种 macOS 安全机制，可通过在根用户账户上添加限制的方式，在操作系统的受保护区域内，阻止潜在的恶意软件修改某些文件夹和文件。SIP 的运行原则是，仅由苹果或由处理特殊权限如苹果软件更新和安装工具签名的进程应当被授权修改受 macOS 保护的组件。  
  
还有一点需要注意的是，目前并不存在无需重启系统和启动 macOS Recovery（内置恢复系统）来禁用 SIP 的方法。MacOS Recovery 要求物理访问已遭攻陷的设备。  
  
然而，微软公司的研究人员发现，具有根权限的攻击者可滥用 macOS 迁移助手工具绕过 SIP 安全执行。MacOS 迁移助手工具是一款内置的 macOS app，使用绕过源自 com.apple.rootless.install.heritable 权限的SIP能力的 systemmigrateiond 守护进程。  
  
安全研究人员演示称，具有 root 权限的攻击者可通过 AppleScript 自动化缓解进程并在将其添加到 SIP 的例外清单后启动恶意 payload，而无需重启系统和从 macOS Recovery 进行引导。  
  
微软威胁情报团队表示，“通过关注由苹果签名的系统进程以及 com.apple.rootless.install.heritable 权限，我们发现两个子进程可在绕过 SIP 检查的安全上下文中获得任意代码执行权限。”  
  
任意 SIP 绕过具有重大风险，尤其是在被恶意创建人员利用时更是如此，原因在于绕过可使恶意代码造成深远影响，如创建无法通过标准删除方法删除的受 SIP 保护的恶意软件。  
  
绕过也极大地扩展了攻击面并导致攻击者通过任意内核代码执行的方式篡改系统完整性，并可能安装 rootkit，隐藏恶意进程和文件，从而躲避安全软件检测。  
  
绕过 SIP 防护还可使透明度同意和管控 (TCC) 策略被完全绕过，从而导致威胁行动者替换 TCC 数据库并获得对受害者私密数据不受限制的访问权限。  
  
这并非微软研究人员近年来发现的首个 macOS 漏洞，另外一个 SIP 绕过 Shrootless 在2021年出现，可使攻击者在受陷 Mac 上执行任意操作，将权限提升至 root 级别并可能在易受攻击设备上安装 rootkit。  
  
最近，微软首席安全研究员 Jonathan Bar Or 还发现了被称为 Achilles 的安全漏洞。攻击者可通过能够绕过 Gatekeeper 执行限制的不可信应用部署恶意软件。他还发现了另一款 macOS 漏洞 powerdir，可导致攻击者绕过 TCC 技术访问用户的受保护数据。  
  
  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Zoom 修复Windows 和 MacOS 平台上的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515248&idx=3&sn=efcb69755e1725002e1132202e9fd131&chksm=ea948d1adde3040cde57da5db0825a83b7d3aab9f8d9b9a0736d4fa3ad90a2a44810426cdecd&scene=21#wechat_redirect)  
  
  
[苹果紧急发布macOS和iOS安全补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513005&idx=4&sn=d917d7842e64544a3258d7d993033621&chksm=ea9482c7dde30bd1b1df774d8f19c6c8ba630dfa0e795ba0ef73db4a1d5ed532d9bcbef75ce1&scene=21#wechat_redirect)  
[微软详述影响苹果 iOS、iPadOS、macOS 设备的沙箱逃逸漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512944&idx=2&sn=d4eadd75c1a517158050fee4b426c96d&chksm=ea94821adde30b0ca1a9fe01b01d12a5925479f01abfd7dd02cf3d8fa29e782d5524bdf64933&scene=21#wechat_redirect)  
  
  
[西部数据app可导致Windows 和 macOS 提权](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511011&idx=1&sn=875472800b32dc8b11c92a6c49270a9c&chksm=ea949a89dde3139f3a9f85a1ace44ff2856996e021b7e086def08bc66230ec0ed14647c4ee59&scene=21#wechat_redirect)  
  
  
[开源的Linphone SIP 电话存在栈漏洞，可远程使客户端设备崩溃](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507604&idx=1&sn=7171a6a61d5cf51a7319a013f598da2d&chksm=ea94effedde366e814e7d08c75786a53f6282c8df842a1919c580db26ce46627ab86ccc64f4c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/microsoft-finds-macos-bug-that-lets-hackers-bypass-sip-root-restrictions/  
  
  
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
  
