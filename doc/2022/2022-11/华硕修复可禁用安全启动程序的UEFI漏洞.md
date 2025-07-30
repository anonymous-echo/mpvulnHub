#  华硕修复可禁用安全启动程序的UEFI漏洞   
Sergiu Gatlan  代码卫士   2022-11-29 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTGcIr99kJDEmlIkWhE8eKGV7v4ejPZwhKn5qia7xUeHaKicTDZKTlWnvZ9Z44ROVJ7bkweTxNmrW0g/640?wx_fmt=gif "")  
  
**华硕修复了影响多款笔记本机型的一个高危漏洞 (CVE-2022-4020)，它可导致本地攻击者禁用目标系统上的UEFI 安全启动特性。**  
  
  
安全启动安全特性通过一个可信平台模块 (TPM) 和UEFI固件拦截计算机上的不可信操作系统引导程序，阻止恶意代码如rootkit何bootkit在启动进程中进行加载。  
  
ESET公司的恶意软件研究员 Martin Smolar 指出，该漏洞是在某些客户的华硕 Notebook 设备上的 HQSwSmiDxe DXE 驱动上发现的。  
  
具有高权限的攻击者可在低复杂度攻击中滥用该漏洞，通过修改BootOrderSecureBOOTdISABLE nvram 变量，无需用户交互即可修改 UEFI 安全启动设置，以禁用安全启动。  
  
华硕公司提到，“攻击者发现，攻击者可创建多个NVRAM 变量（该变量的实际值并不重要，受影响固件驱动仅检查变量是否存在），更改 Secure Boot 设置。”攻击者在受影响的华硕笔记本上利用该漏洞并关闭安全启动特性后，可劫持OS加载进程并加载未签名的引导程序，绕过或禁用防护措施并以系统权限部署恶意payload。  
  
受影响的华硕笔记本机型完整清单包括Aspire A315-22、A115-21、A315-22G、Extensa EX215-21和 EX215-21G。  
  
  
**BIOS更新可用，Windows 更新将发布**  
  
  
  
  
  
华硕公司指出，“华硕建议将BIOS更新至最新版本解决该问题。该更新将包含在Windows 关键更新中。”客户也可从华硕支持网站中下载BIOS更新并手动在受影响系统上进行部署。  
  
相关厂商也修复了类似漏洞。  
  
允许攻击者在OS启动前运行未签名的恶意代码将导致严重后果，包括部署可在OS重新安装和绕过安全解决方案提供的恶意软件防护之间持续的恶意软件。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[华硕：警惕 Cyclops Blink 恶意软件正在攻击路由器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511001&idx=1&sn=0238153b461824d38ec21531bdbb393d&chksm=ea949ab3dde313a5170ec185487dde03b9bbc977c5c0e051d87e36c4caae41139956f79c0d0f&scene=21#wechat_redirect)  
  
  
[研究员在3个微软签名的引导程序中发现UEFI安全引导绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513567&idx=3&sn=d892a2bef63e676b13ad309c36512d2a&chksm=ea9484b5dde30da3176e2496790330c7f56301cfe665999b7c36dc7e274e28f4edc4770ef49d&scene=21#wechat_redirect)  
  
  
[16个UEFI固件漏洞影响惠普多个产品线，其中1个影响无数厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510841&idx=2&sn=9cb332953ae69603c64a2e0c35bb1a45&chksm=ea949a53dde313452596676eaf1949769d92d1122e14fe012b385d90d1d767afc292cdc50c5c&scene=21#wechat_redirect)  
  
  
[LoJax：首个 UEFI rootkit 遭 APT28 利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488200&idx=4&sn=93bbf7ad196dc5f42483d9d10e495663&chksm=ea9723a2dde0aab41af580af4c85129040b4c0bb61860c924250cfd35ced11a318df619a0abf&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/acer-fixes-uefi-bugs-that-can-be-used-to-disable-secure-boot/  
  
  
题图：  
Pexels License  
  
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
  
