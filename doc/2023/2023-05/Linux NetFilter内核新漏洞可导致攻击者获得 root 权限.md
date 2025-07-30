#  Linux NetFilter内核新漏洞可导致攻击者获得 root 权限   
Bill Toulas  代码卫士   2023-05-10 15:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX6Inlu2SGYBwg77ZPry2yAAgEMG81vlTyibUKjGaL84ZXJicHMLoQhia6qGkiaNGZjNnwokM7Ql83icObA/640?wx_fmt=png "")  
  
**Linux NetFilter 内核中出现一个新漏洞 (CVE-2023-32233)，可导致低权限本地用户提权至 root 级别，从而完全控制系统。该漏洞的严重程度尚未得到评估。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRk0LzsVJ6POk2nO2a5ib7ajtoPeSBuPUk31ibXK6dIj1yuSQkNB1PEzsdp2WdEDxPKJYTKJAMbMkiaQ/640?wx_fmt=png "")  
  
  
该漏洞产生的原因在于，Netfilter nf_tables 的配置接收不合法更新，从而导致不合法批量请求的情况出现，引发子系统的内部状态损坏。Netfilter 是一款内置在 Linux 内核中的数据包过滤和网络地址转换 (NAT) 框架，通过前端工具如 IPtables 和 UFW 进行管理。  
  
Linux 基金会昨天发布新的安全公告指出，损坏该系统内部状态可导致释放后使用漏洞，从而导致在内核内存中执行任意读写。发布邮件列表的研究人员指出，已经创建相关 PoC。这名研究员表示该漏洞影响多个 Linux 内核发布，包括当前版本 6.3.1。不过要利用该漏洞，攻击者首先需要具有对 Linux 设备的本地访问权限。  
  
工程师 Pablo Neira Ayuso 通过提交Linux 源代码 commit 解决了该漏洞，他通过引入管理 Netfilter nf_tables 子系统中的匿名集生命周期的两个函数修复了该漏洞。该修复方案通过正确管理匿名集的激活和禁用和阻止进一步更新，阻止了内存损坏以及攻击者利用该漏洞提权至 root 级别的可能性。  
  
  
**Exploit 不久将公开**  
  
  
发现并报告该漏洞的研究员 Patryk Sondej 和 Piotr Krysiuk 已经开发出一款 PoC，可导致低权限本地用户在受影响系统上启动 root shell。该研究人员与 Linux 内核团队私下共享了这些 exploit，协助后者开发出解决方案并提供了关于利用技术的详细描述和 PoC 源代码。  
  
研究员进一步解释称，将在下周发布该漏洞的 exploit 以及关于利用技术的完整详情。他们提到，“根据 linux-distros 列表的政策，该 exploit 丙戌在本安全公告发布的7天内发布。为了满足这一要求，我将在周一15号发布利用技术以及利用源代码。”  
  
获得 Linux 服务器的root 级别权限对于攻击者而言价值较高，他们实际上一直都在关注 Openwall 公告获取新的安全信息以便利用。该漏洞的一个缓解因素是远程攻击者必须首先建立对目标系统的本地访问权限才能利用该漏洞。  
  
  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[【已复现】Linux Kernel 权限提升漏洞安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516406&idx=2&sn=b0ac9c5e379181f6de71e5f0afdecc23&chksm=ea94b19cdde3388ae47cb6b4ff1e53afb3905e4b6e68d53559b0769ef5360da2cb7152a72bae&scene=21#wechat_redirect)  
  
  
[QNAP 提醒用户修复 NAS 设备中的高危 Linux Sudo 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516096&idx=3&sn=82f067c61adcd0aa4a98ca6165d9c9d3&chksm=ea948eaadde307bc40d0015e6feadf0f1264ab387fd2b2500439ce984d5722ddf2e79da15ca4&scene=21#wechat_redirect)  
  
  
[【已复现】Linux Kernel 本地权限提升漏洞(CVE-2022-2602)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515101&idx=1&sn=ee4faf98290cc95a4c8fbff9f40a78b0&chksm=ea948ab7dde303a194ba3873d4707e52a83fb260bd72035306a1bd44c0aba5ca844e99d5603d&scene=21#wechat_redirect)  
  
  
[黑客利用遭PRoot隔离的文件系统劫持Linux设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514929&idx=2&sn=545b07840e9a3fbc97575c0910ce8a0d&chksm=ea948a5bdde3034db90672383a904a56bcb7ace236030f80e826e63d18dbbb43b77025264ca1&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-linux-kernel-netfilter-flaw-gives-attackers-root-privileges/  
  
  
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
  
