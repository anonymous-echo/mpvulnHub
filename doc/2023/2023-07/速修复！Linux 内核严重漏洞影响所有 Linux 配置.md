#  速修复！Linux 内核严重漏洞影响所有 Linux 配置   
Jai Vijayan  代码卫士   2023-07-07 17:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**今年六月中旬，一名安全研究员发现并向 Linux 管理员报告了一个位于 Linux 内核中的一个严重漏洞 (CVE-2023-3269)，它影响 Linux 内核6.1至6.4，可使攻击者在受影响系统上提升权限。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRicJe1G0dSEr7hrV6alX1lI86sGbzVibc7kh7KaSzNjD1hqevItSG5vPpOH8PQRxGlapskGQxeusxA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRicJe1G0dSEr7hrV6alX1lIgwEK7OHSFHaiaQP0IbCAUSibJZcEQqvySnjFnpTwhIRc6mycG2nEq1GQ/640?wx_fmt=gif "")  
  
**影响所有 Linux 配置**  
  
北京大学的安全研究员 Ruihan Li 发现了该漏洞，并表示它影响几乎所有 Linux 内核配置且触发仅需最小能力。由 Linux 创始人 Linux Torvalds 牵头的响应团队花费大约两周的时间开发出一系列补丁修复该漏洞。Li 在GitHub 发布的文章中指出，“6月28日，在Linux 内核6.5的合并窗口期间，该修复方案被并入 Linus 树中。”Linus 提供了一条全面的合并信息，从技术角度阐明该补丁系列。  
  
之后，这些补丁向后兼容至内核6.1.37、6.2.11和6.4.1中，“在7月1日有效地解决了‘Stack Rot’漏洞。完整的利用代码和全面的 write-up将在不晚于7月底的时间公开。”  
  
StackRot 供 Linux 内核处理栈扩展，即自动增长或扩展运行进程的栈内存。管理 Linux 内核中虚拟内存空间的数据结构处理特定内存管理函数的方式导致RCU导致UAF（UAFBR）问题。UAFBR漏洞结合释放后使用漏洞以及Linux 内核中的读复制更新 (RCU) 机制来同步共享数据的使用。释放后使用漏洞即软件在内存引用被取消分配或释放后仍然使用它。这就使攻击者将任意代码插入已被释放但仍然被使用的内存空间。Li 提到，“低权限的本地用户可利用该漏洞攻陷内核并提升权限。”该 Linux 内核使用 RCU 机制释放或取消分配已用的内存空间。  
  
虽然 UAFBR 漏洞可能具有危险性，但由于使用 RCU 回调时会释放内存空间，因此内存取消分配会导致某种延迟，从而使该漏洞难以利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRicJe1G0dSEr7hrV6alX1lIgwEK7OHSFHaiaQP0IbCAUSibJZcEQqvySnjFnpTwhIRc6mycG2nEq1GQ/640?wx_fmt=gif "")  
  
**史无前例的利用**  
  
  
Li 指出，StackRot 的利用可能是第一个成功利用 UAFBR 漏洞的利用。Li 提到，“就我所知，目前尚不存在针对 UAFBR 的可用利用。”这是 UAFBR 漏洞首次被证明可利用的第一个实例。  
  
由 Torvalds 牵头开发的修复方案从本质上来讲是修改了内核的用户模式栈扩展代码，阻止释放后使用条件的产生。Torvalds 表示，“从技术上来讲，这实际上是我们本应该做的事情。但由于严格来讲我们不需要，所以是懒惰的结果（“投机主义”听起来更好，不是吗？）。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Linux NetFilter内核新漏洞可导致攻击者获得 root 权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516449&idx=2&sn=3d707d11e6ef16e4beb82600320a1003&chksm=ea94b04bdde3395db7478af8cdc09378319ac019551a410d1a90692898da9314af37ab22b878&scene=21#wechat_redirect)  
  
  
[Linux 内核逻辑可导致主要云提供商遭 Spectre 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516258&idx=1&sn=398c66d249c56db94150c273a96baea7&chksm=ea94b108dde3381ec91da60fa69e45506cb15bf2a5dbbb1eec8f5a1dc2988530134c4047f0f3&scene=21#wechat_redirect)  
  
  
[脏凭据 (DirtyCred)：已存在8年的Linux内核提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513659&idx=1&sn=f519e177177bc04c8fe5154fbd6457fd&chksm=ea948751dde30e47a24f45d953fba31e321b14e6b9f7f9b1a15e672c312531ec5d03817ab011&scene=21#wechat_redirect)  
  
  
[QNAP 提醒用户修复 NAS 设备中的高危 Linux Sudo 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516096&idx=3&sn=82f067c61adcd0aa4a98ca6165d9c9d3&chksm=ea948eaadde307bc40d0015e6feadf0f1264ab387fd2b2500439ce984d5722ddf2e79da15ca4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/vulnerabilities-threats/stackrot-linux-kernel-bug-exploit-code  
  
  
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
  
