#  AI赋能代码审计：利用微软Security Copilot辅助挖出20个漏洞   
安全内参编译  安全内参   2025-04-03 16:04  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7vhODd2NpT9htG8vABs82YKUn9ib8oc9NVCK83Tiayv09ZFWakH48ZnEGHubHYe7POPdiceIOCvWPO0w/640?wx_fmt=webp&from=appmsg "")  
  
  
微软安全研究员利用Security Copilot辅助分析大型复杂代码项目（GRUB2、U-Boot和Barebox），在其中找出了20个零日漏洞，据估算Security Copilot给研究员节约了约一周的手动分析时间。  
  
  
前情回顾·  
大模型漏洞挖掘能力动态  
- [首次利用大模型发现内存安全零日漏洞 (附大模型挖洞经验)](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247512989&idx=1&sn=3db390e902ccf6b370d33cf57039a63b&scene=21#wechat_redirect)  
  
  
- [突破！首次利用大模型在真实环境发现十余个零日漏洞](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247512862&idx=1&sn=985a72021a5e4cbab44d293299fed951&scene=21#wechat_redirect)  
  
  
- [美国政府发起超亿元奖金挑战赛，悬赏能挖漏洞的下一代AI](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247509480&idx=1&sn=1e6e1dd3e9bb9d765a595f725995be0f&scene=21#wechat_redirect)  
  
  
  
  
安全内参4月3日消息，微软通过其AI驱动的Security Copilot发现了20个此前未知的漏洞，这些漏洞存在于GRUB2、U-Boot和Barebox等开源引导加载程序中。  
  
  
**开源引导程序被曝高危漏洞，**  
  
****  
**可本地预装引导木马**  
  
  
GRUB2是大多数Linux发行版（如Ubuntu）的默认引导加载程序，U-Boot和Barebox则通常用于嵌入式设备和物联网设备。  
  
微软发现，GRUB2中存在11个漏洞，其中包括文件系统解析器中的整数溢出和缓冲区溢出、命令缺陷，以及加密比较中的旁道攻击。  
  
此外，微软还在U-Boot和Barebox中发现了9个缓冲区溢出漏洞，涉及SquashFS、EXT4、CramFS、JFFS2和符号链接的解析。这些漏洞需要物理访问才能被利用。  
  
这些新发现的漏洞影响了依赖UEFI安全启动的设备。在特定条件下，攻击者可以绕过安全保护机制，执行任意代码。  
  
虽然利用这些漏洞可能需要设备的本地访问，但像BlackLotus这样的引导木马攻击，已经证明通过恶意软件也能实现此类攻击。  
  
微软解释道：“尽管威胁行为者可能需要物理访问设备才能利用U-Boot或Barebox中的漏洞，但在GRUB2的情况下，漏洞可能被进一步利用来绕过安全启动，安装隐形引导木马，或者绕过BitLocker等安全机制。”  
  
“安装此类引导木马的后果极为严重，因为它可以让威胁行为者完全控制设备，进而控制启动过程和操作系统，破坏网络中其他设备，并实施其他恶意活动。”   
  
“此外，这还可能导致持久性恶意软件，即使重新安装操作系统或更换硬盘后也能继续存在。”  
  
  
**Security Copilot辅助挖洞，**  
  
****  
**节约了一周人工分析时间**  
  
  
微软威胁情报中心的研究员使用静态代码分析工具CodeQL、模糊测试工具AFL++等，对GRUB2模拟器（grub-emu）进行模糊测试、手动代码分析以及利用微软Security Copilot辅助，成功发现了这些漏洞。  
  
在使用Security Copilot时，研究员首先分析了哪些引导加载程序功能最有可能存在漏洞，Copilot识别出网络、文件系统和加密签名是关键关注领域。考虑到网络漏洞正在持续分析，且加密通常由UEFI处理，研究员决定重点关注文件系统部分。  
  
以JFFS2文件系统代码为例，研究员要求Copilot寻找所有潜在的安全问题，包括可利用性分析。Copilot识别了多个安全问题，研究员进一步请求Copilot筛选出其中五个最紧急的问题。在对这五个问题进行手动审查后，发现其中三个是误报，一个不可利用，剩下的问题是一个需要关注并进一步调查的整数溢出漏洞。  
  
研究员利用Security Copilot成功地在其他GRUB2文件中识别了类似的漏洞模式。尽管存在误报的可能性，研究员还是对GRUB2进行了全面验证和审查，以确保没有遗漏任何问题，并确认了与整数溢出相关的其他漏洞。  
  
微软表示，Security Copilot大大加快了在像GRUB2这样的大型复杂代码库中发现漏洞的过程，节省了大约一周的手动分析时间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7vhODd2NpT9htG8vABs82YK6FLpyJegKhicsibtXS02WiawibGfHEJambzSOUknOQ1tSLGurh4hflp3ag/640?wx_fmt=other&from=appmsg "")  
  
图：Copilot识别漏洞并提出修复建议  
  
不仅如此，AI工具还能够识别出之前未曾发现的漏洞，并提供有针对性的缓解建议，这些建议能够加速安全补丁的发布，尤其是对于那些由志愿者和小型核心团队支持的开源项目。  
  
微软表示，利用分析中的发现，Security Copilot还在使用共享代码的项目中，识别出了类似的错误，比如U-Boot和Barebox。  
  
  
**相关漏洞已发布安全更新**  
  
  
以下是微软在GRUB2中发现的11个漏洞。  
- CVE-2024-56737：由于对非空终止字符串使用不安全的strcpy，导致HFS文件系统挂载中的缓冲区溢出。  
  
- CVE-2024-56738：加密比较函数中存在旁道攻击（grub_crypto_memcmp不是常数时间）。  
  
- CVE-2025-0677：UFS符号链接处理中的整数溢出导致缓冲区溢出。  
  
- CVE-2025-0678：Squash4文件读取中的整数溢出导致缓冲区溢出。  
  
- CVE-2025-0684：ReiserFS符号链接处理中的整数溢出导致缓冲区溢出。  
  
- CVE-2025-0685：JFS符号链接处理中的整数溢出导致缓冲区溢出。  
  
- CVE-2025-0686：RomFS符号链接处理中的整数溢出导致缓冲区溢出。  
  
- CVE-2025-0689：UDF块处理中的越界读取。  
  
- CVE-2025-0690：读取命令中存在带符号整数溢出和越界写入（键盘输入处理程序）。  
  
- CVE-2025-1118：dump命令允许任意内存读取（应在生产环境中禁用）。  
  
- CVE-2025-1125：HFS压缩文件打开时的整数溢出导致缓冲区溢出。  
  
上述所有漏洞的严重性均为中等，只有CVE-2025-0678被评为“高危”（CVSS v3.1评分：7.8）。  
  
微软还在U-Boot和Barebox中分别发现了4、5个漏洞，不过暂无漏洞信息公开。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7vhODd2NpT9htG8vABs82YKPl9ef3TicpyCI6a0Q4c0fONlOFcf820nHgWcBposyfauQur5HDyKK3Q/640?wx_fmt=png&from=appmsg "")  
  
GRUB2、U-Boot和Barebox在2025年2月发布了这些漏洞的安全更新，因此更新到最新版本应该能有效缓解这些漏洞。  
  
  
**参考资料：bleepingcomputer.com**  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
