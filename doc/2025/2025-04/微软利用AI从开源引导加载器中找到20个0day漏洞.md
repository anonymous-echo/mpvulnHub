#  微软利用AI从开源引导加载器中找到20个0day漏洞   
Bill Toulas  代码卫士   2025-04-01 18:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**微软通过其受AI驱动的 Security Copilot 在开源引导加载器 GRUB2、U-Boot 和 Barebox 中发现了20个0day漏洞。**  
  
  
  
  
  
  
  
GRUB2（GRand Unified Bootloader）是多数Linux 发行版本如Ubuntu的默认引导加载器，而U-Boot 和 Barebox 通常用于嵌入式和物联网 (IoT) 设备中。微软在 GRUB2 中发现了11个漏洞，包括位于文件系统解析器中的整数和缓冲区溢出漏洞、命令漏洞以及加密比对中的侧信道漏洞。该公司还在U-Boot 和 Barebox 解析 SquashFS、EXT4、CramFS、JFFS2和符号链接中发现了9个缓冲溢出漏洞，不过利用它们需要物理访问权限。  
  
这些新发现的漏洞影响依赖于UEFI Secure Boot 的设备，如果满足合适的条件，攻击者可绕过安全防护措施，在设备上执行任意代码。虽然利用这些漏洞可能需要对设备拥有本地访问权限，但此前的bootkit 攻击如BlackLotus 通过恶意软件感染实现了这一目标。  
  
微软解释称，“虽然威胁者可能需要具备设备物理访问权限才能利用 U-boot 或 Barebox 中的漏洞，但在 GRUB2 中，这些漏洞可被进一步用于绕过 Secure Boot 并安装隐秘 bootkit 或者可能绕过其它安全机制如 BitLocker。安装此类bootkit 可造成重大影响，因为威胁者可借此完全控制设备，从而控制引导进程和操作系统、攻陷网络上的其它设备并实施其它恶意活动。此外，它可造成可持久性恶意软件，而即使重装操作系统或替换硬盘驱动也无济于事。”  
  
如下是微软从 GRUB2 中发现的漏洞概述：  
  
- CVE-2024-56737 – 位于HFS 文件系统挂载中的缓冲溢出漏洞，因non-null-terminated 字符串上的不安全 strcpy 造成。  
  
- CVE-2024-56738 – 位于加密比对函数(grub_crypto_memcmp not constant-time) 中可导致侧信道攻击的漏洞。  
  
- CVE-2025-0677 – 位于UFS 符号链接处理中的整数溢出漏洞，可导致缓冲区溢出。  
  
- CVE-2025-0678 – Squash4 文件读取中的整数溢出漏洞，可导致缓冲区溢出。  
  
- CVE-2025-0684 – ReiserFS 符号链接处理中的整数溢出漏洞，可导致缓冲区溢出。  
  
- CVE-2025-0685 – JFS 符号链接处理中的整数溢出漏洞，可导致缓冲区溢出。  
  
- CVE-2025-0686 – RomFS 符号链接处理中的整数溢出漏洞，可导致缓冲区溢出。  
  
- CVE-2025-0689 – UDF 块处理中的界外读漏洞。  
  
- CVE-2025-0690 – 读命令（键盘输入句柄）中的有符号整数溢出和界外写漏洞。  
  
- CVE-2025-1118 – dump 命令导致任意内存读（应在生产中禁用）。  
  
- CVE-2025-1125 – Integer overflow in HFS 压缩文件开放中的整数  
  
  
  
溢出漏洞，可导致缓冲区溢出。  
  
除了CVE-2025-0678被评级为“高危”（CVSS v3.1 评分7.8）外，以上漏洞均为中危级别。微软表示，Security Copilot 在大规模的复杂数据库如GRUB2中极大地加速了漏洞发现流程，节约了大概一周的手动分析时间。  
  
该AI 工具不仅找到了0day 漏洞，而且还提供了目标缓解建议，加速了安全补丁的发布，尤其是在志愿者贡献者和小型核心团队支持的开源项目中尤为明显。GRUB2、U-boot 和 Barebox 在2025年2月发布了这些漏洞的安全更新，因此用户应尽快更新至最新版本以缓解漏洞。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[OpenAI 严重漏洞最高赏金提高至10万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522605&idx=1&sn=d013414cab5f1de1d4ec9080c742585e&scene=21#wechat_redirect)  
  
  
[报告：89%的企业生成式AI使用不可见，或造成严重风险](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522363&idx=2&sn=30341de9895d38b4b0408b086cf54477&scene=21#wechat_redirect)  
  
  
[OpenAI禁用朝鲜黑客的ChatGPT账号](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522340&idx=3&sn=b65a3d52caf2088d9510aff887ea70f8&scene=21#wechat_redirect)  
  
  
[微软扩展Copilot AI漏洞奖励计划范围，提高赏金](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522200&idx=1&sn=7bf07566564fbc663142355517974f16&scene=21#wechat_redirect)  
  
  
[2025年值得关注的6个AI相关安全趋势](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521960&idx=1&sn=0d6a17c24199d5949c4ce8e862ae6f51&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/securit  
y/microsoft-uses-ai-to-find-flaws-in-grub2-u-boot-barebox-bootloaders/  
  
  
  
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
  
