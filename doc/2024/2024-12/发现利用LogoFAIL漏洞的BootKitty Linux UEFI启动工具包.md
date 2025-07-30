#  发现利用LogoFAIL漏洞的BootKitty Linux UEFI启动工具包   
鹏鹏同学  黑猫安全   2024-12-03 23:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibibPpyRNUZNvU5gNvdBHK50xVfoEfLwgtukxkYe8NrHmEO9YAKbs9HzQzWuEVNK4NmsQm9qSWBNhQ/640?wx_fmt=png&from=appmsg "")  
  
ESET安全研究人员最近发现了第一个专门攻击 Linux 系统的 UEFI 启动工具包，名为 Bootkitty。该工具包允许攻击者禁用 Linux 内核的签名验证功能，并在 Linux 初始化过程中预加载两个未知的 ELF 可执行文件。11 月 2024 年，一名未知的 UEFI 应用程序，名为 bootkit.efi，上传到了 VirusTotal。  
  
ESET 发布的警告中reads：“我们的初始分析确认，这是一个 UEFI 启动工具包，名为 Bootkitty oleh 它的创建者，-surprisingly 是第一个专门攻击 Linux 的 UEFI 启动工具包，特别是对一些 Ubuntu 版本。”“Bootkitty 签名了自签名证书，因此无法在启用 UEFI 安全启动的系统上运行，除非攻击者安装了证书。”研究人员注意到 bootkit.efi 中的许多艺术ifacts，表明该二进制文件可能是一个概念证明，從未在实际攻击中使用过。Bootkitty 的作者签名了 Bootkitty，使用自签名证书，因此 malware 无法在启用 UEFI 安全启动的系统上运行，除非攻击者安装了证书。Bootkittyypass UEFI 安全启动机制的身份验证函数，允许顺滑地 Linux 内核启动。Bootkitty 支持有限的系统，因为它使用了硬编码的字节模式来修改函数和固定的偏移量来.patch decompressed Linux 内核。  
  
研究人员现在报告称，Bootkitty Linux UEFI 启动工具包利用 LogoFAIL 漏洞 CVE-2023-40238 来攻陷运行在易受攻击的固件上的系统。LogoFAIL 是 UEFI 图像解析组件的一组漏洞，攻击者可以利用它们来劫持启动过程并部署启动工具包。  
  
Bootkitty 通过 tampered BMP 文件来注入 shellcode，绕过安全启动和目标特定的设备，从不同的制造商，如 Acer、HP、Fujitsu 和 Lenovo。尽管已经发布了安全补丁，但仍然有多个设备是易受攻击的。Bootkitty 将 shellcode 嵌入 BMP 文件（‘logofail.bmp’ 和 ‘logofail_fake.bmp’）以绕过安全启动，注入虚假证书到 MokList 变量中。研究人员认为 logofail_fake.bmp 是无害的，但将 logofail.bmp flagged，一个 16MB 文件，显示了一些异常，如 BMP 的宽度和高度为 0xfffffd00 (-768) 和 0x0，重复模式和嵌入 shellcode 一起出现的证书元数据，链接到启动工具包。Bootkitty 的 shellcode 在三个阶段中exploits LogoFAIL：准备启动环境，exploit漏洞，部署恶意 bootloader，替换启动 logo。Bootkitty 恢复了 RLE8ToBlt 函数中的原始指令，尝试擦除任何痕迹。  
  
Bootkitty 主要针对使用 Insyde 固件的联想设备，这可能是由于开发人员测试所致，但未来可能会支持更广泛的设备。易受攻击的型号包括 IdeaPad、Legion 和 Yoga 系列。  
  
报告总结道：“自从我们首次发出关于 LogoFAIL 的警报以来已经一年多了，然而，许多受影响的厂商仍然容易受到一个或多个 LogoFAIL 漏洞变体的攻击。Bootkitty 提醒我们，当这些漏洞没有得到充分解决或修复没有正确部署到现场设备时，后果将是多么严重。”  
  
