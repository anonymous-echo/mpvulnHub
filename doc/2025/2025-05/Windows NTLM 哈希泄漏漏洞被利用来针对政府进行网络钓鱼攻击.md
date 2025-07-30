#  Windows NTLM 哈希泄漏漏洞被利用来针对政府进行网络钓鱼攻击   
Rhinoer  犀牛安全   2025-05-18 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkQ5YJHoFGVzHoiaXZ3e8hBq3yc8os2UEAMFjeP0mUOET60BhagETTmXsKIXibzYjmnSfU7WuwGzIJQ/640?wx_fmt=png&from=appmsg "")  
  
Windows 中存在一个漏洞，它会利用 .library-ms 文件暴露 NTLM 哈希值，而黑客现在正积极利用该漏洞，在针对政府实体和私营公司的网络钓鱼活动中利用该漏洞。  
  
该漏洞编号为CVE-2025-24054 ，已于微软2025 年 3 月补丁星期二发布后修复。最初，该漏洞并未被标记为被主动利用，且评估为“不太可能”被利用。  
  
然而，Check Point 研究人员报告称，在补丁发布后仅几天就观察到了针对 CVE-2025-24054 的活跃利用活动，并在 2025 年 3 月 20 日至 25 日之间达到顶峰。  
  
尽管这些攻击背后的一个 IP 地址之前被关联到俄罗斯国家支持的威胁组织 APT28（“Fancy Bear”），但这并不足以证明其归因可靠。  
  
暴露 NTLM 哈希  
  
NTLM（新技术 LAN 管理器）是一种 Microsoft 身份验证协议，它使用涉及哈希的质询-响应协商而不是传输纯文本密码来对用户进行身份验证。  
  
虽然 NTLM 避免传输纯文本密码，但由于重放攻击和捕获哈希的暴力破解等漏洞，它不再被认为是安全的。  
  
因此，微软已开始逐步淘汰 NTLM 身份验证，转而采用 Kerberos 或 Negotiate。  
  
在 Check Point 发现的攻击中，网络钓鱼电子邮件被发送到波兰和罗马尼亚的实体，其中包含指向 ZIP 存档的 Dropbox 链接，其中包含 .library-ms 文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkQ5YJHoFGVzHoiaXZ3e8hBqXMicryztye04ia8P5UFfFibOwLJ2lkENBNnnEpMqfAClgJmw4ANUG9IWw/640?wx_fmt=png&from=appmsg "")  
  
library-ms 文件是一种合法的文件类型，打开时会显示一个Windows 库或虚拟容器，其中包含来自不同配置源的文件和文件夹。   
  
在这次网络钓鱼攻击中，创建了 library-ms 文件，其中包含攻击者控制的远程 SMB 服务器的路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkQ5YJHoFGVzHoiaXZ3e8hBqePeJ64UE3CPicUrtKekIzokicbQtTbLsMSFaME0ELbrK3lhzvaZm8jOQ/640?wx_fmt=png&from=appmsg "")  
  
当解压包含 .library-ms 文件的 ZIP 文件时，Windows 资源管理器将自动与其交互，从而触发 CVE-2025-24054 漏洞，并导致 Windows 与文件中指定的 URL 建立 SMB 连接。  
  
当 Windows 连接到远程 SMB 服务器时，它将尝试通过 NTLM 进行身份验证，从而允许攻击者捕获用户的 NTLM 哈希。  
  
在后续的攻击活动中，Check Point 发现了包含 .library-ms 附件（不含存档）的网络钓鱼邮件。只需下载 .library-ms 文件即可触发远程服务器的 NTLM 身份验证，这表明无需存档即可利用此漏洞。  
  
Check Point 解释说：“2025 年 3 月 25 日，Check Point Research 发现了一项针对全球公司的活动，这些文件未经压缩就被分发。”  
  
据微软称，此漏洞是通过用户与恶意文件的最少交互触发的，例如选择（单击）、检查（右键单击）或执行除打开或执行文件之外的任何操作。  
  
该恶意档案还包含另外三个文件，分别是“xd.url”、“xd.website”和“xd.link”，它们利用较旧的 NTLM 哈希泄漏漏洞，并且很可能是为了在“library-ms”方法失败时提供冗余而包含的。  
  
Check Point 表示，此次活动中攻击者控制的 SMB 服务器使用的是 159.196.128[.]120 和 194.127.179[.]157 IP 地址。  
  
捕获 NTLM 哈希可能会为绕过身份验证和提升权限打开大门，因此尽管 CVE-2025-24054 仅被评估为“中等”严重性问题，但其潜在后果却十分严重。  
  
由于利用此漏洞所需的交互较少，组织应将此问题视为高风险问题。建议所有组织安装 2025 年 3 月更新，并在不需要时关闭 NTLM 身份验证。  
  
  
信息来源：  
BleepingComputer  
  
