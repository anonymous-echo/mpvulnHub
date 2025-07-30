#  【IoT安全】BMC 固件中的漏洞影响 IoT 设备安全-第 1 部分   
原创 Nozomi  车联网攻防日记   2024-07-17 19:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBQpMBV9zPuIxbY5J5ialUoCVaniaPek9mZu46QwXtibSuLGySI6S4TB8ApIBPlTP2ia2eIbqN00tp3KWCOqNicHZ1A/640?wx_fmt=jpeg&from=appmsg "")  
  
在过去的一年里，Nozomi Networks 实验室对基板管理控制器（BMCs)的安全性进行了研究，特别关注工业物  
  
联网（OT）和物联网（IoT）设备。在这个博客系列的第一部分中，我们揭示了影响基于美国 Megatrends（AMI）MegaRAC SP-X 的 Lanner 设备的 BMCs 的十三个漏洞。通过利用这些漏洞，未经身份验证的攻击者可能在 BMC 上获得具有根权限的远程代码执行（RCE），完全妥协它并控制托管主机。在我们的研究中，我们发现了其他漏洞，其修补仍在进行中，因此目前无法披露；这些将在后续博客文章中进行介绍。  
  
我们的讨论从介绍 BMCs 和漏洞发现的示例开始。然后我们将提供一个攻击者如何利用这些问题最终妥协设备的示例，并最后总结资产所有者可以实施的补救措施。  
## 基板管理控制器（BMC）101  
  
基板管理控制器（BMC）是一种专为远程监控和管理计算机而设计的辅助片上系统。由于具有专用网络接口并与关键硬件组件（例如主板芯片组）紧密耦合，BMC 可以执行完全远程低级系统操作，例如从引导程序直接进行键盘和鼠标交互、系统电源控制、BIOS 固件刷新等。  
  
过去，BMC 仅在 IT 服务器主板中发现，而现在供应商正在将 BMC 的范围扩大到运营技术（OT）和物联网（IoT）领域。其中一家供应商是专门从事嵌入式应用的台湾品牌 Lanner Inc. 值得注意的是，在我们的研究中，我们分析了 Lanner IAC-AST2500A，这是一款扩展卡，可以在 Lanner 设备上实现 BMC 功能。IAC-AST2500A 的固件基于美国 Megatrends（AMI）MegaRAC SP-X 解决方案，这是一种流行的 BMC 固件，也被品牌如华硕、戴尔、技嘉、惠普、联想或英伟达所使用。  
  
在可用的网络服务中，扩展卡具有一个 Web 应用程序，通过该应用程序用户可以完全控制托管主机以及 BMC 本身。图 1 显示了界面的截图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBQpMBV9zPuIxbY5J5ialUoCVaniaPek9m7pq1DSFZS60pLqeGOnr45CGSfeU1xPBGgA4UibdTGTfibAeoRDfZyKZQ/640?wx_fmt=other&from=appmsg "")  
  
图 1. Lanner IAC-AST2500A 的 Web 界面截图  
###  发现漏洞  
  
通过分析 IAC-AST2500A 的 Web 界面，我们发现了十三个漏洞，如下所列：  
- CVE-2021-26727：spx_restservice SubNet_handler_func 多个命令注入和基于堆栈的缓冲区溢出，CVSS v3.1 10（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H）  
  
- CVE-2021-26728：spx_restservice KillDupUsr_func 命令注入和基于堆栈的缓冲区溢出，CVSS v3.1 10（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H）  
  
- CVE-2021-26729: spx_restservice Login_handler_func 命令注入和多个基于堆栈的缓冲区溢出，CVSS v3.1 10 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)  
  
- CVE-2021-26730：spx_restservice Login_handler_func 子函数基于堆栈的缓冲区溢出，CVSS v3.1 10（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H）  
  
- CVE-2021-26731: spx_restservice modifyUserb_func 命令注入和多个基于堆栈的缓冲区溢出，CVSS v3.1 9.1 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)  
  
- CVE-2021-26732：spx_restservice First_network_func Broken Access Control，CVSS v3.1 6.5（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L）  
  
- CVE-2021-26733：spx_restservice FirstReset_handler_func 破坏访问控制，CVSS v3.1 5.3（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L）  
  
- CVE-2021-44776: spx_restservice SubNet_handler_func 破坏访问控制，CVSS v3.1 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L)  
  
- CVE-2021-44467：spx_restservice KillDupUsr_func 破坏访问控制，CVSS v3.1 5.3（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L）  
  
- CVE-2021-44769：TLS 证书生成功能不正确的输入验证，CVSS v3.1 4.9（CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H）  
  
- CVE-2021-46279：会话固定和会话过期不足，CVSS v3.1 5.8（CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L）  
  
- CVE-2021-45925：用户名枚举，CVSS v3.1 5.3（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N）  
  
- CVE-2021-4228: 硬编码的 TLS 证书，CVSS v3.1 5.8 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L)  
  
这些漏洞影响 Lanner IAC-AST2500 标准固件的 1.10.0 版本，除了 CVE-2021-4228 是在 1.00.0 版本上发现的。  
### 攻击链示例：CVE-2021-44467 和 CVE-2021-26728  
  
CVE-2021-44467 和 CVE-2021-26728 描述了一种可能的攻击链，未经身份验证的攻击者可以在 BMC 上以 root 权限实现远程代码执行（RCE）。在登录过程中，Web 应用程序通过确认对话框询问用户是否要终止已登录帐户上的任何其他活动会话（图 2）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBQpMBV9zPuIxbY5J5ialUoCVaniaPek9mElibo0rpQ3xgKdXWZUAFrC7WN73Mm9rQicx2PGMsC6CCTJ3V5uq52rtA/640?wx_fmt=other&from=appmsg "")  
  
图 2. 终止已登录帐户上的其他活动会话  
  
此功能是通过对“/api/KillDupUsr”进行经过身份验证的 POST 请求来实现的，最终由“spx_restservice”的“KillDupUsr_func”函数处理。此功能的开始如图 3 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBQpMBV9zPuIxbY5J5ialUoCVaniaPek9mP1u2PPicibm9ukib486kAq11akTjXLPKpKxIHOibWlxa8nMQerD1hIjphA/640?wx_fmt=other&from=appmsg "")  
  
图 3 CVE 2021 44467  
  
尽管 POST 请求包含 QSESSIONID cookie，但该函数未对用户会话执行任何验证检查。这个漏洞使得未经身份验证的攻击者可以任意终止其他用户的活动会话，导致拒绝服务（DoS）条件（CVE-2021-44467）。继续分析可能会发现更多问题（图 4）。  
  
  
图 4. CVE-2021-26728 在 KillDupUsr_func 中  
  
在第 41 行，“strcat”被调用来复制“v9”的内容，其中包含外部可控的 HTTP 参数“username”的值，到“dest”，一个固定大小的缓冲区。在执行指令之前没有对“v9”的长度进行检查，导致基于堆栈的缓冲区溢出。  
  
在第 46 行，使用“dest”作为参数调用了“safe_system”。尽管名称如此，但事实证明在字符串中注入任意 OS 命令是可能的（例如，子 shell 命令），这些命令由设备执行，导致了命令注入（CVE-2021-26728）。考虑到设备上所有进程都以 root 权限运行，这些组合的弱点使得未经身份验证的攻击者能够完全妥协 BMC 和受管主机。  
##  修复措施  
  
在通过负责任的披露流程与 Lanner 分享了所有漏洞后，供应商为 IAC-AST2500A 开发了更新的 BMC 固件版本，解决了本博客中描述的所有问题。正确的修补版本严格取决于所使用的设备；因此，我们敦促 Lanner 客户联系技术支持以获取适当的软件包。  
  
如果资产所有者无法修补其设备，我们建议强制执行防火墙或网络访问控制规则，以限制网络接口的可达性仅限于信任的人员，或通过入侵检测系统积极监控网络流量。  
  
  
  
**声明：**  
文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与技术交流之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。  
  
  
**本人长期从事车联网攻防一线，如果你是一个车联网攻防的长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
  
5-20人  88元  
  
20-50人   98元  
  
50-100人 128元  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBQpMBV9zPuIxbY5J5ialUoCVaniaPek9mNDpgGf5dRP5TPKTaTtlwXdSK6hTScNPJTkVAMbuicU9qvZZPLW0vRNw/640?wx_fmt=png&from=appmsg "")  
  
  
