#  Windows 7 至 Windows 11 中存在新的 0 Day NTLM 哈希泄露漏洞   
原创 很近也很远  网络研究观   2024-12-07 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwmV7XHsDUYbT9iclMhT5yviaRZKE2iamqBiczByN1EyyC5na90E5Z7hKgjA/640?wx_fmt=png&from=appmsg "")  
  
0patch 的研究人员发现了一个零日漏洞，该漏洞影响所有受支持的 Windows Workstation 和 Server 版本，从 Windows 7 和 Server 2008 R2 到最新的 Windows 11（v24H2）和 Server 2022。  
  
此严重漏洞使攻击者只需诱骗用户在 Windows 资源管理器中查看恶意文件即可捕获用户的 NTLM 凭据。  
  
如果受害者在 Windows 资源管理器中查看恶意文件（例如打开共享文件夹、插入 USB 设备或通过攻击者的网站导航到可能放置恶意文件的下载文件夹），此漏洞可让攻击者提取 NTLM 凭据。  
  
此技术不需要用户打开或执行文件 — 只需查看即可。  
  
虽然0patch已向 Microsoft 报告了此问题，但在官方发布修复程序之前，有关漏洞的详细信息仍未披露，以尽量降低利用风险。  
  
URL 文件 NTLM 哈希泄露漏洞 (0day) - 以及针对该漏洞的免费微补丁  
  
https://blog.0patch.com/2024/12/url-file-ntlm-hash-disclosure.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwLEHxrufz1ltUSIwboen2wjAkjbEzmlhZHUhuzccpGht0jAYIMVsP2Q/640?wx_fmt=png&from=appmsg "")  
  
与此同时，0patch 已开发并分发了针对此漏洞的免费微补丁。  
  
此次发现是 0patch 最近发现的第三个零日漏洞。  
  
之前报告的问题包括 Windows 主题文件漏洞（仍在等待 Microsoft 的官方补丁）和 Server 2012 上的“Mark of the Web”绕过漏洞（也仍未解决）。  
  
此外，安全研究员 Florian 在今年早些时候报告的“EventLogCrasher”漏洞至今仍未得到微软的修复。  
  
该漏洞允许攻击者禁用所有域计算机的事件日志记录。0patch 提供了这些漏洞的唯一可用补丁。  
  
NTLM 协议经常成为攻击者的目标，该协议存在几个已知问题，但微软拒绝修补。  
  
这些包括：  
- PetitPotam  
  
- PrinterBug/SpoolSample  
- DFSCoerce  
尽管微软做出了这一决定，0patch 仍为这些“无法修复”的漏洞提供保护，强调了其作为依赖 NTLM 的组织的重要资源的作用。  
### 非官方修复可用  
###   
  
在 Microsoft 发布官方更新之前，此零日漏洞的微补丁是免费的。  
  
补丁内容包括：  
  
由于这是一个“0day”漏洞，尚无官方供应商修复程序，因此我们免费提供微补丁，直至有官方供应商提供修复程序为止。  
  
微补丁适用于：  
  
 旧版 Windows 版本：  
1. Windows 11 v21H2 - 全面更新  
1. Windows 10 v21H2 - 全面更新  
1. Windows 10 v21H1 - 全面更新  
1. Windows 10 v20H2 - 完全更新  
1. Windows 10 v2004 - 已全面更新  
1. Windows 10 v1909 - 已全面更新  
1. Windows 10 v1809 - 已全面更新  
1. Windows 10 v1803 - 已全面更新  
1. Windows 7 - 已完全更新，无 ESU、ESU 1、ESU 2 或 ESU 3  
1. Windows Server 2012 - 已全面更新，无 ESU 或 ESU 1  
  
1. Windows Server 2012 R2 - 完全更新，无 ESU 或 ESU 1  
1. Windows Server 2008 R2 - 已完全更新，无 ESU、ESU 1、ESU 2、ESU 3 或 ESU 4  
  
 仍在接收 Windows 更新的 Windows 版本：  
1. Windows 11 v24H2 - 已全面更新     
1. Windows 11 v23H2 - 已全面更新  
1. Windows 11 v22H2 - 已全面更新  
1. Windows 10 v22H2 - 全面更新  
1. Windows Server 2022 - 全面更新  
1. Windows Server 2019 - 全面更新   
1. Windows Server 2016 - 全面更新   
1. Windows Server 2012 已通过 ESU 2 全面更新  
1. Windows Server 2012 R2 已通过 ESU 2 全面更新  
旧版系统：包括不带扩展安全更新 (ESU) 的 Windows 7 和 Server 2008 R2。  
全面更新的系统：涵盖最新版本的 Windows 10、Windows 11 和受支持的 Windows Server。  
  
微补丁已经分发到并应用于所有受影响的在线计算机，这些计算机都具有 PRO 或企业帐户中的 0patch Agent（除非企业组设置阻止这样做）。  
  
此类漏洞会定期被发现，攻击者对此了如指掌。如果您使用的 Windows 不再接收官方安全更新，0patch 将确保这些漏洞不会在您的计算机上被利用 - 您甚至不必知道或关心这些事情。  
  
如果您是 0patch 的新用户，请在0patch Central创建一个免费帐户，开始免费试用，然后安装并注册 0patch Agent。  
  
https://central.0patch.com/  
  
其他一切都将自动进行。无需重新启动计算机。  
  
运行过时的 Windows 系统或依赖 NTLM 身份验证的组织面临着未修补漏洞带来的巨大风险。  
  
0patch 目前可保护大约 40% 的用户免受零日漏洞和 Microsoft 不再支持的漏洞的攻击。  
  
建议用户遵循以下步骤  
1. 1.在 0patch Central 注册并安装 0patch Agent 来保护您的系统。  
1. 2. 尽可能禁用 NTLM 并转换到更安全的身份验证协议。  
1. 3. 限制对共享文件夹和 USB 设备的访问，并实施严格的下载控制。  
