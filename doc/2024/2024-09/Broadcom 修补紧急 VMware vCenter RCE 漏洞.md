#  Broadcom 修补紧急 VMware vCenter RCE 漏洞   
 独眼情报   2024-09-21 10:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSm6qHNpicgBuBD41Ajfj5EBibvbRSPWQDdIUw1BnpRtgI6RwpCmS3TKofTrXIq27qwIKykrwaeFDlQ/640?wx_fmt=png&from=appmsg "")  
  
  
Broadcom 已  
发布  
更新以解决 VMware vCenter Server 中可能导致远程代码执行的严重漏洞。该漏洞编号为 CVE-2024-38812，CVSS 评分为 9.8，与 DCE/RPC 协议中的缓冲区溢出有关。  
  
据开发人员称，具有网络访问权限的攻击者可以通过发送特制的网络数据包来利用此漏洞，从而能够在 vCenter 服务器上执行远程代码。  
  
该漏洞与另外两个远程代码执行漏洞 CVE-2024-37079 和 CVE-2024-37080 类似，这两个漏洞已于 2024 年 6 月得到解决。这两个漏洞的 CVSS 评分均为 9.8。  
  
此外，权限提升漏洞 CVE-2024-38813（评分 7.5）也已修复。该漏洞允许具有网络访问权限的攻击者将权限提升至 root 级别。发送特制的网络数据包也会触发该攻击。  
  
这两个漏洞都是由 TZL 团队的安全研究人员在 2024 年 6 月在中国举办的 Matrix Cup 网络安全竞赛中发现的。  
  
补丁适用于以下版本：  
- vCenter Server 8.0（已在 8.0 U3b 版本中修复）；  
  
- vCenter Server 7.0（已在 7.0 U3s 版本中修复）；  
  
- VMware Cloud Foundation 5.x（补丁程序在版本 8.0 U3b 中可用）；  
  
- VMware Cloud Foundation 4.x（已在版本 7.0 U3s 中修复）。  
  
博通强调，截至目前，尚无证据表明这些漏洞被野外利用，但强烈建议用户更新系统以防范潜在的攻击。  
  
这些  
漏洞  
源于内存管理错误，可能通过利用 VMware vCenter 服务来执行远程代码。  
  
这些发展恰逢美国网络安全和基础设施安全局 (CISA) 和联邦调查局发布的联合公告，强调需要解决跨站点脚本 (XSS) 漏洞，攻击者可以利用这些漏洞来破坏系统。  
> https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24968  
  
  
  
  
  
