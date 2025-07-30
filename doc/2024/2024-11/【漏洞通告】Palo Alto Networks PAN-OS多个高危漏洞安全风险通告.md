#  【漏洞通告】Palo Alto Networks PAN-OS多个高危漏洞安全风险通告   
 嘉诚安全   2024-11-20 01:56  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Palo Alto Networks PAN-OS中存在一个身份验证绕过漏洞和一个权限提升漏洞，漏洞编号分别是：  
CVE-2024-0012和CVE-2024-9474。  
  
  
Palo Alto Networks是全球知名的网络安全厂商，PAN-OS是Palo Alto Networks为其防火墙设备开发的操作系统。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
**1、CVE-2024-0012**  
  
Palo Alto Networks PAN-OS身份验证绕过漏洞，经研判，该漏洞为  
**高危**漏洞，已发现被  
**在野利用**。可能导致未经身份验证的攻击者通过网络访问管理Web界面，从而获得PAN-OS管理员权限以执行管理操作、篡改配置或利用其他经过身份验证的特权提升漏洞（如CVE-2024-9474）。  
  
  
**2、CVE-2024-9474**  
  
Palo Alto Networks PAN-OS权限提升漏洞，经研判，该漏洞为  
**高危**漏洞，已发现被  
**在野利用**  
。可能导致具有管理Web界面访问权限的PAN-OS管理员以root权限对防火墙执行恶意操作。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
  
**CVE-2024-0012**  
  
PAN-OS 11.2 < 11.2.4-h1  
  
PAN-OS 11.1 < 11.1.5-h1  
  
PAN-OS 11.0 < 11.0.6-h1  
  
PAN-OS 10.2 < 10.2.12-h2  
  
  
**CVE-2024-9474**  
  
PAN-OS 11.2 < 11.2.4-h1  
  
PAN-OS 11.1 < 11.1.5-h1  
  
PAN-OS 11.0 < 11.0.6-h1  
  
PAN-OS 10.2 < 10.2.12-h2  
  
PAN-OS 10.1 < 10.1.14-h6  
  
  
**修复建议**  
  
  
  
  
  
  
  
  
目前这些漏洞已经修复，受影响用户可升级到以下版本：  
  
  
**CVE-2024-0012**  
  
PAN-OS 11.2  >= 11.2.4-h1  
  
PAN-OS 11.1  >= 11.1.5-h1  
  
PAN-OS 11.0  >= 11.0.6-h1  
  
PAN-OS 10.2  >= 10.2.12-h2  
  
  
**CVE-2024-9474**  
  
PAN-OS 11.2 >= 11.2.4-h1  
  
PAN-OS 11.1 >= 11.1.5-h1  
  
PAN-OS 11.0 >= 11.0.6-h1  
  
PAN-OS 10.2 >= 10.2.12-h2  
  
PAN-OS 10.1 >= 10.1.14-h6  
  
  
下载链接：  
  
https://www.paloaltonetworks.com/network-security/pan-os  
  
参考链接：  
  
https://support.paloaltonetworks.com/support  
  
https://security.paloaltonetworks.com/CVE-2024-0012  
  
https://security.paloaltonetworks.com/CVE-2024-9474  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
