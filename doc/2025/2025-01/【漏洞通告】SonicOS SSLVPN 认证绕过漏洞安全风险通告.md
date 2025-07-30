#  【漏洞通告】SonicOS SSLVPN 认证绕过漏洞安全风险通告   
 嘉诚安全   2025-01-10 03:18  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到SonicOS SSLVPN中存在一个认证绕过漏洞，漏洞编号为：  
CVE-2024-53704。  
  
  
SonicOS SSLVPN是一款为中小企业设计的SSL VPN设备，旨在提供安全的远程访问解决方案，允许用户通过加密的网络连接安全地访问内部网络资源。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
存在于SonicOS SSLVPN的认证机制中，允许远程攻击者绕过认证。攻击者可以利用这一漏洞在未经过适当认证的情况下访问受保护的资源。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Gen7 Firewalls: SonicOS 7.1.* <= 7.1.1-7058 和 SonicOS 7.1.2-7019  
  
Gen7 NSv: SonicOS 7.1.* <= 7.1.1-7058 和 SonicOS 7.1.2-7019  
  
TZ80: SonicOS 8.0.0-8035  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
SonicWall建议所有受影响的用户立即升级到最新的修复版本：  
  
https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0003  
  
修复缓解措施：  
  
1.对SonicOS SSLVPN相关的接口作访问限制，只允许受信任的IP地址范围访问管理界面，以减少潜在攻击者的机会；  
  
2.关注SonicWall的官方安全通告，以便在新的漏洞或威胁出现时及时获得信息，并采取相应的防护措施。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
