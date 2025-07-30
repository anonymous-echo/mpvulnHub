#  【漏洞通告】Ivanti 多款产品缓冲区溢出漏洞安全风险通告   
 嘉诚安全   2025-01-10 03:18  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Ivanti多款产品中存在缓冲区溢出漏洞，漏洞编号为：  
CVE-2025-0282。  
  
  
Ivanti Connect Secure，以前称为Pulse Connect Secure，是一款提供SSL VPN解决方案的产品，允许远程用户通过一个安全的通道访问企业资源，确保数据在传输过程中的加密和安全。Ivanti Connect Secure是由Pulse Secure公司开发的，该公司后来被Ivanti收购，因此产品名称发生了变化。Ivanti Policy Secure则是一个网络访问控制 (NAC) 解决方案。Ivanti Neurons for ZTA gateways是用于实现零信任访问的网关设备，通过动态验证和授权来保护网络资产。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
**已发现被在野利用**  
。Ivanti Connect Secure、Ivanti Policy Secure和Ivanti Neurons for ZTA网关中存在一个基于堆栈的缓冲区溢出漏洞，未经身份验证的远程攻击者可以在易受攻击的设备上实现远程代码执行。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
22.7R2 <= Ivanti Connect Secure <= 22.7R2.4  
  
22.7R1 <= Ivanti Policy Secure <= 22.7R1.2  
  
22.7R2 <= Ivanti Neurons for ZTA <= 22.7R2.3  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前官方已有可更新版本，建议受影响用户升级至最新版本：  
  
Ivanti Connect Secure >= 22.7R2.5  
  
Ivanti Neurons for ZTA gateways >= 22.7R2.5(1月21日前不可用)  
  
官方补丁下载地址：  
  
https://portal.ivanti.com/  
  
参考链接：  
  
https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283?language=en_US  
  
https://securityonline.info/cve-2025-0282-cvss-9-0-ivanti-confirms-active-exploitation-of-critical-flaw/  
  
https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day/  
  
https://www.tenable.com/blog/cve-2025-0282-ivanti-connect-secure-zero-day-vulnerability-exploited-in-the-wild  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
