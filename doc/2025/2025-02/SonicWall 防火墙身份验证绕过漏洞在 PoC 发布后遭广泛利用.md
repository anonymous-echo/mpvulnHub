#  SonicWall 防火墙身份验证绕过漏洞在 PoC 发布后遭广泛利用   
 独眼情报   2025-02-16 10:05  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSf5zABxZAxnOLic84fic72BKBgzTzIQib7lpvy39caUnk1E7CNz6OWOrKoNrFiatRGmbtrX6HlchwqMQ/640?wx_fmt=png&from=appmsg "")  
  
网络安全公司警告称，SonicWall 防火墙中一个严重的身份验证绕过漏洞（CVE-2024-53704）目前正在被积极利用。  
  
2025 年 2 月 10 日，Bishop Fox 的研究人员公开发布了概念验证 (PoC) 漏洞代码，随后攻击次数激增，这加大了未修补设备的组织面临的风险。  
  
CVE-2024-53704 的CVSS 评分为 9.3，存在于 SonicOS 的 SSL VPN 身份验证机制中，SonicOS 是 SonicWall 的第 6 代、第 7 代和 TZ80 防火墙所采用的操作系统。  
  
攻击者可以通过向端点发送包含 base64 编码的空字节字符串的精心设计的会话 cookie 来远程劫持活动的 VPN 会话/cgi-bin/sslvpnclient。  
  
成功利用该漏洞可绕过多因素身份验证 (MFA)、暴露私有网络路由并允许未经授权访问内部资源。受感染的会话还使威胁行为者能够终止合法用户连接。  
  
SonicWall 于 2025 年 1 月 7 日首次披露了该漏洞，并敦促立即修补。当时，该供应商报告称没有证据表明存在野外利用。  
# CVE-2024-53704 被野外利用  
  
然而，Bishop Fox于 2 月 10 日发布的 PoC降低了攻击者的进入门槛。到 2 月 12 日，Arctic Wolf观察到攻击尝试来自不到 10 个不同的 IP 地址，主要托管在虚拟专用服务器 (VPS)上。  
  
安全分析师将这种快速武器化归因于该漏洞的严重影响以及 Akira 和 Fog 等勒索软件组织历史上针对 SonicWall 设备的攻击。  
  
截至2月7日，据Bishop Fox报告，超过4,500台暴露在互联网上的SonicWall SSL VPN服务器仍未打补丁。受影响的固件版本包括：  
- SonicOS 7.1.x（最高至 7.1.1-7058）  
  
- SonicOS 7.1.2-7019  
  
- SonicOS 8.0.0-8035  
  
修补版本（例如 SonicOS 8.0.0-8037 和 7.1.3-7015）于 2025 年 1 月发布。  
  
此次攻击的利用模式与之前的攻击活动相似。2024 年末，Akira勒索软件关联公司利用被入侵的 SonicWall VPN 帐户入侵网络，通常会在首次访问后的数小时内加密数据。  
  
Arctic Wolf 警告称，CVE-2024-53704 同样可以作为勒索软件部署、凭证盗窃或间谍活动的门户。  
  
SonicWall 和网络安全机构强调采取紧急行动：  
  
将固件升级到固定版本（例如，8.0.0-8037 或 7.1.3-7015）。如果无法立即修补，请在公共接口上禁用 SSL VPN 。将 VPN 访问限制在受信任的 IP 范围内，并对其余用户强制实施 MFA。随着攻击的不断发生，组织必须优先修补以降低风险。公共 PoC 代码的融合、高攻击可行性以及 SonicWall 在企业网络中的突出地位凸显了这一紧迫性。  
  
正如 Arctic Wolf 警告的那样，考虑到漏洞的严重性和勒索软件参与者的敏捷性，延迟可能会带来“灾难性的网络入侵”风险。  
# Poc及技术分析  
>   
> https://bishopfox.com/blog/sonicwall-cve-2024-53704-ssl-vpn-session-hijacking  
  
  
  
