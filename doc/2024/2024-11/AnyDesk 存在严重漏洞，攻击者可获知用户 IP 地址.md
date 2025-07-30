#  AnyDesk 存在严重漏洞，攻击者可获知用户 IP 地址   
会杀毒的单反狗  军哥网络安全读报   2024-11-23 01:00  
  
**导****读**  
  
  
  
流行的远程桌面应用程序
AnyDesk 中发现一个严重漏洞，可能允许攻击者泄露用户的 IP 地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaEEPc9lFaUHdt5In70UKt5BZnwWBojEOUXVtxleicjgkoHD7AaE1QiaGAazqzsd3Eka2VaNzW26TMicg/640?wx_fmt=webp&from=appmsg "")  
  
  
该漏洞被编号为
CVE-2024-52940，影响 Windows 系统上的 AnyDesk 8.1.0 及更早版本。  
  
  
安全研究员
Ebrahim Shafiei (EbraSha) 于 2024 年 10 月 27 日发现了此漏洞。它利用了 AnyDesk 的“允许直接连接”功能。  
  
  
当启用此选项并将攻击者系统上的连接端口设置为
7070 时，就可以仅使用其AnyDesk ID 检索目标的公共 IP 地址，而无需在目标系统上进行任何配置更改。  
  
  
此  
0  
day  
漏洞带来严重隐私风险，会无意中暴露网络流量中的敏感 IP
信息。  
  
  
此外，安全分析师发现攻击者可以通过在自己的系统上进行网络嗅探轻松识别这些信息。此外，如果攻击者和目标都在同一个本地网络上，那么目标的私有
IP 地址也可能被访问。  
  
### AnyDesk 漏洞详情  
  
  
该漏洞已被美国国家标准与技术研究院
(NIST)、Tenable 和 MITRE 录入，编号为 CVE-2024-52940。该漏洞的 CVSS 基本评分为 7.5，表明其严重程度较高。  
  
  
该漏洞的关键方面包括：  
- 仅使用
AnyDesk ID 即可检索远程系统的公共 IP 地址  
  
- 在本地网络连接中检测私有
IP 的可能性  
  
- 利用该漏洞不需要复杂的依赖关系或特定的先决条件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEEPc9lFaUHdt5In70UKt5BhadU1miclzbfyYsquyLJPoyg00J5lfYIklV9FDSJhT8nGc4FRloqgdQ/640?wx_fmt=png&from=appmsg "")  
  
使用 Abdal
Sniffer 工具捕获网络流量（来源 - GitHub）  
  
  
此漏洞引发了人们对用户隐私和安全的严重担忧。恶意行为者可能会利用此漏洞来：  
- 追踪用户位置  
  
- 发起有针对性的攻击  
  
- 绕过某些依赖 IP
身份验证的安全措施  
  
目前，AnyDesk
尚未发布官方补丁或修复版本来解决此漏洞。  
  
  
建议用户采取以下预防措施：  
- 如果不是绝对必要，请禁用
AnyDesk 设置中的“允许直接连接”功能  
  
- 监视任何可疑的连接尝试  
  
- 使用 AnyDesk
时使用VPN 服务来掩盖您的真实 IP 地址  
  
- 保持 AnyDesk
更新并关注公司的任何安全公告  
  
- AnyDesk
用户应保持警惕，并考虑其他远程桌面解决方案，直到修复程序发布。网络安全社区热切期待 AnyDesk 的官方回应和补丁来解决这一严重漏洞。  
  
- 随着远程工作持续盛行，用户和软件开发人员都必须优先考虑远程访问工具的安全性。  
  
**新闻链接：**  
  
https://cybersecuritynews.com/critical-anydesk-vulnerability-let-attackers-uncover-user-ip-address/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
