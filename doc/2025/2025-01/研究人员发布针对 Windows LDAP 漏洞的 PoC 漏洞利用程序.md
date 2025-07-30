#  研究人员发布针对 Windows LDAP 漏洞的 PoC 漏洞利用程序   
原创 很近也很远  网络研究观   2025-01-05 13:27  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxMO0Ea981O1SvHIhJXbLlyqlKIgZTN18SSAdCsOYq9MgP4t0qtRFrKtREr1MS2ea8rRQpiccDdXfcQ/640?wx_fmt=png&from=appmsg "")  
  
SafeBreach Labs 发布了针对 CVE-2024-49113 的概念验证 (PoC) 漏洞利用，该漏洞是 Microsoft Windows 轻量级目录访问协议 (LDAP) 中的拒绝服务 (DoS) 漏洞。  
  
  
除此之外，研究人员还详细介绍了他们利用相关 CVE-2024-49112（远程代码执行 (RCE) 漏洞）的尝试，强调了其可能造成的严重影响。  
  
  
这些漏洞影响 Microsoft Windows 和 Windows Server 平台，已在 2024 年 12 月的安全更新中得到解决。  
  
  
英国 NHS 国家网络安全运营中心 (CSOC) 已将漏洞利用可能性归类为高，并敦促各组织迅速采取行动。  
  
### 漏洞分析  
###   
  
CVE-2024-49113 被归类为拒绝服务 (DoS) 问题，CVSS 评分为 7.5。  
  
  
它允许未经身份验证的远程攻击者发送恶意 LDAP 请求，从而导致 Windows Server 系统崩溃、中断操作并需要重新启动才能恢复功能。  
  
  
虽然其直接影响仅限于服务停机，但其在企业环境中造成大面积中断的可能性使其成为一个关键问题。  
  
  
另一方面，CVE-2024-49112 是一个更严重的远程代码执行 (RCE) 漏洞，CVSS 评分为 9.8。  
  
  
它使攻击者能够编写恶意 LDAP 调用来执行任意代码，从而授予他们对 LDAP 服务的控制权。  
  
  
由于 LDAP 是基于目录的身份验证和系统管理不可或缺的一部分，因此成功利用此漏洞可能会导致整个系统受到攻击。  
  
  
这两个漏洞均已在微软 2024 年 12 月的安全更新中修复。  
  
  
但 CVE-2024-49113 PoC 的发布凸显了组织如果尚未这样做则应立即应用更新的紧迫性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxMO0Ea981O1SvHIhJXbLlyqz4URKcgkjLkg0rQGosa7SaZLOIIpibQBo6FOaLn0ia7uO2X4dMkg5iasQ/640?wx_fmt=png&from=appmsg "")  
  
### SafeBreach 的利用方法  
###   
  
CVE-2024-49113 的 PoC（称为 LDAP Nightmare）演示了该漏洞的利用机制：  
  
1. 异步 LDAP 服务器已配置为监听连接。  
1.   
1. 使用 Netlogon 远程协议 (NRPC)，受害服务器被强制向攻击者控制的服务器发送 LDAP 查询。  
1.   
1. 攻击者服务器特制的响应利用此漏洞，导致目标系统崩溃。  
1.   
为 CVE-2024-49112 创建 PoC 的尝试仍不完整，但包含对利用方法的详细见解。  
  
  
根据 SafeBreach 博客，RCE 漏洞可以使用类似的 LDAP 交互技术进行武器化，对未修补的系统构成重大风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxMO0Ea981O1SvHIhJXbLlyqt5GU2Pvu6VcFDf8dztw4PxTx8yeYGHo7k7YpwlL97uq3Khtd1VXia5Q/640?wx_fmt=png&from=appmsg "")  
  
LDAPNightmare：SafeBreach Labs 发布首个针对 CVE-2024-49113 的概念验证漏洞  
  
了解 SafeBreach Labs的研究人员如何利用 Windows 轻量级目录访问协议 (LDAP) 拒绝服务漏洞开发零点击 PoC 漏洞，导致未修补的 Windows 服务器崩溃。  
  
https://www.safebreach.com/blog/ldapnightmare-safebreach-labs-publishes-first-proof-of-concept-exploit-for-CVE-2024-49113/  
  
  
攻击流程：  
  
1. 攻击者向受害者服务器发送 DCE/RPC 请求；  
  
2. 受害者被触发发送有关 SafeBreachLabs.pro 的 DNS SRV 查询；  
  
3. 攻击者的 DNS 服务器使用攻击者的主机名和 LDAP 端口进行响应 ；  
  
4. 受害者发送广播 NBNS 请求来查找收到的主机名（攻击者的）的 IP 地址；  
  
5. 攻击者发送一个 NBNS 响应，其中包含其 IP 地址；  
  
6 受害者成为 LDAP 客户端并向攻击者的机器发送 CLDAP 请求；  
  
7. 攻击者发送带有特定值的 CLDAP 引用响应数据包，导致 LSASS 崩溃并强制受害者服务器重新启动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxMO0Ea981O1SvHIhJXbLlyq9HESGJkPCDvZ6yjaxvPx1s6MNAwiagicQCxq3Ie9tK7J64esibuYqn3Hw/640?wx_fmt=png&from=appmsg "")  
  
漏洞利用过程  
  
### 微软的回应  
###   
  
这两个漏洞都包含在微软2024 年 12 月补丁星期二更新中，该更新解决了 72 个漏洞，包括 CVE-2024-49112 和 CVE-2024-49113。  
  
  
这些漏洞的补丁是累积更新 KB5048685 的一部分，针对 Windows 11 版本 22H2 和 23H2 以及 Windows Server 变体。  
  
  
12 月的更新是一个关键版本，因为它包含针对诸如 CVE-2024-49138（Windows 通用日志文件系统中的零日漏洞）等活跃被利用的漏洞的修复程序。  
  
  
为了减轻这些漏洞带来的风险，受影响的组织应确保安装 Microsoft 的 2024 年 12 月更新，将 LDAP 服务器访问限制在受信任的系统，并实施严格的访问控制措施。  
  
  
如果不需要 LDAP，请在易受攻击的服务器上禁用它。  
  
