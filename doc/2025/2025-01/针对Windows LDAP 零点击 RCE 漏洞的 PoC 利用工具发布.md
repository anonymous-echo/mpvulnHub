#  针对Windows LDAP 零点击 RCE 漏洞的 PoC 利用工具发布   
会杀毒的单反狗  军哥网络安全读报   2025-01-03 01:01  
  
**导****读**  
  
  
  
研究人员公布了针对 Windows 轻量级目录访问协议 (LDAP) 中一个严重漏洞的概念验证 (PoC) 代码，该漏洞编号为CVE-2024-49112。  
  
  
微软于 2024 年 12 月 10 日补丁日更新中披露了该漏洞，其 CVSS 严重性评分为 9.8，对企业网络构成重大风险。  
  
  
CVE-2024-49112 是一个远程代码执行 (RCE) 漏洞，会影响 Windows 服务器，包括域控制器 (DC)。DC 是组织网络中的关键组件，因为它们管理身份验证和用户权限。  
  
  
利用此漏洞可能允许攻击者使未修补的服务器崩溃或在LDAP 服务上下文中执行任意代码，从而可能危及整个域。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaF67kEVvgr3vXibaKLvAmI5NZv7ib2fuxyUVhhDaMaPOk2LduDJEYuj2iaTbpaEyYWtCL4LKzqvMfxqg/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞源于 LDAP 相关代码中的整数溢出。未经身份验证的攻击者可以通过发送特制的 RPC 调用来触发恶意 LDAP 查询，从而利用该漏洞。如果成功，这可能会导致服务器崩溃或进一步利用 RCE。  
  
### CVE-2024-49112的 PoC 发布  
###   
  
SafeBreach Labs 开发了该漏洞的一个零点击 PoC ，称为“LDAPNightmare”，证明了 CVE-2024-49112 的严重性。  
  
  
该漏洞利用以下攻击流程使未修补的 Windows 服务器崩溃：  
  
攻击者向受害服务器发送 DCE/RPC 请求。  
  
受害者向攻击者的 DNS 服务器查询信息。  
  
攻击者使用主机名和 LDAP 端口进行响应。  
  
受害者发送 NBNS 广播来定位攻击者的主机名。  
  
攻击者以其 IP 地址回复。  
  
受害者成为 LDAP 客户端并向攻击者的机器发送 CLDAP 请求。  
  
  
攻击者发送恶意的引荐响应，导致 LSASS（本地安全机构子系统服务）崩溃并重新启动服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaF67kEVvgr3vXibaKLvAmI5Nibuh0ib9VSBFJlSIEZa1QCJPIamh4krrfcH3o9vGa1fltXXav0ATicibYw/640?wx_fmt=png&from=appmsg "")  
  
  
SafeBreach 证实微软的补丁通过解决整数溢出问题有效地缓解了此漏洞。  
  
  
该漏洞影响修补之前的所有 Windows Server 版本，包括Windows Server 2019 和 2022。利用该漏洞攻击者可以控制域环境，使其成为勒索软件团伙和其他威胁组织的主要目标。  
  
### 安全建议：  
  
立即应用微软2024年12月的补丁。  
  
监视可疑的 DNS SRV 查询、CLDAP 引用响应和 DsrGetDcNameEx2 调用，直到修补完成。  
  
使用 SafeBreach 的 PoC 工具（可在GitHub上获取）测试他们的环境。  
  
  
此 PoC 的发布凸显了解决 CVE-2024-49112 的紧迫性。SafeBreach 的研究不仅强调了该漏洞的潜在影响，还为组织提供了验证其防御能力的工具。  
  
  
微软已经发布了针对该漏洞的补丁；企业必须优先修补并实施强有力的监控，以保护关键基础设施免遭攻击。  
  
  
新闻链接：  
  
https://cybersecuritynews.com/poc-windows-ldap-rce-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
