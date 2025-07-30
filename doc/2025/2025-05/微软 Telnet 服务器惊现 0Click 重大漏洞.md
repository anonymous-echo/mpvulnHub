#  微软 Telnet 服务器惊现 0Click 重大漏洞   
看雪学苑  看雪学苑   2025-05-06 09:59  
  
近日  
，**微软 Telnet 服务器被发现存在一个极其严重的 0Click 漏洞，该漏洞使得攻击者能够完全绕过身份验证机制，甚至无需有效凭据就有可能获得管理员访问权限，**严重威胁到组织的信息安全。  
这一漏洞**主要影响从 Windows 2000 到 Windows Server 2008 R2 的旧版 Microsoft 操作系统，**尽管这些系统较为陈旧，但仍有不少组织出于对旧版应用程序或基础设施的依赖而继续使用。  
  
  
此漏洞是由名为 Hacker Fantastic 的安全研究员发现的，**其根源在于 Telnet 的 MS-TNAP（Microsoft Telnet Authentication Protocol）扩展中的 NTLM 身份验证过程中存在错误配置。**具体而言，该漏洞主要涉及在身份验证握手过程中，对 SSPI（Security Support Provider Interface）标志的错误配置。服务器使用 SECPKG_CRED_BOTH 标志初始化 NTLM 安全，并使用具有 ASC_REQ_DELEGATE 和 ASC_REQ_MUTUAL_AUTH 标志的 AcceptSecurityContext()，这种组合会导致认证关系发生颠倒，欺骗服务器向客户端进行身份验证，而非验证客户端的身份。  
  
  
目前，一个名为 “telnetbypass.exe” 的概念验证利用程序已被发布，虽然其源代码被扣留以减少广泛利用，但该程序能够通过发送精心设计的相互身份验证数据包，绕过主机上的任何账户的身份验证。  
  
  
由于目前微软尚未发布官方补丁，因此**安全专家建议组织机构立即采取以下措施来降低风险：**  
  
-立刻在所有受影响的系统上禁用 Telnet Server 服务；  
  
-用更安全的替代方案如 SSH 替代 Telnet，以进行远程管理；  
  
-实施网络过滤，仅允许受信任的网络访问 Telnet；  
  
-部署应用程序控制，阻止未经授权的 Telnet 客户端连接。  
  
  
有安全分析师指出，虽然此漏洞较为严重，但其影响范围仅限于旧系统。Telnet 作为一个已经“过时”的协议，并未安装在默认的 Windows 版本中，且所影响的 Windows 版本早已超出支持周期。然而，对于那些仍在维护旧版基础设施的组织来说，必须高度重视这一威胁。  
  
  
事实上，这并非 Telnet 协议首次出现安全问题。Telnet 协议因以明文形式传输用户凭据和数据，长期以来一直被视为一种安全风险较高的协议。随着更安全的协议如 SSH 的出现，许多组织已逐渐减少了对 Telnet 的依赖。然而，在某些特定环境中，如工业控制、学术研究以及部分企业内部，Telnet 仍然被广泛使用。此次 0Click 漏洞的曝光，无疑给仍在使用 Telnet 协议的组织敲响了警钟。  
  
  
值得注意的是，尽管微软尚未发布官方补丁，但一些第三方安全公司已经开始研究并提供临时的保护措施。例如，某些网络安全部署可以通过更新其入侵检测和预防系统（IDS/IPS）的签名数据库，以识别和阻止利用该漏洞的恶意流量。此外，一些安全软件也可以通过监控系统行为，检测到异常的 Telnet 连接活动，从而及时发现潜在的攻击行为。  
  
  
对于那些仍在使用受影响的 Windows 系统的组织来说，除了立即采取上述防御措施外，还应制定长期的升级计划，逐步迁移到受支持的现代操作系统，并淘汰旧的、不安全的协议和服务。这不仅有助于保护组织的数据安全，还能提高整体的系统性能和可靠性。  
  
  
  
资讯来源：  
cybersecuritynews  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
