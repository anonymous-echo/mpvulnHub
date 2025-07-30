#  【PoC】0-Click NTLM 身份验证绕过 Microsoft Telnet 服务器 0day，无补丁   
 独眼情报   2025-04-29 02:27  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRdZkYibzIISHYreiaU77xEbViaWTIuYNoQoHJaZVJeGJ1DL3yUla2doDtPKGrXDA02TibCVCBlSBDaAw/640?wx_fmt=png&from=appmsg "")  
  
一项影响 Microsoft Telnet 服务器的严重漏洞已被发现，允许远程攻击者完全绕过身份验证并获得管理员访问权限，而无需有效的凭据。Hacker Fantastic 的报告详细介绍了该漏洞——涉及 **Microsoft Telnet 身份验证协议 (MS-TNAP)**  
 ——对旧版 Windows 系统构成了重大安全威胁， **目前尚无官方补丁可用**  
 。  
  
根据报告https://github.com/hackerhouse-opensource/hfwintelnet  
，“**Microsoft Telnet 服务器中一个关键的 0-click 远程身份验证绕过漏洞允许攻击者在无需有效凭据的情况下以任何用户（包括管理员）的身份获得访问权限。**  
”该漏洞源于 Telnet 服务器处理 NTLM 身份验证过程时的配置错误。  
  
该漏洞影响广泛的 Microsoft 操作系统，包括：  
- Windows 2000  
  
- Windows XP  
  
- Windows Server 2003  
  
- Windows Vista  
  
- Windows Server 2008  
  
- Windows 7  
  
- Windows Server 2008 R2  
  
漏洞源于 Telnet 服务器不正确地初始化 NTLM 身份验证凭据，并错误地处理相互身份验证。 具体来说，服务器在身份验证握手期间设置了易受攻击的 SSPI 标志：  
  
“ 服务器使用 SECPKG_CRED_BOTH 标志初始化 NTLM 安全性 ”并且“ 使用 AcceptSecurityContext()  
 与 ASC_REQ_DELEGATE  
 和 ASC_REQ_MUTUAL_AUTH  
 标志，”报告解释说。  
  
这种错误的配置导致身份验证关系的危险逆转——使服务器向客户端验证自身，而不是验证客户端的身份。  
  
Hacker Fantastic 发布的 PoC 漏洞利用程序通过以下步骤利用此漏洞：  
1. 请求具有特定标志的相互认证。  
  
1. 对目标管理员帐户使用 NULL 密码。  
  
1. 操纵 SSPI 标志以触发服务器的身份验证逻辑缺陷。  
  
1. 发送欺骗服务器的修改后的 NTLM Type 3 消息。  
  
1. 实现完全的身份验证绕过，最终以**管理员权限**  
打开 Telnet 会话。  
  
如前所述，“ 攻击者可以通过发送相互身份验证数据包并利用 SSPI 配置来绕过服务器端身份验证，从而绕过对主机上任何帐户的身份验证。”  
  
发布的 PoC，telnetbypass.exe  
，针对 localhost 或已加入域的主机，并且需要 Telnet 服务器服务正在运行。  
  
令人担忧的是，“ 目前还没有针对此漏洞的补丁。” 因此，建议各组织立即采取保护措施：  
- 在所有系统上**禁用 Telnet 服务器服务**  
 。  
  
- **过渡到更安全的替代方案**  
 ，如 SSH，用于远程管理。  
  
- **实施网络级过滤**  
 ，仅将 Telnet 访问限制在受信任的 IP 和网络。  
  
- 使用应用程序控制策略**阻止未经授权的 Telnet 客户端**  
 。  
  
重要的是，为了最大限度地降低大规模 利用 的风险，“ 此漏洞利用的源代码已被保留。” 目前仅向公众发布了一个二进制 PoC。https://github.com/hackerhouse-opensource/hfwintelnet  
  
  
