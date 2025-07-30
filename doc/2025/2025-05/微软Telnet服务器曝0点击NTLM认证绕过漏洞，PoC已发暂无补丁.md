#  微软Telnet服务器曝0点击NTLM认证绕过漏洞，PoC已发暂无补丁   
 网络安全与人工智能研究中心   2025-05-02 08:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUSicwuicfUyAydJhQTRo5N6XPD9LxvGALWdC7ZZVI2R6skN0r8WUhrjcA/640?wx_fmt=gif&from=appmsg "")  
  
  
网络安全研究人员发现微软Telnet服务器存在严重漏洞，远程攻击者无需有效凭证即可完全绕过认证机制，获取管理员权限。根据Hacker Fantastic发布的报告，该漏洞涉及微软Telnet认证协议(MS-TNAP)，对传统Windows系统构成重大安全威胁，且目前尚无官方补丁。  
  
  
报告指出："微软Telnet服务器中存在一个关键的0点击远程认证绕过漏洞，攻击者无需有效凭证即可获得包括管理员在内的任意用户访问权限"。该漏洞源于Telnet服务器处理NTLM（NT LAN Manager）认证流程时的配置错误。  
  
  
**01**  
  
  
  
**受影响系统范围**  
  
  
该漏洞影响以下广泛使用的微软操作系统版本：  
  
- Windows 2000  
  
- Windows XP  
  
- Windows Server 2003  
  
- Windows Vista  
  
- Windows Server 2008  
  
- Windows 7  
  
- Windows Server 2008 R2  
  
  
  
  
**02**  
  
  
  
**漏洞技术原理**  
  
  
漏洞成因在于Telnet服务器错误地初始化NTLM认证凭据并错误处理双向认证。具体表现为服务器在认证握手阶段设置了存在缺陷的SSPI（安全支持提供程序接口）标志：  
  
  
报告解释称："服务器使用SECPKG_CRED_BOTH标志初始化NTLM安全机制"，并且"调用AcceptSecurityContext()函数时启用了ASC_REQ_DELEGATE和ASC_REQ_MUTUAL_AUTH标志"。  
  
  
这种错误配置导致认证关系出现危险逆转——服务器反而向客户端证明自身身份，而非验证客户端身份。  
  
  
**03**  
  
  
  
**漏洞利用过程**  
  
  
Hacker Fantastic发布的概念验证(PoC)利用程序通过以下步骤实施攻击：  
  
1. 使用特定标志请求双向认证  
  
1. 为目标管理员账户使用NULL空密码  
  
1. 操纵SSPI标志触发服务器认证逻辑缺陷  
  
1. 发送经过篡改的NTLM Type 3类型消息欺骗服务器  
  
1. 最终完全绕过认证，开启具有管理员权限的Telnet会话  
  
  
  
  
报告强调："攻击者可通过发送双向认证数据包并利用SSPI配置绕过服务端认证，从而获取主机上任意账户的访问权限"  
  
  
已发布的PoC工具**telnetbypass.exe**针对本地主机或域内主机，要求目标系统Telnet Server服务处于运行状态。  
  
  
**04**  
  
  
  
**缓解措施建议**  
  
  
令人担忧的是，"目前该漏洞尚无补丁"。建议相关组织立即采取以下防护措施：  
  
- **禁用所有系统上的Telnet Server服务**  
  
- **采用SSH等更安全的远程管理方案替代Telnet**  
  
- **实施网络层过滤，**  
仅允许可信IP和网络访问Telnet服务  
  
- **应用控制策略**  
阻止未经授权的Telnet客户端连接  
  
  
  
  
值得注意的是，为降低大规模利用风险，"该漏洞利用的源代码暂未公开"，目前仅向公众发布了二进制格式的PoC程序。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUMk71re53Z8Xju62nS9agGCNgUNjPibQP7YZthr22UXppftxLN0kp97A/640?wx_fmt=png&from=appmsg "")  
  
来源｜“FreeBuf”公众号  
  
编辑｜音叶泽  
  
审核｜秦川原  
  
  
