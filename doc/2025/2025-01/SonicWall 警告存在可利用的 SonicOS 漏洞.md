#  SonicWall 警告存在可利用的 SonicOS 漏洞   
鹏鹏同学  黑猫安全   2025-01-09 23:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicu2HNRPyaqf04vvicNicnh8od3nDxibCniav9b5KFferP44qYcx47XtsmJZtypTIGLQIrMGNyeVWVC5A/640?wx_fmt=png&from=appmsg "")  
  
SonicWall 敦促客户升级其防火墙的 SonicOS 固件，以修补一个被追踪为 CVE-2024-53704（CVSS 评分为 8.2）的认证绕过漏洞。该漏洞存在于 SSL VPN 和 SSH 管理中，据供应商称，该漏洞“容易被实际利用”。  
  
“我们已经识别出一个高风险（CVE 评分 8.2）的防火墙漏洞，该漏洞容易被实际利用，特别是对于启用了 SSL VPN 或 SSH 管理的客户，应立即通过升级到最新的固件来缓解该漏洞。最新的固件将于明天，即 2025 年 1 月 7 日在网上发布。同一固件升级还包含了对其他一些不太严重的漏洞的缓解措施。”公司在通过电子邮件发送给客户的通知中写道。  
  
以下是所有安全通告及相关漏洞的列表。再次强调，此次升级解决了一个对 SSL VPN 用户的高风险漏洞，这些用户应被视为面临即将被利用的风险，并立即进行更新。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicu2HNRPyaqf04vvicNicnh8oIiaYDWmt00y4Cb1m6OYRxgZOWOgjOArvHogMUyDpfCGMICiarAtvb0Bg/640?wx_fmt=png&from=appmsg "")  
  
公司鼓励所有客户将其防火墙升级到下面列出的最新维护版本。以下是解决上表中列出的漏洞的发布版本：  
- Gen 6 / 6.5 硬件防火墙：SonicOS 6.5.5.1-6n 或更高版本  
  
- Gen 6 / 6.5 NSv 防火墙：SonicOS 6.5.4.v-21s-RC2457 或更高版本  
  
- Gen 7 防火墙：SonicOS 7.0.1-5165 或更高版本；7.1.3-7015 及更高版本  
  
- TZ80：SonicOS 8.0.0-8037 或更高版本  
  
供应商还提供了以下缓解措施：  
  
为了最小化 SSLVPN 漏洞的潜在影响，请确保访问仅限于受信任的来源，或从互联网禁用 SSLVPN 访问。有关禁用防火墙 SSLVPN 访问的更多信息，请参阅：how-can-i-setup-ssl-vpn。  
  
公司在变通方案会话中发布的通知中写道。“为了最小化 SSH 漏洞的潜在影响，我们建议将防火墙管理限制为受信任的来源，或从互联网访问禁用防火墙 SSH 管理。”  
  
  
