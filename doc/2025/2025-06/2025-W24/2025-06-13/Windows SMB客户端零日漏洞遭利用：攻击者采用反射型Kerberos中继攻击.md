#  Windows SMB客户端零日漏洞遭利用：攻击者采用反射型Kerberos中继攻击  
邑安科技  邑安全   2025-06-13 02:12  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sVmibsmbia4yXKcwL3UUgmibqg0qfeZZ4VIic2icZVZybAj7iaicfTfXfjkdxp4sZoBRiaPqzhJTPbFo2E0g/640?wx_fmt=png&from=appmsg "")  
  
一个影响 Windows 系统的关键零日漏洞，允许攻击者通过新颖的反射式 Kerberos 中继攻击实现权限提升。  
  
该漏洞被命名为 CVE-2025-33073，由 Microsoft 于 2025 年 6 月 10 日修补，作为其每月补丁星期二安全更新的一部分。  
  
Microsoft 已将此漏洞的 CVSS 评分为 9.8（严重），因为该漏洞的攻击复杂度较低，并且对机密性、完整性和可用性的影响较大。  
  
反射式 Kerberos 中继攻击  
  
RedTeam 渗透测试报告称，反射式 Kerberos 中继攻击代表了身份验证中继技术的重大发展，绕过了自 2008 年以来实施的 NTLM 反射限制。  
  
攻击从身份验证强制开始，攻击者使用技术强制 Windows 主机使用计算机帐户的凭据通过 SMB 对其系统进行身份验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sVmibsmbia4yXKcwL3UUgmibqjLA1qHdvNL9EFbKtQTfx70FJrHfGP0UI12LZnia0AlCfcfzr0CGzmLA/640?wx_fmt=png&from=appmsg "")  
  
核心技术挑战涉及使用  
  
 CredUnmarshalTargetInfo/CREDENTIAL_TARGET_INFORMATIONW 技巧将强制目标和服务主体名称 （SPN） 解耦，该技巧最初由 Google Project Zero 的 James Forshaw 开创。  
  
此技术允许攻击者注册指向其攻击系统的主机名，同时导致为完全不同的主机颁发 Kerberos 票证。  
  
研究人员使用他们的 wspcoerce 工具演示了这种攻击，其命令结构如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sVmibsmbia4yXKcwL3UUgmibqYwnyvHtQpibcRQ1jvno4wPEjjActicgmYLlK8NLSglOjqapvVW2g0b0A/640?wx_fmt=png&from=appmsg "")  
  
该攻击还需要绕过 NTLM 优先级，因为 Windows 在连接到自身时默认为 NTLM。攻击者必须修改 krbrelayx 等工具才能不通告 NTLM 功能，从而强制进行 Kerberos 身份验证。  
  
该漏洞最令人担忧的方面是其意外的权限提升功能。  
  
当攻击者将 Kerberos 票证中继回原始主机时，他们不会接收具有计算机帐户权限的低权限会话，而是获得足以远程执行代码的 NT AUTHORITY\SYSTEM 权限。  
  
研究人员推测，这是由于 Windows 对本地环回身份验证的保护，该身份验证将 Kerberos 票证链接到其原始进程。  
  
系统似乎对攻击场景感到困惑，其中高权限 NT AUTHORITY\SYSTEM 帐户使用低权限计算机帐户凭据执行身份验证。  
  
这会导致包含将票证链接到原始进程的 KERB_AD_RESTRICTION_ENTRY 和 KERB_LOCAL 结构，最终继承 NT AUTHORITY\SYSTEM 权限。  
<table><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td data-colwidth="160" style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="14330498" msthash="77" style="box-sizing: border-box;font-weight: bold;"><span leaf=""><span textstyle="" style="font-size: 15px;">风险因素</span></span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="3259074" msthash="78" style="box-sizing: border-box;font-weight: bold;"><span leaf=""><span textstyle="" style="font-size: 15px;">详</span></span></strong></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="160" style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">受影响的产品</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">Windows 10（所有版本）、Windows 11（24H2 之前）、Windows Server 2019–2025</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td data-colwidth="160" style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">冲击</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">权限提升</span></span></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="160" style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">利用先决条件</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">1. 通过 SMB</span></span><span leaf=""><br/></span><span leaf=""><span textstyle="" style="font-size: 15px;">进行身份验证强制 2.能够将 Kerberos 票证中继到易受攻击的 SMB 实施</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td data-colwidth="160" style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">CVSS 3.1 分数</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section style="margin-top: 8px;margin-bottom: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">9.8（严重）</span></span></section></td></tr></tbody></table>  
缓解策略  
  
该漏洞影响 Windows 10、11 和 Server 版本 2019 到 2025，在补丁前环境中没有已知的免疫版本。  
  
但是，成功利用该漏洞需要身份验证强制和 SMB 中继功能。SMB 强制对早于 23H2 的所有客户端和服务器都能可靠地工作，而较新的服务器版本可能具有不同的敏感性。  
  
强制服务器端 SMB 签名时，将阻止 SMB 中继。虽然此保护在 Windows 11 24H2 客户端和域控制器上默认启用，但在大多数服务器上仍然是可选的。  
  
组织应优先启用服务器端 SMB 签名和其他安全功能（如通道绑定和 EPA），因为这些缓解措施对 NTLM 和 Kerberos 安全性都至关重要。  
  
这一发现突显了围绕基于 Kerberos 的攻击不断变化的威胁态势，并强调为 NTLM 开发的安全措施对于 Kerberos 环境仍然同样重要。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/windows-smb-client-zero-day-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
