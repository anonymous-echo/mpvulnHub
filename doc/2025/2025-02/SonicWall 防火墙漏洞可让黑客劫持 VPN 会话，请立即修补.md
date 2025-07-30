#  SonicWall 防火墙漏洞可让黑客劫持 VPN 会话，请立即修补   
Rhinoer  犀牛安全   2025-02-21 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdI130nQpDquOBRHth8aTcMqrp73HhYzrlCicqykslyYmjdRcQIic1R4hg/640?wx_fmt=png&from=appmsg "")  
  
Bishop Fox 的安全研究人员公布了 CVE-2024-53704 漏洞的完整利用细节，该漏洞允许绕过某些版本的 SonicOS SSLVPN 应用程序中的身份验证机制。  
  
该供应商在 1 月 7 日发布的公告中警告了该漏洞极高的利用可能性，并敦促管理员升级其 SonicOS 防火墙的固件以解决该问题。  
  
SonicWall在当时发送给客户的电子邮件中警告称：“我们发现一个防火墙漏洞，对于启用了 SSL VPN 或 SSH 管理的客户来说，该漏洞很容易被实际利用，应立即升级到最新固件来缓解该漏洞。”  
  
该漏洞允许远程攻击者在未经身份验证的情况下劫持活动的 SSL VPN 会话，从而授予他们未经授权访问受害者网络的权限。  
  
1 月 22 日，Bishop Fox 的研究人员宣布 ，经过“大量的逆向工程努力”，他们已经开发出针对 CVE-2024-53704 的漏洞利用方法，证实了 SonicWall 对该漏洞利用潜力的担忧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdgqLMd6qKuBaiahlaMK7yB2e9wpNWI4W0lF239QSffbCa5nMRHL0tQbg/640?wx_fmt=png&from=appmsg "")  
  
在等待系统管理员安装可用补丁一段时间后，Bishop Fox 于周一公布了完整的漏洞利用细节。  
  
该漏洞的工作原理是将一个包含 base64 编码的空字节字符串的特制会话 cookie 发送到“/cgi-bin/sslvpnclient”的 SSL VPN 身份验证端点。  
  
这会触发错误的会话验证，因为该机制假定该请求与活动的 VPN 会话相关联。  
  
这将使受害者退出登录，并让攻击者访问会话，从而允许他们读取用户的虚拟办公室书签、获取 VPN 客户端配置设置、打开到内部网络的 VPN 隧道并提供对私有网络资源的访问权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdvmaI03Gg3ql4na0mFLW9Zj60WZoUFsRw45lbSkyuJia4JOPqYZ5TBRw/640?wx_fmt=png&from=appmsg "")  
  
研究人员测试了分析的有效性，并创建了概念验证漏洞代码来模拟身份验证绕过攻击。响应标头显示他们已成功劫持活动会话。  
  
研究人员表示：“通过这种方式，我们能够识别被劫持会话的用户名和域名，以及用户能够通过 SSL VPN 访问的私人路由。”  
  
有安全更新可用  
  
该问题影响 SonicOS 版本 7.1.x（最高 7.1.1-7058）、7.1.2-7019 和 8.0.0-8035。这些版本运行在多种型号的第六代和第七代防火墙以及 SOHO 系列设备中。  
  
SonicOS 8.0.0-8037 及更高版本、7.0.1-5165 及更高版本、7.1.3-7015 及更高版本以及 6.5.5.1-6n 及更高版本中提供了修复。有关特定型号的信息，请在此处查看 SonicWall 的公告。  
  
Bishop Fox 表示，截至 2 月 7 日的互联网扫描显示，大约有 4,500 台暴露在互联网上的 SonicWall SSL VPN 服务器没有安装修复 CVE-2024-53705 的安全更新。  
  
由于有效的概念验证漏洞现已公开，管理员应尽快应用更新，因为 CVE-2024-53705 的利用风险已显著增加。  
  
  
信息来源：BleepingComputer  
  
