#  ScreenConnect 管理员应尽快修补关键的 RCE 漏洞   
 关键基础设施安全应急响应中心   2024-04-01 15:47  
  
ConnectWise 提醒 ScreenConnect 管理员应立即修补其服务器，以防止威胁分子用远程代码执行 (RCE) 攻击。  
  
据悉，此安全错误是由于身份验证绕过弱点造成的，攻击者可以利用该弱点来访问机密数据，或在不需要用户交互的低复杂性攻击中在服务器上远程执行任意代码。  
  
该公司还修复了远程桌面软件中的一个路径漏洞，该漏洞只能被具有高权限的攻击者滥用。  
  
ConnectWise称：“没有证据表明这些漏洞已被广泛利用，但内部部署合作伙伴必须立即采取行动，以解决这些已识别的安全风险。”  
  
ConnectWise 尚未为影响所有运行 ScreenConnect 23.9.7 及更早版本的服务器的两个安全缺陷分配 CVE ID。  
  
ScreenConnect.com 云或 Hostedrmm.com 上托管的 ScreenConnect 云服务器已受到保护，免受潜在攻击，建议使用本地软件的管理员立即将其服务器更新到 ScreenConnect 版本 23.9.8。  
  
Huntress 安全研究人员在报告中说，他们已经创建了一个概念验证 (PoC) 漏洞，可用于绕过未修补的 ScreenConnect 服务器上的身份验证。  
  
在 Censys 暴露管理平台上进行搜索后，他们发现了超过 8800 台容易受到攻击的服务器。  
  
Shodan 还跟踪超 7600 个 ScreenConnect 服务器，其中只有 160 个当前运行经过修补的ScreenConnect 23.9.8 版本。  
  
上个月，CISA、NSA 和 MS-ISAC 发布了联合咨询警告，称攻击者越来越多地使用合法的远程监控和管理 (RMM) 软件（例如 ConnectWise ScreenConnect）进行恶意操作。  
  
通过使用远程桌面软件作为目标网络的入口点，威胁分子可以以本地用户身份访问其系统，而无需管理员权限或安装新的完整软件。  
  
这使得他们能够绕过安全控制，并利用受损用户的权限来访问网络上的其他设备。  
  
多年来，攻击者一直利用 ScreenConnect 进行恶意目的，包括窃取数据以及在受害者被破坏的系统上部署勒索软件负载。最近，Huntress 还发现威胁分子使用本地 ScreenConnect 实例持续访问被黑网络。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/connectwise-urges-screenconnect-admins-to-patch-critical-rce-flaw/  
  
  
  
原文来源：  
嘶吼专业版  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
