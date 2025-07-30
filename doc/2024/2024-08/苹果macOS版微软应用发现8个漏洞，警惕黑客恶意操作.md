#  苹果macOS版微软应用发现8个漏洞，警惕黑客恶意操作   
 网络安全应急技术国家工程中心   2024-08-22 17:51  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176kKIynmxjU7vP9PgHDWriciaiayg1T9ffib5LeTZukQg7K5ZDSV1Y9gTM80khdy13DFSI9CGeM29OmcWA/640?wx_fmt=jpeg&from=appmsg "")  
  
近期，Cisco Talos研究称，macOS版微软应用存在八个漏洞。利用TCC框架的弱点，黑客可以绕过权限执行恶意操作。  
  
TCC（Transparency, Consent, and Control）是一种安全策略，它要求应用程序在访问用户数据和系统资源之前必须获得用户的同意，从而保护数据和资源。  
  
然而，研究人员发现，他们可以利用微软应用程序中的漏洞来绕过TCC并在未经用户同意的情况下访问敏感的用户数据和资源。  
  
Cisco Talos在2024年8月19日发布的研究，揭露了macOS系统中存在的安全漏洞，特别是针对库（libraries）的权限/权利的利用，也被称为库注入或Dylib劫持。  
  
攻击者利用macOS系统中的已知漏洞，比如Microsoft Teams中禁用的库验证功能，来获得未授权的访问权限。  
  
他们通过诱使用户打开恶意附件或点击被破坏的链接，将恶意库注入到应用程序的程中，绕过安全措施，窃取权限。  
  
以下是Talos识别的漏洞列表，以及它们的Talos ID和关联的CVE：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6x58K4V5rbbWicxZVA9R5RZxrCFcHek73bgw6Rsa868UEtJ59ib7leEt7Gf4CbXTq4nc1kvoHKoAPuA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
这些漏洞可能允许攻击者在没有用户交互的情况下发送电子邮件、拍照或录制视频。  
  
微软公司认为这些问题的风险等级较低。不过研究人员目前已经报告了四个应用程序存在这些漏洞，并且进行了更新，更新后的版本不再容易受到最初描述的攻击场景的影响。  
  
  
  
原文来源  
：E安全  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
