#  CISA警告：JetBrains TeamCity漏洞被利用   
THN  知机安全   2024-03-09 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfOhxqASobwL65UiamWiaLqDGgtsPbX9yltHuLPvfepIaOyUM7OdSkdFyhz7y2KjpQf1icYCVtO9ajIAQ/640?wx_fmt=png "")  
  
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) on Thursday added a critical security flaw impacting JetBrains TeamCity On-Premises software to its Known Exploited Vulnerabilities (KEV) catalog, based on evidence of active exploitation.  
  
美国网络安全与基础设施安全局（CISA）于周四将一项影响JetBrains TeamCity On-Premises软件的关键安全漏洞添加到其已知受攻击漏洞（KEV）目录中，根据活跃利用的证据。  
  
The vulnerability, tracked as CVE-2024-27198 (CVSS score: 9.8), refers to an authentication bypass bug that allows for a complete compromise of a susceptible server by a remote unauthenticated attacker.  
  
该漏洞被标记为CVE-2024-27198（CVSS评分：9.8），指的是一种绕过身份验证的漏洞，允许远程未经身份验证的攻击者完全控制易受攻击的服务器。  
  
It was addressed by JetBrains earlier this week alongside CVE-2024-27199 (CVSS score: 7.3), another moderate-severity authentication bypass flaw that allows for a "limited amount" of information disclosure and system modification.  
  
这个漏洞已在本周早些时候由JetBrains解决，同时还解决了CVE-2024-27199（CVSS评分：7.3），另一个中等严重性的身份验证绕过漏洞，允许"有限数量"的信息泄露和系统修改。  
  
"The vulnerabilities may enable an unauthenticated attacker with HTTP(S) access to a TeamCity server to bypass authentication checks and gain administrative control of that TeamCity server," the company noted at the time.  
  
公司在当时指出，这些漏洞可能使未经身份验证的攻击者通过HTTP(S)访问TeamCity服务器绕过身份验证检查，并获得对该TeamCity服务器的管理权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfOhxqASobwL65UiamWiaLqDGgpia0uaohUdiclIHf1ibbYntk30QicxTrgjw8eict2bHiapbc5IcTFoib9QdQg/640?wx_fmt=png "")  
  
Threat actors have been observed weaponizing the twin flaws to deliver Jasmin ransomware as well as create hundreds of rogue user accounts, according to CrowdStrike and LeakIX. The Shadowserver Foundation said it detected exploitation attempts starting from March 4, 2024.  
  
据CrowdStrike和LeakIX称，已经观察到威胁行为者武器化这两个漏洞，传送Jasmin勒索软件并创建数百个虚假用户帐户。Shadowserver Foundation称，它从2024年3月4日开始检测到利用尝试。  
  
Statistics shared by GreyNoise show that CVE-2024-27198 has come under broad exploitation from over a dozen unique IP addresses shortly after public disclosure of the flaw.  
  
GreyNoise分享的统计数据显示，在漏洞公开披露后不久，CVE-2024-27198已被十几个独特IP地址广泛利用。  
  
In light of active exploitation, users running on-premises versions of the software are advised to apply the updates as soon as possible to mitigate potential threats. Federal agencies are required to patch their instances by March 28, 2024.  
  
鉴于活跃利用，建议运行软件的本地版本的用户尽快应用更新以减轻潜在威胁。联邦机构必须在2024年3月28日之前修补其实例。  
  
**参考资料**  
  
[1]https://thehackernews.com/2024/03/cisa-warns-of-actively-exploited.html  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选双语资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的双语新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
