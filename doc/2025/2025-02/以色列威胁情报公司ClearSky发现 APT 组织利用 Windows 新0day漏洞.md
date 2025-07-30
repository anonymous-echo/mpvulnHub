#  以色列威胁情报公司ClearSky发现 APT 组织利用 Windows 新0day漏洞   
会杀毒的单反狗  军哥网络安全读报   2025-02-15 01:00  
  
**导****读**  
  
  
  
以色列威胁情报公司 ClearSky Cyber  
  
Security 周四透露，它发现一个 APT  
   
组织正在利用新 Windows 漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaH8rg3aRbpH7pSdXEXBIwvIMW1vGq5TTLCcphvq4E80WksLqPkAtPAibZ8VvK1p7vhPtPJVWFbKJrA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
ClearSky 承诺将在即将发布的博客文章中分享更多细节，但 X 上的发贴表明 Windows 漏洞已被利用为  
0day  
漏洞，因为似乎尚未分配 CVE。   
  
  
该公司表示，微软已经意识到了这一漏洞，但将其归类为“低严重性”。  
  
  
ClearSky 将该问题描述为“UI 漏洞”，并发现Mustang Panda威胁组织利用该漏洞的证据。  
  
  
该安全公司在 X 的官方账号发布了一些技术细节：  
  
  
当文件从压缩的“RAR”文件中提取出来时，它们对用户是隐藏的。如果将压缩文件提取到文件夹中，则该文件夹在 Windows 资源管理器 GUI 中显示为空。  
  
  
当使用“dir”命令列出目标文件夹内的所有文件和文件夹时，提取的文件和文件夹对用户来说是“不可见/隐藏”的。如果威胁行为者或用户知道确切的路径，他们也可以从命令行提示符执行这些压缩文件。  
  
  
对受系统保护的文件执行‘attrib -s -h’的结果是，从类型‘未知’ActiveX 组件创建了一种未知的文件类型。  
  
  
微软  
2  
月补丁日更新解决了 50 多个漏洞，其中包括两个已被利用的  
0day  
漏洞，即 CVE-2025-21391（一个 Windows 存储权限提升问题，可用于从系统中删除文件）和 CVE-2025-21418（一个 Windows 辅助功能驱动程序缺陷，可用于将权限提升至系统）。   
  
  
新闻链接：  
  
https://www.securityweek.com/new-windows-zero-day-exploited-by-chinese-apt-security-firm/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
以色列威胁情报公司ClearSky发现 APT 组织利用 Windows 新  
0day  
漏洞  
  
https://www.securityweek.com/new-windows-zero-day-exploited-by-chinese-apt-security-firm/  
  
  
Salt Typhoon瞄准思科旧漏洞，引发新一轮电信黑客攻击  
  
https://www.securityweek.com/salt-typhoon-targeting-old-cisco-vulnerabilities-in-fresh-telecom-hacks/  
  
  
Lazarus Group 在针对开发人员的攻击中部署 Marstech1 JavaScript 植入程序  
  
https://thehackernews.com/2025/02/lazarus-group-deploys-marstech1.html  
  
  
曹县APT43 使用 PowerShell 和 Dropbox 针对韩国发起网络攻击  
  
https://thehackernews.com/2025/02/north-korean-apt43-uses-powershell-and.html  
  
  
微软：与俄罗斯有关的黑客利用“设备代码钓鱼”劫持账户  
  
https://thehackernews.com/2025/02/microsoft-russian-linked-hackers-using.html  
  
  
微软：俄罗斯“Seashell Blizzard”黑客已获得关键基础设施访问权限  
  
https://www.securityweek.com/russian-seashell-blizzard-hackers-gain-maintain-access-to-high-value-targets-microsoft/  
  
  
FINALDRAFT 恶意软件利用微软Graph API进行间谍活动  
  
https://thehackernews.com/2025/02/finaldraft-malware-exploits-microsoft.html  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
新的“who  
ami  
”攻击利用 AWS AMI 名称混淆进行远程代码执行  
  
https://thehackernews.com/2025/02/new-whoami-attack-exploits-aws-ami-name.html  
  
  
RansomHub 成为 2024 年最大的勒索软件集团，攻击全球 600 多家组织  
  
https://thehackernews.com/2025/02/ransomhub-becomes-2024s-top-ransomware.html  
  
  
恶意 PirateFi 游戏利用 Vidar 恶意软件感染 Steam 用户  
  
https://www.bleepingcomputer.com/news/security/malicious-piratefi-game-infects-steam-users-with-vidar-malware/  
  
  
新日铁遭到 BianLian 勒索病毒攻击  
  
https://cybernews.com/news/nippon-steel-claimed-by-bianlian-ransomware-group/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
黑客在 Palo Alto 防火墙漏洞（CVE-2025-0108）披露第二天开始利用  
  
https://www.securityweek.com/hackers-exploit-palo-alto-firewall-vulnerability-day-after-disclosure/  
  
  
CVE-2025-0108漏洞技术细节：  
  
https://www.assetnote.io/resources/research/nginx-apache-path-confusion-to-auth-bypass-in-pan-os  
  
  
SonicWall 防火墙漏洞PoC发布后不久就被利用  
  
https://www.securityweek.com/sonicwall-firewall-vulnerability-exploited-after-poc-publication/  
  
  
PostgreSQL 漏洞与 BeyondTrust 零日漏洞一起被利用进行针对性攻击  
  
https://thehackernews.com/2025/02/postgresql-vulnerability-exploited.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
