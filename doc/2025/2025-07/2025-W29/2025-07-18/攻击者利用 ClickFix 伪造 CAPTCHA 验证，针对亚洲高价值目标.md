> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795759&idx=1&sn=7c479d5b28c684db1282fa88ee91e978

#  攻击者利用 ClickFix 伪造 CAPTCHA 验证，针对亚洲高价值目标  
会杀毒的单反狗  军哥网络安全读报   2025-07-18 01:00  
  
**导****读**  
  
  
  
一场针对多个亚洲敏感地区的复杂间谍活动已经出现，该活动利用武器化的快捷方式文件和欺骗性的社会工程技术渗透到中国、中国香港和巴基斯坦的高价值目标。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHbAD5a54IavNXqE5CQ8RhKbpt6s3JglhKvkYHcAgXOUQ1ibDyZWvLw4HUkS6Js4PhZBBK31qqXIkg/640?wx_fmt=png&from=appmsg "")  
  
  
研究人员以代号 UNG0002  
  
跟踪该威胁组织，该组织在从 2024 年 5 月至今的两个主要行动阶段中表现出了非凡的持久性和技术发展。  
  
  
该恶意活动采用多阶段感染链，首先在诱饵文档中嵌入武器化的 LNK 文件，然后执行 VBScript、进行批处理，最后部署基于 PowerShell 的有效载荷。  
  
  
这种复杂的方法允许威胁组织绕过传统的安全措施，同时在整个感染过程中保持较低的检测率。  
  
  
该威胁集群的行动涵盖两大主要活动：“Operation Cobalt Whisper“（2024年5月至2024年9月）和“Operation AmberMist”（2025年1月至2025年5月）。在“Operation Cobalt Whisper”期间，观察到20条感染链，针对国防、电工工程和民航领域。  
  
  
最近的“Operation AmberMist”活动已发展到针对游戏、软件开发和学术机构，并使用了改进的轻量级植入程序，包括Shadow RAT、Blister DLL Implant和INET RAT。表明其情报收集任务更为广泛。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHbAD5a54IavNXqE5CQ8RhKdVJjw4Svtf2xhyrWDX8nFrg4bZ3Sbs5dMW7u1XYV5WaCYN4Ju2nbrg/640?wx_fmt=png&from=appmsg "")  
  
  
该活动最显著的创新涉及滥用 ClickFix 技术，这是一种社会工程方法，向受害者提供虚假的 CAPTCHA 验证页面，旨在诱骗他们执行恶意的 PowerShell 脚本。  
  
  
安全研究人员观察到威胁组织专门伪造巴基斯坦海事部网站以增强其欺骗性页面的合法性的情况。  
  
### 高级感染机制和持久性策略  
###   
  
感染机制通过多层次的系统入侵方法展现出惊人的复杂性。  
  
  
攻击始于受害者收到以简历为主题的诱饵 ZIP 文件，使用针对特定行业的真实简历文件，包括游戏 UI 设计师和来自知名机构的计算机科学专业学生的虚假个人资料。  
  
  
其中包含伪装成合法 PDF 文档的恶意 LNK 文件。执行后，这些快捷方式文件会启动一个复杂的攻击链，涉及 VBScript 脚本、批处理脚本处理和PowerShell执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHbAD5a54IavNXqE5CQ8RhKCkFQDqBy0rX38hHCx4dAmEPS2KAkhWEGYK5SRdHXojIicaY1ht48mZQ/640?wx_fmt=png&from=appmsg "")  
  
  
技术分析表明，UNG0002 采用DLL 侧加载技术，特别是针对合法的 Windows 应用程序，例如 Rasphone.exe 和 Node-Webkit 二进制文件。  
  
恶意软件利用这些可信进程来执行恶意负载，同时逃避检测机制。  
  
  
分析过程中发现的程序数据库 (PDB) 路径表明内部代号为“Mustang”和“ShockWave”，表明有组织的开发实践，其中 C:\Users\The Freelancer\source\repos\JAN25\mustang\x64\Release\mustang.pdb 和 C:\Users\Shockwave\source\repos\memcom\x64\Release\memcom.pdb 路径分别嵌入在 Shadow RAT 和 INET RAT 中。  
  
  
持久基础设施保持一致的命令和控制操作，部署自定义植入物，包括 Shadow RAT、INET RAT 和 Blister DLL 加载器。  
  
  
这些工具提供了全面的系统访问，实现了数据泄露、远程命令执行和跨受损网络的横向移动功能，使 UNG0002 成为对区域网络安全的巨大威胁。  
  
  
详细技术报告：  
  
https://www.seqrite.com/blog/ung0002-espionage-campaigns-south-asia/  
  
  
新闻链接：  
  
https://cybersecuritynews.com/ung0002-actors-deploys-weaponize-lnk-files/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
攻击者利用 ClickFix 伪造的 CAPTCHA 验证页面，针对亚洲高价值目标  
  
https://cybersecuritynews.com/ung0002-actors-deploys-weaponize-lnk-files/  
  
  
Proofpoint  
发现针对半导体行业的网络钓鱼攻击  
  
https://cybersecuritynews.com/chinese-state-sponsored-hackers-attacking-semiconductor-industry/  
  
  
黑客组织“Salt Typhoon”袭击了国民警卫队一个网络，并窃听与其他单位的通信  
  
https://www.securityweek.com/chinas-salt-typhoon-hacked-us-national-guard/  
  
  
曹县黑客利用 67 个恶意 npm 软件包传播 XORIndex 恶意软件  
  
https://gbhackers.com/north-korean-hackers-exploit-67-malicious-npm-packages/  
  
  
曹县黑客利用 Zoom 攻击加密货币公司  
  
https://gbhackers.com/north-korean-hackers-exploit-zoom-invites-in-attacks/  
  
  
伊朗黑客组织瞄准美国关键基础设施，包括供水系统  
  
https://gbhackers.com/iranian-threat-actors-target-u-s-critical-infrastructure/  
  
  
针对东南亚政府组织的攻击使用新型隐蔽 C2 通信  
  
https://thehackernews.com/2025/07/state-backed-hazybeacon-malware-uses.html  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
黑客利用 DNS 盲点隐藏和传播恶意软件  
  
https://cybersecuritynews.com/dns-blind-spots-exploited/  
  
  
Microsoft Teams 语音通话被滥用来推广 Matanbuchus 恶意软件  
  
https://www.bleepingcomputer.com/news/security/microsoft-teams-voice-calls-abused-to-push-matanbuchus-malware/  
  
  
黑客利用 GitHub 存储库托管 Amadey 恶意软件和数据窃取程序  
  
https://thehackernews.com/2025/07/hackers-use-github-repositories-to-host.html  
  
  
H2Miner 挖矿木马攻击 Linux、Windows 和容器  
  
https://cybersecuritynews.com/h2miner-attacking-linux-windows/  
  
  
Stormous 勒索软件组织攻击美医疗机构，声称窃取了 60 万名患者数据  
  
https://securityaffairs.com/180057/data-breach/180057stormous-ransomware-gang-targets-north-country-healthcare-claims-600k-patient-data-stolen.html  
  
  
黑客利用 Apache HTTP 服务器漏洞部署 Linuxsys 加密货币挖矿程序  
  
https://thehackernews.com/2025/07/hackers-exploit-apache-http-server-flaw.html  
  
  
两起新的 DoS 攻击活动利用了超过 400 万台暴露的设备  
  
https://gbhackers.com/over-4-million-exposed-devices/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Oracle 将于 2025 年 7 月修复 200 个漏洞  
  
https://www.securityweek.com/oracle-patches-200-vulnerabilities-with-july-2025-cpu/  
  
  
思科发布多个漏洞的补丁，其中包括思科 ISE 中导致远程代码执行 (RCE) 的严重漏洞  
  
https://www.securityweek.com/cisco-patches-another-critical-ise-vulnerability/  
  
  
NVIDIA 容器工具包漏洞允许提升任意代码执行权限  
  
https://cybersecuritynews.com/nvidia-container-toolkit-vulnerability-2/  
  
  
Google Gemini AI 漏洞可能导致 Gmail 入侵和网络钓鱼  
  
https://securityboulevard.com/2025/07/google-gemini-ai-flaw-could-lead-to-gmail-compromise-phishing/  
  
  
新的 TeleMessage SGNL 漏洞正被攻击者积极利用  
  
https://hackread.com/telemessage-sgnl-flaw-actively-exploited-by-attackers/  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
