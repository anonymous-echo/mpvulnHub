> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795533&idx=1&sn=72c3ca5e960d19d7c59bd5ff386a0eca

#  WinRAR 目录漏洞允许使用恶意文件执行任意代码  
会杀毒的单反狗  军哥网络安全读报   2025-06-25 01:00  
  
**导****读**  
  
  
  
WinRAR 软件中发现一个严重级别安全漏洞，远程攻击者可以利用该漏洞通过恶意存档文件执行任意代码。  
  
  
该漏洞编号为 CVE-2025-6218，CVSS 评分 7.8，漏洞影响广泛使用的文件压缩实用程序对存档文件中目录路径的处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFGzicYibUPSzv9Wq34XB1V6SHnXMSicgTT0gZC5OMs2HgvrALuYGFC1rib5Enj0r7XwVjBtZzg7iawiaQQ/640?wx_fmt=png&from=appmsg "")  
  
  
这个远程代码执行 (RCE) 漏洞允许攻击者在当前用户的上下文中执行恶意代码，但成功利用该漏洞需要用户交互。  
  
  
漏洞利用机制的核心在于存档文件中精心设计的文件路径，这可能导致 WinRAR 进程遍历到非预期的目录。  
  
  
此路径遍历攻击绕过了正常的安全边界，使攻击者能够将文件写入预期提取目录之外的位置。 此类漏洞尤其危险，因为与其他攻击技术结合时，它们可能导致整个系统被攻陷。  
  
  
技术分析表明，该漏洞存在于 WinRAR 处理存档文件时的文件路径处理例程中。  
  
  
发现并报告该漏洞的安全研究员 whs3-detonator 发现，包含恶意目录路径的特制存档文件可以操纵提取过程。  
  
  
攻击媒介要求目标用户访问恶意网页或打开恶意存档文件，这使其容易受到社会工程攻击。该技术利用了档案文件结构中嵌入的目录遍历序列。 这些序列可以包含相对路径指示符，例如“../”模式，允许攻击者导航到预期的提取目录之外。  
  
  
一旦成功，该漏洞就可以以运行 WinRAR 的用户权限执行任意代码。  
  
  
建议用户更新到 WinRAR 7.11 以修复漏洞。由于严重性等级高且可能针对其系统进行远程代码执行攻击，组织应优先考虑此更新。  
  
  
新闻链接：  
  
https://cybersecuritynews.com/winrar-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
APT组织利用ShortLeash 后门感染 SOHO 路由器，构建间谍网络基础设施  
  
https://www.securityweek.com/chinese-apt-hacking-routers-to-build-espionage-infrastructure/  
  
  
朝鲜黑客利用 Zoom 会议系统入侵受害者系统  
  
https://www.securityweek.com/north-korean-hackers-take-over-victims-systems-using-zoom-meeting/  
  
  
APT28 黑客利用 Signal 聊天对乌克兰发起新的恶意软件攻击  
  
https://www.bleepingcomputer.com/news/security/apt28-hackers-use-signal-chats-to-launch-new-malware-attacks-on-ukraine/  
  
  
以色列官员称伊朗利用安全摄像头引导导弹袭击  
  
https://therecord.media/iran-espionage-israeli-security-cameras-missile-attacks  
  
  
与伊朗有关的网络攻击扰乱了阿尔巴尼亚首都的公共服务  
  
https://therecord.media/tirana-albania-government-cyberattack-iran-linked-group  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
黑客攻击超过 70 台 Exchange 服务器，通过键盘记录器窃取凭证  
  
https://thehackernews.com/2025/06/hackers-target-65-microsoft-exchange.html  
  
  
Androxgh0st 僵尸网络扩大影响范围，攻击美国大学服务器  
  
https://hackread.com/androxgh0st-botnet-expand-exploit-us-university-servers/  
  
  
警惕窃取用户凭证的假冒 SonicWall VPN 应用  
  
https://www.theregister.com/2025/06/24/unknown_crims_using_hacked_sonicwall/  
  
  
卡巴斯基发现TikTok克隆版传播恶意软件，攻击针对加密货币钱包  
  
https://dataconomy.com/2025/06/24/kaspersky-finds-tiktok-clones-spreading-malware/  
  
  
技术支持诈骗使用赞助广告和搜索参数注入来诱骗用户给他们打电话  
  
https://www.securityweek.com/apple-netflix-microsoft-sites-hacked-for-tech-support-scams/  
  
  
Prometei挖矿僵尸网络活动激增  
  
https://www.securityweek.com/prometei-botnet-activity-spikes/  
  
  
密歇根州医院网络遭勒索软件攻击  
  
https://therecord.media/mclaren-health-care-data-breach-notification-ransomware  
  
  
美国众议院因安全问题禁止在政府设备上使用 WhatsApp  
  
https://securityaffairs.com/179297/mobile-2/us-house-banned-whatsapp-on-government-devices.html  
  
  
新的 FileFix 攻击利用 Windows 文件资源管理器执行恶意命令  
  
https://cybersecuritynews.com/filefix-attack/  
  
  
复杂的恶意软件活动利用混淆的 Skimmer 攻击 WordPress 和 WooCommerce 网站  
  
https://cybersecuritynews.com/malware-campaign-targets-wordpress-and-woocommerce-sites/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Aviatrix 云控制器漏洞可通过身份验证绕过实现远程代码执行  
  
https://gbhackers.com/aviatrix-cloud-controller-flaw/  
  
  
Zimbra Classic Web 客户端漏洞允许任意 JavaScript 执行  
  
https://gbhackers.com/zimbra-classic-web-client-vulnerability/  
  
  
Teleport 中的关键身份验证绕过漏洞已修复  
  
https://www.securityweek.com/critical-authentication-bypass-flaw-patched-in-teleport/  
  
  
Notepad++漏洞使攻击者获得完全系统控制权  
  
https://cybersecuritynews.com/notepad-vulnerability/  
  
  
WinRAR 目录漏洞允许使用恶意文件执行任意代码  
  
https://cybersecuritynews.com/winrar-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
