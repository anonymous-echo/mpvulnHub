#  Salt Typhoon 威胁组织利用较旧的漏洞破坏了思科边缘设备   
会杀毒的单反狗  军哥网络安全读报   2025-02-14 01:01  
  
**导****读**  
  
  
  
根据 Recorded Future 旗下 Insikt Group 周四发布的研究报告，Salt Typhoon（Recorded Future 称之为“RedMike”）在 2024 年 12 月至 2025 年 1 月期间发起了一场针对未打补丁的思科边缘设备的攻击活动。Insikt Group 研究人员观察到，该威胁组织在两个月内试图入侵全球 1,000 多台此类设备。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFYCYxxf9rJIcJBzDZzVciakUcsFgWUNGvXEAT5dcfQDhjZvlu1iaicGQ0wvicOuTasteiaAHxHuTTDExw/640?wx_fmt=png&from=appmsg "")  
  
  
具体来说，Salt Typhoon 最初利用了Cisco IOS XE 软件 Web 用户界面中的权限提升漏洞CVE-2023-20198来获取 root 访问权限，并利用相关权限提升漏洞CVE-2023-20273来获取 root 访问权限。  
  
  
这两个漏洞都是在 2023 年 10 月作为0day漏洞披露的，当时这些漏洞被广泛利用，并已感染了数千台设备。  
  
  
Insikt Group 研究人员发现，五家机构的思科设备遭到入侵，其中包括一家美国电信和互联网服务提供商以及一家英国电信提供商的美国分支机构。研究人员还发现，Salt Typhoon 针对的是全球多所大学的思科设备，包括加州大学洛杉矶分校、洛约拉马利蒙特大学、犹他理工大学和加州州立大学。  
  
  
报告称：“RedMike 可能针对这些大学，以获取与电信、工程和技术相关领域的研究，特别是加州大学洛杉矶分校和代尔夫特理工大学等机构的研究。”  
  
  
Insikt Group 发现，超过一半的思科设备位于美国、南美和印度，还发现超过 12,000 台思科设备的网络用户界面暴露在互联网上。  
  
  
Recorded Future 称，报告中描述的五家电信提供商是研究人员能够确认成功利用思科漏洞的唯一案例。Recorded Future 不排除其他设备和组织也受到攻击。  
  
  
Insikt Group 研究人员表示，一些组织在思科零日漏洞首次披露一年多后仍未缓解这些漏洞。  
  
  
“补丁管理和部署是一个具有挑战性的问题，尤其是在拥有数万个工作站和支持网络设备的大型企业中。”“有效且安全的补丁部署涉及测试和验证、规划停机时间（这对员工和客户来说都非常昂贵且具有破坏性），以及调整补丁可能意外中断的工作流程或自动化。”  
  
  
Recorded Future 建议各组织优先修补此类设备中的漏洞，并监控配置更改。此外，研究人员敦促用户避免在互联网上公开面向公众的设备管理界面和非必要服务。  
  
  
技术报告：  
  
https://go.recordedfuture.com/hubfs/reports/cta-cn-2025-0213.pdf  
  
  
新闻链接：  
  
https://www.cybersecuritydive.com/news/china-backed-hackers-continue-cyberattacks-on-telecom-companies/740066/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
微软：俄罗斯“Seashell Blizzard”黑客已获得关键基础设施访问权限  
  
https://www.securityweek.com/russian-seashell-blizzard-hackers-gain-maintain-access-to-high-value-targets-microsoft/  
  
  
Lazarus Group 将恶意软件隐藏在 GitHub 和开源软件包中  
  
https://www.computing.co.uk/news/2025/security/lazarus-malware-github-open-source  
  
  
曹县 APT43 使用 PowerShell 和 Dropbox 针对韩国发起网络攻击  
  
https://thehackernews.com/2025/02/north-korean-apt43-uses-powershell-and.html  
  
  
FINALDRAFT 恶意软件利用微软Graph API进行间谍活动  
  
https://thehackernews.com/2025/02/finaldraft-malware-exploits-microsoft.html  
  
  
Salt Typhoon 威胁组织利用较旧的漏洞破坏了思科边缘设备  
  
https://www.cybersecuritydive.com/news/china-backed-hackers-continue-cyberattacks-on-telecom-companies/740066/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
电路板制造商 Unimicron 成为勒索软件攻击目标  
  
https://www.securityweek.com/circuit-board-maker-unimicron-targeted-in-ransomware-attack/  
  
  
Astaroth 网络钓鱼工具包绕过 2FA 劫持 Gmail 和 Microsoft 帐户  
  
https://hackread.com/astaroth-phishing-kit-bypasses-2fa-hijack-gmail-microsoft/  
  
  
利用旧版 ThinkPHP 和 ownCloud 漏洞的攻击激增  
  
https://www.bleepingcomputer.com/news/security/surge-in-attacks-exploiting-old-thinkphp-and-owncloud-flaws/  
  
  
黑客利用 Webflow CDN PDF 上的 CAPTCHA 技巧绕过安全扫描程序  
  
https://thehackernews.com/2025/02/hackers-use-captcha-trick-on-webflow.html  
  
  
黑客泄露 1200 万 Zacks Investment 用户的账户数据  
  
https://www.bleepingcomputer.com/news/security/hacker-leaks-account-data-of-12-million-zacks-investment-users/  
  
  
网络间谍可能以发动勒索软件攻击作为副业  
  
https://www.securityweek.com/chinese-cyberspy-possibly-launching-ransomware-attacks-as-side-job/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Palo Alto Networks 修复 PAN-OS 软件中的身份验证绕过漏洞  
  
https://thehackernews.com/2025/02/palo-alto-networks-patches.html  
  
  
Google 发布 Chrome 133 更新，以解决四个高严重性漏洞  
  
https://www.securityweek.com/google-pays-out-55000-bug-bounty-for-chrome-vulnerability/  
  
  
Rapid7 在 PostgreSQL 中发现了一个新的  
0day  
漏洞  
  
https://www.securityweek.com/rapid7-flags-new-postgresql-zero-day-connected-to-beyondtrust-exploitation/  
  
  
FortiOS 漏洞允许超级管理员权限提升  
  
https://hackread.com/fortios-vulnerability-super-admin-privilege-escalation/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
