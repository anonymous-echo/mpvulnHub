#  俄罗斯 APT28 利用 Microsoft Outlook 漏洞攻击捷克、德国实体   
会杀毒的单反狗  军哥网络安全读报   2024-05-05 09:00  
  
**导****读**  
  
  
  
捷克和德国周五透露，它们是与俄罗斯有联系的APT28黑客组织进行的长期网络间谍活动的目标，此举引起了欧盟
(EU)、北约 (NATO) 的谴责。  
  
  
捷克共和国外交部
(MFA) 在一份声明中表示，该国一些未透露姓名的实体因去年初曝光的 Microsoft Outlook 安全漏洞而遭到攻击。  
  
  
所涉及的安全漏洞是CVE-2023-23397，这是
Outlook 中现已修补的一个关键权限提升漏洞，可能允许攻击者访问 Net-NTLMv2 哈希值，然后使用它们通过中继攻击来验证自己的身份。  
  
  
德国政府将攻击者归咎于针对社会民主党执行委员会的网络攻击，该攻击在“相对较长的时间内”使用相同的
Outlook 漏洞，使其能够“危害大量电子邮件帐户”。  
  
  
该活动针对的一些垂直行业包括位于德国、乌克兰和欧洲的物流、军备、航空航天工业、IT
服务、基金会和协会，联邦监管机构还暗示该组织参与了 2015 年对德国联邦议会的攻击行动。  
  
  
APT28
经评估与俄罗斯联邦军事情报机构 GRU 的军事单位 26165 有联系，也被更广泛的网络安全社区命名为：BlueDelta、Fancy
Bear、Forest Blizzard（以前称为 Strontium）、FROZENLAKE、Iron Twilight、Pawn Storm、
Sednit、Sofacy 和 TA422。  
  
  
上月末，微软将黑客组织归因于利用 Microsoft Windows Print Spooler
组件（CVE-2022-38028，CVSS 评分：7.8）作为  
0day  
漏洞攻击，传播一种名为 GooseEgg 的先前未知的自定义恶意软件，以渗透乌克兰、欧洲和北美的政府、非政府、教育和交通部门机构。  
  
  
今年 2
月初，协调一致的多国联合执法行动破坏了由美国和德国数百个小型办公室和家庭办公室 (SOHO) 路由器组成的僵尸网络，APT28
攻击者据信利用这些路由器来隐藏其恶意活动，例如利用 CVE -2023-23397 针对感兴趣的目标。  
  
  
根据Trend Micro
本周的一份报告（  
https://www.trendmicro.com/en_us/research/24/e/router-roulette.html），第三方犯罪代理僵尸网络可以追溯到
2016 年，不仅包含Ubiquiti 的路由器，还包括其他基于 Linux 的路由器、Raspberry Pi 和虚拟专用服务器 (VPS) 。  
  
  
“[僵尸网络背后的]攻击者设法将一些
EdgeRouter 机器人从 2024 年 1 月 26 日关闭的 C&C [命令与控制]服务器转移到 2024 年 2 月上旬新建立的
C&C 基础设施。”该公司表示，加上法律限制和技术挑战，无法彻底清理所有陷入困境的路由器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaG9pOzTcfh4fTAJUQKGiavSJHKXGM8KewYIxHA2IiabFPozmGtiaKZDH3JnCC7jKm0XjnNh1icxnG5XLw/640?wx_fmt=png&from=appmsg "")  
  
  
俄罗斯国家支持的网络威胁活动——数据盗窃、破坏性攻击、DDoS
活动和影响行动——预计也会对 APT44 等多个组织的美国、英国和欧盟等地区构成严重风险。根据 Google Cloud 子公司 Mandiant
上周发布的评估，该软件还包括 Sandworm、COLDRIVER、KillNet、APT29 和 APT28。  
  
  
来自
Cloudflare 和 NETSCOUT 的数据显示，在瑞典加入北约联盟后，针对瑞典的 DDoS 攻击激增，这与芬兰 2023
年加入北约期间观察到的模式类似。  
  
  
NETSCOUT表示：“这些攻击的罪魁祸首可能包括黑客组织
NoName057、Anonymous Hundred、Russian Cyber  
  
 Army Team 和 KillNet。” “所有这些团体都是出于政治动机。”  
  
  
与此同时，加拿大、英国和美国的政府机构发布了一份新的联合情况说明书（  
https://www.cisa.gov/news-events/alerts/2024/05/01/cisa-and-partners-release-fact-sheet-defending-ot-operations-against-ongoing-pro-russia-hacktivist），以帮助保护关键基础设施组织免受明显亲俄罗斯的黑客活动分子自
2022 年起采用技术 (OT) 系统针对工业控制系统（ICS）和小规模运营系统发起的持续攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaG9pOzTcfh4fTAJUQKGiavSJ9QnO7lDMbP0BNWSFektORjHicTgib7t8rIcFSAraA8bdC3pBPaWslTiag/640?wx_fmt=png&from=appmsg "")  
  
  
这些机构表示：“亲俄黑客活动似乎主要局限于操纵 ICS 设备以造成滋扰影响的简单技术。” “调查发现，攻击者能够使用对不安全和配置错误的 OT 环境构成物理威胁的技术。”  
  
  
这些攻击的目标包括北美和欧洲关键基础设施部门的组织，包括供水和废水系统、水坝、能源以及粮食和农业部门。  
  
  
据观察，黑客组织通过利用暴露在互联网的连接以及与此类环境中普遍存在的人机界面（HMI）相关的工厂默认密码来获得远程访问，然后篡改任务关键参数，关闭警报机制，通过更改管理密码来锁定操作员。  
  
  
缓解威胁的建议包括强化人机界面、限制
OT 系统在互联网上的暴露、使用强而独特的密码，以及对 OT 网络的所有访问实施多因素身份验证。  
  
  
警报称：“这些黑客活动分子试图通过人机界面（HMI）等软件组件，利用虚拟网络计算（VNC）远程访问软件和默认密码来破坏模块化、暴露于互联网的工业控制系统（ICS）。”  
  
  
**参考链接：**  
https://thehackernews.com/2024/05/microsoft-outlook-flaw-exploited-by.html  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
奇安信  
X实验室披露恶意 Android 后门可让黑客窃取手机内容  
  
https://blog.xlab.qianxin.com/playing-possum-whats-the-wpeeper-backdoor-up-to/  
  
  
黑客越来越多地滥用
Microsoft Graph API 进行隐秘恶意软件通信  
  
https://thehackernews.com/2024/05/hackers-increasingly-abusing-microsoft.html  
  
  
伊朗黑客冒充记者部署后门恶意软件  
  
https://www.bleepingcomputer.com/news/security/iranian-hackers-pose-as-journalists-to-push-backdoor-malware/  
  
  
美国国家安全局
(NSA) 和联邦调查局 (FBI) 就朝鲜黑客从可信来源欺骗电子邮件发出警报  
  
https://thehackernews.com/2024/05/nsa-fbi-alert-on-n-korean-hackers.html  
  
  
针对思科防火墙的
ArcaneDoor 间谍活动  
  
https://www.securityweek.com/arcanedoor-espionage-campaign-targeting-cisco-firewalls-linked-to-china/  
  
  
电子邮件安全漏洞是朝鲜社会工程攻击的最新途径  
  
https://www.securityweek.com/us-says-north-korean-hackers-exploiting-weak-dmarc-settings/  
  
https://therecord.media/north-korea-kimsuky-hackers-dmarc-emails  
  
  
被 FBI
破坏的僵尸网络仍被俄罗斯间谍和网络犯罪分子使用  
  
https://www.securityweek.com/botnet-disrupted-by-fbi-still-used-by-russian-spies-cybercriminals/  
  
  
俄罗斯黑客瞄准北美和欧洲的工业系统  
  
https://www.securityweek.com/russian-hackers-target-industrial-systems-in-north-america-europe/  
  
  
北约和欧盟谴责俄罗斯对德国和捷克的网络攻击  
  
https://www.bleepingcomputer.com/news/security/nato-and-eu-condemn-russias-cyberattacks-against-germany-czechia/  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
微软对所有消费者帐户实行无密码验证  
  
https://cybernews.com/news/microsoft-passkey-accounts/  
  
  
微软警告流行
Android 应用程序中存在“Dirty Stream脏流”漏洞  
  
https://www.securityweek.com/microsoft-warns-of-dirty-stream-vulnerability-in-popular-android-apps/  
  
  
研究人员发现，五分之一的
Docker Hub 存储库是恶意目的  
  
https://cybernews.com/security/fifth-of-docker-hub-repositories-malicious/  
  
  
CISA 去年向
1,750 个组织发出勒索软件漏洞警告，只有一半组织采取了行动  
  
https://www.cybersecuritydive.com/news/cisa-ransomware-vulnerability-warnings/714951/  
  
  
美国 UnitedHealth
首席执行官告诉参议院，公司向黑客支付了 2200 万美元赎金  
  
https://www.cnbc.com/2024/05/01/unitedhealth-ceo-says-company-paid-hackers-22-million-ransom.html  
  
  
Dropbox
称黑客在泄露期间获取了密码和身份验证信息  
  
https://therecord.media/dropbox-data-breach-notification  
  
  
LockBit
公布从法国戛纳医院窃取的机密数据  
  
https://therecord.media/lockbit-ransomware-hopital-de-cannes-data-published  
  
  
ZLOADER恶意软件增加了ZEUS银行木马的反分析功能  
  
https://securityaffairs.com/162688/cyber-crime/zloader-malware-anti-analysis-feature.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
四个严重漏洞使
HPE Aruba 设备面临 RCE 攻击  
  
https://thehackernews.com/2024/05/four-critical-vulnerabilities-expose.html  
  
  
CISA
表示，GitLab 的一个关键密码重置漏洞（CVE-2023-7028）正在被攻击利用  
  
https://www.securityweek.com/1400-gitlab-servers-impacted-by-exploited-vulnerability/  
  
  
Android
漏洞可能会在启用 VPN 终止开关的情况下泄漏 DNS 流量  
  
https://www.bleepingcomputer.com/news/security/android-bug-can-leak-dns-traffic-with-vpn-kill-switch-enabled/  
  
  
福布斯：国外安全研究人员警告20个安全漏洞“对小米用户构成威胁”  
  
https://www.forbes.com/sites/thomasbrewster/2024/05/02/xiaomi-vulnerabilities-pose-a-threat-to-all-users-researchers-warn/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
