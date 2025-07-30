#  俄黑客组织 APT28 利用 MDaemon 0day漏洞攻击Webmail 服务器   
会杀毒的单反狗  军哥网络安全读报   2025-05-16 01:00  
  
**导****读**  
  
  
  
根据 ESET 的最新发现，与俄罗斯有关的威胁组织涉嫌通过跨站点脚本 (XSS) 漏洞（包括 MDaemon 中的0day漏洞）针对 Roundcube、Horde、MDaemon 和 Zimbra 等网络邮件服务器进行网络间谍活动。  
  
  
这项活动始于2023年，  
ESET  
将其命名为“Operation RoundPress”。该活动被中等程度地归咎于俄黑客组织APT28，该组织也被称为BlueDelta、Fancy Bear、Fighting Ursa、Forest Blizzard、FROZENLAKE、Iron Twilight、ITG05、Pawn Storm、Sednit、Sofacy和TA422。  
  
  
ESET 研究人员称： “此次行动的最终目标是窃取特定电子邮件账户的机密数据。大多数受害者是东欧的政府机构和国防公司，我们也观察到非洲、欧洲和南美洲的政府也成为攻击目标。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFLNuwhDfKSjwNKiaZOwDWSd7mLViaHicUvuU4lAZBqtBSunSGgC8cwUtdMmEumfQZF8fLskohm5sjlw/640?wx_fmt=png&from=appmsg "")  
  
受害者分布  
  
  
这并非 APT28 首次涉足利用 Web 邮件软件漏洞的攻击。2023 年 6 月，Recorded Future披露了该威胁组织如何利用 Roundcube 中的多个漏洞（CVE-2020-12641、CVE-2020-35730 和 CVE-2021-44026）进行侦察和数据收集。  
  
  
2024年该行动的大多数目标是乌克兰、保加利亚和罗马尼亚目标，其他目标包括希腊、喀麦隆、厄瓜多尔、塞尔维亚和塞浦路斯的政府、军事和学术组织。  
  
  
这些攻击利用 Horde、MDaemon 和 Zimbra 中的 XSS 漏洞，在 Web 邮件窗口上下文中执行任意 JavaScript 代码。美国网络安全和基础设施安全局 (CISA) 于 2024 年 2 月将 CVE-2023-43770添加到其已知被利用漏洞 (KEV) 目录中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFLNuwhDfKSjwNKiaZOwDWSdlzwpMd58HhR3Ohy4mejS1aTmbv9WduWCc0PbXts0riaJRgH0ONiczF6g/640?wx_fmt=png&from=appmsg "")  
  
攻击链  
  
  
MDaemon XSS 漏洞被评估为威胁组织利用的  
0day  
漏洞。该漏洞的 CVE 编号为CVE-2024-11182 （CVSS 评分：5.3），于去年 11 月在24.5.1 版本中进行了修补。  
  
  
要想成功利用该漏洞，必须说服目标用户在存在漏洞的 Web 邮件门户中打开电子邮件，前提是该邮件能够绕过软件的垃圾邮件过滤器并进入用户的收件箱。  
  
  
电子邮件内容本身是无害的，因为触发 XSS 漏洞的恶意代码位于电子邮件正文的 HTML 代码中，因此用户无法看到。  
  
  
成功利用该漏洞后，一个名为 SpyPress 的混淆 JavaScript 有效载荷将被执行，该载荷能够窃取 Webmail 凭证，并从受害者邮箱中获取电子邮件消息和联系信息。尽管该恶意软件缺乏持久性机制，但每次打开这封带有陷阱的电子邮件时，它都会重新加载。  
  
  
ESET 表示：“此外，我们还检测到一些能够创建 Sieve 规则的 SpyPress.ROUNDCUBE 有效载荷。SpyPress.ROUNDCUBE 会创建一条规则，将每封收到的电子邮件的副本发送到攻击者控制的电子邮件地址。Sieve 规则是 Roundcube 的一项功能，因此即使恶意脚本不再运行，该规则也会被执行。”  
  
  
收集到的信息随后会通过 HTTP POST 请求泄露到硬编码的命令与控制 (C2) 服务器。此外，研究人员还发现该恶意软件的部分变种会捕获登录历史记录、双因素身份验证 (2FA) 代码，甚至会为 MDAEMON 创建应用程序密码，以便在密码或 2FA 代码更改后仍能访问邮箱。  
  
  
技术报告：  
  
https://www.welivesecurity.com/en/eset-research/operation-roundpress/  
  
  
链接：  
  
https://thehackernews.com/2025/05/russia-linked-apt28-exploited-mdaemon.html  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
俄黑客组织 APT28 利用 MDaemon   
0day  
漏洞攻击Webmail 服务器  
  
https://thehackernews.com/2025/05/russia-linked-apt28-exploited-mdaemon.html  
  
  
亲乌克兰黑客发起的攻击抹去俄罗斯三分之一的法庭文件档案  
  
https://therecord.media/russia-court-system-hack-third-of-case-files-deleted  
  
  
研究人员发现曹县  
APT37  
组织对韩国安全机构的网络间谍活动  
  
https://therecord.media/apt37-scarcruft-cyber-espionage-campaign-south-korea  
  
  
曹县黑客在新一轮间谍活动中瞄准乌克兰政府  
  
https://therecord.media/north-korea-hackers-target-ukraine-to-understand-russian-war-efforts  
  
  
曹县黑客冒充美国IT工作者打黑工挣了8800 万美元  
https://hackread.com/north-korean-hackers-stole-88m-posing-us-tech-workers/  
  
  
趋势科技报告：  
APT  
黑客破坏中国台湾无人机供应链  
  
https://therecord.media/chinese-hackers-target-taiwan-military-sector  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
微软历史上持续时间最长的  
Outlook  
宕机事件影响数百万用户  
  
https://cybersecuritynews.com/microsoft-outlook-down/  
  
  
黑客滥用谷歌服务发送恶意执法请求  
  
https://cybersecuritynews.com/hackers-abuse-google-services/  
  
  
“Meta Mirage”网络钓鱼活动对企业构成威胁  
  
https://www.cysecurity.news/2025/05/meta-mirage-phishing-campaign-poses.html  
  
  
Interlock 勒索软件攻击国防承包商及其供应链  
  
https://cybersecuritynews.com/interlock-ransomware-attacking-defense-contractors/  
  
  
针对拉丁美洲西班牙语用户的复杂网络钓鱼活动出现  
  
https://cybersecuritynews.com/weaponized-html-files-to-deliver-horabot-malware/  
  
  
Windows CLFS   
0day  
漏洞遭 Play 勒索软件组织利用  
  
https://www.cysecurity.news/2025/05/windows-clfs-zero-day-flaw-exploited-in.html  
  
  
吉娃娃窃密木马利用 Google Drive 文档窃取浏览器登录凭证  
  
https://cybersecuritynews.com/chihuahua-stealer-leverages-google-drive-document/  
  
  
TransferLoader 恶意软件允许攻击者在受感染系统上执行任意命令  
  
https://cybersecuritynews.com/transferloader-malware-allows-attackers-to-execute-arbitrary-commands/  
  
  
FrigidStealer 恶意软件通过虚假 Safari 浏览器更新攻击 macOS 用户  
  
https://hackread.com/frigidstealer-malware-macos-fake-safari-browser-update/  
  
  
美国钢铁巨头纽柯公司因网络攻击致生产中断  
  
https://www.securityweek.com/production-at-steelmaker-nucor-disrupted-by-cyberattack/  
  
  
无文件 Remcos RAT 攻击利用 PowerShell 脚本逃避检测  
  
https://hackread.com/fileless-remcos-rat-attack-antivirus-powershell-scripts/  
  
  
Coinbase 遭黑客攻击——大规模数据泄露导致损失 4 亿美元  
  
https://cybersecuritynews.com/coinbase-hacked/  
  
  
Xinbi：价值 80 亿美元的杀猪盘诈骗和朝鲜黑客交易市场在科罗拉多州注册  
  
https://www.elliptic.co/blog/xinbi-guarantee  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
施乐发布 FreeFlow 打印服务器 v2 2025 年 4 月安全补丁更新  
  
https://cybersecuritynews.com/xerox-freeflow-print-server-v2-vulnerability/  
  
  
Chrome 更新修复存在野外利用的高危漏洞（CVE-2025-4664）  
  
https://www.securityweek.com/chrome-136-update-patches-vulnerability-with-exploit-in-the-wild/  
  
  
英特尔、AMD、Arm 应对新的 CPU 攻击  
  
https://www.securityweek.com/chipmaker-patch-tuesday-intel-amd-arm-respond-to-new-cpu-attacks/  
  
  
Ivanti 修复两个 EPMM 漏洞，这些漏洞已被广泛利用以执行远程代码  
  
https://www.securityweek.com/ivanti-patches-two-epmm-zero-days-exploited-to-hack-customers/  
  
  
ICS 补丁日：西门子、施耐德、菲尼克斯电气修复漏洞  
  
https://www.securityweek.com/ics-patch-tuesday-vulnerabilities-addressed-by-siemens-schneider-phoenix-contact/  
  
  
Adobe 修复大量严重程度较高的软件漏洞  
  
https://www.securityweek.com/adobe-patches-big-batch-of-critical-severity-software-flaws/  
  
  
Fortinet 修复针对 FortiVoice 设备的  
0day  
漏洞  
  
https://www.securityweek.com/fortinet-patches-zero-day-exploited-against-fortivoice-appliances/  
  
  
Juniper、VMware 和 Zoom 修复其产品中的数十个漏洞  
  
https://www.securityweek.com/vulnerabilities-patched-by-juniper-vmware-and-zoom/  
  
  
Outlook RCE 漏洞允许攻击者执行任意代码  
  
https://cybersecuritynews.com/outlook-remote-code-execution-vulnerability/  
  
  
Windows CLFS 零日漏洞遭广泛利用  
  
https://gbhackers.com/windows-clfs-zero-day-vulnerability-exploited/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
