#  俄罗斯黑客组织Romcom利用0day漏洞攻击 Firefox、Tor 用户   
会杀毒的单反狗  军哥网络安全读报   2024-11-27 01:00  
  
**导****读**  
  
  
  
一个俄罗斯黑客组织  
Romcom  
利用两个此前未知的漏洞攻击
Windows PC 上的 Firefox 和 Tor 浏览器用户。  
  
  
防病毒提供商
ESET 将该攻击描述为潜在的“大规模活动”，其目标是欧洲和北美的用户。  
  
  
俄罗斯黑客通过一个恶意网页传播黑客攻击，这些网页似乎伪装成虚假新闻机构。如果易受攻击的浏览器访问该页面，它可以秘密触发软件漏洞，在受害者的电脑上安装后门。  
  
  
**ESET
警告称，用户无需与该网页进行任何交互。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGXJCK474Bta9g8vFNWDWVYMQwNBpfiaEJe21kzqRAw9GpoDic7iblOoiafvPL1v69W4IGmjCYboPEyrQ/640?wx_fmt=png&from=appmsg "")  
  
  
目前尚不清楚黑客如何传播恶意网页链接。但第一个漏洞（称为CVE-2024-9680）可导致
Firefox 和 Tor 浏览器在正常受限制的进程中运行恶意代码。  
  
  
黑客利用
Windows 10 和 11
中的第二个漏洞（称为CVE-2024-49039）发动攻击，以便在浏览器之外和操作系统上执行更多恶意代码。秘密下载并安装一个能够监视 PC
的后门，包括收集文件、截屏以及窃取浏览器 cookie 和保存的密码。  
  
      
  
Mozilla、Tor
和 Microsoft 都已修补了漏洞。Tor 浏览器基于 Firefox。Mozilla 于 10 月 8
日私下报告了此问题，这两款浏览器都在第二天修补了此漏洞。与此同时，Microsoft于 11 月 12 日修补了另一个漏洞。  
  
  
如果用户未能及时打补丁，黑客仍可继续利用该攻击。ESET
提供的遥测数据显示，某些国家可能有多达 250 名用户遭遇过该攻击，攻击始于 10 月，甚至可能更早。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGXJCK474Bta9g8vFNWDWVYbWdUHmMyECaajFM2kXPkarvsm8f5TnMtMTZoQOPuSpLRGTia2Dj1gBw/640?wx_fmt=png&from=appmsg "")  
  
  
  
ESET  
将这些攻击与一个名为“RomCom”的俄罗斯黑客组织联系起来，该组织一直专注于网络犯罪和间谍活动。  
  
  
ESET  
追踪了该组织一系列的攻击活动：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGXJCK474Bta9g8vFNWDWVYxOWWO3ZLmIuiaCbm2ibHMefqVpKJrOerOwsuhgY3zF2gMOSQUAoFibHicw/640?wx_fmt=png&from=appmsg "")  
  
  
将两个  
0  
day  
漏洞串联起来，RomCom
便可以利用无需用户交互的漏洞进行攻击。这种复杂程度表明威胁组织有意愿并有手段获得或开发隐身能力。  
  
  
详细技术报告：  
  
https://www.welivesecurity.com/en/eset-research/romcom-exploits-firefox-and-windows-zero-days-in-the-wild/  
  
  
Mzoilla  
官方漏洞公告：  
  
https://blog.mozilla.org/security/2024/10/11/behind-the-scenes-fixing-an-in-the-wild-firefox-exploit/  
  
  
**新闻链接：**  
  
https://www.pcmag.com/news/russian-hackers-used-zero-day-attack-to-hit-firefox-tor-users  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
俄罗斯网络间谍入侵目标街对面的大楼，实施
Wi-Fi 攻击  
  
https://www.securityweek.com/russian-cyberspies-hacked-building-across-street-from-target-for-wi-fi-attack/  
  
  
俄罗斯黑客组织Romcom利用  
0  
day漏洞攻击
Firefox、Tor 用户  
  
https://www.pcmag.com/news/russian-hackers-used-zero-day-attack-to-hit-firefox-tor-users  
  
  
与俄罗斯有关的
APT TAG-110 的目标是欧洲和亚洲  
  
https://securityaffairs.com/171343/apt/tag-110-targets-asia-europe.html  
  
  
Gelsemium黑客组织利用新型间谍恶意软件攻击
Linux 系统  
  
https://therecord.media/china-hackers-linux-malware-target  
  
  
趋势科技发布APT
组织 Earth Estries 的活动报告  
  
https://www.trendmicro.com/en_us/research/24/k/earth-estries.html  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
Google
Play 商店中高风险的“SpyLoan”安卓应用激增  
  
https://www.pcmag.com/news/risky-spyloan-android-apps-surge-on-google-play-store  
  
  
黑客部署大规模新型
IoT 僵尸网络，发起 DDoS 攻击  
  
https://hackread.com/matrix-hackers-new-iot-botnet-ddos-attacks/  
  
  
RansomHub勒索软件团伙声称对美国两个市政府发动勒索软件攻击  
  
https://therecord.media/ransomhub-cybercrime-coppell-texas-minneapolis-parks-agency  
  
  
英国医院集团宣布网络攻击后发生“重大事件”  
  
https://therecord.media/england-hospitals-cyberattack-nhs-wirral  
  
  
一款 MacOS
恶意软件即服务Banshee Stealer 源代码在GitHub公开  
  
https://securityaffairs.com/171423/malware/the-source-code-of-banshee-stealer-leaked-online.html  
  
  
“Cyber  
Volk”黑客活动分子利用勒索软件支持俄罗斯  
  
https://therecord.media/cybervolk-india-hacktivists-russia-ransomware  
  
  
供应链技术提供商
Blue Yonder 遭遇勒索软件攻击，零售商陷入困境  
  
https://therecord.media/retailers-struggle-after-ransomware-attack-on-supply-chain-tech-company  
  
  
SafePay
勒索软件组织声称从车辆追踪解决方案提供商 Microlise 窃取超过 1TB 的数据  
  
https://www.securityweek.com/microlise-confirms-data-breach-as-ransomware-group-steps-forward/  
  
  
网络攻击破坏博彩技术供应商
IGT 的系统  
  
https://www.securityweek.com/cyberattack-disrupts-systems-of-gambling-giant-igt/  
  
  
PyPI
Python 库“aiocpa”被发现通过 Telegram Bot 窃取加密密钥  
  
https://thehackernews.com/2024/11/pypi-python-library-aiocpa-found.html  
  
  
恶意软件滥用有缺陷的
Avast Anti-Rootkit 驱动程序  
  
https://securityaffairs.com/171340/hacking/avast-anti-rootkit-driver-abused-malware-campaign.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
VMware 修补
Aria Operations 中的高危漏洞  
  
https://www.securityweek.com/vmware-patches-high-severity-vulnerabilities-in-aria-operations/  
  
  
IBM
修补数据虚拟化管理器、安全 SOAR 中的 RCE 漏洞  
  
https://www.securityweek.com/ibm-patches-rce-vulnerabilities-in-data-virtualization-manager-security-soar/  
  
  
CISA 警告利用
CVE-2023-28461 的攻击  
  
https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/  
  
  
20 万个
WordPress 网站使用的反垃圾邮件插件发现严重漏洞  
  
https://www.securityweek.com/critical-vulnerabilities-found-in-anti-spam-plugin-used-by-200000-wordpress-sites/  
  
  
“NachoVPN”漏洞允许恶意
VPN 服务器在未修补的 Palo Alto 和 SonicWall SSL-VPN 客户端安装恶意更新  
  
https://www.bleepingcomputer.com/news/security/new-nachovpn-attack-uses-rogue-vpn-servers-to-install-malicious-updates/  
  
  
黑客利用 Array
Networks SSL VPN 产品中的严重漏洞  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-bug-in-array-networks-ssl-vpn-products/  
  
  
QNAP 和
Veritas 周末披露 30 多个漏洞  
  
https://www.theregister.com/2024/11/26/qnap_veritas_vulnerabilities  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
