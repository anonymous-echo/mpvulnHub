#  ViciousTrap 威胁组织利用思科漏洞用 5,300 台受感染设备构建全球蜜罐   
会杀毒的单反狗  军哥网络安全读报   2025-05-24 01:00  
  
**导****读**  
  
  
  
网络安全研究人员称，代号为 ViciousTrap 的威胁组织入侵了 84 个国家近 5,300 个独特的网络边缘设备，并将它们变成了类似蜜罐的网络。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaHw3LpNt4kY4C8icGmkc2ibAiasm824NsCfRmk0w992Oh7QiauBUMS7xZA72wiaViaiafR408ajruSksSsgA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
据观察，威胁组织利用影响思科小型企业 RV016、RV042、RV042G、RV082、RV320 和 RV325 路由器的严重安全漏洞 (CVE-2023-20118)，将这些路由器集中到一组蜜罐中。  
  
  
法国安全公司  
  
Sekoia 在周四发布的分析报告中表示：“感染链涉及执行一个名为 NetGhost 的 shell 脚本，该脚本将来自受感染路由器特定端口的传入流量重定向到攻击者控制的蜜罐式基础设施，从而使他们能够劫持网络流量。”  
  
![恶意陷阱重定向基础设施](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHw3LpNt4kY4C8icGmkc2ibAia0SY4sLlNHEdy8OIe6KqDIkDqQzU3wv0wz39MrFTwPelQIl0URrtD2w/640?wx_fmt=png&from=appmsg "")  
  
Sekoia  
公司此前将 CVE-2023-20118 的漏洞利用归咎于另一个名为PolarEdge的僵尸网络。  
  
  
虽然没有证据表明这两组活动有关联，但人们相信 ViciousTrap 背后的威胁组织很可能通过入侵各种面向互联网的设备来建立蜜罐基础设施，包括来自 Araknis Networks、ASUS、D-Link、Linksys 和 QNAP 等 50 多个品牌的 SOHO 路由器、SSL VPN、DVR 和 BMC 控制器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHw3LpNt4kY4C8icGmkc2ibAiaXIZqXXxINmNMibT57dFfIgIR2Owa14tibQnGF0tXyIwzbSHgibGia2fAjA/640?wx_fmt=png&from=appmsg "")  
  
  
这种设置将允许攻击者观察跨多个环境的攻击尝试，并可能收集非公开或零日漏洞，并重复使用其他威胁攻击者获得的访问权限。  
  
  
该攻击链利用 CVE-2023-20118 漏洞，通过 ftpget 下载并执行 bash 脚本，然后连接外部服务器获取 wget 二进制文件。下一步，该思科漏洞再次被利用，执行使用先前释放的 wget 获取的第二个脚本。  
  
  
第二阶段的 Shell 脚本（内部称为 NetGhost）配置为将网络流量从受感染系统重定向到攻击者控制的第三方基础设施，从而方便中间人 (AitM) 攻击。该脚本还具有从受感染主机中移除自身的功能，以最大程度地减少取证痕迹。  
  
  
Sekoia 表示，所有攻击尝试都源自一个 IP 地址（“101.99.91[.]151”），最早的活动可以追溯到 2025 年 3 月。  
  
  
一个月后观察到的一个值得注意的事件是，据说 ViciousTrap 攻击者将之前在 PolarEdge 僵尸网络攻击中使用的未记录的 Web Shell 重新用于他们自己的行动。  
  
  
安全研究人员 Felix Aimé 和 Jeremy Scion 表示：“这一假设与攻击者使用 NetGhost 的情况相符。重定向机制有效地将攻击者定位为静默观察者，能够收集漏洞利用尝试，甚至可能收集传输中的 Web Shell 访问。”  
  
  
就在本月，攻击活动还针对华硕路由器发起了攻击，但使用的是不同的 IP 地址（“101.99.91[.]239”），尽管尚未发现威胁组织在受感染设备上创建任何蜜罐。该活动中使用的所有 IP 地址均位于马来西亚，属于托管服务提供商 Shinjiru 运营的自治系统 (AS45839)。  
  
  
Sekoia 总结道：“尽管我们非常有信心地认为 ViciousTrap 是一个蜜罐式网络，但它的最终目标仍不明确。”  
  
  
技术报告：  
  
https://blog.sekoia.io/vicioustrap-infiltrate-control-lure-turning-edge-devices-into-honeypots-en-masse/  
  
  
新闻链接：  
  
https://thehackernews.com/2025/05/vicioustrap-uses-cisco-flaw-to-build.html  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
ViciousTrap 威胁组织利用思科漏洞用  
  
5,300 台受感染设备构建全球蜜罐  
  
https://thehackernews.com/2025/05/vicioustrap-uses-cisco-flaw-to-build.html  
  
  
俄黑客组织 TAG-110 利用启用宏的 Word 文档攻击塔吉克斯坦  
  
https://www.recordedfuture.com/research/russia-aligned-tag-110-targets-tajikistan-with-macro-enabled  
  
  
俄黑客组织 Killnet 以新身份回归  
  
https://therecord.media/russian-hacker-group-killnet-returns-with-new-identity  
  
  
黑客利用  
 Cityworks   
0  
day  
漏洞攻击美市政部门  
  
https://www.securityweek.com/cityworks-zero-day-exploited-by-chinese-hackers-in-us-local-government-attacks/  
  
  
APT  
组织利用 Ivanti 漏洞攻击关键部门  
  
https://www.securityweek.com/chinese-spies-exploit-ivanti-vulnerabilities-against-critical-sectors/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
谷歌、微软、Facebook 等公司的 1.84 亿个密码被泄露  
  
https://www.zdnet.com/article/massive-data-breach-exposes-184-million-passwords-for-google-microsoft-facebook-and-more/  
  
  
欧洲刑警组织打击全球勒索软件网络，缴获300台服务器和350万欧元  
  
https://thehackernews.com/2025/05/300-servers-and-35m-seized-as-europol.html  
  
  
3AM 勒索软件攻击者冒充 IT 支持人员入侵网络  
  
https://www.tripwire.com/state-of-security/3am-ransomware-attackers-pose-it-support-compromise-networks  
  
  
Winos 4.0 恶意软件伪装成 VPN 和 QQ 浏览器攻击目标用户  
  
https://gbhackers.com/winos-4-0-malware-masquerades-as-vpn-and-qqbrowser/  
  
  
DanaBot 僵尸网络被破坏，16 名嫌疑人被起诉  
  
https://www.securityweek.com/danabot-botnet-disrupted-by-law-enforcement-16-suspects-charged/  
  
  
美国中西部电信公司 Cellcom 在服务中断数日后确认发生网络事件  
  
https://therecord.media/midwestern-cellcom-telcom-cyberattack  
  
  
新型 Formjacking 恶意软件攻击电商页面窃取信用卡数据  
  
https://cybersecuritynews.com/new-formjacking-malware-attacking-e-commerce-pages/  
  
  
黑客利用TikTok视频通过ClickFix技术传播Vidar和StealC恶意软件  
  
https://thehackernews.com/2025/05/hackers-use-tiktok-videos-to-distribute.html  
  
  
黑客利用虚假 Ledger 应用程序攻击 macOS 用户并部署恶意软件  
  
https://cybersecuritynews.com/hackers-attacking-macos-users-with-fake-ledger-apps/  
  
  
研究人员发现 ALCATRAZ 恶意软件使用的基础设施和 TTP  
  
https://cybersecuritynews.com/researchers-uncovered-ttps-used-by-alcatraz/  
  
  
威胁组织以 4,000 美元价格出售汉堡王备份系统 RCE 漏洞  
  
https://gbhackers.com/threat-actor-sells-burger-king-backup-system/  
  
  
威胁组织利用版权钓鱼诱饵传播 Rhadamanthys 窃取程序  
  
https://cybersecuritynews.com/threats-actors-deliver-rhadamanthys-stealer/  
  
  
犯罪分子利用虚假人工智能工具传播信息窃取木马Noodlophile  
  
https://www.cysecurity.news/2025/05/cybercriminals-employ-fake-ai-tools-to.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Fortinet 0Day 漏洞 PoC 发布，该漏洞正在被野外利用  
  
https://cybersecuritynews.com/fortinet-0-day-vulnerability-poc/  
  
  
NETGEAR 路由器漏洞允许攻击者获得完全管理员访问权限  
  
https://gbhackers.com/netgear-router-flaw/  
  
  
Commvault 漏洞遭利用，多家公司受到警告  
  
https://www.securityweek.com/companies-warned-of-commvault-vulnerability-exploitation/  
  
  
Apple XNU 内核漏洞可使攻击者提升权限  
  
https://gbhackers.com/apple-xnu-kernel-flaw/  
  
  
Chrome 0Day 漏洞 CVE-2025-4664 暴露 Windows、Linux 浏览器活动  
  
https://hackread.com/chrome-0-day-cve-2025-4664-windows-linux-browser-activity/  
  
  
GitLab Duo 漏洞遭利用，可注入恶意链接并窃取源代码  
  
https://gbhackers.com/gitlab-duo-vulnerability-exploited/  
  
  
因对漏洞分级存在  
  
分歧，发现者公布了“BadSuccessor”漏洞的完整细节  
  
https://www.securityweek.com/akamai-microsoft-disagree-on-severity-of-unpatched-badsuccessor-flaw/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
