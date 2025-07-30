#  以色列公司 Cellebrite 利用安卓 0day漏洞进行间谍软件攻击   
会杀毒的单反狗  军哥网络安全读报   2024-12-17 01:00  
  
**导****读**  
  
  
  
研究人员发现了一个安卓  
0day  
漏洞，该漏洞被用于悄悄部署针对塞尔维亚记者的定制监控间谍软件。调查显示，该技术与以色列取证供应商 Cellebrite 有关。  
  
  
在周一发布的一份技术报告中，该组织详细介绍了一种名为“NoviSpy”的新间谍软件感染记者和活动人士的设备。  
  
  
研究人员表示：“如果这些工具没有受到严格的控制和监督，那么利用 Cellebrite UFED 和类似的移动取证工具下载个人的整个数字生活的能力将带来巨大风险”。  
   
  
  
该报告揭示了记者斯拉维莎·米拉诺夫 (Slaviša Milanov) 的案件，他的 Android 版  
  
Redmi Note 10S 设备遭到黑客攻击。取证分析显示，攻击者利用 Android  
0day  
漏洞绕过加密保护措施并解锁设备，为安装 NoviSpy 铺平了道路。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaF90RaoAEYcGwibW2X9cMsYSXgpOeOIVQtG6gEMeDTd9ybgzicPYO6ErQjoqiarBMicibib5wI8EBwDVY2g/640?wx_fmt=png&from=appmsg "")  
  
  
研究人员表示，特权提升  
  
0day  
漏洞随后在高通 10 月份的安全更新中得到修补，影响了使用流行高通芯片组的 Android 设备，并影响全球数百万台 Android 设备。  
   
  
  
在另一个案例中，研究人员记录了一名环保活动人士的 Android 设备记录了一系列未接来电，这些来电都是无效的、看似随机的号码。  
  
  
研究人员检查了该设备，没有发现任何篡改的证据，但警告说，针对 Android 设备的零点击攻击存在明显的“知识差距”。  
  
  
这些痕迹与零点击攻击的预期结果一致，该攻击针对的是 Android 通话功能，例如 Android 设备中用于富通信套件 (RCS) 通话的 Voice-over-Wifi 或 Voice-over-LTE (VoLTE) 功能。这两项功能都在这部手机上启用，从而提供了潜在的远程攻击面。”  
  
  
研究人员表示：“2018 年和 2019 年，NSO 集团客户利用 WhatsApp 中的零点击漏洞攻击 Android 用户时，也观察到了类似的未接来电痕迹。”  
  
  
“虽然我们无法确定这些来自无效号码的未接电话是否确实是零点击感染尝试的痕迹，但这一事件凸显了活动家和安全研究人员需要持续监控和收集可能发生的攻击的证据以供分析。”  
  
  
研究人员注意到 Cellebrite 声称其制定了严格的政策以防止其产品被滥用，但警告称，这一发现“明确证明记者的手机在未经任何正当程序的情况下就成为攻击目标”。  
  
  
研究人员发现了之前未知的 NoviSpy 间谍软件的痕迹，该软件在感染后可以从目标手机中捕获敏感的个人数据，并能够远程打开手机的麦克风或摄像头。  
  
  
研究人员的报告描述了首次利用 Cellebrite 移动取证技术实现的经过法医记录的间谍软件感染。  
  
  
技术报告：  
https://www.securityweek.com/wp-content/uploads/2024/12/Amnesty-Cellebrite.pdf  
  
  
新闻链接：  
  
https://www.securityweek.com/android-zero-day-exploited-in-serbian-spyware-campaigns-amnesty-international-points-to-cellebrite/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
新的 Glutton 恶意软件利用 Laravel 和 ThinkPHP 等流行 PHP 框架  
  
https://thehackernews.com/2024/12/new-glutton-malware-exploits-popular.html  
  
  
以色列公司 Cellebrite  
  
利用  
  
Android  
0day  
漏洞进行间谍软件攻击  
  
https://www.securityweek.com/android-zero-day-exploited-in-serbian-spyware-campaigns-amnesty-international-points-to-cellebrite/  
  
  
Yokai 后门攻击活动利用 DLL 侧载技术攻击泰国官员  
  
https://thehackernews.com/2024/12/thai-officials-targeted-in-yokai.html  
  
  
Winnti 黑客利用新的 Glutton PHP 后门攻击其他威胁组织  
  
https://www.bleepingcomputer.com/news/security/winnti-hackers-target-other-threat-actors-with-new-glutton-php-backdoor/  
  
  
与伊朗有关的 IOCONTROL 恶意软件针对 SCADA 和基于 Linux 的物联网平台  
  
https://thehackernews.com/2024/12/iran-linked-iocontrol-malware-targets.html  
  
  
网络犯罪工具成为侵入乌克兰军事设备的途径  
  
https://therecord.media/turla-secret-blizzard-russia-espionage-ukraine-cybercrime-tools  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
美国大型汽车零部件公司 LKQ 遭受网络攻击  
  
https://www.securityweek.com/major-auto-parts-firm-lkq-hit-by-cyberattack/  
  
  
Cicada3301 勒索软件声称对法国标致经销商发起攻击  
  
https://hackread.com/cicada3301-ransomware-french-peugeot-dealership/  
  
  
Citrix 警告针对 NetScaler 设备的密码喷洒攻击  
  
https://www.securityweek.com/citrix-warns-of-password-spraying-attacks-targeting-netscaler-appliances/  
  
  
DrayTek 路由器中未记录的漏洞被利用于勒索软件活动，危害 300 多个组织  
  
https://www.securityweek.com/undocumented-draytek-vulnerabilities-exploited-to-hack-hundreds-of-orgs/  
  
  
恶意广告通过虚假 CAPTCHA 页面推送 Lumma 信息窃取程序  
  
https://www.bleepingcomputer.com/news/security/malicious-ads-push-lumma-infostealer-via-fake-captcha-pages/  
  
  
Microsoft Teams 网络钓鱼传播 DarkGate RAT  
  
https://www.darkreading.com/cyberattacks-data-breaches/vishing-via-microsoft-teams-spreads-darkgate-rat  
  
  
德克萨斯理工大学健康科学中心系统数据泄露影响 140 万名患者  
  
https://www.bleepingcomputer.com/news/security/texas-tech-university-system-data-breach-impacts-14-million-patients/  
  
  
ConnectOnCall 远程医疗应用程序漏洞导致超过 910,000 名患者的健康数据泄露  
  
https://www.bleepingcomputer.com/news/security/connectoncall-breach-exposes-health-data-of-over-910-000-patients/  
  
  
PUMAKIT：一款采用先进隐身机制的复杂  
Linux  
rootkit  
  
https://securityaffairs.com/172016/malware/pumakit-sophisticated-rootkit.html  
  
  
FBI 发现 HiatusRAT 恶意软件攻击针对网络摄像头、DVR  
  
https://www.bleepingcomputer.com/news/security/fbi-spots-hiatusrat-malware-attacks-targeting-web-cameras-dvrs/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
大众汽车信息娱乐系统存在多个缺陷，可能导致车辆被实时追踪  
  
https://securityaffairs.com/172024/hacking/volkswagen-group-infotainment-unit-flaws.html  
  
  
研究人员发现 iOS 和 macOS 中允许绕过 TCC 的符号链接漏洞  
  
https://thehackernews.com/2024/12/researchers-uncover-symlink-exploit.html  
  
  
OpenWrt 严重漏洞使设备面临恶意固件注入风险  
  
https://thehackernews.com/2024/12/critical-openwrt-vulnerability-exposes.html  
  
  
戴尔产品存在严重漏洞，可导致攻击者入侵受影响系统  
  
https://cybersecuritynews.com/dell-vulnerabilities-alert/  
  
  
部分高通 CPU 在主流 Linux 上暴露于 Spectre 漏洞  
  
https://www.phoronix.com/news/Qualcomm-Spectre-Mainline-Patch  
  
  
微软修补了服务器端更新目录和 Windows Defender 中潜在的严重漏洞  
  
https://www.securityweek.com/microsoft-patches-vulnerabilities-in-windows-defender-update-catalog/  
  
  
对 Cleo 文件传输软件中严重漏洞的利用仍在继续  
  
https://www.cybersecuritydive.com/news/security-cleo-file-transfer-cve-delayed/735517  
  
  
锐捷Reyee云管理平台发现严重漏洞  
  
https://www.securityweek.com/critical-vulnerabilities-found-in-ruijie-reyee-cloud-management-platform/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
