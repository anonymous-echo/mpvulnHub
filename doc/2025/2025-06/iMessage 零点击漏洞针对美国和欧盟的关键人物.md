#  iMessage 零点击漏洞针对美国和欧盟的关键人物  
会杀毒的单反狗  军哥网络安全读报   2025-06-07 01:00  
  
**导****读**  
  
  
  
移动  
 EDR   
安全平台iVerify 的研究人员发现一个 iMessage 零点击漏洞，该漏洞被利用来针对美国和欧盟的高价值目标（包括政治人物、媒体专业人士和人工智能公司的高管）进行有针对性的攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGGIuQMBzNQtvwemMPzfyRzVZOEY0w02icyVWYHEI1JbmxrdW5Fz0vjyePOQ9W3yxSRvYiaLz0kJMAA/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞名为 NICKNAME，可在无需任何用户交互的情况下入侵 iPhone。该漏洞似乎是一项复杂的移动间谍软件活动的一部分。  
  
  
根据 iVerify 的报告，他们观察到 2024 年末和 2025 年初美国和欧盟知名实体的 iPhone 上出现了异常活动。其中包括罕见的崩溃，这些崩溃仅占 50,000 部 iPhone 样本崩溃日志的 0.0001%，是高级零点击 iMessage 攻击的典型特征。  
  
  
通过取证分析，NICKNAME 漏洞被发现存在于高价值目标的苹果设备。这些目标包括政界人士、媒体专业人士以及人工智能公司的高管。  
  
  
漏洞利用了 imagentiPhone 进程中的一个缺陷，漏洞通过 iMessage 发送的一系列快速昵称更新触发。此操作会导致“释放后使用”内存损坏，从而为攻击者获取控制权创造了机会。  
  
  
iVerify 经过高度深入的技术调查，识别出六台疑似目标设备，其中四台显示出清晰的 NICKNAME 特征，两台表明已成功利用。  
  
  
苹果在iOS 18.3.1修复了该漏洞，iVerify 警告称，NICKNAME 可能只是更大规模、更活跃的漏洞利用链的一部分。  
  
  
技术报告：  
  
https://welcome.iverify.io/hubfs/iVerify-Nickname-Vulnerability-Report.pdf  
  
  
新闻链接：  
  
https://hackread.com/nickname-zero-click-imessage-exploit-figures-us-eu/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
韩国研究人员发现针对全球加密货币用户的复杂恶意软件活动  
  
https://cybersecuritynews.com/threat-actors-using-vipersoftx-malware/  
  
  
iMessage 零点击漏洞针对美国和欧盟的关键人物  
  
https://hackread.com/nickname-zero-click-imessage-exploit-figures-us-eu/  
  
  
破坏性恶意软件“PathWiper”瞄准乌克兰关键基础设施  
  
https://www.securityweek.com/destructive-pathwiper-targeting-ukraines-critical-infrastructure/  
  
  
伊朗APT组织“BladedFeline”在目标网络潜伏了8年  
  
https://gbhackers.com/iranian-apt-bladedfeline-remains-hidden/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
配置错误的 HMI（人机界面）将美国供水系统暴露在互联网  
  
https://www.securityweek.com/misconfigured-hmis-expose-us-water-systems-to-anyone-with-a-browser/  
  
  
麒麟勒索软件利用 Fortinet 漏洞在受影响的设备上实现远程代码执行  
  
https://securityaffairs.com/178736/hacking/attackers-exploit-fortinet-flaws-to-deploy-qilin-ransomware.html  
  
  
Play 勒索软件组织自 2022 年以来已攻击 900 个组织  
  
https://securityaffairs.com/178702/cyber-crime/play-ransomware-group-hit-900-organizations-since-2022.html  
  
  
新的 ClickFix 攻击利用伪造的 Cloudflare 人工检查来静默安装恶意软件  
  
https://cybersecuritynews.com/new-clickfix-attack-exploits-fake-cloudflare-human-check/  
  
  
InfoStealer  
  
恶意软件可窃取 Chromium 浏览器中的敏感数据  
  
https://gbhackers.com/new-rust-developed-infostealer/  
  
  
Chrome 扩展程序漏洞暴露敏感 API 密钥、机密和令牌  
  
https://gbhackers.com/chrome-extensions-flaw/  
  
  
对利用 CVE-2024-3721 的 TBK DVR 设备进行 Mirai 攻击的分析  
  
https://securelist.com/mirai-botnet-variant-targets-dvr-devices-with-cve-2024-3721/116742/  
  
  
微软协助CBI捣毁针对日本公民实施复杂诈骗的印度呼叫中心  
  
https://thehackernews.com/2025/06/microsoft-helps-cbi-dismantle-indian.html  
  
  
8600 万 AT&T 客户记录在暗网出售  
  
https://www.zdnet.com/article/86-million-a-t-customer-records-reportedly-up-for-sale-on-the-dark-web/  
  
  
文本共享网站Paste.ee 沦为网络武器：恶意攻击者传播 XWorm 和 AsyncRAT  
  
https://gbhackers.com/paste-ee-turned-cyber-weapon/  
  
  
阿迪达斯确认用户服务提供商遭黑客攻击导致数据泄露  
  
https://www.cysecurity.news/2025/06/adidas-confirms-data-leak-after-user.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
HPE Insight 远程支持工具中发现严重 RCE 漏洞  
  
https://gbhackers.com/critical-rce-flaw-found/  
  
  
思科发布公开 PoC 修复 ISE 关键漏洞  
  
https://www.securityweek.com/cisco-patches-critical-ise-vulnerability-with-public-poc/  
  
  
VMware NSX XSS 漏洞允许攻击者注入恶意代码  
  
https://cybersecuritynews.com/vmware-nsx-xss-vulnerability/  
  
  
数千台华硕路由器受到隐秘持久后门的影响  
  
https://www.cysecurity.news/2025/06/thousands-of-asus-routers-affected-by.html  
  
  
NetMRI 中存在 6 个严重漏洞，可使攻击者获得完全管理员访问权限  
  
https://gbhackers.com/researcher-found-6-critical-vulnerabilities-in-netmri/  
  
  
Wireshark 漏洞可通过恶意数据包注入发起 DoS 攻击  
  
https://cybersecuritynews.com/wireshark-vulnerability-enables-dos-attack/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
