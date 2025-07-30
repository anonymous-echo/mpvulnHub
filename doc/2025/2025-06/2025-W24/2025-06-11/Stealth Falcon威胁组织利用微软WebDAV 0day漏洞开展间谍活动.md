#  Stealth Falcon威胁组织利用微软WebDAV 0day漏洞开展间谍活动  
会杀毒的单反狗  军哥网络安全读报   2025-06-11 01:03  
  
**导****读**  
  
  
  
Check Point 研究人员发现 Stealth Falcon 威胁组织利用微软零日漏洞开展网络间谍活动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEjIU3iaC84xWwE4xeJriboDTz0XDyI9P3umQ94ELLuv1TwaZuhaIAL09JsRiaY2xdzdJku9XHUr4Xtg/640?wx_fmt=png&from=appmsg "")  
  
  
此次行动部署了一套复杂的自定义加载器和植入程序，旨在规避检测、阻碍分析，并选择性地仅在有价值的目标上激活。  
  
  
2025年3月，Check Point Research 发现一起针对土耳其一家大型国防机构的网络攻击企图。  
  
  
攻击者利用 Windows 中一个此前未知的远程代码执行漏洞，从他们控制的远程 WebDAV 服务器执行文件，从而利用合法的 Windows 内置工具静默运行恶意代码。  
  
  
在负责任地披露漏洞后，微软将该漏洞编号为 CVE-2025-33053，并于2025年6月10日发布了补丁。  
  
  
根据所使用的技术、活动背后的基础设施以及预期目标的概况，Check Point Research 将此活动归咎于与阿联酋关联的 APT 组织Stealth Falcon。  
  
  
Stealth Falcon是谁？  
  
  
Stealth Falcon，又名FruityArmor，是一个长期活跃的网络间谍组织，至少自 2012 年以来一直活跃，其攻击记录涵盖中东和非洲地区的政治和战略实体。  
  
  
Stealth Falcon 的攻击策略不断演变，但其重点始终是政府和国防部门的高价值目标。  
  
  
攻击如何进行？  
  
  
此次攻击始于一个看似标准的快捷方式文件——一个伪装成与军事装备损坏相关的 PDF 文档的 .url 文件。该文件由一家土耳其大型国防公司的消息来源提交给 VirusTotal，很可能是通过钓鱼邮件发送的，Stealth Falcon 此前曾多次使用过这种伎俩。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEjIU3iaC84xWwE4xeJriboDTW5E2SGvIjwZsUOAJiaBt2NdxwTtU1M51fAPvC4JicXKBWPSuoVukY2pA/640?wx_fmt=png&from=appmsg "")  
  
  
这个快捷方式文件之所以危险，是因为它能够静默运行攻击者控制的远程服务器中的代码。攻击者操纵了 Windows 文件执行搜索顺序。他们诱骗内置的 Windows 实用程序执行托管在其远程服务器上的恶意程序。  
  
  
这种技术使得Stealth Falcon无需将感染链第一阶段的文件直接植入受害者计算机即可运行其代码。此外，该技术还帮助他们通过依赖合法、可信的Windows组件进行攻击，从而逃避检测。  
  
  
Horus Loader：间谍活动的定制入口点  
  
  
一旦快捷方式文件被激活，它就会启动攻击的下一阶段：一个多阶段加载器，Horus Loader，以埃及猎鹰神的名字命名，与该组织的代号相呼应。  
  
  
Horus Loader 的设计理念是灵活且具有规避能力。它可以：  
- 清理感染链早期留下的痕迹  
- 绕过基本检测机制  
- 放下并打开诱饵文件以避免引起怀疑  
- 谨慎部署最终的间谍软件有效载荷  
  
最终载荷：一个名为  
  
Horus Agent  
  
的定制间谍软件  
  
  
当受害者忙于查看诱饵文档时，恶意软件会在后台悄悄地继续工作。接下来是该行动中技术最先进的阶段之一：部署一个名为“Horus Agent”的定制间谍工具。  
  
  
是为 Mythic 构建的私人植入物，Mythic 是一种合法的开源命令和控制 (C2) 框架，常用于红队行动。  
  
  
与现成的恶意软件不同，Horus 采用 C++ 编写，从头构建，充分考虑了隐蔽性和灵活性。它与其他已知的 Mythic 代理程序仅具有一些基本特征——足以在平台上运行，但不足以轻易被检测到或根据代码相似性进行归因。  
  
  
安装完成后，Horus Agent 会连接到其 C2 服务器，并开始使用 Mythic 框架轮询指令。虽然部分命令是内置的，但 Stealth Falcon 还开发了一些定制命令，以增强隐身性和灵活性，展现出其静默收集情报并在极少被发现的情况下执行有效载荷的意图。  
  
  
与早期修改版的 Mythic agents  
  
不同，Horus  
  
似乎是量身定制的。它强调隐身、反分析保护和精简的指令集，专注于识别目标并选择性地部署更多有效载荷。这种精简的设计表明它对目标环境和防御工具有着深入的了解，有助于该组织在保护其更广泛的工具集的同时保持低调。  
  
  
完整技术报告：  
  
https://research.checkpoint.com/2025/stealth-falcon-zero-day/  
  
  
新闻链接：  
  
https://blog.checkpoint.com/research/inside-stealth-falcons-espionage-campaign-using-a-microsoft-zero-day/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
Rare Werewolf APT 使用合法软件攻击数百家俄罗斯企业  
  
https://thehackernews.com/2025/06/rare-werewolf-apt-uses-legitimate.html  
  
  
曹县APT 黑客瞄准社交媒体用户传播恶意软件  
  
https://gbhackers.com/north-korean-apt-hackers-target-users/  
  
  
FIN6 利用 AWS 托管的 LinkedIn 虚假简历传播 More_eggs 恶意软件  
  
https://thehackernews.com/2025/06/fin6-uses-aws-hosted-fake-resumes-on.html  
  
  
Stealth Falcon 威胁组织利用微软WebDAV   
0day  
漏洞开展间谍活动  
  
https://blog.checkpoint.com/research/inside-stealth-falcons-espionage-campaign-using-a-microsoft-zero-day/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
北美最大的食品杂货经销商遭受网络攻击  
  
https://www.securityweek.com/whole-foods-distributor-united-natural-foods-hit-by-cyberattack/  
  
  
HelloTDS 恶意软件通过 FakeCaptcha 基础设施传播，感染数百万台设备  
  
https://gbhackers.com/hellotds-malware-spread-via-fakecaptcha-infrastructure/  
  
  
下载量超过百万的热门 NPM 软件包遭恶意软件攻击  
  
https://www.techradar.com/pro/security/popular-npm-packages-with-over-a-million-downloads-hit-by-malware  
  
  
两款 Mirai 僵尸网络 Lzrd 和 Resgod 被发现利用 Wazuh 安全软件漏洞  
  
https://hackread.com/two-mirai-botnets-lzrd-resgod-exploiting-wazuh-flaw/  
  
  
传感器制造商 Sensata 表示，勒索软件攻击导致敏感信息被盗  
  
https://www.securityweek.com/sensitive-information-stolen-in-sensata-ransomware-attack/  
  
  
黑客利用合法远程监控和管理工具 ConnectWise ScreenConnect 部署恶意软件  
  
https://cybersecuritynews.com/hackers-continue-to-leverage-connectwise-screenconnect-tool/  
  
  
基于 Rust 的 Myth Stealer 恶意软件通过虚假游戏网站传播  
  
https://thehackernews.com/2025/06/rust-based-myth-stealer-malware-spread.html  
  
  
新黑客组织利用 LockBit 勒索软件变种攻击俄罗斯公司  
  
https://therecord.media/new-hacker-group-lockbit-target-russia  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Chrome 和 Chromium 中的  
0day  
漏洞使 Windows 和 Linux 用户面临数据风险  
  
https://www.cysecurity.news/2025/06/zero-day-flaw-in-chrome-and-chromium.html  
  
  
Ivanti Workspace Control 硬编码密钥缺陷暴露 SQL 凭据  
  
https://www.bleepingcomputer.com/news/security/ivanti-workspace-control-hardcoded-key-flaws-expose-sql-credentials/  
  
  
漏洞暴露了所有 Google 用户的电话号码  
  
https://www.securityweek.com/vulnerabilities-exposed-phone-number-of-any-google-user/  
  
  
Salesforce Industry Cloud行业软件中发现 5 个  
0day  
漏洞和 15 个错误配置  
  
https://www.securityweek.com/five-zero-days-15-misconfigurations-found-in-salesforce-industry-cloud/  
  
  
Adobe 发布补丁修复 254 个漏洞  
  
https://thehackernews.com/2025/06/adobe-releases-patch-fixing-254.html  
  
  
Fortinet 安全更新：重要补丁修复多个产品漏洞  
  
https://cybersecuritynews.com/fortinet-security-update/  
  
  
严重远程代码执行 (RCE) 漏洞影响超过 80,000 台 Roundcube 服务器  
  
https://www.securityweek.com/exploited-vulnerability-impacts-over-80000-roundcube-servers/  
  
  
微软  
6  
月补丁日：修复 66 个漏洞，包括一个被积极利用的 0Day 漏洞  
  
https://hackread.com/june-2025-patch-tuesday-microsoft-bugs-active-0-day/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
