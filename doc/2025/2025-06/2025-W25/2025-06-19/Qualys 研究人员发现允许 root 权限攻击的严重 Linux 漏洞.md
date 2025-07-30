> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795477&idx=1&sn=c8cc84db69bc662ea39715896bbf0262

#  Qualys 研究人员发现允许 root 权限攻击的严重 Linux 漏洞  
会杀毒的单反狗  军哥网络安全读报   2025-06-19 01:01  
  
**导****读**  
  
  
  
Qualys 威胁研究部门 (TRU) 发现两个相互关联的本地权限提升 (LPE) 漏洞 - CVE-2025-6018和CVE-2025-6019 。这两个漏洞使攻击者能够以最小的努力获得对各种 Linux 发行版的完全 root 访问权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGjV40ZOJHNMxuekSuTkkYNhV7DduprIjuJYXdW4g5mt7rOlHQMtSTobESoCvGImgq8q7jSUnOrbQ/640?wx_fmt=png&from=appmsg "")  
  
  
这些缺陷会影响桌面和服务器安装，并且其利用只需要本地用户会话（例如 SSH），因此对企业和个人而言都构成严重风险。  
  
  
CVE-2025-6018：SUSE Linux 中的 PAM 配置错误  
  
  
第一个是本地权限提升 (LPE) 漏洞，编号为 CVE-2025-6018，它影响 openSUSE Leap 15 和 SUSE Linux Enterprise 15 中的 PAM 配置。  
  
  
这种错误配置会导致任何本地登录会话（包括通过 SSH 的会话）被视为用户实际在场。该状态称为“allow_active”，授予通常为机器上的用户保留某些特权操作访问权限。  
  
  
CVE-2025-6019：libblockdev/udisks 权限提升  
  
  
第二个漏洞 CVE-2025-6019 位于 libblockdev 中，可通过 udisks 守护进程触发，该守护进程在几乎所有 Linux 发行版中都默认安装。一旦用户获得 allow_active 状态，此漏洞即可启用完全 root 访问权限。  
  
  
这两个漏洞结合在一起，创建了一条从非特权到 root 访问权限的直接且低成本的途径。  
  
### 漏洞链影响  
###   
  
udisks 守护进程及其 libblockdev 后端用于管理磁盘和存储设备。根据设计，它们会向标记为“活跃”的用户授予更多权限。PAM 漏洞破坏了这种信任模型，将常规会话变成了安全隐患。  
  
  
该漏洞链尤其危险，因为不需要额外的软件或物理访问，只需通过 SSH 登录到易受攻击的系统即可。  
  
  
Qualys 威胁研究部门 (TRU) 已在 Ubuntu、Debian、Fedora 和 openSUSE Leap 15 上成功演示了此漏洞利用链 。  
  
  
攻击者仅使用默认安装的组件就可以轻松地从标准 SSH 会话跳转到完全 root 权限。  
  
  
TRU 的研究人员表示：“这不需要什么特别的东西。每个链接都预先安装在主流 Linux 发行版及其服务器版本上。”  
  
### 漏洞的主要风险：  
###   
  
完全接管受影响的系统；逃避端点检测工具；安装持久后门；通过横向移动威胁整个网络。  
  
  
安全专家建议受影响的用户立即修补漏洞，另外建议：  
- 修改 org.freedesktop.udisks2.modify-device 的默认 polkit 规则  
- 将 allow_active 设置从 yes 更改为 auth_admin  
- 遵循 SUSE、Ubuntu 和其他厂商的建议  
如果不迅速采取行动，整个网络面临被攻陷的风险。通过此漏洞获得的 root 访问权限可实现难以察觉的持久化攻击和跨系统攻击，从而加大企业基础设施的风险。  
  
  
漏洞公告：  
  
https://blog.qualys.com/vulnerabilities-threat-research/2025/06/17/qualys-tru-uncovers-chained-lpe-suse-15-pam-to-full-root-via-libblockdev-udisks  
  
  
研究人员同时公开了漏洞细节：  
  
https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt  
  
  
新闻链接：  
  
https://www.infosecurity-magazine.com/news/linux-flaws-allowing-root-access/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
Team46  
    
利用 Google Chrome 零日漏洞 CVE-2025-2783 部署 Trinper 后门  
  
https://thehackernews.com/2025/06/google-chrome-zero-day-cve-2025-2783.html  
  
  
俄罗斯黑客利用应用特定密码绕过 Gmail MFA  
  
https://www.securityweek.com/russian-hackers-bypass-gmail-mfa-with-app-specific-password-ruse/  
  
  
Kimsuky 和   
  
Konni APT 组织是针对东亚地区最活跃的攻击组织  
  
https://cybersecuritynews.com/kimsuky-and-konni-apt-groups-accounts-most-active-attacks/  
  
  
新型 Sorillus RAT 通过隧道服务攻击欧洲组织  
  
https://gbhackers.com/new-sorillus-rat-targets-european-organizations/  
  
  
Water Curse 黑客组织利用 76 个 GitHub 账户传播多级恶意软件  
  
https://cybersecuritynews.com/water-curse-hacker-group-weaponized-76-github-accounts/  
  
  
XDSpy 威胁组织利用 Windows LNK 零日漏洞（ZDI-CAN-25373）攻击东欧和俄罗斯实体  
  
https://gbhackers.com/xdspy-threat-actors-exploit-windows-lnk-zero-day-vulnerability/  
  
  
新型 KimJongRAT 窃密木马利用武器化的 LNK 文件部署基于 Powershell 的 Dropper  
  
https://cybersecuritynews.com/new-kimjongrat-stealer-using-weaponized-lnk-file/  
  
  
亲以色列黑客组织攻击伊朗银行  
  
https://techcrunch.com/2025/06/17/pro-israel-hacktivist-group-claims-responsibility-for-alleged-iranian-bank-hack/  
  
  
黑客冒充美国政府入侵英国著名俄罗斯问题研究员电子邮件账户  
  
https://therecord.media/keir-giles-russia-researcher-email-hacked  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
新型 Sorillus RAT 通过隧道服务攻击欧洲组织  
  
https://gbhackers.com/new-sorillus-rat-targets-european-organizations/  
  
  
Chollima 黑客利用新的 GolangGhost RAT 针对币圈  
  
https://gbhackers.com/chollima-hackers-target-windows-and-macos/  
  
  
ClickFix 恶意软件变种“LightPerlGirl”以隐秘攻击方式攻击  
  
https://www.securityweek.com/new-clickfix-malware-variant-lightperlgirl-targets-users-in-stealthy-hack/  
  
  
RapperBot 僵尸网络攻击峰值超过 50,000 次，针对网络边缘设备  
  
https://cybersecuritynews.com/rapperbot-botnet-attack-peaks-50000-attacks/  
  
  
1,500 多名 Minecraft 玩家被 GitHub 上伪装成游戏模组的 Java 恶意软件感染  
  
https://thehackernews.com/2025/06/1500-minecraft-players-infected-by-java.html  
  
  
新的恶意软件活动利用 Cloudflare 隧道通过网络钓鱼链传播 RAT  
  
https://thehackernews.com/2025/06/new-malware-campaign-uses-cloudflare.html  
  
  
麒麟勒索软件成为针对 Windows、Linux 和 ESXi 系统的主要威胁  
  
https://gbhackers.com/qilin-ransomware-emerges-as-a-major-threat/  
  
  
以 DMV 为主题的网络钓鱼攻击针对美国公民窃取敏感数据  
  
https://cybersecuritynews.com/dmv-themed-phishing-attacks/  
  
  
BlackHat AI 黑客工具 WormGPT 变种由 Grok 和 Mixtral 提供支持  
  
https://cybersecuritynews.com/wormgpt-variant/  
  
  
攻击者利用 Langflow 服务器中的 CVE-2025-3248 通过下载脚本传播 Flodrix 僵尸网络  
  
https://securityaffairs.com/179094/malware/news-flodrix-botnet-targets-vulnerable-langflow-servers.html  
  
  
美国医疗服务公司 Episource 数据泄露，影响 540 万人  
  
https://www.securityweek.com/data-breach-at-healthcare-services-firm-episource-impacts-5-4-million-people/  
  
  
攻击者利用新的 Winos 4.0 恶意软件针对 Windows 系统  
  
https://cybersecuritynews.com/threat-actors-attacking-with-winos-4-0-malware/  
  
  
新的 Chaos RAT 变种针对 Windows 和 Linux 系统窃取敏感数据  
  
https://gbhackers.com/new-chaos-rat-variants-targeting-windows-and-linux-systems/  
  
  
新型 KimJongRAT 窃取恶意软件利用武器化的 LNK 文件部署基于 PowerShell 的植入器  
  
https://gbhackers.com/new-kimjongrat-stealer-uses-weaponized-lnk-file/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Qualys 研究人员发现允许 root 权限攻击的严重 Linux 漏洞  
  
https://www.infosecurity-magazine.com/news/linux-flaws-allowing-root-access/  
  
  
CISA 警告 Linux 内核权限提升漏洞（CVE-2023-0386）遭利用  
  
https://thehackernews.com/2025/06/cisa-warns-of-active-exploitation-of.html  
  
  
LangSmith Prompt Hub 中的 AgentSmith 漏洞暴露了用户 API 密钥和数据  
  
https://hackread.com/agentsmith-flaw-langsmith-prompt-hub-api-keys-data/  
  
  
Citrix NetScaler 中的关键漏洞已修复  
  
https://www.securityweek.com/critical-vulnerability-patched-in-citrix-netscaler/  
  
  
谷歌发布 Chrome 137 更新，以解决浏览器 V8 和 Profiler 组件中的两个内存漏洞  
  
https://www.securityweek.com/chrome-137-update-patches-high-severity-vulnerabilities/  
  
  
谷歌 Gerrit 平台漏洞导致包括 ChromiumOS 在内的 18 个谷歌项目暴露于黑客手中  
  
https://gbhackers.com/googles-gerrit-platform-flaw-exposes-18-google-projects/  
  
  
Veeam、BeyondTrust 产品中的代码执行漏洞已修复  
  
https://www.securityweek.com/code-execution-vulnerabilities-patched-in-veeam-beyondtrust-products/  
  
  
Zyxel 关键漏洞沉寂许久后遭积极利用  
  
https://www.cybersecuritydive.com/news/vulnerability-zyxel-exploitation/750922/  
  
  
10 万个 WordPress 网站受到 AI Engine WordPress 插件中 MCP 权限提升的影响  
  
https://www.wordfence.com/blog/2025/06/100000-wordpress-sites-affected-by-privilege-escalation-via-mcp-in-ai-engine-wordpress-plugin/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
