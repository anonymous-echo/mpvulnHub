#  APT组织利用 Ivanti 漏洞攻击关键部门   
会杀毒的单反狗  军哥网络安全读报   2025-05-26 01:01  
  
**导****读**  
  
  
  
据 EclecticIQ 报道，一个网络黑客组织利用最近的两个 Ivanti Endpoint Manager Mobile (EPMM) 漏洞，针对欧洲、北美和亚太地区的关键部门发动攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaG419MlPx6vQQ8ZsKwbtoGUqcUnzYsEVcnBeh7cicUic4ia7lXpWvOyk3DLHqBGxIjdx9qmxqM8zK7Rg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这两个漏洞的严重程度为中等，分别为 CVE-2025-4427 和 CVE-2025-4428，分别允许攻击者绕过身份验证和远程执行任意代码。  
  
  
这些漏洞影响集成到 EPMM 中的两个开源库，可以串联起来在易受攻击的部署上实现未经身份验证的远程代码执行 (RCE)。  
  
  
Ivanti于 5 月 13 日修补了这两个安全漏洞，并警告称，这些漏洞已被用作0day漏洞武器，攻击有限数量的客户。  
  
  
Wiz 本周警告称， 针对该安全缺陷的概念验证 (PoC) 漏洞代码被公开发布，威胁组织开始在野外使用这些代码。  
  
  
为了验证 Wiz 的发现，EclecticIQ 也警告称这些漏洞正被持续利用，并将观察到的攻击归咎于威胁组织UNC5221。  
  
  
该组织自 2023 年以来就以针对边缘设备中的0day漏洞利用而闻名，据观察，该组织从易受攻击的设备中窃取大量数据，包括个人身份信息 (PII)、凭证和其他敏感信息。  
  
  
自 5 月 15 日起，该黑客组织针对航空、国防、金融、地方政府、医疗保健和电信组织等面向互联网的易受攻击的 EPMM 实例，以窃取包含核心运营数据的文件。  
  
  
EclecticIQ 确定的目标包括德国最大的电信供应商之一、一家网络安全公司、一家美国枪支制造商以及韩国的一家跨国银行。  
  
  
EclecticIQ 指出： “鉴于 EPMM 在管理和向企业移动设备推送配置方面的作用，成功利用该漏洞可能允许攻击者远程访问、操纵或破坏整个组织内的数千台托管设备。”  
  
  
作为攻击的一部分，UNC5221 部署了 FRP（快速反向代理），这是一种为持久访问建立反向 SOCKS5 代理的开源工具，以及 KrustyLoader，它通常用于部署 Sliver 后门。  
  
  
EclecticIQ 表示，该黑客组织还被发现使用 shell 命令进行侦察并实时隐藏其踪迹，“可能使用 HTTP GET 请求窃取数据，然后擦除文件”。  
  
  
EclecticIQ 高度确信，观察到的 Ivanti EPMM 攻击活动很可能与网络间谍组织 UNC5221 有关。基础设施重用和观察到的间谍技术与该组织先前开展的活动高度吻合。  
  
  
技术报告：  
  
https://blog.eclecticiq.com/china-nexus-threat-actor-actively-exploiting-ivanti-endpoint-manager-mobile-cve-2025-4428-vulnerability  
  
  
新闻链接：  
  
https://www.securityweek.com/chinese-spies-exploit-ivanti-vulnerabilities-against-critical-sectors/  
  
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
  
欧洲刑警组织打击全球勒索软件网络，缴获300台服务器和350万欧元  
  
https://thehackernews.com/2025/05/300-servers-and-35m-seized-as-europol.html  
  
  
专家警告：AI仅用20张图片即可制作深度伪造视频  
  
https://www.cysecurity.news/2025/05/ai-can-create-deepfake-videos-of.html  
  
  
前白宫顾问称，网络犯罪比国家背景的  
APT  
行动  
“  
大几个数量级  
”  
  
https://www.theregister.com/2025/05/24/cyber_crime_bigger_than_nation_state/  
  
  
谷歌称攻击英国公司的攻击者现在将目标转向美国商店  
  
https://www.cysecurity.news/2025/05/google-claims-attackers-that-hit-uk.html  
  
  
基于.Net 的 Chihuahua 信息窃取程序利用 Google Drive 窃取浏览器凭证和加密钱包  
  
https://cybersecuritynews.com/net-based-chihuahua-infostealer-exploit-google-drive-steals-browser-credentials-and-crypto-wallets/  
  
  
网络攻击者利用 JPG 文件部署勒索软件而不被发现  
  
https://www.cysecurity.news/2025/05/cyberattackers-use-jpg-files-to-deploy.html  
  
  
黑客利用TikTok视频通过ClickFix技术传播Vidar和StealC恶意软件  
  
https://thehackernews.com/2025/05/hackers-use-tiktok-videos-to-distribute.html  
  
  
1.84亿条数据库记录泄露：微软、苹果、谷歌、Facebook、PayPal登录信息被发现  
  
https://www.techrepublic.com/article/news-database-leak-184-million-credentials/  
  
  
黑客利用虚假 Ledger 应用程序攻击 macOS 用户并部署恶意软件  
  
https://cybersecuritynews.com/hackers-attacking-macos-users-with-fake-ledger-apps/  
  
  
Silver Fox（银狐）利用伪造的 VPN 和浏览器 NSIS 安装程序传播 Winos 4.0 恶意软件  
  
https://thehackernews.com/2025/05/hackers-use-fake-vpn-and-browser-nsis.html  
  
  
犯罪分子利用虚假人工智能工具传播信息窃取木马Noodlophile  
  
https://www.cysecurity.news/2025/05/cybercriminals-employ-fake-ai-tools-to.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
研究人员发现微软  
  
Copilot AI for SharePoint 存在重大漏洞  
  
https://www.cysecurity.news/2025/05/pen-test-partners-uncovers-major.html  
  
  
Zimbra CVE-2024-27443 XSS 漏洞影响 12.9 万台服务器  
  
https://hackread.com/zimbra-cve-2024-27443-xss-flaw-hit-sednit-servers/  
  
  
GitLab Duo 漏洞可导致攻击者注入恶意链接并窃取源代码  
  
https://cybersecuritynews.com/gitlab-duo-inject-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
