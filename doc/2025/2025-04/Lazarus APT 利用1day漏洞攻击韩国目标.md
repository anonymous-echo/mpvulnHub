#  Lazarus APT 利用1day漏洞攻击韩国目标   
会杀毒的单反狗  军哥网络安全读报   2025-04-25 01:00  
  
**导****读**  
  
  
  
臭名昭著的 Lazarus APT组织最近发起一场网络间谍活动，被追踪为“Operation SyncHole”，自 2024 年 11 月以来，已危害至少六个韩国机构，涉及软件、IT、金融、半导体和电信领域。  
  
  
根据详细研究，攻击者采用了水坑攻击和利用韩国广泛使用的软件（包括 Cross EX 和 Innorix Agent）中的漏洞组合。  
  
  
此次行动展示了Lazarus组织对当地软件生态系统的深刻理解，攻击利用了韩国网上银行和政府服务不可或缺的应用程序。  
  
  
该活动的复杂性在于它利用了  
1  
Day  
漏洞，这些漏洞在发现后不久就得到了修补，但在短暂的暴露时间内被利用，展示了 Lazarus 在利用新发现的弱点进行攻击方面的灵活性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHhNBCzyRJQwgvLUz6k8TrvgpL0o8xFpumK021O0icBxxYybfTXMTMSQRXYXTKAUCugKDMEfB3dYTQ/640?wx_fmt=png&from=appmsg "")  
  
  
此次攻击始于用户访问被入侵的韩国媒体网站，触发了通过水坑策略投放 ThreatNeedle 后门。  
  
  
Lazarus 利用合法浏览器支持软件 Cross EX 中的漏洞，将恶意软件注入 SyncHost.exe 进程，从而实现权限提升和持久化。  
  
  
同时，Innorix Agent（版本高达 9.2.18.496）中一个  
1day  
漏洞促进了网络内的横向移动，从而允许部署 ThreatNeedle 和 LPEClient 等其他有效载荷。  
  
  
该行动分为两个阶段：第一阶段依赖于 ThreatNeedle 和 wAgent 的更新变体，第二阶段引入 SIGNBT（版本 0.0.1 和 1.2）和 COPPERHEDGE 进行侦察和有效载荷投放。  
  
  
值得注意的是，该恶意软件采用了高级加密（ThreatNeedle 采用 Curve25519，SIGNBT 采用 RSA）和模块化结构，反映了Lazarus不断演变的策略。  
  
  
研究人员观察到了新的库，例如 wAgent 中的 GNU 多精度 (GMP)，以及 Agamemnon 下载程序中的 Tartarus-TpAllocInject 等技术，强调了它们专注于绕过现代安全解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHhNBCzyRJQwgvLUz6k8TrvKnGPHRwD1plVxMzun4VPxXkY8WNhLvIzUbs9ibgzhZbV8leFPjfY0gw/640?wx_fmt=png&from=appmsg "")  
  
  
基础设施分析显示，受到攻击的韩国合法网站被重新用作命令和控制 (C2) 服务器，其中 www  
[  
.  
]  
smartmanagerex[.]com 等域名模仿受信任的供应商以逃避检测。  
  
  
安全研究人员与韩国互联网安全局 (KrCERT/CC) 迅速做出反应，修补了被利用的软件漏洞，包括 Innorix Agent (KVE-2025-0014) 中之前未知的  
0day  
漏洞。  
  
  
研究人员警告说，鉴于目标软件的广泛使用，可能有更多组织受到威胁。Lazarus 持续关注韩国供应链，这表明此类攻击将持续下去，并可能利用未被发现的  
0day  
漏洞。  
  
  
技术报告：  
  
https://securelist.com/operation-synchole-watering-hole-attacks-by-lazarus/116326/  
  
  
新闻链接：  
  
https://gbhackers.com/lazarus-apt-targets-organizations/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
俄罗斯黑客利用微软 OAuth 2.0 攻击组织  
  
https://gbhackers.com/russian-hackers-exploit-microsoft-oauth-2-0/  
  
  
匿名者黑客组织（Anonymous）泄露 10TB 俄罗斯敏感数据  
  
https://www.cysecurity.news/2025/04/cyber-vigilantes-strike-again-as.html  
  
  
Lazarus APT 利用  
1day  
漏洞攻击韩国目标  
  
https://gbhackers.com/lazarus-apt-targets-organizations/  
  
  
与伊朗有关的黑客利用 MURKYTOUR 恶意软件通过虚假招聘活动攻击以色列  
  
https://thehackernews.com/2025/04/iran-linked-hackers-target-israel-with.html  
  
  
曹县黑客在单日网络钓鱼攻击中窃取 TRON 用户 1.37 亿美元  
  
https://thehackernews.com/2025/04/dprk-hackers-steal-137m-from-tron-users.html  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
XRP官方Ledger NPM软件包中发现后门  
  
https://hackread.com/backdoor-found-in-official-xrp-ledger-npm-package/  
  
  
超过 16,000 台 Fortinet 设备感染了 Symlink 后门  
  
https://www.cysecurity.news/2025/04/over-16000-fortinet-devices-infected.html  
  
  
FBI确认2024年网络犯罪造成166亿美元损失  
  
https://www.cybersecurity-insiders.com/fbi-confirms-16-6-billion-losses-to-cyber-crime-in-2024/  
  
  
黑客利用 Ivanti Connect Secure 0-Day 漏洞部署 DslogdRAT 和 Web Shell  
  
https://gbhackers.com/hackers-exploit-ivanti-connect-secure-0-day/  
  
  
新的隐写术活动利用 MS Office 漏洞传播 AsyncRAT  
  
https://gbhackers.com/new-steganography-campaign-exploits-ms-office-vulnerability/  
  
  
加州蓝盾保险公司因配置错误泄露 470 万会员健康数据  
  
https://www.securityweek.com/blue-shield-of-california-data-breach-impacts-4-7-million-people/  
  
  
耶鲁纽黑文健康中心 (YNHHS) 数据泄露影响 550 万名患者  
  
https://www.securityweek.com/5-5-million-patients-affected-by-data-breach-at-yale-new-haven-health/  
  
  
网络犯罪团伙利用 Google 表单从受害者那里窃取敏感信息  
  
https://www.welivesecurity.com/en/scams/how-fraudsters-abuse-google-forms-spread-scams/  
  
  
威胁组织利用不安全的 Kubernetes 集群进行加密货币挖矿  
  
https://gbhackers.com/threat-actors-exploiting-unsecured-kubernetes-clusters/  
  
  
ToyMaker 黑客通过 SSH 和文件传输工具入侵多台主机  
  
https://gbhackers.com/toymaker-hackers-compromise-numerous-hosts/  
  
  
赛门铁克将 Betruger 后门恶意软件与 RansomHub 勒索软件攻击联系起来  
  
https://www.cysecurity.news/2025/04/symantec-links-betruger-backdoor.html  
  
  
新的 SessionShark 网络钓鱼工具包绕过 MFA 窃取 Office 365 登录信息  
  
https://hackread.com/sessionshark-phishing-kit-bypass-mfa-steal-office-365-logins/  
  
  
Darcula 将 GenAI 添加到网络钓鱼工具包中  
  
https://thehackernews.com/2025/04/darcula-adds-genai-to-phishing-toolkit.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
思科多款工具面临 Erlang/OTP SSH 远程代码执行漏洞威胁  
  
https://gbhackers.com/multiple-cisco-tools-at-risk/  
  
  
Zyxel RCE 漏洞允许在无需任何身份验证的情况下执行任意查询  
  
https://cybersecuritynews.com/zyxel-rce-vulnerability-authentication/  
  
  
Citrix NetScaler 控制台漏洞（ CVE-2024-6235） PoC 发布  
  
https://cybersecuritynews.com/citrix-netscaler-console-vulnerability/  
  
  
NVIDIA NeMo 框架漏洞可导致攻击者执行远程代码  
  
https://cybersecuritynews.com/nvidia-nemo-framework-vulnerability/  
  
  
Redis DoS 漏洞：攻击者可耗尽服务器内存或导致服务器崩溃  
  
https://cybersecuritynews.com/redis-dos-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
