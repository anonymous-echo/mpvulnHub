#  Ivanti Connect Secure VPN 成为新0day攻击的目标   
会杀毒的单反狗  军哥网络安全读报   2025-01-10 01:00  
  
**导****读**  
  
  
  
Google 旗下的 Mandiant 将新修补的 Ivanti VPN   
0day  
漏洞的利用与网络间谍联系起来。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaEI5fQDUTBdhSm4rsfmjj8YiabnrYkWWMAg0QzA9aWQlpUlGHgwZLa59RrfQImjE2O1PsicZDkmYMyQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Ivanti 周三向客户发出警报，其 Connect Secure (ICS) VPN 设备中已修复两个漏洞，分别为 CVE-2025-0282 和 CVE-2025-0283。  
  
  
Ivanti 警告称，CVE-2025-0282 是一种严重的基于堆栈的缓冲区溢出漏洞，可让未经身份验证的远程攻击者执行任意代码。该漏洞已被利用来攻击有限数量的客户。  
  
  
Ivanti 并未透露有关这些攻击的任何细节，只是表示，入侵是使用该公司的完整性检查工具 (ICT) 和商业安全监控工具发现的。  
  
  
与 Ivanti 合作调查这些攻击的 Mandiant 研究人员透露，该漏洞利用与  
APT  
组织有关。Mandiant 在 2024 年 12 月中旬开始发现 CVE-2025-0282 被利用。  
  
  
Mandiant 表示，目前无法将 CVE-2025-0282 的利用归因于特定的威胁组织。攻击者部署了一个被追踪为 Spawn 的恶意软件家族，该家族之前被归因于一个间谍组织，被追踪为UNC5337。  
  
  
Spawn 恶意软件家族包括 SpawnAnt 安装程序、SpawnMole 隧道程序和名为 SpawnSnail 的 SSH 后门。  
  
  
Mandiant 以中等可信度认为，UNC5337 是UNC5221的一部分，该威胁组织之前曾利用 Ivanti 产品漏洞（例如 CVE-2023-46805 和 CVE-2024-21887）。这些攻击的受害者包括MITRE和CISA。  
  
  
在利用新 Ivanti ICS   
0day  
漏洞 CVE-2025-0282 的攻击中，Mandiant 还发现了之前未知的恶意软件家族，它们被命名为 DryHook 和 PhaseJam。这些恶意软件尚未与已知威胁组织联系起来。  
  
  
Mandiant 解释道：“可能有多个参与者负责创建和部署这些不同的代码系列（即 Spawn、DryHook 和 PhaseJam），但截至发布此报告时，我们没有足够的数据来准确评估针对 CVE-2025-0282 的威胁参与者的数量。”  
  
  
在 Mandiant 观察到的攻击中，黑客首先向目标设备发送请求，以确定其软件版本，因为漏洞利用是特定于版本的。然后，他们利用 CVE-2025-0282、禁用 SELinux、进行配置更改、执行脚本并部署 Web Shell，为部署恶意软件做准备。  
  
  
PhaseJam 恶意软件是一种植入程序，旨在修改 Ivanti Connect Secure 组件、部署 Web Shell 并覆盖可执行文件以方便执行任意命令。该恶意软件可帮助攻击者建立初始立足点，使他们能够执行命令、将文件上传到设备并窃取数据。  
  
  
攻击者在后利用阶段使用了 DryHook 恶意软件来窃取凭证。  
  
  
为了在系统升级过程中保持持久性，攻击者利用了 SpawnAnt 恶意软件，该恶意软件会将自身及其组件复制到一个特殊的升级分区。此外，PhaseJam 恶意软件会阻止系统升级，但会显示虚假的升级进度条以避免引起怀疑。  
  
  
Mandiant 警告称，如果概念验证 (PoC) 漏洞被创建并公开，CVE-2025-0282 可能会被更多威胁组织利用。  
  
  
CISA 周三将 Ivanti Connect Secure   
0day  
漏洞添加到其已知利用漏洞 (KEV) 目录中，指示联邦机构在 1 月 15 日之前解决该安全漏洞。   
  
  
值得注意的是，Ivanti 已经发布了针对 Connect Secure 的补丁，但 ZTA 网关的 Policy Secure 和 Neurons 也受到影响，并且它们要到 1 月 21 日才会收到补丁。  
  
  
技术报告：  
  
https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day  
  
  
新闻链接：  
  
https://www.securityweek.com/exploitation-of-new-ivanti-vpn-zero-day-linked-to-chinese-cyberspies/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
黑客声称入侵俄罗斯管理财产和土地记录的国家机构  
  
https://therecord.media/hackers-claim-to-breach-russian-state-agency-land-records  
  
  
MirrorFace 利用 ANEL 和 NOOPDOOR 对日本发动长达数年的网络攻击  
  
https://thehackernews.com/2025/01/mirrorface-leverages-anel-and-noopdoor.html  
  
  
Ivanti Connect Secure VPN 成为新  
0day  
攻击的目标  
  
https://www.securityweek.com/exploitation-of-new-ivanti-vpn-zero-day-linked-to-chinese-cyberspies/  
  
  
俄罗斯 ISP 确认乌克兰黑客“摧毁”其网络  
  
https://www.bleepingcomputer.com/news/security/russian-isp-confirms-ukrainian-hackers-destroyed-its-network/  
  
  
卡巴斯基报告：Eagerbee 后门针对中东政府机构和 ISP  
  
https://www.bleepingcomputer.com/news/security/eagerbee-backdoor-deployed-against-middle-eastern-govt-orgs-isps/  
  
  
伊朗和俄罗斯实体因利用人工智能和网络战术干预选举而受到制裁  
  
https://thehackernews.com/2025/01/iranian-and-russian-entities-sanctioned.html  
  
  
美国财政部远程支持平台遭到入侵  
  
https://www.bleepingcomputer.com/news/security/us-treasury-department-breached-through-remote-support-platform/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
研究人员发现依赖过期域名的数千个活跃黑客后门  
  
https://hackread.com/live-hacker-backdoors-found-in-expired-domains/  
  
  
Proton 从全球中断中恢复后，Proton Mail 仍处于瘫痪状态  
  
https://www.bleepingcomputer.com/news/technology/proton-mail-still-down-as-proton-recovers-from-worldwide-outage/  
  
  
黑客利用电子贺卡传播恶意软件  
  
https://cybernews.com/security/group-greeting-e-card-malware-campaign-infects-thousands/  
  
  
虚假 CrowdStrike 工作邀请电子邮件传播挖矿木马  
  
https://www.bleepingcomputer.com/news/security/fake-crowdstrike-job-offer-emails-target-devs-with-crypto-miners/  
  
  
医疗账单公司 Medusind 称数据泄露影响 36 万人  
  
https://www.securityweek.com/medical-billing-firm-medusind-says-data-breach-impacts-360000-people/  
  
  
卡西欧称黑客在 10 月份勒索软件攻击中窃取了 8,500 人的个人数据  
  
https://techcrunch.com/2025/01/08/casio-says-hackers-stole-personal-data-of-8500-people-during-october-ransomware-attack/  
  
  
研究人员发现一种名为NonEuclid的新型远程访问木马  
  
https://thehackernews.com/2025/01/researchers-expose-noneuclid-rat-using.html  
  
  
新的 Banshee Stealer 变种利用 Apple XProtect 加密技术绕过防病毒软件  
  
https://thehackernews.com/2025/01/new-banshee-stealer-variant-bypasses.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
未修复的严重漏洞影响 Fancy Product Designer WordPress 插件  
  
https://www.bleepingcomputer.com/news/security/unpatched-critical-flaws-impact-fancy-product-designer-wordpress-plugin/  
  
  
GFI KerioControl 防火墙漏洞遭野外利用  
  
https://www.securityweek.com/gfi-keriocontrol-firewall-vulnerability-exploited-in-the-wild/  
  
  
SonicWall 修补防火墙中的身份验证绕过漏洞  
  
https://www.securityweek.com/sonicwall-patches-authentication-bypass-vulnerabilities-in-firewalls/  
  
  
Palo Alto Networks 修复已停用的迁移工具中的高危漏洞  
  
https://www.securityweek.com/palo-alto-networks-patches-high-severity-vulnerability-in-retired-migration-tool/  
  
  
SonicWall、Palo Alto Expedition 和 Aviatrix 控制器中的主要漏洞已修复  
  
https://thehackernews.com/2025/01/major-vulnerabilities-patched-in.html  
  
  
GFI KerioControl 中存在严重 RCE 缺陷，允许通过 CRLF 注入执行远程代码  
  
https://thehackernews.com/2025/01/critical-rce-flaw-in-gfi-keriocontrol.html  
  
  
不安全的物联网云再次来袭：Reyee  
平台连接设备遭 RCE 攻击  
  
https://claroty.com/team82/research/the-insecure-iot-cloud-strikes-again-rce-on-ruijie-cloud-connected-devices  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
