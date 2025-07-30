#  Lazarus 黑客组织利用 MagicLine4NX 软件中的0day漏洞对韩国目标进行供应链攻击   
 军哥网络安全读报   2023-11-26 09:00  
  
**导****读**  
  
  
  
英国国家网络安全中心 (NCSC) 和韩国国家情报院 (NIS) 警告称，朝鲜 Lazarus 黑客组织利用 MagicLine4NX
软件中的  
0day  
漏洞对企业进行供应链攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFCS1ev5BEcmSCnWPI6x5YaibORhfvchgxgLBJ52GS2v7HOLeKbYY8NbfVMJ5tianfdjbnO5lH3amKQ/640?wx_fmt=png&from=appmsg "")  
  
MagicLine4NX是韩国Dream
Security公司开发的一款安全认证软件，用于组织机构的安全登录。  
  
  
根据联合网络安全咨询（  
https://www.documentcloud.org/documents/24174869-rok-uk-joint-cyber-security-advisoryeng），朝鲜的  
APT  
组织利用产品中的  
0  
day  
漏洞来破坏其目标，主要是韩国机构。  
  
  
该通报描述道：“2023
年 3 月，网络攻击者连续利用安全认证和网络链接系统的软件漏洞，对目标组织的内网进行未经授权的访问。  
  ”  
  
  
“它利用MagicLine4NX安全认证程序的软件漏洞首次入侵目标的联网计算机，并利用联网系统的  
0day  
漏洞进行横向移动并获得未经授权的访问。”  
  
  
这次攻击首先侵入一家媒体网站，将恶意脚本嵌入文章中，从而引发“水坑”攻击。  
  
  
当特定 IP
范围的特定目标访问受感染网站上的文章时，脚本会执行恶意代码以触发 MagicLine4NX 软件中的上述漏洞， 影响 1.0.0.26 之前的版本。  
  
  
这导致受害者的计算机连接到攻击者的
C2（命令和控制）服务器，允许他们通过利用网络链接系统中的漏洞来访问互联网端服务器。  
  
  
朝鲜  
APT  
黑客利用该系统的数据同步功能，将信息窃取代码传播到业务侧服务器，从而危害目标组织内的PC。  
  
  
删除的代码连接到两台
C2 服务器，一台充当中间网关，另一台位于互联网外部。  
  
  
恶意代码的功能包括侦察、数据泄露、从
C2 下载和执行加密的有效负载以及横向网络移动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFCS1ev5BEcmSCnWPI6x5Ya7z3hyPnCnORYbZD2FuiaXtXdQ0NTzlJf6Jz3rlGlMwHyTh8fI6czYVQ/640?wx_fmt=png&from=appmsg "")  
  
攻击链 （ncsc.go.kr）  
  
  
有关这次攻击的详细信息，代号为“Dream Magic”，归因于 Lazarus APT  
组织，可以参考在这份AhnLab
报告（  
https://asec.ahnlab.com/wp-content/uploads/2023/10/20231013_Lazarus_OP.Dream_Magic.pdf），该报告仅提供韩语版本。  
  
  
朝鲜官方背景的黑客组织始终依赖供应链攻击和利用  
0  
day  
漏洞作为其网络战策略的一部分。  
  
  
2023 年 3
月，人们发现 Lazarus 的一个子组织“Labyrinth Chollima”对 VoIP 软件制造商 3CX进行了供应链攻击
，破坏了全球多家知名公司的安全。  
  
  
上周五， 微软披露了[针对讯连科技的供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649789946&idx=1&sn=a859610109c06a42e03918c88a366219&chksm=f2815fc8c5f6d6de91e8d0bbe9e74a2f47be545c94203a53db40b1859e647671f6cffa6e5516&scene=21#wechat_redirect)  
，Lazarus 黑客组织利用该攻击分发木马化、数字签名的讯连科技安装程序，用“LambLoad”恶意软件感染至少一百台计算机。  
  
  
朝鲜黑客组织利用此类攻击来针对特定公司，无论是网络间谍活动、金融欺诈还是加密货币盗窃。  
  
  
**参考链接：**  
https://www.bleepingcomputer.com/news/security/uk-and-south-korea-hackers-use-zero-day-in-supply-chain-attack/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
在针对阿富汗政府的
APT 攻击中检测到新的“HrServ.dll”Web Shell  
  
https://thehackernews.com/2023/11/new-hrservdll-web-shell-detected-in-apt.html  
  
  
苹果在收到黑客威胁  
iOS  
设备的警告后派遣专家前往印度调查  
  
https://cybernews.com/news/apple-experts-india-hacker-threat/  
  
  
Konni
Campaign 部署具有 UAC 绕过功能的高级 RAT  
  
https://www.infosecurity-magazine.com/news/konni-deploys-advanced-rat-with/  
  
  
朝鲜黑客通过虚构的招聘面试使用恶意软件针对软件开发人员  
  
https://thehackernews.com/2023/11/north-korean-hackers-pose-as-job.html  
  
  
微软报告：Lazarus
黑客在供应链攻击中破坏了讯连科技  
  
https://www.bleepingcomputer.com/news/security/microsoft-lazarus-hackers-breach-cyberlink-in-supply-chain-attack/  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
通用电气调查网络攻击和数据盗窃指控  
  
https://www.bleepingcomputer.com/news/security/general-electric-investigates-claims-of-cyber-attack-data-theft/  
  
  
Atomic
Stealer 恶意软件通过虚假浏览器更新攻击 macOS  
  
https://www.bleepingcomputer.com/news/security/atomic-stealer-malware-strikes-macos-via-fake-browser-updates/  
  
  
网络犯罪分子使用
Telekopye Telegram 机器人大规模策划网络钓鱼诈骗  
  
https://thehackernews.com/2023/11/cybercriminals-using-telekopye-telegram.html  
  
  
Rhysida，大英图书馆网络攻击背后的新勒索软件团伙  
  
https://www.theguardian.com/technology/2023/nov/24/rhysida-the-new-ransomware-gang-behind-british-library-cyber-attack  
  
  
针对 IT 提供商
CTS 的网络攻击影响了数十家英国律师事务所  
  
https://www.bleepingcomputer.com/news/security/cyberattack-on-it-provider-cts-impacts-dozens-of-uk-law-firms/  
  
  
汽车零部件巨头
AutoZone 的 185,000 人受到 MOVEit 黑客攻击的影响  
  
https://www.securityweek.com/185000-individuals-impacted-by-moveit-hack-at-car-parts-giant-autozone/  
  
  
新的“InfectedSlurs”僵尸网络利用两个  
0  
Day  
漏洞感染网络监控摄像头（NVR） 和路由器  
  
https://www.bleepingcomputer.com/news/security/new-botnet-malware-exploits-two-zero-days-to-infect-nvrs-and-routers/  
  
  
网络攻击泄露了
27,000 名纽约市律师协会成员的数据  
  
https://therecord.media/cyberattack-leaked-data-nyc-bar  
  
  
堪萨斯州官员将法院系统五周的中断归咎于勒索软件攻击  
  
https://www.bleepingcomputer.com/news/security/kansas-courts-confirm-data-theft-ransom-demand-after-cyberattack/  
  
  
美国医疗保健
SaaS 服务提供商Welltok 遭到黑客攻击，850 万美国患者数据泄露  
  
https://www.bleepingcomputer.com/news/security/welltok-data-breach-exposes-data-of-85-million-us-patients/  
  
  
黑客创建虚假银行应用程序来窃取印度用户的财务数据  
  
https://therecord.media/hackers-create-fake-banking-apps-targeting-indian-users  
  
  
DarkGate 和
Pikabot 恶意软件成为 Qakbot 的继任者  
  
https://www.bleepingcomputer.com/news/security/darkgate-and-pikabot-malware-emerge-as-qakbots-successors/  
  
  
MacOS 成为
ClearFake 恶意软件活动的目标  
  
https://cybernews.com/security/clearfake-malware-mac-os-targeted/  
  
  
多个政府机构和网络安全组织已针对多个利用
Citrix Bleed 的攻击发出警报  
  
https://www.infosecurity-magazine.com/news/lockbit-affiliates-exploit-citrix/  
  
  
美国网络警察打击“杀猪盘”诈骗，返还
900 万美元的受害者加密货币资产  
  
https://www.theregister.com/2023/11/22/us_cybercops_take_on_pig/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
3 个严重漏洞使
ownCloud 用户面临数据泄露风险  
  
https://thehackernews.com/2023/11/warning-3-critical-vulnerabilities.html  
  
  
CISA
命令联邦机构修补 Looney Tunables Linux 漏洞  
  
https://www.bleepingcomputer.com/news/security/cisa-orders-federal-agencies-to-patch-looney-tunables-linux-bug/  
  
  
流行笔记本电脑上的
Windows Hello 指纹验证被绕过  
  
https://www.securityweek.com/windows-hello-fingerprint-authentication-bypassed-on-popular-laptops/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
