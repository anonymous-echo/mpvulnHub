#  新的 Mirai 僵尸网络利用0day漏洞攻击工业路由器   
会杀毒的单反狗  军哥网络安全读报   2025-01-08 01:00  
  
**导****读**  
  
  
  
一个相对较新的基于 Mirai 的僵尸网络日益复杂，现在正在利用  
0day  
漏洞攻击工业路由器和智能家居设备的安全漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGeUJJibz7bmVC0EdPYhibhEakv82iaua8oOpAViarhoplbVyUCcGEIctHMdCbdDBbJgicYVsYkqZjEyvw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
据监测僵尸网络发展和攻击情况的奇安信 X Lab 研究人员称，对以前未知的漏洞的利用始于 2024 年 11 月。  
  
  
其中一个安全问题是 CVE-2024-12856，这是 Four-Faith 工业路由器中的一个漏洞，VulnCheck 于 12 月下旬发现该漏洞，但在 12 月 20 日左右注意到有人试图利用该漏洞。  
  
  
利用  
0day  
漏洞的手段包括利用 CVE-2024-12856   
0day  
漏洞，影响 Four-Faith 路由器，以及利用 Neterbit 路由器和 Vimar 智能家居设备漏洞的其他自定义漏洞。  
  
### 僵尸网络概况  
###   
  
该僵尸网络在去年 2 月被发现的，目前每天有 15,000 个活跃的机器人节点，主要位于中国、美国、俄罗斯、土耳其和伊朗。  
  
  
其主要目标似乎是针对指定目标进行分布式拒绝服务 (DDoS) 攻击以牟利，每天针对数百个实体，活动在 2024 年 10 月和 11 月达到高峰。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGeUJJibz7bmVC0EdPYhibhEamQBLiaxVIn2GowoE8RcrSwTP1icG9qhMtZ4o4g49svnfN0ficvvZEuJVA/640?wx_fmt=png&from=appmsg "")  
  
目标国家分布，来源：X Lab  
  
  
该恶意软件利用超过 20 个漏洞的公共和私人漏洞，传播到互联网暴露的设备，目标是 DVR、工业和家用路由器以及智能家居设备。  
  
  
具体目标包括：  
  
华硕路由器（通过 N-day 漏洞）。  
  
某为路由器（来自 CVE-2017-17215）  
  
Neterbit 路由器（自定义漏洞）  
  
LB-Link 路由器（来自 CVE-2023-26801）  
  
Four-Faith 工业路由器（通过  
0day  
漏洞 CVE-2024-12856 发起攻击）  
  
PZT 相机（通过 CVE-2024-8956 和 CVE-2024-8957）  
  
凯卫数字视频录像机  
  
Lilin DVR（通过远程代码执行漏洞）  
  
通用 DVR（使用 TVT editBlackAndWhiteList RCE 等漏洞）  
  
Vimar 智能家居设备（可能利用了未公开的漏洞）  
  
各种 5G/LTE 设备（可能由于配置错误或凭证薄弱）  
  
  
该僵尸网络具有针对弱 Telnet 密码的暴力破解模块，使用具有独特签名的自定义 UPX 打包，并实现基于 Mirai 的命令结构来更新客户端、扫描网络和进行 DDoS 攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGeUJJibz7bmVC0EdPYhibhEavkX5YRZJpK44ps9AkWGyIafHwMUGibj1kBYEhCN1AQ1gcqDWib0Px5MA/640?wx_fmt=png&from=appmsg "")  
  
僵尸网络攻击量，来源：X Lab  
  
  
X Lab 报告称，僵尸网络的 DDoS 攻击持续时间短，仅持续 10 到 30 秒，但强度高，流量超过 100 Gbps，即使对于强大的基础设施也会造成破坏。  
  
  
“攻击目标遍布全球，分布于各个行业。” 奇安信  
X Lab研究人员称：“主要攻击目标分布在中国、美国、德国、英国和新加坡。”  
  
  
总体而言，僵尸网络展示出一种独特的能力，可以利用 n-day 甚至  
0day  
漏洞在不同类型的设备中维持高感染率。  
  
  
用户可以按照一般建议来保护他们的设备，安装供应商提供的最新设备更新，在不需要时禁用远程访问，并更改默认管理员帐户凭据。  
  
  
技术报告：  
  
https://blog.xlab.qianxin.com/gayfemboy/  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/new-mirai-botnet-targets-industrial-routers-with-zero-day-exploits/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
卡巴斯基报告：Eagerbee 后门针对中东政府机构和 ISP  
  
https://www.bleepingcomputer.com/news/security/eagerbee-backdoor-deployed-against-middle-eastern-govt-orgs-isps/  
  
  
伊朗和俄罗斯实体因利用人工智能和网络战术干预选举而受到制裁  
  
https://thehackernews.com/2025/01/iranian-and-russian-entities-sanctioned.html  
  
  
美国财政部远程支持平台遭到入侵  
  
https://www.bleepingcomputer.com/news/security/us-treasury-department-breached-through-remote-support-platform/  
  
  
乌克兰国家登记处遭受网络攻击，婚姻登记和房地产交易中断  
  
https://therecord.media/cyberattack-on-ukraine-state-register-disrupts-real-estate-marriages  
  
  
Cloud Atlas 部署 VBCloud 恶意软件：超过 80% 的目标位于俄罗斯  
  
https://thehackernews.com/2024/12/cloud-atlas-deploys-vbcloud-malware.html  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
车牌读取器正在泄露实时视频和车辆数据  
  
https://www.wired.com/story/license-plate-reader-live-video-data-exposed/  
  
  
卡西欧称 10 月份勒索软件攻击中 8500 人的数据被泄露  
  
https://www.bleepingcomputer.com/news/security/casio-says-data-of-8-500-people-exposed-in-october-ransomware-attack/  
  
  
2024 年，钱包窃取恶意软件窃取了价值 5 亿美元的加密货币  
  
https://www.securityweek.com/wallet-drainer-malware-used-to-steal-500-million-in-cryptocurrency-in-2024/  
  
  
新的 Mirai 僵尸网络利用  
0day  
漏洞攻击工业路由器  
  
https://www.bleepingcomputer.com/news/security/new-mirai-botnet-targets-industrial-routers-with-zero-day-exploits/  
  
  
2024 年，钱包窃取恶意软件窃取了价值 5 亿美元的加密货币  
  
https://www.securityweek.com/wallet-drainer-malware-used-to-steal-500-million-in-cryptocurrency-in-2024/  
  
  
Tenable 因错误更新而禁用 Nessus 代理  
  
https://www.securityweek.com/tenable-disables-nessus-agents-over-faulty-updates/  
  
  
黑客入侵了阿根廷机场安全部门的工资系统  
  
https://therecord.media/hackers-target-airport-security-payroll  
  
  
俄罗斯论坛上的新 PhishWP 插件将网站变成钓鱼页面  
  
https://hackread.com/phishwp-plugin-russian-hacker-forum-phishing-sites/  
  
  
特斯拉在拉斯维加斯爆炸事件中共享数据意味着什么  
  
https://www.securityweek.com/is-your-car-spying-on-you-what-it-means-that-tesla-shared-data-in-the-las-vegas-explosion/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
BIOS 缺陷使 iSeq DNA 测序仪面临 bootkit 攻击  
  
https://www.bleepingcomputer.com/news/security/bios-flaws-expose-iseq-dna-sequencers-to-bootkit-attacks/  
  
  
戴尔、HPE、联发科修补其产品中的漏洞  
  
https://www.securityweek.com/dell-hpe-mediatek-patch-vulnerabilities-in-their-products/  
  
  
CISA 警告称，Oracle 和 Mitel 存在严重漏洞，可能被利用进行攻击  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-of-critical-oracle-mitel-flaws-exploited-in-attacks/  
  
  
易受攻击的 Moxa 设备使工业网络面临攻击  
  
https://www.bleepingcomputer.com/news/security/vulnerable-moxa-devices-expose-industrial-networks-to-attacks/  
  
  
Nuclei 漏洞扫描程序中发现代码执行缺陷  
  
https://www.securityweek.com/code-execution-flaw-found-in-nuclei-vulnerability-scanner/  
  
  
不安全的物联网云再次来袭：Reyee  
平台连接设备遭 RCE 攻击  
  
https://claroty.com/team82/research/the-insecure-iot-cloud-strikes-again-rce-on-ruijie-cloud-connected-devices  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
