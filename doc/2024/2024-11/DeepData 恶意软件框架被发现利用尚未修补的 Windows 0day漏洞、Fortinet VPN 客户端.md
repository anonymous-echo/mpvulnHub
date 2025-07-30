#  DeepData 恶意软件框架被发现利用尚未修补的 Windows 0day漏洞、Fortinet VPN 客户端   
会杀毒的单反狗  军哥网络安全读报   2024-11-19 01:00  
  
**导****读**  
  
  
  
网络安全公司
Volexity 报告称，DeepData 恶意软件框架被发现利用 Windows 版 Fortinet VPN 客户端中的0day漏洞窃取凭证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaH1t3Y4vrlAxr0bs4z6WflxV8GzOFzfJCNT3l5ujJficzGIVBI1oHOfOPib9uHyrFafvahyZRVPvHVA/640?wx_fmt=png&from=appmsg "")  
  
  
DeepData
是一个依赖多个插件的监控框架，它针对存储在浏览器、通信应用程序和密码管理器中的敏感信息，并可以使用系统的麦克风录制音频。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaH1t3Y4vrlAxr0bs4z6WflxN0DQ2kiaGr31JyuTJ42BoKgHRjhwYlVzaBPXkthdTQGVLtguhftN8pg/640?wx_fmt=jpeg "")  
  
DEEPDATA的加载器、核心和插件的架构  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaH1t3Y4vrlAxr0bs4z6Wflxk28HlMqH1Z73vVTsfW4Rky8I4Tlpux761MojXWcBj2s8pib4yw4ibJBw/640?wx_fmt=png&from=appmsg "")  
  
执行链  
  
  
据黑莓称，DeepData
和LightSpy iOS 恶意软件均被高级持续性威胁 (APT) 组织 APT41 用于监视东南亚目标。  
  
  
周五，Volexity 透露，DeepData 被发现利用0day漏洞攻击 Fortinet 的 Windows VPN 客户端，从进程内存中提取用户名、密码和其他信息。  
  
  
该网络安全公司表示，该漏洞于
7 月份报告给 Fortinet，当时已确认会影响当时最新版本的 Fortinet VPN。该漏洞没有 CVE 标识符，且似乎仍未得到修补。  
  
  
SecurityWeek已通过电子邮件向
Fortinet 索要有关此事的声明，并将在收到回复后立即更新本文。  
  
  
Volexity 还指出，DeepData 框架是由 BrazenBamboo APT开发的，该组织还创建了 LightSpy 和 DeepPost 后利用数据泄露工具。  
  
  
该网络安全公司发现
DeepData 和 LightSpy 之间存在相似之处，包括插件文件和函数名称、共享程序数据库开发路径、某些 JSON
文件的共享格式、类似的插件代码执行缺陷以及基础设施重叠。  
  
  
“Volexity
认为 BrazenBamboo 是这些恶意软件系列的开发者，但不一定是使用这些恶意软件的运营商之一（可能有很多）。Volexity 还发现了 LightSpy
的新 Windows 变体，在撰写本文时尚未记录在案。”Volexity 表示。  
  
  
该网络安全公司还提请注意
LightSpy 恶意软件的 Windows 变体，该变体与已知的 iOS、Android 和 macOS 变体一起用于攻击，并指出Lookout
去年详细介绍的DragonEgg Android 间谍软件实际上就是 LightSpy。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaH1t3Y4vrlAxr0bs4z6WflxmEmXYnZUiapjKRX9pib0yohYak4oicBy2NOI93Dv9qTicoa4IX0ImavrGA/640?wx_fmt=png&from=appmsg "")  
  
  
该间谍软件的
Windows 变体与其他记录的版本具有不同的架构，由内存中的 shellcode 执行，使用 WebSocket 和 HTTPS
进行通信，并由编排器和插件组成。  
  
  
该恶意软件的大部分代码都在内存中执行，所观察到的插件具有与之前与
LightSpy 相同的数据收集和用户监视功能。  
  
  
Volexity
发现了大约 30 个托管 DeepData 和 LightSpy 的命令和控制 (C&C) 服务器，以及 BrazenBamboo
用于托管与这些恶意软件家族无直接关联的其他工具和应用程序的其他基础设施。  
  
  
“Volexity 的分析表明，BrazenBamboo 是一个资源丰富的APT组织，拥有多平台能力，并且能够长期运营。其能力的广度和成熟度表明其开发功能强大，运营需求推动了开发产出。”该网络安全公司指出。  
  
  
技术报告：  
- https://blogs.blackberry.com/en/2024/04/lightspy-returns-renewed-espionage-campaign-targets-southern-asia-possibly-india  
  
- https://www.volexity.com/blog/2024/11/15/brazenbamboo-weaponizes-forticlient-vulnerability-to-steal-vpn-credentials-via-deepdata/  
  
- https://www.threatfabric.com/blogs/lightspy-implant-for-ios  
  
- https://www.lookout.com/threat-intelligence/article/wyrmspy-dragonegg-surveillanceware-apt41  
  
****  
**新闻链接：**  
  
https://www.securityweek.com/fortinet-vpn-zero-day-exploited-in-malware-attacks-remains-unpatched-report/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
WhatsApp
的诉讼文件中详细记录了 1,400 起 Pegasus 间谍软件感染事件  
  
https://therecord.media/pegasus-spyware-infections-detailed-whatsapp-lawsuit  
  
  
匈牙利确认国防采购机构遭黑客攻击  
  
https://therecord.media/hungary-defense-procurement-agency-hacked  
  
  
BrazenBamboo
APT 利用 FortiClient 零日漏洞窃取用户凭证  
  
https://cybersecuritynews.com/brazenbamboo-apt-forticlient-zero-day/  
  
  
APT 组织
DONOT 对巴基斯坦海事和国防工业发起网络攻击  
  
https://thecyberexpress.com/apt-group-donot-targets-pakistan/  
  
  
D  
eepData
恶意软件框架被发现利用尚未修补的 Windows 0day漏洞 Fortinet VPN 客户端  
  
https://www.securityweek.com/fortinet-vpn-zero-day-exploited-in-malware-attacks-remains-unpatched-report/  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
俄克拉荷马医疗中心遭勒索软件攻击，影响
133,000 人  
  
https://www.securityweek.com/ransomware-attack-on-oklahoma-medical-center-impacts-133000/  
  
  
美国联合药房据称遭
Embargo 勒索软件攻击  
  
https://www.scworld.com/brief/american-associated-pharmacies-allegedly-breached-by-embargo-ransomware-1  
  
  
2024
年医疗保健行业遭遇 264 次勒索软件攻击  
  
https://www.medicalbuyer.co.in/healthcare-sector-witnesses-264-ransomware-attacks-in-2024/  
  
  
Facebook
上的虚假 Bitwarden 广告推送窃取信息的 Chrome 扩展程序  
  
https://www.bleepingcomputer.com/news/security/fake-bitwarden-ads-on-facebook-push-info-stealing-chrome-extension/  
  
  
美国国会图书馆称黑客入侵部分电子邮件  
  
https://www.securityweek.com/library-of-congress-says-an-adversary-hacked-some-emails/  
  
  
英国软件公司
Microlise 证实黑客窃取了公司数据  
  
https://therecord.media/microlise-british-software-company-data-breach  
  
  
瑞士网络机构警告称恶意软件正通过邮政快递传播  
  
https://therecord.media/malware-delivered-by-mail-swiss-cyber-agency  
  
  
网络钓鱼电子邮件越来越多地使用
SVG 附件来逃避检测  
  
https://www.bleepingcomputer.com/news/security/phishing-emails-increasingly-use-svg-attachments-to-evade-detection/  
  
  
美国政府机构遭
DocuSign 恶意网络钓鱼诈骗  
  
https://hackread.com/us-govt-agencies-impersonate-docusign-phishing-scams/  
  
  
网络犯罪分子利用
Strela Stealer 恶意软件瞄准西班牙、德国和乌克兰受害者  
  
https://therecord.media/cybercriminals-taget-spain-germany-ukraine-strela-stealer-malware  
  
  
新型隐秘恶意软件
BabbleLoader 可传播 WhiteSnake 和 Meduza 信息窃取程序  
  
https://thehackernews.com/2024/11/new-stealthy-babbleloader-malware.html  
  
  
网络钓鱼攻击利用
Microsoft Visio 文件和 SharePoint  
  
https://blog.knowbe4.com/phishing-attacks-exploit-microsoft-visio-files  
  
  
美国太空科技巨头
Maxar 披露员工数据泄露事件  
  
https://www.bleepingcomputer.com/news/security/us-space-tech-giant-maxar-discloses-employee-data-breach/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
VMware
披露难以修复的 vCenter Server 漏洞利用情况  
  
https://www.securityweek.com/vmware-discloses-exploitation-of-hard-to-fix-vcenter-server-flaw/  
  
  
影响五种已停产的
GeoVision 产品型号的0day漏洞(CVE-2024-11120,CVSS 评分为 9.8）)已被僵尸网络利用  
  
https://www.securityweek.com/discontinued-geovision-products-targeted-in-botnet-attacks-via-zero-day/  
  
  
WordPress
插件严重漏洞导致超过 400 万个网站暴露  
  
https://thehackernews.com/2024/11/urgent-critical-wordpress-plugin.html  
  
  
Palo Alto Networks 发布了利用新发现的防火墙  
0day  
漏洞发起攻击的 IoC  
  
https://www.securityweek.com/palo-alto-networks-releases-iocs-for-new-firewall-zero-day/  
  
  
美国环保署指出，为大约
1.1 亿人提供服务的 300 多个饮用水系统存在安全漏洞  
  
https://www.securityweek.com/300-drinking-water-systems-in-us-exposed-to-disruptive-damaging-hacker-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
