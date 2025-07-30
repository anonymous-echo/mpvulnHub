#  与俄罗斯有关的 TAG-110 组织利用 HATVIBE 和 CHERRYSPY 瞄准亚洲和欧洲   
会杀毒的单反狗  军哥网络安全读报   2024-11-22 01:01  
  
**导****读**  
  
  
  
I  
nsikt Group 研究人员发现，俄罗斯正在开展一项网络间谍活动，该活动使用定制恶意软件，针对中亚、东亚和欧洲的人权组织、私人保安公司以及国家和教育机构。  
  
  
这些攻击被归咎于一个被追踪为 TAG-110 的威胁组织。  
  
  
根据 Recorded Future 旗下 Insikt Group 的一份报告，该行为者可能与俄罗斯网络间谍组织 BlueDelta（也称为 APT28 或 Fancy Bear）有关。TAG-110 是一个与俄罗斯结盟的威胁组织，其目标是中亚、东亚和欧洲的组织。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHmKXz18BW4rla1ZNW84oVwIFIr3u1r2ursqDibYGlrSQpze99wVj3XChxyT6pBVoPZfbVeXuOe0Ug/640?wx_fmt=png&from=appmsg "")  
  
  
自今年 7 月以来，Insikt Group 已发现 60 多名 TAG-110 受害者，主要分布在塔吉克斯坦、吉尔吉斯斯坦、土库曼斯坦和哈萨克斯坦。他们感染了该组织的自定义恶意软件，包括Hatvibe加载程序和Cherryspy后门。  
  
  
Insikt Group 表示，为了将这些工具传送到目标系统，该组织使用了恶意 Microsoft Word 电子邮件附件并利用了易受攻击的面向 Web 的服务。  
  
  
TAG-110 使用自定义恶意软件工具 HATVIBE 和 CHERRYSPY，主要攻击政府实体、人权组织和教育机构。该活动的策略与 UAC-0063 的历史活动一致，后者归因于俄罗斯 APT 组织 BlueDelta (APT28)。  
  
  
HATVIBE 充当加载器来部署 CHERRYSPY，CHERRYSPY 是一个用于数据泄露和间谍活动的 Python 后门。初始访问通常是通过网络钓鱼电子邮件或利用易受攻击的面向 Web 的服务（如 Rejetto HTTP 文件服务器）来实现的。  
  
  
Insikt Group 的报告称，TAG-110 据称自 2021 年以来一直在为俄罗斯政府从事间谍活动，主要针对中亚实体。该组织还针对印度、以色列、蒙古和乌克兰的受害者。研究人员预计，TAG-110 的活动将在短期内持续下去，重点可能是后苏联中亚国家、乌克兰及其盟友。  
  
### 主要发现  
  
  
TAG-110 是一个与 UAC-0063 重叠的威胁组织，有中等信心与俄罗斯 APT 组织 BlueDelta (APT28) 有联系。  
  
  
目标：中亚和邻近地区的政府、人权组织和教育机构。  
  
  
使用的恶意软件：HATVIBE（自定义 HTML 应用程序加载器）和 CHERRYSPY（基于 Python 的后门）是该活动的核心。  
  
  
影响规模：自 2024 年 7 月以来，已确定 11 个国家的 62 名受害者，其中哈萨克斯坦、吉尔吉斯斯坦和乌兹别克斯坦发生了重大事件。  
  
### HATVIBE  
  
  
HATVIBE 可充当 CHERRYSPY 等其他恶意软件的加载器。它通过恶意电子邮件附件或利用面向 Web 的漏洞进行传播，并通过 mshta.exe 实用程序执行的计划任务实现持久性。  
  
  
HATVIBE 的混淆技术包括 VBScript 编码和 XOR 加密。部署后，它会使用 HTTP PUT 请求与命令和控制 (C2) 服务器通信，提供关键的系统详细信息。  
  
### CHERRYSPY  
  
  
CHERRYSPY 是一款基于 Python 的后门程序，它通过实现安全的数据泄露来补充 HATVIBE。它使用强大的加密方法（包括 RSA 和高级加密标准 (AES)）与其 C2 服务器建立通信。  
  
  
TAG-110 使用 CHERRYSPY 来监视受害者的系统并提取敏感信息，通常针对政府和研究机构。  
  
  
完整报告：  
https://go.recordedfuture.com/hubfs/reports/CTA-RU-2024-1121.pdf  
  
  
**新闻链接：**  
  
https://therecord.media/central-asia-cyber-espionage-tag-110-russia  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
与俄罗斯有关的
TAG-110 组织利用 HATVIBE 和 CHERRYSPY 瞄准亚洲和欧洲  
  
https://www.recordedfuture.com/research/russia-aligned-tag-110-targets-asia-and-europe  
  
  
Gelsemium
组织利用新的 WolfsBane 后门攻击 Linux 系统  
  
https://thehackernews.com/2024/11/chinese-apt-gelsemium-targets-linux.html  
  
  
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
  
  
黑客利用
T-Mobile 和其他美国电信公司开展间谍活动  
  
https://thehackernews.com/2024/11/chinese-hackers-exploit-t-mobile-and.html  
  
  
黑客利用
SIGTRAN、GSM 协议渗透电信网络  
  
https://thehackernews.com/2024/11/china-backed-hackers-leverage-sigtran.html  
  
  
FrostyGoop
的放大：仔细观察恶意软件工件、行为和网络通信  
  
https://unit42.paloaltonetworks.com/frostygoop-malware-analysis/  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
金融软件公司
Finastra 正在调查数据泄露事件  
  
https://www.securityweek.com/financial-software-firm-finastra-investigating-data-breach/  
  
  
法国医院遭受网络攻击，75
万名患者健康数据遭泄露  
  
https://www.bleepingcomputer.com/news/security/cyberattack-at-french-hospital-exposes-health-data-of-750-000-patients/  
  
  
微软查获埃及网络钓鱼服务行动“ONNX”使用的
240 个网站  
  
https://therecord.media/microsoft-seizes-websites-onnx-phishing  
  
  
FBI 称
BianLian 总部位于俄罗斯，从勒索软件攻击转向敲诈勒索  
  
https://therecord.media/fbi-says-bianlian-based-in-russia-switching-tactics  
  
  
美国最大的博彩公司遭遇网络攻击，正在努力恢复系统  
  
https://therecord.media/gambling-lottery-giant-hit-with-disruptive-cyberattack  
  
  
Ransomhub
勒索软件团伙声称对墨西哥政府法律事务办公室发起攻击  
  
https://securityaffairs.com/171257/data-breach/mexico-suffers-ransomware-attack.html  
  
  
墨西哥政府调查该国法律事务办公室遭勒索软件攻击的事件  
  
https://www.securityweek.com/mexicos-president-says-government-is-investigating-reported-ransomware-hack-of-legal-affairs-office/  
  
  
145,000
个工业系统暴露在网络上，许多工业公司受到攻击  
  
https://www.securityweek.com/ics-security-145000-systems-exposed-to-web-many-industrial-firms-hit-by-attacks/  
  
  
2,000 个
Palo Alto 防火墙因新漏洞而遭入侵  
  
https://www.securityweek.com/2000-palo-alto-firewalls-compromised-via-new-vulnerabilities/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Ubuntu Needrestart 软件包中发现存在十年之久的安全漏洞，攻击者可以获得  
Root  
权限  
  
https://thehackernews.com/2024/11/decades-old-security-vulnerabilities.html  
  
  
谷歌的 AI
OSS-Fuzz 工具在开源项目中发现了 26 个漏洞  
  
https://thehackernews.com/2024/11/googles-ai-powered-oss-fuzz-tool-finds.html  
  
  
MITRE 更新
25 个最危险软件漏洞列表  
  
https://www.securityweek.com/mitre-updates-list-of-25-most-dangerous-software-vulnerabilities/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
