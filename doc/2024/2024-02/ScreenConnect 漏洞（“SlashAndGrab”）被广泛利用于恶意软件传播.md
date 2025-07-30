#  ScreenConnect 漏洞（“SlashAndGrab”）被广泛利用于恶意软件传播   
 军哥网络安全读报   2024-02-24 09:00  
  
**导****读**  
  
  
  
影响
ConnectWise 的 ScreenConnect 远程桌面访问产品的严重漏洞已被广泛利用来传播勒索软件和其他类型的恶意软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHfphlg2fibCW8smA0ROQy81LNckgtnnT4Q6Z8H4IEPKPfO5jhLQykP4V7TzuHOhXzoNKZIFRibvVyQ/640?wx_fmt=png&from=appmsg "")  
  
  
ConnectWise
于 2 月 19 日通知客户，它已发布针对关键身份验证绕过缺陷和高严重性路径遍历问题的补丁。该安全漏洞当时没有 CVE 标识符。  
  
  
第二天，该公司警告说，它已经意识到野外的利用企图。  
  
  
CVE
标识符现已分配给这两个漏洞：CVE-2024-1709 为身份验证绕过漏洞，CVE-2024-1708 为路径遍历漏洞。  
  
  
威胁检测和响应公司
Huntress（将这些缺陷称为SlashAndGrab）在概念验证 (PoC) 漏洞利用已经可用后，于 2 月 21 日披露了技术细节。  
   
  
  
身份验证绕过漏洞允许攻击者创建具有管理员权限的新帐户。然后可以利用路径遍历来执行任意代码。  
  
  
有几份报告表明
CVE-2024-1709 被广泛利用，但尚不清楚 CVE-2024-1708 是否也被利用。  
  
  
Huntress报告称，看到
SlashAndGrab 被利用来传播 LockBit 勒索软件、Cobalt Strike、SSH 隧道、远程管理工具和加密  
  
货币挖矿程序。该公司确定的受害者包括地方政府、应急系统和医疗机构。  
  
  
Sophos
还报告称看到了LockBit 勒索软件的传播，考虑到该网络犯罪企业最近成为了一场极具破坏性的执法行动的目标，这一点很有趣。  
  
  
Sophos
表示：“尽管针对 LockBit 采取了执法行动，但一些附属机构似乎仍在运行。”  
  
  
该网络安全公司还发现通过利用
ScreenConnect 漏洞传播 AsyncRAT、各种信息窃取程序和 SimpleHelp 远程访问软件。  
  
  
非营利网络安全组织
Shadowserver 基金会报告称，截至 2 月 21 日，已发现超过8,200 个暴露于互联网且易受攻击的ScreenConnect
实例。易受攻击实例的比例最高的是美国，其次是加拿大和英国。  
  
  
Shadowserver
表示：“CVE-2024-1709 在野外被广泛利用——迄今为止，我们的传感器已发现 643 个 IP 受到攻击。”  
  
  
CISA 已将
CVE-2024-1709 添加到其已知被利用的漏洞目录中，并指出该机构已意识到勒索软件攻击中的利用情况。  
  
  
**参考链接：**  
https://www.securityweek.com/slashandgrab-screenconnect-vulnerability-widely-exploited-for-malware-delivery/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
欧洲议会国防小组委员会电话显示黑客攻击  
“  
痕迹  
”  
  
https://therecord.media/europe-parliament-phones-traces-hacking  
  
  
俄罗斯 Turla
网络间谍利用新后门瞄准波兰非政府组织  
  
https://www.securityweek.com/russian-turla-cyberspies-target-polish-ngos-with-new-backdoor/  
  
  
卡巴斯基称黑客组织ROOTK1T针对穆斯林国家  
  
https://www.nst.com.my/news/nation/2024/02/1016161/hacker-group-rootk1t-targeting-muslim-countries-says-kaspersky  
  
  
APT 组织
Mustang Panda 通过名为 DOPLUGS 的 PlugX（又名 Korplug）后门变体瞄准多个亚洲目标  
  
https://securityaffairs.com/159464/apt/mustang-panda-doplugs-backdoor.html  
  
  
Zardoor
后门警报：威胁行为者瞄准伊斯兰慈善机构  
  
https://securityboulevard.com/2024/02/zardoor-backdoor-alert-threat-actors-target-islamic-charity/  
  
  
俄罗斯政府软件被部署
Konni RAT 恶意软件后门  
  
https://thehackernews.com/2024/02/russian-government-software-backdoored.html  
  
  
与俄罗斯有关的信息运动旨在在乌克兰人中“散布怀疑”  
  
https://therecord.media/information-campaign-aimed-at-ukrainians-sow-doubt  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
LockBit
被取缔：警方关闭了 Mega、Tutanota 和 Protonmail 上的 14,000 多个账户  
  
https://therecord.media/lockbit-ransomware-takedown-mega-tutanota-protonmail  
  
  
AT&T
表示其美国手机网络中断并非由网络攻击造成  
  
https://www.securityweek.com/att-says-the-outage-to-its-us-cellphone-network-was-not-caused-by-a-cyberattack/  
  
  
德国电池制造商Varta
的工厂在网络攻击两周后生产仍处于暂停状态  
  
https://therecord.media/varta-battery-plant-production-on-hold-after-cyberattack  
  
  
微软发布用于生成人工智能的红队工具  
  
https://www.securityweek.com/microsoft-releases-red-teaming-tool-for-generative-ai/  
  
  
澳大利亚电信运营商
Telco Tangerine数据泄露，23 万人受影响  
  
https://www.securityweek.com/230k-individuals-impacted-by-data-breach-at-australian-telco-tangerine/  
  
  
卡巴斯基报告：三分之一的菲律宾人面临恶意
USB 设备的威胁  
  
https://www.noypigeeks.com/spotlight/filipinos-risk-malicious-usb/  
  
  
索尼子公司Insomniac
Games 提醒员工遭受勒索软件数据泄露事件影响  
  
https://www.bleepingcomputer.com/news/security/insomniac-games-alerts-employees-hit-by-ransomware-data-breach/  
  
  
LockBit
勒索软件团伙拥有超过 1.1 亿美元未使用的比特币  
  
https://www.bleepingcomputer.com/news/security/lockbit-ransomware-gang-has-over-110-million-in-unspent-bitcoin/  
  
  
休眠的 PyPI
软件包受到感染，可传播 Nova Sentinel 恶意软件  
  
https://thehackernews.com/2024/02/dormant-pypi-package-compromised-to.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
新的 WiFi
漏洞允许攻击者伪造热点并拦截数据  
  
https://cybernews.com/security/wifi-vulnerabilities-allow-attackers-overtake-networks/  
  
  
Apple
Shortcuts 漏洞暴露敏感信息  
  
https://www.securityweek.com/apple-shortcuts-vulnerability-exposes-sensitive-information/  
  
  
研究人员详细介绍了苹果最近的零点击快捷方式漏洞（CVE-2024-23204）  
  
https://thehackernews.com/2024/02/researchers-detail-apples-recent-zero.html  
  
  
ScreenConnect
漏洞（“SlashAndGrab”）被广泛利用于恶意软件传播  
  
https://www.securityweek.com/slashandgrab-screenconnect-vulnerability-widely-exploited-for-malware-delivery/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
