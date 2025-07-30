#  不明黑客利用0day漏洞对 Palo Alto Networks 防火墙进行后门攻击   
会杀毒的单反狗  军哥网络安全读报   2024-04-13 09:00  
  
**导****读**  
  
  
  
Volexity 安全研究人员警告说，疑似国家背景的不明黑客组织已成功利用 Palo Alto Networks 防火墙中的  
0day  
漏洞已有两周多的时间。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGX94qmLTMQwybibQF8RgdR2xelXEnVXmkhqj9y3B1eq5t9tx5mibhyE0zo9fNFRsxCge69icFzEE0ZA/640?wx_fmt=png&from=appmsg "")  
  
Palo Alto
Networks于周五披露了该漏洞（  
https://security.paloaltonetworks.com/CVE-2024-3400），警告称其已意识到有限的野外利用情况，并承诺在未来两天内提供补丁。  
  
  
该安全缺陷被追踪为CVE-2024-3400（CVSS
评分为 10/10），被描述为命令注入问题，允许未经身份验证的攻击者以 root 权限在受影响的防火墙上执行任意代码。  
  
  
据供应商称，所有运行
PAN-OS 版本 10.2、11.0 和 11.1 且启用了 GlobalProtect 网关和设备遥测的设备都容易受到攻击。其他 PAN-OS
版本、云防火墙、Panorama 设备和 Prisma Access 不受影响。  
  
  
“Palo Alto
Networks 已意识到有人恶意利用此问题。我们正在以“MidnightEclipse
行动”的名义跟踪此漏洞的初始利用，因为我们非常有信心地评估，迄今为止我们分析的已知利用仅限于单个攻击者。”该公司在博客文章（  
https://unit42.paloaltonetworks.com/cve-2024-3400/）中表示。  
  
  
Volexity
将CVE-2024-3400
漏洞归因于一个有国家背景的黑客，追踪编号为“UTA0218”，攻击者似乎能力很强，“有一个明确的剧本，说明如何进一步实现其目标”  
。  
  
  
“Volexity
评估认为，根据开发和利用此类性质的漏洞所需的资源、攻击者针对的受害者类型以及安装 Python 后门和所显示的功能，UTA0218
很可能是国家支持的黑客组织，意图进一步访问受害者网络。”该网络安全公司（  
https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/）指出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGX94qmLTMQwybibQF8RgdR2WOoT4oArFibsB5SeiaS8Us9hRtY4uuEeic6hXokoWRSjjw8dwZrgchZTg/640?wx_fmt=png&from=appmsg "")  
  
该公司目前无法将该活动与先前已知的黑客组织联系起来。  
  
  
目前尚不清楚这种利用的范围有多广泛，但
Volexity 表示，“有证据表明，潜在的侦察活动涉及更广泛的利用，旨在识别易受攻击的系统”。  
  
  
该网络安全公司表示，自 3 月 26 日以来，UTA0218 已成功利用  
0day  
漏洞攻击多个组织。在两个实例中，攻击者还注入了一个名为 Upstyle 的基于 Python 的后门，并用它来执行其他命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGX94qmLTMQwybibQF8RgdR2YxxxkSzOpfwTWfwhGVn6TDvCI1QSdWuS4z58NniaiatPQiahic0lQKKM4g/640?wx_fmt=png&from=appmsg "")  
  
  
“成功利用设备后，UTA0218
从他们控制的远程服务器下载了额外的工具，以便于访问受害者的内部网络。他们迅速在受害者的网络中横向移动，提取敏感凭证和其他文件，以便在入侵期间和之后可能进行访问。”Volexity
解释道。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGX94qmLTMQwybibQF8RgdR2RttEBuI77ibpU3fuhJXQCjnGYIGnmyEfCQwyafnsZEZibLy6GCk73s4g/640?wx_fmt=png&from=appmsg "")  
  
攻击链  
  
  
研究人员发现攻击在防火墙上创建了一个
cron 作业，以持续从远程服务器获取文件并执行其内容。我们看到攻击者手动管理命令与控制 (C&C)
服务器的访问控制列表，以确保只能从与其通信的设备进行访问。  
  
  
还观察到
UTA0218 部署了用 Python 编写的反向 shell 和开源 SSH 反向 shell，下载 GOST（GO Simple
Tunnel）等反向代理工具，并从受感染的防火墙中窃取配置数据。  
  
  
在一次攻击中，攻击者使用帕洛阿尔托网络防火墙的高特权服务帐户通过
SMB 和 WinRM 横向移动。随后，UTA0218 窃取了 Active Directory 数据库、关键数据、Windows
事件日志、登录信息、cookie 和浏览器数据，并能够解密存储的凭据。  
  
  
“没有观察到
UTA0218
在受害者网络内的系统上部署恶意软件或其他持久性方法。被盗的数据确实使攻击者能够有效地破坏所有域帐户的凭据。此外，攻击者获得了访问权限，并可能使用从浏览器数据中获取的有效凭据或
cookie 来访问特定的用户工作站。”Volexity 解释道。  
  
  
CVE-2024-3400
的补丁预计将于 4 月 14 日发布。与此同时，建议组织在其防火墙上禁用设备遥测，并应用 Palo Alto Networks
在其公告中详细介绍的其他缓解建议。  
  
  
建议认为自己因该  
0  
day  
漏洞而受到损害的组织收集日志、创建技术支持文件并保留取证工件。他们还应该寻找潜在的横向移动，并应考虑防火墙上的所有敏感数据受到损害。  
  
  
Palo Alto
Networks 和 Volexity 警告称，UTA0218 和其他攻击者对 CVE-2024-3400
的利用可能会在未来几天内激增，这主要是由于补丁尚未推出。  
  
  
**参考链接：**  
https://www.securityweek.com/state-sponsored-hackers-exploit-zero-day-to-backdoor-palo-alto-networks-firewalls/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
黑客利用  
0  
day漏洞对 Palo Alto Networks
防火墙进行后门攻击  
  
https://www.securityweek.com/state-sponsored-hackers-exploit-zero-day-to-backdoor-palo-alto-networks-firewalls/  
  
  
美国政府因俄罗斯黑客窃取微软重要信件而保持高度戒备  
  
https://securityweek.com/us-government-on-high-alert-as-russian-hackers-steal-critical-correspondence-from-microsoft/  
  
  
伊朗
MuddyWater 黑客在最新活动中采用新的 C2 工具“DarkBeatC2”  
  
https://thehackernews.com/2024/04/iranian-muddywater-hackers-adopt-new-c2.html  
  
  
芯片制造商
Nexperia 遭黑客攻击  
  
https://cybernews.com/news/nexperia-chipmaker-hacked/  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
流行的 Rust
Crate liblzma-sys 受到 XZ Utils 后门攻击的影响  
  
https://thehackernews.com/2024/04/popular-rust-crate-liblzma-sys.html  
  
  
信用卡窃取器伪装成无害的
Facebook 追踪器  
  
https://thehackernews.com/2024/04/sneaky-credit-card-skimmer-disguised-as.html  
  
  
LastPass
员工遭遇 Deepfake 电话攻击  
  
https://www.securityweek.com/lastpass-employee-targeted-with-deepfake-calls/  
  
  
攻击者操纵
GitHub 搜索来传播恶意软件  
  
https://www.securityweek.com/threat-actors-manipulate-github-search-to-deliver-malware/  
  
  
针对流媒体服务  
   
Roku 的网络攻击影响
576,000 个帐户  
  
https://cybernews.com/news/roku-cyberattack-impacts-576000-accounts/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Palo Alto
Networks 就防火墙漏洞被利用发出警告  
  
https://www.securityweek.com/palo-alto-networks-warns-of-exploited-firewall-vulnerability/  
  
  
“BatBadBut”命令注入漏洞影响多种编程语言  
  
https://www.securityweek.com/batbadbut-command-injection-vulnerability-affects-multiple-programming-languages/  
  
  
未修补的
D-Link NAS 设备漏洞的利用激增  
  
https://www.securityweek.com/exploitation-of-unpatched-d-link-nas-device-vulnerabilities-soars/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
