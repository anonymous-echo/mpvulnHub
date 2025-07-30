#  Salt Typhoon 使用定制恶意软件 JumbledPath 监视美国电信服务商   
会杀毒的单反狗  军哥网络安全读报   2025-02-21 01:01  
  
**导****读**  
  
  
  
Cisco Talos 研究人员报告称，Salt Typhoon威胁组织使用一种名为 JumbledPath 的定制实用程序来监视美国电信网络流量。  
  
  
思科 Talos 研究人员的报告称，Salt Typhoon 入侵美国主要电信公司已超过三年，主要使用被盗凭证，漏洞利用有限。  
  
  
思科表示，该 APT 组织仅在一次事件中利用了其产品中的一个新漏洞，即漏洞 CVE-2018-0171。该漏洞影响思科 IOS 软件和思科 IOS XE 软件的智能安装功能，未经身份验证的远程攻击者可利用该漏洞重新加载易受攻击的设备或在受影响的设备上执行任意代码。  
  
  
“在这次活动中没有发现新的思科漏洞。虽然有报道称 Salt Typhoon 正在滥用其他三个已知的思科漏洞，但我们尚未发现任何证据来证实这些说法。”思科 Talos 发布的报告写道。  
  
  
思科报告称，Salt Typhoon 使用窃取的凭证、捕获的网络配置以及拦截的 SNMP、TACACS 和 RADIUS 流量来收集更多凭证，以便进一步访问。然而，目前尚不清楚该组织如何获得攻击中使用的凭证。  
  
  
该组织通过 TFTP/FTP 窃取设备配置，泄露弱加密密码、SNMP 凭据和网络详细信息以供进一步侦察。威胁组织依靠机器对机器的转移在电信网络内部进行横向移动。  
  
  
攻击者还从一家电信公司运营的受感染设备转向另一家电信公司的设备。我们认为，与初始电信公司相关的设备只是用作跳跃点，而不是预期的最终目标。  
  
  
其中一些跳跃点还被用作出站数据泄露操作的第一跳。这种转变大部分包括使用来自不同制造商的网络设备。  
  
  
攻击者通过启用 Guest Shell 执行命令、修改访问控制列表 (ACL) 和创建隐秘的隐藏账户来操纵网络设置。  
  
  
Salt Typhoon 使用 JumbledPath 工具通过跳转主机远程捕获数据包、清除日志并窃取加密数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGaRPXk4iaec1qJOzRrlCS5mt6HUSWywzGuOWzC3NUAg3SiaqMWdicIXxSScFC8s7jy5cicuuOcUVgXcQ/640?wx_fmt=png&from=appmsg "")  
  
  
JumbledPath 用 GO 编写，并使用 x86-64 架构编译为 ELF 二进制文件，以便在 Linux 操作系统上使用该实用程序。  
  
  
攻击者试图通过改变环回地址来绕过 ACL、清除日志来隐藏活动、禁用 Guest Shell 以及修改 AAA 设置以进行未经授权的访问，从而逃避检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGaRPXk4iaec1qJOzRrlCS5mKGy3yfR61Rtt5dmqKyiaKMNPQiaMJoawOhYgOBuHo0uxzZ0mD0SvIM4g/640?wx_fmt=png&from=appmsg "")  
  
  
详细技术报告：  
  
https://blog.talosintelligence.com/salt-typhoon-analysis/  
  
  
新闻链接：  
  
https://securityaffairs.com/174460/apt/salt-typhoon-custom-malware-jumbledpath-to-spy-u-s-telecom-providers.html  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
安全专家在多部私营企业的手机上发现 Pegasus 间谍软件感染  
  
https://therecord.media/pegasus-spyware-infections-iverify  
  
  
Salt Typhoon 使用定制恶意软件 JumbledPath 监视美国电信服务商  
  
https://securityaffairs.com/174460/apt/salt-typhoon-custom-malware-jumbledpath-to-spy-u-s-telecom-providers.html  
  
  
曹县黑客利用求职骗局瞄准自由职业开发者以部署恶意软件  
  
https://thehackernews.com/2025/02/north-korean-hackers-target-freelance.html  
  
  
APT-C-28 组织利用无文件 RokRat 恶意软件发起新网络攻击  
  
https://cybersecuritynews.com/apt-c-28-group-launched-new-cyber-attack-with-fileless-rokrat-malware/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
矿业公司 NioCorp 因 BEC 网络钓鱼攻击损失 50 万美元  
  
https://www.securityweek.com/mining-company-niocorp-loses-500000-in-bec-hack/  
  
  
新型勒索软件 NailaoLocker 攻击欧洲医疗保健系统  
  
https://cybersecuritynews.com/new-nailaolocker-ransomware/  
  
  
跟踪软件应用程序 Cocospy 和 Spyic 正在泄露数百万人的手机数据  
  
https://techcrunch.com/2025/02/20/stalkerware-apps-cocospy-spyic-exposing-phone-data-of-millions-of-people/  
  
  
新型恶意软件 FrigidStealer 通过虚假浏览器更新感染 macOS  
  
https://hackread.com/frigidstealer-malware-infect-macos-fake-browser-updates/  
  
  
隐藏在盗版游戏中的加密挖矿程序主要出现在俄罗斯计算机上  
  
https://therecord.media/xmrig-cryptominer-pirated-video-games-russia  
  
  
攻击者利用 Check Point 漏洞部署 ShadowPad 和勒索软件  
  
https://thehackernews.com/2025/02/chinese-linked-attackers-exploit-check.html  
  
  
新的 Bookworm 恶意软件使用 SLL 侧载技术攻击 Windows  
  
https://gbhackers.com/new-bookworm-malware-using-sll-sideloading-technique/  
  
  
网络犯罪分子利用 Eclipse Jarsigner 通过 ZIP 存档部署 XLoader 恶意软件  
  
https://thehackernews.com/2025/02/cybercriminals-use-eclipse-jarsigner-to.html  
  
  
Rhadamanthys 信息窃取者利用 Microsoft 管理控制台执行恶意脚本  
  
https://cybersecuritynews.com/rhadamanthys-infostealer-exploiting-microsoft-management/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
NVIDIA CUDA 工具包中发现多个漏洞  
  
https://unit42.paloaltonetworks.com/nvidia-cuda-toolkit-vulnerabilities/  
  
  
微软修补被利用的 Power Pages 权限提升漏洞（CVE-2025-24989）  
  
https://www.securityweek.com/microsoft-patches-exploited-power-pages-vulnerability/  
  
  
严重 Microsoft Bing 漏洞导致远程代码执行攻击  
  
https://gbhackers.com/critical-microsoft-bing-vulnerability  
  
  
针对 Ivanti EPM 关键漏洞的 PoC 发布  
  
https://www.securityweek.com/poc-exploit-published-for-critical-ivanti-epm-vulnerabilities/  
  
  
IBM OpenPages 漏洞使攻击者能够窃取身份验证凭证  
  
https://cybersecuritynews.com/ibm-openpages-vulnerability/  
  
  
新的 Zhong 恶意软件利用 AnyDesk 工具攻击金融科技和加密货币  
  
https://cybersecuritynews.com/new-zhong-malware-exploit-anydesk-tool/  
  
  
Citrix NetScaler 漏洞导致系统遭受未经授权执行命令  
  
https://gbhackers.com/citrix-netscaler-vulnerability-exposes-systems/  
  
  
Atlassian 修补了 Confluence 和 Crowd 中的严重漏洞  
  
https://www.securityweek.com/atlassian-patches-critical-vulnerabilities-in-confluence-crowd/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
