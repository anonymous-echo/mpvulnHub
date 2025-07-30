#  微软 0-Click Telnet 漏洞可导致无需用户操作即可窃取凭证   
会杀毒的单反狗  军哥网络安全读报   2025-05-07 01:03  
  
**导****读**  
  
  
  
微软的 Telnet 客户端 (telnet.exe) 中发现一个严重漏洞，攻击者可以利用该漏洞从毫无戒心的用户那里窃取 Windows 凭据，甚至在某些网络场景下无需交互即可实现。  
  
  
安全研究人员警告称，这种“零点击”漏洞可能在企业环境中被轻易利用，对网络完整性造成严重后果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGvuTuhPS1I4JAiaDwjU3zHR6OuVF4G1TmSnzo65tVEITzNnibzcjZeybibCzvIyM6hDy2shzBlw4Itg/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的核心在于 Microsoft Telnet 客户端的 MS-TNAP 身份验证协议。  
  
  
当 Windows 用户连接到恶意 Telnet 服务器时，无论是通过手动打开连接还是单击特制的 telnet://超链接（可以嵌入在电子邮件、网站或文档中），客户端都会启动身份验证。  
  
  
如果服务器位于 Intranet 或受信任区域内 - 或者系统策略允许静默身份验证 - Windows 将自动传输用户的 NTLM 身份验证数据，所有这些都无需警告或要求用户批准。  
  
  
Internet 区域： 在发送凭据之前会提示用户。  
  
  
内联网/受信任站点区域： 凭证可能会自动发送 - 无提示，无警告。  
  
  
对于已将内部 IP 范围或主机添加到受信任区域但未指定协议的组织来说，这种行为尤其危险。  
  
  
例如，输入  
 192.168.1.1   
这样的  
 IP  
（不指定  
  
http://  
）意味着  
    
该主机信任所有协议（包括  
 Telnet  
），而不仅仅是  
 Web   
流量。  
  
  
攻击者可以通过以下方式利用此漏洞：  
  
  
设置恶意  
 Telnet   
服务器。  
  
  
诱使用户点击  
  
telnet://  
  
链接（例如，通过网络钓鱼电子邮件）。  
  
  
从连接客户端捕获  
 NTLM   
哈希。  
  
  
捕获的哈希值随后可用于  
 NTLM   
中继攻击或使用  
 Hashcat   
等工具离线破解，从而使攻击者有可能访问敏感系统和数据。  
  
### 概念验证和漏洞代码  
###   
  
一个可行的概念验证已经投入使用，逐步演示了如何收集身份验证数据。  
  
  
例如，该漏洞记录 NTLM 身份验证交换并以与流行密码破解工具兼容的格式输出捕获的哈希值。  
  
  
hashcat -m 5600 -a 0 -O netntlmv2.hash passwords.txt  
  
  
上述命令使攻击者能够破解针对密码列表收集的 NTLMv2 哈希值，如果使用弱密码，则可以在几秒钟内恢复凭据。  
  
### 缓解措施和建议  
###   
  
审查受信任区域： 确保 Intranet/受信任站点区域中的主机/IP 使用协议说明符（例如 http://）输入，而不仅仅是原始IP。  
  
  
禁用 Telnet 客户端： 除非绝对必要，否则在所有 Windows 机器上卸载或禁用 Telnet 功能。  
  
  
用户意识培训： 培训用户避免点击可疑的 telnet:// 链接或打开未知的 LNK 文件。  
  
  
所有安装了 Telnet 客户端的受支持和不受支持的Windows版本都存在此漏洞，包括 Windows 7–11、Windows Server 2008–2025 和旧版平台。  
  
  
详细漏洞信息：  
  
https://github.com/hackerhouse-opensource/telnetclientpoc  
  
  
新闻链接：  
  
https://gbhackers.com/critical-microsoft-0-click-telnet-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
ESET 分析  
APT  
组织进行中间人攻击的工具  
  
https://www.securityweek.com/chinese-apts-adversary-in-the-middle-tool-dissected/  
  
  
苹果向 100 个国家的受害者发出可能遭受间谍软件攻击的通知  
  
https://therecord.media/apple-spyware-victims-notified-countries  
  
  
SentinelOne 成为朝鲜黑客、勒索软件组织的攻击目标  
  
https://www.securityweek.com/sentinelone-targeted-by-north-korean-it-workers-ransomware-groups-chinese-hackers/  
  
  
法国指责俄罗斯对数十家实体发动网络攻击  
  
https://www.securityweek.com/france-blames-russia-for-cyberattacks-on-dozen-entities/  
  
  
伊朗黑客利用 VPN 漏洞和恶意软件持续访问中东关键基础设施两年  
  
https://thehackernews.com/2025/05/iranian-hackers-maintain-2-year-access.html  
  
  
阿塞拜疆指责俄黑客对当地媒体发动网络攻击  
  
https://therecord.media/azerbaijan-blames-media-cyberattacks-russia-apt29  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
黑客只需一个简单的表情符号即可绕过微软、Nvidia 和 Meta AI 过滤器  
  
https://cybersecuritynews.com/hackers-can-bypass-microsoft-nvidia-meta-ai-filters/  
  
  
诈骗者利用 Venom Spider 恶意软件攻击人力资源专业人士  
  
https://www.scworld.com/news/malware-scammers-target-hr-professionals-with-venom-spider-malware  
  
  
带有后门的 Magento 插件攻击了 1,000 家在线商店  
  
https://www.scworld.com/brief/backdoored-magento-plugins-hit-1000-online-stores  
  
  
威胁组织规避 SentinelOne EDR，部署 Babuk 勒索软件  
  
https://gbhackers.com/threat-actor-evades-sentinelone-edr/  
  
  
GitHub 上的恶意 Go 模块隐藏 Linux Wiper 恶意软件  
  
https://www.bleepingcomputer.com/news/security/linux-wiper-malware-hidden-in-malicious-go-modules-on-github/  
  
  
超过 1,200 个 SAP 实例暴露于严重漏洞并被广泛利用  
  
https://www.cysecurity.news/2025/05/over-1200-sap-instances-exposed-to.html/  
  
  
微软警告攻击者利用配置错误的 Apache Pinot 安装实例  
  
https://www.securityweek.com/microsoft-warns-of-attackers-exploiting-misconfigured-apache-pinot-installations/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
三星MagicINFO漏洞在PoC发布几天后被利用  
  
https://securityaffairs.com/177529/hacking/samsung-magicinfo-vulnerability-exploited-after-poc-publication.html  
  
  
微软 0-Click Telnet 漏洞可导致无需用户操作即可窃取凭证  
  
https://gbhackers.com/critical-microsoft-0-click-telnet-vulnerability/  
  
  
AI Builder Langflow 中的关键漏洞（ CVE-2025-3248）受到攻击  
  
https://www.securityweek.com/critical-vulnerability-in-ai-builder-langflow-under-attack/  
  
  
Android 五月更新修复 FreeType 漏洞（CVE-2025-27363）  
  
https://www.securityweek.com/android-update-patches-freetype-vulnerability-exploited-as-zero-day/  
  
  
可蠕虫的 AirPlay 漏洞可通过公共 Wi-Fi 在 Apple 设备上实现零点击 RCE  
  
https://thehackernews.com/2025/05/wormable-airplay-flaws-enable-zero.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
