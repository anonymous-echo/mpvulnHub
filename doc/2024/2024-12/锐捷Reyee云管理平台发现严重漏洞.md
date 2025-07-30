#  锐捷Reyee云管理平台发现严重漏洞   
会杀毒的单反狗  军哥网络安全读报   2024-12-14 01:00  
  
**导****读**  
  
  
  
网络安全公司 Claroty 的警告称，Reyee 云管理平台和 Reyee OS 网络设备中的漏洞可能允许黑客控制数万台设备。  
  
  
Ruijie 设备使用 MQTT 消息协议进行通信，其中设备使用用户名/密码对向代理进行身份验证，其中用户名是序列号，密码是反向序列号的 SHA256 计算。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFTEcTKicyLYxAzkewKP0nZYW0azOZcynymNkOibmfskLPkbB810OSkTfvzibz08HQXdu3JpRKribKOZQ/640?wx_fmt=png&from=appmsg "")  
  
  
Claroty 在一份咨询报告中警告称：“这意味着，只要知道设备的序列号，我们就可以生成其 MQTT 用户名/密码对，并代表其向 Ruijie 的 MQTT 代理进行身份验证。问题是序列号并不是一个强标识符，因为它通常遵循顺序模式。 ”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFTEcTKicyLYxAzkewKP0nZYAt19MSJXujyarf2Uc5iaL6nHQWv2dbdXz5Jast5TKgh6KKHIAdylkNw/640?wx_fmt=png&from=appmsg "")  
  
  
成功连接到锐捷的 MQTT 代理，并了解设备如何向云端通知事件并从云端接收命令后，Claroty 发现它可以检索“所有云连接设备的序列号”列表，这意味着它可以为其中任何一个设备生成凭据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFTEcTKicyLYxAzkewKP0nZY55Tq1p56sjs5iaSzW1ib7ZxCv8SCghld4lG9QKnU4KHNZOgbYL4gze4Q/640?wx_fmt=png&from=appmsg "")  
  
  
该网络安全公司表示：“这意味着我们可以发起各种拒绝服务攻击，包括通过代表设备进行身份验证来断开设备连接，甚至向云端发送虚假消息和事件；向这些设备的用户发送虚假数据。”  
  
  
Claroty 还发现，锐捷实施了一种 RCE 即服务机制来控制连接云端的设备，并且可以模拟云端并向所有设备发送操作系统命令。  
  
  
该安全公司表示，攻击者可以将设备序列号与所有者的电话号码关联起来，从云账户中窃取敏感信息，并且攻击者可以接收发送到所有设备的所有 MQTT 消息。  
  
  
Claroty 总共向锐捷报告了 10 个漏洞，其中包括三个严重漏洞：CVE-2024-47547（CVSS 评分为 9.4），一个弱密码恢复机制问题；CVE-2024-48874（CVSS 评分为 9.8），一个服务器端请求伪造 (SSRF) 错误；以及 CVE-2024-52324（CVSS 评分为 9.8），使用固有危险函数导致任意命令执行。  
  
  
该安全公司还设计了一种名为“芝麻开门”的攻击，攻击者可以在使用锐捷接入点的 Wi-Fi 网络附近访问内部网络，而无需知道 Wi-Fi 凭证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFTEcTKicyLYxAzkewKP0nZYRIkfKK38lP4118GzZSUhyLUa6wmqYvWL5xghPpDeG8DJPYksRL0eZA/640?wx_fmt=png&from=appmsg "")  
  
  
通过与 Ruijie 接入点相邻，攻击者可以嗅探其原始信标消息、提取序列号，然后利用 Ruijie 的 MQTT 通信中的缺陷向设备发送命令并建立反向 shell。  
  
  
Claroty 发现大约有 50,000 台设备可能受到这些漏洞的影响，但表示锐捷已经解决了其云平台中的所有安全缺陷，不需要用户采取任何行动。  
  
  
锐捷网络是一家专门为企业、教育机构、政府组织和服务提供商提供网络基础设施产品的公司。他们为客户提供交换机、接入点和云服务等网络设备。锐捷业务遍及 90 多个国家，拥有 8,000 多名员工，营收达 16 亿美元。  
  
  
锐捷设备可用于各种场合，例如机场航站楼或购物中心提供免费 Wi-Fi 的接入点。  
  
  
技术报告：  
https://claroty.com/team82/research/the-insecure-iot-cloud-strikes-again-rce-on-ruijie-cloud-connected-devices  
  
  
新闻链接：  
  
https://www.securityweek.com/critical-vulnerabilities-found-in-ruijie-reyee-cloud-management-platform/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
俄罗斯秘密暴雪 APT 组织利用 Kazuar 后门攻击乌克兰  
  
https://securityaffairs.com/171896/apt/secret-blizzard-targets-ukraine-with-kazuar-backdoor.html  
  
  
伊朗黑客利用 IOCONTROL 恶意软件攻击美国和以色列的 OT、IoT 设备  
  
https://www.securityweek.com/iranian-hackers-use-iocontrol-malware-to-target-ot-iot-devices-in-us-israel/  
  
  
新型隐秘 Pumakit Linux rootkit 恶意软件被发现  
  
https://www.bleepingcomputer.com/news/security/new-stealthy-pumakit-linux-rootkit-malware-spotted-in-the-wild/  
  
  
Gamaredon 在前苏联国家部署 Android 间谍软件“BoneSpy”和“PlainGnome”  
  
https://thehackernews.com/2024/12/gamaredon-deploys-android-spyware.html  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
黑客可能窃取了比特币 ATM 运营商 Byte Federal 的个人数据  
  
https://www.securityweek.com/hackers-possibly-stole-personal-data-from-bitcoin-atm-operator-byte-federal/  
  
  
土耳其应用程序《古兰经》泄露了超过 360 万条高度敏感数据记录  
  
https://cybernews.com/security/sigma-telecom-data-leak/  
  
  
加拿大眼科护理公司 Care1 泄露 2.2TB 患者记录  
  
https://hackread.com/canadian-eyecare-firm-care1-exposes-patient-records/  
  
  
Sinkholes 僵尸网络感染了德国 30,000 台 BadBox 设备  
  
https://www.bleepingcomputer.com/news/security/germany-blocks-badbox-malware-loaded-on-30-000-android-devices/  
  
  
390,000+ WordPress 凭证通过恶意 GitHub 存储库托管 PoC 漏洞被窃取  
  
https://thehackernews.com/2024/12/390000-wordpress-credentials-stolen-via.html  
  
  
汽车零部件巨头 LKQ 称网络攻击扰乱了加拿大业务部门  
  
https://www.bleepingcomputer.com/news/security/auto-parts-giant-lkq-says-cyberattack-disrupted-canadian-business-unit/  
  
  
Citrix 分享针对正在进行的 Netscaler 密码喷洒攻击的缓解措施  
  
https://www.bleepingcomputer.com/news/security/citrix-shares-mitigations-for-ongoing-netscaler-password-spray-attacks/  
  
  
CISA 警告水务设施注意保护在线暴露的 HMI 系统  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-water-facilities-to-secure-hmi-systems-exposed-online/  
  
  
CISA 确认勒索软件攻击利用了关键的 Cleo 漏洞  
  
https://www.bleepingcomputer.com/news/security/cisa-confirms-critical-cleo-bug-exploitation-in-ransomware-attacks/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
微软修补了服务器端更新目录和 Windows Defender 中潜在的严重漏洞  
  
https://www.securityweek.com/microsoft-patches-vulnerabilities-in-windows-defender-update-catalog/  
  
  
对 Cleo 文件传输软件中严重漏洞的利用仍在继续  
  
https://www.cybersecuritydive.com/news/security-cleo-file-transfer-cve-delayed/735517  
  
  
OpenWrt 严重漏洞致设备遭受恶意固件注入  
  
https://thehackernews.com/2024/12/critical-openwrt-vulnerability-exposes.html  
  
  
锐捷Reyee云管理平台发现严重漏洞  
  
https://www.securityweek.com/critical-vulnerabilities-found-in-ruijie-reyee-cloud-management-platform/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
