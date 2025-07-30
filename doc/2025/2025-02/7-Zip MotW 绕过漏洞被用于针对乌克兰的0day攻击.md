#  7-Zip MotW 绕过漏洞被用于针对乌克兰的0day攻击   
会杀毒的单反狗  军哥网络安全读报   2025-02-05 01:00  
  
**导****读**  
  
  
  
自 2024 年 9 月以来，俄罗斯黑客利用 7-Zip 漏洞作为  
0  
day漏洞武器，该漏洞允许攻击者绕过 Windows 安全功能 Mark of the Web (MotW)。  
  
  
据趋势科技研究人员称，该漏洞被用于针对乌克兰政府和私人组织的 SmokeLoader 恶意软件活动。  
  
  
Web 标记是一项 Windows 安全功能，旨在警告用户他们即将执行的文件来自不受信任的来源，并通过附加提示请求确认步骤。绕过 MoTW 可让恶意文件在受害者的计算机上运行而无需发出警告。  
  
  
从网络下载文档和可执行文件或以电子邮件附件形式接收时，Windows 会向文件添加一个称为“Web 标记” （MoTW）的特殊“Zone.Id”备用数据流。  
  
  
当尝试打开下载的文件时，Windows 将检查是否存在 MoTW，如果存在，则向用户显示其他警告，询问他们是否确定要运行该文件。同样，当在 Word 或 Excel 中打开带有 MoTW 标志的文档时，Microsoft Office 将生成其他警告并关闭宏。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGicjYUjPrumlbia3Ik4mxV5UuickapMToVpIBAYZICYtQgHzhky3ibxgv8I7SYUG69ibvvKWsb3nHgk3Q/640?wx_fmt=png&from=appmsg "")  
  
Windows 中的 MoTW 警告  
,  
来源：BleepingComputer  
  
  
由于 Web 标记的安全功能可防止危险文件自动运行，攻击者通常会尝试找到 MoTW 绕过方法，以便他们的文件自动运行和执行。  
  
### 攻击中利用 MoTW 绕过技术  
###   
  
趋势科技的零日计划 (ZDI) 团队于 2024 年 9 月 25 日首次发现该漏洞，目前追踪为 CVE-2025-0411，并在俄罗斯威胁组织发起的攻击中观察到该漏洞利用。  
  
  
黑客利用 CVE-2025-0411，使用双重存档文件（存档中的存档）来利用 MoTW 标志缺乏继承，从而导致恶意文件执行而不会触发警告。  
  
  
这些特制的档案文件通过被入侵的乌克兰政府账户的钓鱼邮件发送给目标，以绕过安全过滤器并显得合法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGicjYUjPrumlbia3Ik4mxV5U5yICpB5ksLZ7FCDZXSzn7P3pXZWiaiaI7YZCORNkGhcoibkz1A7o7G0Cg/640?wx_fmt=png&from=appmsg "")  
  
攻击活动中使用的钓鱼电子邮件样本，来源：趋势科技  
  
  
攻击者将有效载荷隐藏在 7-Zip 文件中，使其看起来是无害的 Word 或 PDF 文档。  
  
  
虽然打开父档案确实会传播 MoTW 标志，但 CVE-2025-0411 漏洞导致该标志不会传播到内部档案的内容，从而允许恶意脚本和可执行文件直接启动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGicjYUjPrumlbia3Ik4mxV5U7vdz8vdoWOicpAKsVMfeqDo92f1kgEnFdtg6C4iaWRghUicHQL3erWncw/640?wx_fmt=png&from=appmsg "")  
  
被屏蔽文件的真实内容，来源：趋势科技  
  
  
最后一步会触发 SmokeLoader 负载，这是一种恶意软件投放器，过去用于安装信息窃取程序、木马、勒索软件或创建后门以实现持续访问。  
  
  
趋势科技表示这些攻击影响了以下组织：  
- 乌克兰国家行政局 (SES) ——司法部  
- 扎波罗热汽车制造厂 (PrJSC     ZAZ) ——汽车、公共汽车和卡车制造商  
- Kyivpastrans ——基辅公共交通服务  
- SEA 公司——家用电器、电气设备和电子产品制造商  
- 韦尔霍维纳地区国家管理局——伊万诺-弗兰科夫斯克州管理局  
- VUSA——保险公司  
- 德尼普罗市地区药房——地区药房  
- Kyivvodokanal ——基辅供水公司  
- 扎利希奇基市议会——市议会  
###   
### 更新 7-Zip  
###   
  
2024 年 11 月 30 日发布的24.09 版本中解决了该风险。但是，因 7-Zip 不包含自动更新功能，因此 7-Zip 用户运行过时版本的情况很常见。  
  
  
强烈建议用户下载最新版本以确保免受此漏洞的影响。  
  
  
技术报告：  
  
https://www.trendmicro.com/en_us/research/25/a/cve-2025-0411-ukrainian-organizations-targeted.html  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/7-zip-motw-bypass-exploited-in-zero-day-attacks-against-ukraine/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
7-Zip MotW 绕过漏洞被用于针对乌克兰的  
0day  
攻击  
  
https://www.bleepingcomputer.com/news/security/7-zip-motw-bypass-exploited-in-zero-day-attacks-against-ukraine/  
  
  
俄罗斯黑客涉嫌入侵英国首相个人电子邮件账户  
  
https://therecord.media/keir-starmer-email-hack-russia-suspected  
  
  
网络间谍利用新型 SSH 后门攻击网络设备  
  
https://www.bleepingcomputer.com/news/security/chinese-cyberspies-use-new-ssh-backdoor-in-network-device-hacks/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
新型 ValleyRAT 恶意软件变种通过虚假 Chrome 下载进行传播  
  
https://hackread.com/valleyrat-malware-variant-fake-chrome-downloads/  
  
  
2024 年发现 22 个新的 Mac 恶意软件家族  
  
https://www.securityweek.com/22-new-mac-malware-families-seen-in-2024/  
  
  
信息窃取攻击激增，威胁欧洲、中东和非洲地区组织的数据安全  
  
https://www.infosecurity-magazine.com/news/surge-in-infostealer-attacks-emea/  
  
  
与 DaggerFly 相关的 Linux 恶意软件瞄准网络设备  
  
https://www.infosecurity-magazine.com/news/daggerfly-linux-malware-network/  
  
  
恶意软件伪装成 DeepSeek 软件包攻击开发人员  
  
https://www.securityweek.com/developers-targeted-with-malware-disguised-as-deepseek-package/  
  
  
日本运动服装公司美津浓在 2024 年勒索软件攻击后确认数据泄露  
  
https://therecord.media/mizuno-data-breach-notification  
  
  
Coyote 恶意软件扩大影响范围  
  
https://thehackernews.com/2025/02/coyote-malware-expands-reach-now.html  
  
  
恶意 Go 软件包利用模块镜像缓存实现持久远程访问  
  
https://thehackernews.com/2025/02/malicious-go-package-exploits-module.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Microsoft SharePoint 连接器漏洞可能导致 Power Platform 上的凭据被盗  
  
https://thehackernews.com/2025/02/microsoft-sharepoint-connector-flaw.html  
  
  
谷歌修复了被积极利用的安卓内核  
0day  
漏洞  
  
https://securityaffairs.com/173812/hacking/google-android-kernel-zero-day-flaw.html  
  
  
Contec CMS8000 病人监护仪不包含恶意后门，但存在不安全和易受攻击的设计  
  
https://www.securityweek.com/contec-patient-monitors-not-malicious-but-still-pose-big-risk-to-healthcare/  
  
  
微软修复 Azure AI 人脸服务严重漏洞，CVSS 评分达 9.9  
  
https://thehackernews.com/2025/02/microsoft-patches-critical-azure-ai.html  
  
  
Zyxel 不会修补报废路由器中新发现的漏洞  
  
https://www.bleepingcomputer.com/news/security/zyxel-wont-patch-newly-exploited-flaws-in-end-of-life-routers/  
  
  
Netgear 警告用户修补关键 WiFi 路由器漏洞  
  
https://www.bleepingcomputer.com/news/security/netgear-warns-users-to-patch-critical-wifi-router-vulnerabilities/  
  
  
AMD 修补可能破坏机密计算保护的 CPU 漏洞  
  
https://www.securityweek.com/amd-patches-cpu-vulnerability-found-by-google/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
