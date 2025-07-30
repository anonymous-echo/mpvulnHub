#  R 编程语言中的漏洞可能助长供应链攻击   
会杀毒的单反狗  军哥网络安全读报   2024-05-01 09:30  
  
**导****读**  
  
  
  
AI 安全公司
HiddenLayer 警告称，当加载和引用恶意 RDS 文件时，R 编程语言实现中的漏洞可被利用来执行任意代码，并且可能被用作供应链攻击的一部分。  
  
  
该漏洞编号为CVE-2024-27322（CVSS
评分为 8.8），是在 R 的序列化和反序列化过程中发现的，该过程用于创建和加载 RDS（R 数据序列化）文件。  
  
  
R
是一种开源编程语言，支持数据可视化、机器学习和统计计算，广泛用于金融、政府和医疗保健等行业的统计分析，在人工智能和机器学习应用中也很受欢迎。  
  
  
R
有自己的序列化格式，在保存和加载包时使用。编译包时，将创建一个包含要序列化对象的 .rdb 文件和一个包含与这些对象及其偏移量关联元数据的 .rdx 文件。  
  
  
“加载包时，.rdx
文件中以 RDS 格式存储的元数据用于定位 .rdb 文件中的对象。然后这些对象被解压缩和反序列化，本质上是将它们加载为 RDS 文件。”
HiddenLayer 解释道。  
  
  
因为 R 支持创建
Promise 对象的指令（该对象具有符号（变量）和附加的表达式，表达式仅在访问符号后运行）和惰性求值（仅在需要时才求值符号的策略）。  
  
  
攻击者可以使用将变量设置为未绑定值的指令和包含任意代码的表达式来创建
Promise 对象。由于惰性求值，仅当访问与 RDF 文件关联的符号时才求值并运行表达式，并且当用户引用该符号时将执行代码。  
  
  
“一旦 R
创建并加载恶意文件，无论如何引用变量，漏洞都会运行。”HiddenLayer 继续说道。  
  
  
详细漏洞报告参考链接：  
https://hiddenlayer.com/research/r-bitrary-code-execution/  
  
### 漏洞可用于软件供应链攻击  
  
  
该安全公司还警告说，由于
RDS 包允许用户与其他人共享编译后的 R 代码，并且由于有大量专用于 R 的 GitHub 存储库，攻击者可能会在针对 R 用户的供应链攻击中滥用此漏洞。  
  
  
readRDS
是可用于利用该漏洞的 R 函数之一，在超过 135,000 个 R 源文件中被引用，而CRAN的存储库声称拥有超过 20,000
个包并允许任何人上传代码，但不会检查新包这个漏洞。  
  
  
“通过查看存储库，我们发现大量使用是在不受信任的用户提供的数据上，这可能会导致运行该程序的系统完全受到损害。一些包含潜在易受攻击代码的源文件包括来自
R Studio、Facebook、Google、Microsoft、AWS 和其他主要软件供应商的项目。”HiddenLayer 解释道。  
  
  
要接管 R
包，攻击者只需用恶意文件覆盖 .rdx 文件，确保包加载后立即自动执行代码。通过修改可能的系统包，例如编译器，恶意代码将在R初始化时执行。  
  
  
CVE-2024-27322
的补丁包含在 R Core 版本 4.4.0 中，该版本于 4 月 24 日作为源代码发布，随后很快发布了 Windows 和 Mac
二进制文件。更新后的版本也将包含在各种 Linux 发行版中。  
  
  
**参考链接：**  
https://www.securityweek.com/vulnerability-in-r-programming-language-enables-supply-chain-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
霍尼韦尔：  
针对工业组织的
USB 恶意软件攻击变得更加复杂  
  
https://www.securityweek.com/honeywell-usb-malware-attacks-on-industrial-orgs-becoming-more-sophisticated/  
  
  
白俄罗斯网络游击队声称已渗透白俄罗斯安全部门，访问了
8,600 多名员工的人事档案  
  
https://www.securityweek.com/hackers-claim-to-have-infiltrated-belarus-main-security-service/  
  
  
乌克兰军事情报机构声称俄罗斯执政党网站遭到攻击  
  
https://therecord.media/ukraine-military-intelligence-untied-russia-party  
  
  
堪萨斯城一个向公路沿线司机提供实时天气和交通信息的系统因网络攻击而瘫痪  
  
https://therecord.media/kansas-city-traffic-system-cyberattack  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
芬兰黑客因获取数千份心理治疗记录并索要赎金而入狱  
  
https://www.securityweek.com/finnish-hacker-gets-prison-for-accessing-thousands-of-psychotherapy-records-and-demanding-ransoms/  
  
  
Docker Hub
用户成为无镜像恶意存储库的目标  
  
https://www.securityweek.com/docker-hub-users-targeted-with-imageless-malicious-repositories/  
  
  
数以百万计的
Docker 存储库被发现推送恶意软件、网络钓鱼网站  
  
https://www.bleepingcomputer.com/news/security/millions-of-docker-repos-found-pushing-malware-phishing-sites/  
  
  
五年来，Docker
Hub 上植入了数百万个恶意“Imageless（无图像）”容器  
  
https://thehackernews.com/2024/04/millions-of-malicious-imageless.html  
  
  
新的 Wpeeper
Android 恶意软件隐藏在被黑客入侵的 WordPress 网站后面  
  
https://www.bleepingcomputer.com/news/security/new-wpeeper-android-malware-hides-behind-hacked-wordpress-sites/  
  
  
美国邮政服务
(USPS) 的网络钓鱼网站获得的流量与真实网站一样多  
  
https://www.bleepingcomputer.com/news/security/us-post-office-phishing-sites-get-as-much-traffic-as-the-real-one/  
  
  
Latrodectus
恶意软件正在使用 Microsoft Azure 和 Cloudflare 诱饵在网络钓鱼活动中传播  
  
https://www.bleepingcomputer.com/news/security/new-latrodectus-malware-attacks-use-microsoft-cloudflare-themes/  
  
  
Sophos
发布勒索软件状况报告显示，勒索软件付款去年增加了 500%  
  
https://finance.yahoo.com/news/ransomware-payments-increase-500-last-103000570.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
针对 Windows
内核 EoP 漏洞（CVE-2024-26218）的 PoC 发布  
  
https://gbhackers.com/windows-kernel-eop-exploit-released/  
  
  
R
编程语言中的漏洞可能助长供应链攻击  
  
https://www.securityweek.com/vulnerability-in-r-programming-language-enables-supply-chain-attacks/  
  
  
Judge0
中的三个关键漏洞导致沙箱逃逸、主机接管  
  
https://www.securityweek.com/critical-vulnerabilities-in-judge0-lead-to-sandbox-escape-host-takeover/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
