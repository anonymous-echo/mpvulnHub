> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795636&idx=1&sn=000d2e7e424e164f95c2e9ad3f81c1e4

#  “CitrixBleed 2”漏洞 PoC 被公开  
会杀毒的单反狗  军哥网络安全读报   2025-07-07 01:01  
  
**导****读**  
  
  
  
Citrix NetScaler 设备中存在的新严重漏洞引发了安全专家的警告，该漏洞可能被广泛利用，这与 2023 年引发广泛影响的毁灭性“ CitrixBleed ”攻击有着惊人的相似之处。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFA3w2J18eHcZRXWGWqc0fNFjSjGdxdyVktl8XRHAytSCcB9eK9Z6Hg93JwKibIdhjm55VmxuTON5w/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞编号为 CVE-2025-5777，被称为“CitrixBleed 2”，允许攻击者直接从设备内存中窃取敏感信息，可能绕过多因素身份验证并劫持用户会话。  
  
  
watchTower Labs 研究人员披露的漏洞分析显示，该内存泄漏漏洞影响配置为远程访问网关的 NetScaler ADC 和 NetScaler Gateway 设备。  
  
  
该漏洞的 CVSS 严重性评分为 9.3，源于输入验证不足，导致处理身份验证请求时内存溢出。  
  
  
最初的 CitrixBleed 漏洞 ( CVE-2023-4966 ) 被勒索软件团体和  
APT  
组织广泛利用，导致引人注目的漏洞攻击活动，包括对波音和康卡斯特的 Xfinity 服务的攻击，影响了 3600 万客户。  
  
  
网络安全公司 ReliaQuest报告称，他们观察到“中等置信度”指标，表明该漏洞已被利用进行有针对性的攻击。  
  
  
证据包括被劫持的 Citrix Web 会话，在用户不知情的情况下授予身份验证，表明成功绕过了多因素身份验证。  
  
  
研究人员发现了几个令人担忧的模式：跨可疑 IP 地址的会话重用、与Active Directory侦察相关的 LDAP 查询，以及在受感染环境中部署的多个 ADExplorer64.exe 工具实例。  
  
  
攻击者似乎正在使用消费级 VPN 服务来掩盖其活动，同时进行入侵后侦察。  
  
  
watchTower Labs 的分析显示，该漏洞的利用方式出奇地简单。攻击者只需向 Citrix Gateway 登录端点发送一个格式错误的 HTTP 请求，且该请求中没有正确的参数值，即可触发内存泄漏，从而暴露设备内存中未初始化的包含敏感数据的变量。  
  
  
研究人员解释说：“这里底层发生的事情是典型的 C 语言恶意攻击案例。后端解析器最终会返回一个未初始化的局部变量”，其中包含之前存储在内存中的所有数据，可能包括会话令牌和其他敏感信息。  
  
  
当攻击者向终端发送包含格式错误的登录参数的 HTTP POST 请求时，该漏洞就会显现/p/u/doAuthentication.do。系统不会正确初始化内存变量，而是返回之前存储在内存中的残留数据，这构成了 CWE-457 的典型案例：未初始化变量的使用。  
  
  
安全研究员 Kevin Beaumont（创造了“CitrixBleed 2”这个绰号）指出，根据 Shodan 搜索，超过 5 万个潜在易受攻击的 NetScaler 实例暴露在互联网上。  
  
  
Shadowserver 基金会发现，尽管 Citrix 于 6 月 17 日发布了修复程序，但截至 2025 年 6 月下旬，仍有超过 1200 台设备未打补丁。  
  
  
Citrix 已发布受支持版本的安全更新，并强烈敦促各组织立即升级。  
  
  
该公司建议在补丁完成后终止所有活动的 ICA 和 PCoIP 会话，以防止潜在的会话劫持。运行已停用 12.1 和 13.0 版本的企业必须升级到受支持的版本，因为这些版本将不会收到安全补丁。  
  
  
鉴于最初的 CitrixBleed 攻击造成的严重影响，且在补丁发布后的数月内仍继续被利用，安全专家强调，组织不能延迟修补工作。  
  
  
该漏洞与之前的漏洞相似，表明它可能会成为寻求初步访问企业网络的网络犯罪分子青睐的工具。  
  
  
漏洞详细分析：  
  
https://labs.watchtowr.com/how-much-more-must-we-bleed-citrix-netscaler-memory-disclosure-citrixbleed-2-cve-2025-5777/  
  
  
新闻链接：  
  
https://cybersecuritynews.com/citrixbleed-2-poc-released/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
曹县  
APT  
组织通过虚假的 Zoom 更新传播 macOS NimDoor 恶意软件  
  
https://securityaffairs.com/179643/malware/north-korea-linked-threat-actors-spread-macos-nimdoor-malware-via-fake-zoom-updates.html  
  
  
APT  
组织利用 Ivanti   
0day  
漏洞攻击法国基础设施  
  
https://www.cysecurity.news/2025/07/chinese-attackers-target-france.html  
  
  
NightEagle APT 利用 Microsoft Exchange 漏洞攻击中国军事和科技部门  
  
https://thehackernews.com/2025/07/nighteagle-apt-exploits-microsoft.html  
  
  
2025 年上半年，黑客组织盗窃  
21  
亿美元加密货币，其中七成与曹县黑客有关  
  
https://www.cysecurity.news/2025/07/north-korea-linked-hackers-behind-21.html  
  
  
“LapDogs”黑客劫持数百台设备，攻击针对亚太敏感地区  
  
https://www.msn.com/en-us/money/other/china-backed-lapdogs-hackers-hijacked-hundreds-of-devices-in-an-outlandish-intel-campaign-aimed-at-us-and-asian-targets/ar-AA1HD71N  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
XWorm——最活跃的 RAT 使用新型 Stager 和 Loader 绕过防御  
  
https://cybersecuritynews.com/xworm-the-most-active-rat-uses-new-stagers/  
  
  
Scattered Spider勒索软件攻击激增，FBI向航空公司和保险公司发出警告  
  
https://www.cysecurity.news/2025/07/fbi-warns-airlines-and-insurers-as.html  
  
  
Scattered Spider 升级其攻击手段，滥用合法工具逃避检测并保持持久性  
  
https://cybersecuritynews.com/scattered-spider-upgraded-their-tactics-to-abuse-legitimate-tools/  
  
  
“Dire Wolf”勒索软件袭击科技和制造业，目标涉及11个国家  
  
https://www.cysecurity.news/2025/07/dire-wolf-gang-hits-tech-and.html  
  
  
一项名为IconAds的移动广告欺诈行动已被挫败，涉及 352 个 Android 应用程序  
  
https://thehackernews.com/2025/07/mobile-security-alert-352-iconads-fraud.html  
  
  
贩毒集团入侵摄像头和手机，监视联邦调查局并识别证人  
  
https://www.malwarebytes.com/blog/news/2025/07/drug-cartel-hacked-cameras-and-phones-to-spy-on-fbi-and-identify-witnesses  
  
  
夏威夷航空公司遭黑客攻击，航空业警告称可能存在Scattered Spider袭击  
  
https://www.securityweek.com/hawaiian-airlines-hacked-as-aviation-sector-warned-of-scattered-spider-attacks/  
  
  
澳航遭受网络攻击，大量客户数据被盗  
  
https://therecord.media/qantas-airline-data-breach  
  
  
数十款假钱包插件涌入 Firefox 商店，盗取加密货币  
  
https://www.bleepingcomputer.com/news/security/dozens-of-fake-wallet-add-ons-flood-firefox-store-to-drain-crypto/  
  
  
Ahold Delhaize 报告重大数据泄露事件，影响美国超过 200 万员工  
  
https://www.cysecurity.news/2025/07/ahold-delhaize-reports-major-data.html  
  
  
黑客利用恶意 PDF 冒充 Microsoft、DocuSign 和 Dropbox 进行有针对性的网络钓鱼攻击  
  
https://gbhackers.com/cybercriminals-use-malicious-pdfs/  
  
  
黑客瞄准 Linux SSH 服务器部署 TinyProxy 和 Sing-Box 代理工具  
  
https://gbhackers.com/hackers-target-linux-ssh-servers/  
  
  
DCRat 针对 Windows 系统进行远程控制、键盘记录、屏幕捕获和数据窃取  
  
https://gbhackers.com/dcrat-targets-windows-systems/  
  
  
TA829 黑客采用新的 TTP 和升级的 RomCom 后门来逃避检测  
  
https://cybersecuritynews.com/ta829-hackers-employs-new-ttps/  
  
  
Snake 键盘记录器利用 Java 实用程序逃避安全工具的检测  
  
https://gbhackers.com/snake-keyloggers-exploit-java-utilities/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
联想预装 Windows 目录发现重大漏洞：可写文件可实现隐秘的 AppLocker 绕过  
  
https://cybersecuritynews.com/writable-file-in-lenovos-windows-directory/  
  
  
Apache APISIX 漏洞导致错误配置下跨发行者访问  
  
https://gbhackers.com/apache-apisix-vulnerability/  
  
  
Apache Tomcat 和 Camel 漏洞遭恶意利用  
  
https://cybersecuritynews.com/apache-tomcat-and-camel-vulnerabilities/  
  
  
多个 PHP 漏洞允许 SQL 注入和 DoS 攻击  
  
https://cybersecuritynews.com/multiple-php-vulnerabilities/  
  
  
海康威视applyCT漏洞致设备遭受代码执行攻击  
  
https://cybersecuritynews.com/hikvision-applyct-vulnerability/  
  
  
Next.js 漏洞允许攻击者通过缓存投毒触发 DoS  
  
https://gbhackers.com/next-js-vulnerability-allows-attackers-to-trigger-dos/  
  
  
Azure API 漏洞暴露 VPN 密钥并通过内置角色授予过度特权访问权限  
  
https://gbhackers.com/azure-api-vulnerabilities-expose-vpn-keys/  
  
  
“CitrixBleed 2”漏洞 PoC 发布  
  
https://cybersecuritynews.com/citrixbleed-2-poc-released/  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
