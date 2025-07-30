#  Ubuntu Needrestart 软件包中发现存在十年之久的安全漏洞，可以获得Root权限   
会杀毒的单反狗  军哥网络安全读报   2024-11-21 01:00  
  
**导****读**  
  
  
  
Ubuntu
Server（自 21.04 版起）默认安装的 needrestart
包中被发现存在多个已有十年历史的安全漏洞，这些漏洞可能允许本地攻击者在无需用户交互的情况下获得 root 权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFxWlOoADH4NjfpLZfzgIicZyx1z0yPcAIvnicbibKvaxiaHTU2bNCtZAgbOPQ34w9bOMDICS0CLibItqw/640?wx_fmt=png&from=appmsg "")  
  
  
Qualys
威胁研究部门 (TRU)于上个月初发现并报告了这些漏洞，并表示这些漏洞很容易被利用，因此用户必须迅速采取行动来修复。  
  
  
据信这些漏洞自
2014 年 4 月 27 日发布的needrestart 0.8引入解释器支持以来就一直存在。  
  
  
Ubuntu
在一份公告中表示：“这些 needrestart 漏洞允许本地特权升级 (LPE)，这意味着本地攻击者能够获得 root 权限” ，并指出这些问题已在 3.8
版中得到解决。“这些漏洞影响 Debian、Ubuntu 和其他 Linux 发行版。”  
  
  
Needrestart
是一个实用程序，它可以扫描系统以确定在应用共享库更新后需要重新启动的服务，以避免整个系统重新启动。  
  
  
具体来说，如果服务正在使用过时的共享库（例如在软件包更新期间替换库），它会标记服务以进行重新启动。  
  
  
由于它集成到服务器映像中，因此
needrestart 设置为在 APT 操作（如安装、升级或删除，包括无人值守升级）后自动运行。其主要作用是识别在关键库更新后需要重新启动的服务，例如 C
库 (glibc)。此过程可确保服务使用最新的库版本，而无需完全重启系统，从而提高正常运行时间和性能。  
  
  
通过使用最新的库及时更新服务，needrestart
对于维护 Ubuntu Server 的安全性和效率至关重要。  
  
  
Qualys 威胁研究部门发现的5个漏洞：  
- CVE-2024-48990（CVSS 评分：7.8） - 该漏洞允许本地攻击者通过诱骗 needrestart 使用攻击者控制的 PYTHONPATH 环境变量运行 Python
     解释器，从而以 root 身份执行任意代码  
  
- CVE-2024-48991（CVSS 评分：7.8） - 该漏洞允许本地攻击者通过赢得竞争条件并诱骗 needrestart 运行自己的伪 Python 解释器，以 root
     身份执行任意代码  
  
- CVE-2024-48992（CVSS 评分：7.8） - 该漏洞允许本地攻击者通过诱骗 needrestart 使用攻击者控制的 RUBYLIB 环境变量运行 Ruby 解释器，从而以
     root 身份执行任意代码  
  
- CVE-2024-11003（CVSS 评分：7.8）和CVE-2024-10224（CVSS 评分：5.3）- 这两个漏洞允许本地攻击者利用libmodule-scandeps-perl 软件包（版本 1.36 之前）中的问题以 root 身份执行任意 shell 命令  
  
成功利用上述缺陷可以允许本地攻击者为
PYTHONPATH 或 RUBYLIB 设置特  
  
制的环境变量，从而导致在运行 needrestart 时执行指向攻击者环境的任意代码。  
  
  
Ubuntu
指出：“在 CVE-2024-10224 中，[...] 攻击者控制的输入可能导致 Module::ScanDeps Perl 模块通过 open()
一个‘讨厌的管道’（例如通过传递‘commands|’作为文件名）或通过将任意字符串传递给 eval() 来运行任意 shell 命令。”  
  
  
“就其本身而言，这不足以实现本地权限提升。然而，在
CVE-2024-11003 中，needrestart 将攻击者控制的输入（文件名）传递给 Module::ScanDeps，并以 root
权限触发CVE-2024-10224。CVE-2024-11003 的修复消除了 needrestart 对 Module::ScanDeps 的依赖。”  
  
  
虽然强烈建议用户下载最新的补丁，Ubuntu
表示用户可以根据需要禁用解释器扫描器，重新启动配置文件作为临时缓解措施，并确保在应用更新后恢复更改。  
  
  
Qualys 公司
TRU 产品经理 Saeed Abbasi 表示：“needrestart
实用程序中的这些漏洞允许本地用户通过在软件包安装或升级期间执行任意代码来提升其权限，其中 needrestart 通常以 root 用户身份运行。”  
  
  
“利用这些漏洞的攻击者可以获得
root 访问权限，从而损害系统完整性和安全性。”  
  
  
参考漏洞公告  
:  
  
https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart  
  
https://ubuntu.com/blog/needrestart-local-privilege-escalation  
  
  
**新闻链接：**  
  
https://thehackernews.com/2024/11/decades-old-security-vulnerabilities.html  
  
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
  
福特指责第三方供应商造成数据泄露  
  
https://www.securityweek.com/ford-says-leaked-data-comes-from-supplier-and-is-not-sensitive/  
  
  
Ghost
Tap：黑客利用 NFCGate 通过移动支付窃取资金  
  
https://thehackernews.com/2024/11/ghost-tap-hackers-exploiting-nfcgate-to.html  
  
  
Ngioweb
僵尸网络助长 NSOCKS 住宅代理网络利用物联网设备  
  
https://thehackernews.com/2024/11/ngioweb-botnet-fuels-nsocks-residential.html  
  
  
金融科技巨头
Finastra 调查 SFTP 黑客攻击后的数据泄露事件  
  
https://www.bleepingcomputer.com/news/security/fintech-giant-finastra-investigates-data-breach-after-sftp-hack/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Ubuntu Needrestart 软件包中发现存在十年之久的安全漏洞，攻击者可以获得  
Root  
权限  
  
https://thehackernews.com/2024/11/decades-old-security-vulnerabilities.html  
  
  
Apple 确认 macOS 系统遭受  
0day  
漏洞攻击  
  
https://www.securityweek.com/apple-confirms-zero-day-attacks-hitting-intel-based-macs/  
  
  
Oracle 修补 Agile PLM 中一个已被广泛利用的高严重性信息泄露  
0day  
漏洞  
  
https://www.securityweek.com/oracle-patches-exploited-agile-plm-zero-day/  
  
  
D-Link
敦促用户淘汰受未修复 RCE 漏洞影响的 VPN 路由器  
  
https://www.bleepingcomputer.com/news/security/d-link-urges-users-to-retire-vpn-routers-impacted-by-unfixed-rce-flaw/  
  
  
六种已停产的
D-Link 路由器型号受到远程代码执行 (RCE) 漏洞的影响，该漏洞不会得到修补  
  
https://www.securityweek.com/d-link-warns-of-rce-vulnerability-in-legacy-routers/  
  
  
CISA 警告
Kemp LoadMaster 漏洞正在遭到利用  
  
https://www.securityweek.com/cisa-warns-of-progress-kemp-loadmaster-vulnerability-exploitation/  
  
  
苹果发布紧急更新，修复被积极利用的零日漏洞  
  
https://thehackernews.com/2024/11/apple-releases-urgent-updates-to-patch.html  
  
  
MITRE 分享
2024 年最危险的 25 个软件漏洞  
  
https://www.bleepingcomputer.com/news/security/mitre-shares-2024s-top-25-most-dangerous-software-weaknesses/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
