> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795784&idx=1&sn=fb915e868a9d8d22b81e2dc4bbf431a6

#  APT41威胁组织针对非洲IT基础设施  
会杀毒的单反狗  军哥网络安全读报   2025-07-22 01:00  
  
**导****读**  
  
  
  
卡巴斯基分析师最近发现网络间谍组织 APT41 针对非洲地区 IT 服务发起的复杂针对性攻击，攻击者将内部服务、IP 地址和代理服务器的硬编码名称直接嵌入到他们的恶意软件中，展现了深度的事先侦察。  
  
  
在受害者基础设施内受感染的 SharePoint 实例上建立了一个关键的命令和控制 (C2) 服务器，允许进行隐秘的内部通信。  
  
  
此次入侵最初是通过多个工作站上的可疑活动检测到的，由 Impacket 工具包的 WmiExec 模块发出的警报触发。  
  
  
这表现为一个涉及 svchost.exe 生成 cmd.exe 的进程链，其中命令输出重定向到管理网络共享上的文件，以点分数字模式命名。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFnHHLLDG3Y6CahZlmucfaxTtehet8HJrKYib836m1yZC8uia0R8UqSE58flIsjqgHtcnMzN4LqkBLw/640?wx_fmt=png&from=appmsg "")  
  
WmiExec 进程树  
  
  
类似地，Atexec 模块用于创建计划任务，以直接或通过内部代理探测 C2 可用性。  
  
  
报告称，追踪到的源头是一个未受监控的受感染主机，该主机在服务账户下运行 Impacket，后来被集成到遥测中以进行更深入的分析。  
  
  
初次执行后，攻击者短暂暂停操作，然后使用 netstat 和 tasklist 等侦察命令恢复，以识别正在运行的进程和端口，可能是为了寻找 EDR 或 XDR 代理等安全解决方案。  
  
### 权限提升  
###   
  
权限提升涉及使用 reg.exe 转储 SYSTEM 和 SAM 注册表配置单元，尽管监控系统受到阻止，但仍成功从不安全的主机收集凭据。  
  
  
攻击者利用具有本地管理员权限的域帐户和具有域管理员权限的备份帐户通过 SMB 进行横向移动，将 Cobalt Strike 和自定义代理等工具传输到 C:\Windows\Tasks 或 C:\ProgramData 等路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFnHHLLDG3Y6CahZlmucfaxulicZ9uR4uOdibMrRjC6Qm8nlPSyW73jD6jNErhcNzewiaFkvZ5CtQULA/640?wx_fmt=png&from=appmsg "")  
  
通过特权账户进行横向移动  
  
  
执行通过 WMI 远程进行，Cobalt Strike 部署为加密有效负载（例如 TXT 或 INI 文件），通过cookie_exporter.exe 或 TmPfw.exe 等合法应用程序中的DLL 侧加载解密。  
  
  
恶意 DLL 包括针对调试环境和语言包的反分析检查（例如，避免在日语、韩语或中文系统运行），在将有效载荷注入内存或新进程之前，使用 SSE 加速例程对其进行解密。  
  
  
自定义 C# 木马 agent.exe 和 agentx.exe 与 SharePoint C2 上的 CommandHandler.aspx Web shell 进行通信，以通过 upload.ashx 执行命令和泄露数据，收集浏览器历史记录、文档和配置。  
  
  
其他工具包括用于获取凭证和项目数据的修改版 Pillager 窃取程序，编译为 wmicodegen.dll 并通过 convert-moftoprovider.exe 侧载；Checkout 用于获取浏览器和信用卡信息；RawCopy 用于提取原始注册表文件；以及通过 java.exe 侧载的 Mimikatz DLL 用于凭证转储。  
  
  
使用从模拟域（如 github.githubassets.net）下载的恶意 HTA 文件建立反向 shell，从而实现持久命令访问。  
  
  
回顾性分析表明，IIS Web 服务器是初始入口点，在 ASP.NET 临时文件中托管Cobalt Strike和Neo-reGeorg Web Shell（检测为 HEUR:Backdoor.MSIL.WebShell.gen），代理 Impacket 启动的外部流量。  
  
  
基于各种攻击技术步骤 (TTP)，例如 Impacket/WMI 使用、DLL 侧载、C:\Windows\Temp 文件放置以及类似的 C2 域名（例如 s3-azure.com 变体），  
  
卡巴斯基高度可信地认为该攻击与 APT41 有关。  
  
  
完整技术报告：  
  
https://securelist.com/apt41-in-africa/116986/  
  
  
新闻链接：  
  
https://gbhackers.com/apt41-hackers-exploiting-atexec-and-wmiexec-windows-modules/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
UNG0002 利用 Cobalt Strike 和 Metasploit 向目标组织部署武器化的 LNK 文件  
  
https://gbhackers.com/ung0002-deploys-weaponized-lnk-files/  
  
  
APT41威胁组织针对非洲IT基础设施发起间谍活动  
  
https://gbhackers.com/apt41-hackers-exploiting-atexec-and-wmiexec-windows-modules/  
  
  
伊朗 APT 利用 DCHSpy 间谍软件新变种攻击 Android 用户  
  
https://www.securityweek.com/new-variants-of-dchspy-spyware-used-by-iranian-apt-to-target-android-users/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
黑客利用 Apache HTTP 服务器漏洞部署 Linuxsys 加密货币挖矿程序  
  
https://thehackernews.com/2025/07/hackers-exploit-apache-http-server-flaw.html  
  
  
Ivanti 零日漏洞被利用，导致 MDifyLoader 被释放并发起内存 Cobalt Strike 攻击  
  
https://thehackernews.com/2025/07/ivanti-zero-days-exploited-to-drop.html  
  
  
DeerStealer 恶意软件通过武器化的 .LNK 和 LOLBin 工具传播  
  
https://gbhackers.com/deerstealer-malware-spread-through-weaponized-lnk/  
  
  
攻击者入侵热门 npm 软件包，窃取维护者的代币  
  
https://gbhackers.com/threat-actors-compromise-popular-npm-packages/  
  
  
攻击者利用 Zoho WorkDrive 文件夹传播经混淆的 PureRAT 恶意软件  
  
https://cybersecuritynews.com/threat-actors-leverage-zoho-workdrive-folder/  
  
  
印度加密货币交易所 CoinDCX 确认遭黑客攻击，损失 4400 万美元  
  
https://techcrunch.com/2025/07/21/indian-crypto-exchange-coindcx-confirms-44-million-stolen-during-hack/  
  
  
新型勒索软件 KAWA4096 利用 Windows 管理工具删除卷影副本  
  
https://cybersecuritynews.com/new-kawa4096s-ransomware/  
  
  
World Leaks 称戴尔数据遭泄露，泄露 1.3 TB 文件  
  
https://hackread.com/world-leaks-dell-data-breach-leaks-1-3-tb-of-files/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
微软发布 SharePoint   
0day  
漏洞紧急补丁，但问题尚未完全解决  
  
https://www.zdnet.com/article/microsoft-fixes-two-sharepoint-zero-days-under-attack-but-its-not-over-how-to-patch/  
  
  
HPE警告称Aruba硬编码凭证可使攻击者绕过设备身份验证  
  
https://cybersecuritynews.com/hpe-aruba-hardcoded-credentials/  
  
  
PHP PDO 漏洞允许攻击者注入恶意 SQL 命令  
  
https://gbhackers.com/php-pdo-flaw/  
  
  
攻击者可利用 Lighthouse Studio RCE 漏洞获取服务器访问权限  
  
https://gbhackers.com/attackers-can-exploit-lighthouse-studio-rce-bug/  
  
  
Livewire 漏洞可能导致数百万 Laravel 应用遭受远程代码执行攻击  
  
https://cybersecuritynews.com/livewire-rce-vulnerability/  
  
  
Microsoft AppLocker 漏洞可使恶意应用程序绕过安全限制  
  
https://gbhackers.com/microsoft-applocker-flaw/  
  
  
利用 CrushFTP 零日漏洞可获得服务器管理员访问权限  
  
https://www.securityweek.com/exploited-crushftp-zero-day-provides-admin-access-to-servers/  
  
  
新的 7-Zip 漏洞可使武器化的 RAR5 文件造成系统崩溃  
  
https://cybersecuritynews.com/7-zip-vulnerability-crash-system/  
  
  
Fortinet FortiWeb 漏洞在 PoC 发布后遭广泛利用  
  
https://www.securityweek.com/fortinet-fortiweb-flaw-exploited-in-the-wild-after-poc-publication/  
  
  
Nvidia工具包严重漏洞导致AI云服务易受黑客攻击  
  
https://www.securityweek.com/critical-nvidia-toolkit-flaw-exposes-ai-cloud-services-to-hacking/  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
