#  Microsoft 发布2024年3月补丁日安全更新，修复了60个漏洞，包括18个RCE   
 军哥网络安全读报   2024-03-13 09:00  
  
**导****读**  
  
  
  
今天是微软2024年3月补丁日，微软发布了针对60个漏洞的安全更新，其中包括18个远程代码执行漏洞。  
  
  
本月补丁仅修复了两个严重级别漏洞：Hyper-V
远程代码执行漏洞和拒绝服务漏洞。  
  
  
按漏洞类别统计：  
- 24个特权提升漏洞  
  
- 3个安全功能绕过漏洞  
  
- 18个远程代码执行漏洞  
  
- 6个信息泄露漏洞  
  
- 6个拒绝服务漏洞  
  
- 2个欺骗漏洞  
  
60 个安全漏洞总数不包括 3 月 7 日修复的 4 个 Microsoft Edge 缺陷。微软没有在今天的补丁日更新中披露任何  
0day  
漏洞。  
  
  
本次更新修复以下组件的安全漏洞：  
  
  
Microsoft Windows 、  
Office  
、Azure、.NET框架和Visual Studio、SQL Server、Windows Hyper-V、Skype、适用于
Android 的 Microsoft 组件、和微软Dynamics。  
  
  
微软还修复了另外五个 Chromium 缺陷。  
  
  
其中  
两个漏洞（编号为CVE-2024-21407 和 CVE-2024-21408）被评为“严重”级，而其余漏洞为“重要”级。  
  
  
漏洞
CVE-2024-21407 是 Windows Hyper-V 中的远程代码执行漏洞。  
  
  
“此漏洞需要来宾虚拟机上经过身份验证的攻击者向虚拟机上的硬件资源发送特制的文件操作请求，这可能会导致在主机服务器上远程执行代码。”
安全公告（https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21407）中写道：“成功利用此漏洞需要攻击者收集特定环境的信息，并在利用之前采取其他措施来准备目标环境。”  
  
  
漏洞
CVE-2024-21408 是 Windows Hyper-V 中的拒绝服务漏洞。  
  
  
Microsoft
解决的评分最高的漏洞是开放管理基础设施 (OMI) 远程代码执行漏洞，编号为CVE-2024-21334（CVSS 评分 9.8）。  
  
  
未经身份验证的远程攻击者可以触发此漏洞，在可通过
Internet 访问的 OMI 实例上执行代码。  
  
  
“目前尚不清楚有多少系统可以通过互联网访问，但数量可能很大。微软给出了“利用可能性较小”的评级，但考虑到这是一个针对重要目标的简单释放后使用
(UAF) 漏洞，预计 TCP 端口 5986 的扫描很快就会增加。” 据 ZDI报道。  
  
  
本月补丁日没有修复任何  
0  
day  
漏洞，但包含一些有趣的缺陷  
:  
  
  
CVE-2024-21400  
- Microsoft Azure Kubernetes 服务机密容器特权提升漏洞  
  
  
Microsoft
修复了 Azure Kubernetes 服务中的一个漏洞，该漏洞可能允许攻击者获得提升的权限并窃取凭据。  
  
  
Microsoft
安全公告解释道：“成功利用此漏洞的攻击者可能会窃取凭据并影响超出 Azure Kubernetes 服务机密容器 (AKSCC) 管理的安全范围的资源。”  
  
  
CVE-2024-26199 - Microsoft Office 权限提升漏洞  
  
  
Microsoft
修复了 Office 漏洞，该漏洞允许任何经过身份验证的用户获得系统权限。  
  
  
“任何经过身份验证的用户都可能触发此漏洞  
,  
它不需要管理员或其他提升的权限。”微软解释道。  
  
  
CVE-2024-20671 - Microsoft Defender 安全功能绕过漏洞  
  
  
微软修复了一个
Microsoft Defender 漏洞，微软解释说：“成功利用此漏洞的经过身份验证的攻击者可能会阻止 Microsoft Defender 启动。”  
  
  
这将通过
Windows 设备上自动安装的 Windows Defender 反恶意软件平台更新来解决。  
  
  
此缺陷已在反恶意软件平台
4.18.24010.12 版本中修复。  
  
  
CVE-2024-21411 - Skype for Consumer 远程代码执行漏洞  
  
  
微软修复了
Skype for Consumer 的一个远程代码执行漏洞，该漏洞可能由恶意链接或图像触发。  
  
  
微软解释说：“攻击者可以通过即时消息向用户发送恶意链接或恶意图像，然后说服用户单击该链接或图像来利用该漏洞。”  
  
  
更多信息参考微软安全更新发行说明：  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Mar  
  
  
**参考链接：**  
https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2024-patch-tuesday-fixes-60-flaws-18-rce-bugs/  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
Dropbox
用于在新颖的网络钓鱼活动中窃取凭据并绕过 MFA  
  
https://www.infosecurity-magazine.com/news/dropbox-credentials-bypass-mfa/  
  
  
微软证实俄罗斯黑客窃取了源代码和一些客户机密  
  
https://thehackernews.com/2024/03/microsoft-confirms-russian-hackers.html  
  
  
俄罗斯当局以网络间谍罪名拘留一名韩国公民  
  
https://securityaffairs.com/160396/breaking-news/russia-arrested-south-korean-national.html  
  
  
英国莱斯特市议会的  
 IT   
系统和电话因网络攻击而瘫痪  
  
https://www.hackread.com/leicester-council-cyber-attack-system-phone-down/  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
Ivanti
遭到入侵后，CISA 上个月被迫关闭两个系统  
  
https://therecord.media/cisa-takes-two-systems-offline-following-ivanti-compromise  
  
  
EquiLend
勒索软件攻击导致数据泄露  
  
https://www.securityweek.com/equilend-ransomware-attack-leads-to-data-breach/  
  
  
150,000
个系统可能受到最近的 Fortinet 漏洞 CVE-2024-21762 的影响  
  
https://www.securityweek.com/possibly-exploited-fortinet-flaw-impacts-many-systems-but-still-no-sign-of-mass-attacks/  
  
  
新的
BianLian 勒索软件攻击中利用了 TeamCity 漏洞  
  
https://securityaffairs.com/160357/hacking/bianlian-group-ttack-jetbrains-teamcity.html  
  
  
Magnet
Goblin 黑客利用 Ivanti 漏洞植入自定义 Linux 恶意软件  
  
https://www.csoonline.com/article/1312702/magnet-goblin-hackers-used-ivanti-bugs-to-drop-custom-linux-malware.html  
  
  
FBI
表示，勒索软件攻击更频繁地攻击关键基础设施  
  
https://www.cybersecuritydive.com/news/ransomware-hitting-critical-infrastructure-fbi/709814/  
  
  
斯坦福大学称
27,000 人的数据在 9 月份勒索软件攻击中泄露  
  
https://therecord.media/stanford-data-leaked-Akira-ransomware-attack  
  
  
假冒
Zoom、Skype 和 Google Meet 网站正在传播恶意软件  
  
https://www.uctoday.com/collaboration/fake-zoom-skype-and-google-meet-sites-are-spreading-malware/  
  
  
宏碁证实菲律宾员工数据在黑客论坛上泄露  
  
https://www.bleepingcomputer.com/news/security/acer-confirms-philippines-employee-data-leaked-on-hacking-forum/  
  
  
这些 PyPI
Python 包可能会耗尽你的加密钱包  
  
https://thehackernews.com/2024/03/watch-out-these-pypi-python-packages.html  
  
  
恶意软件活动利用
Popup Builder WordPress 插件感染 3,900 多个网站  
  
https://thehackernews.com/2024/03/malware-campaign-exploits-popup-builder.html  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
Microsoft 发布了 202  
4  
 年
3 月补丁日安全更新，修复了60个漏洞，包括18个RCE  
  
https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2024-patch-tuesday-fixes-60-flaws-18-rce-bugs/  
  
  
研究人员揭露了可用于网络攻击的
Microsoft SCCM （系统中心配置管理器）错误配置  
  
https://www.bleepingcomputer.com/news/security/researchers-expose-microsoft-sccm-misconfigs-usable-in-cyberattacks/  
  
  
被利用的建筑门禁系统漏洞在披露
5 年后得到修补  
  
https://www.securityweek.com/exploited-building-access-system-vulnerability-patched-years-after-disclosure/  
  
  
SAP
修补关键命令注入漏洞  
  
https://www.securityweek.com/sap-patches-critical-command-injection-vulnerabilities/  
  
  
Adobe
修补企业产品中的严重缺陷  
  
https://www.securityweek.com/adobe-patches-critical-flaws-in-enterprise-products/  
  
  
西门子和施耐德电气发布
2024 年 3 月补丁日公告，向客户通报 200 多个漏洞  
  
https://www.securityweek.com/ics-patch-tuesday-siemens-ruggedcom-devices-impacted-by-45-fortinet-vulnerabilities/  
  
  
严重漏洞允许访问
QNAP NAS 设备  
  
https://www.securityweek.com/critical-vulnerability-allows-access-to-qnap-nas-devices/  
  
  
Google
Chrome 中检测到新漏洞，请更新您的浏览器  
  
https://www.deccanherald.com/technology/new-vulnerabilities-detected-in-google-chrome-update-your-browser-cert-in-2931011  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
