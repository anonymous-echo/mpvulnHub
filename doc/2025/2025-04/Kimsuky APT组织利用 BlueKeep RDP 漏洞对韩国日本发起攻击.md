#  Kimsuky APT组织利用 BlueKeep RDP 漏洞对韩国日本发起攻击   
会杀毒的单反狗  军哥网络安全读报   2025-04-22 01:00  
  
**导****读**  
  
  
  
研究人员发现与曹县关联的  
APT  
组织 Kimsuky 的攻击活动，该组织利用已修补的 Microsoft 远程桌面服务漏洞来获取初始访问权限。  
  
  
在调查一起安全漏洞时，韩国安博士实验室安全情报中心 (ASEC) 的研究人员发现了与朝鲜有关联的组织Kimsuky的攻击活动，其追踪编号为 Larva-24005。攻击者利用 RDP 漏洞获取了目标系统的初始访问权限。  
  
  
ASEC 发布的报告中写道：“在某些系统中，初始访问权限是通过利用 RDP 漏洞 (BlueKeep，CVE-2019-0708) 获得的。虽然在受感染的系统中发现了 RDP 漏洞扫描程序，但没有证据表明其被实际使用。”  
  
  
 “威胁组织还使用其他手段传播恶意软件，例如将同一文件附加到电子邮件中，并利用 Microsoft Office 公式编辑器漏洞 (CVE-2017-11882) 。”  
  
  
一旦获得系统访问权限，攻击者就会通过安装 MySpy 恶意软件和 RDPWrap 来修改配置，以维持远程访问。  
  
  
在最后阶段，攻击者部署了 KimaLogger 或 RandomQuery 键盘记录器来记录键盘操作。专家观察到 Kimsuky 从受感染的系统向韩国和日本发送钓鱼邮件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHFEbVQ7JYAgFpfmQkRUPkJKDuRK2lz9lzO91OT3a0HpgVCYKzVfoBbQjnLmRFrEdE8Wep2yic0mrA/640?wx_fmt=png&from=appmsg "")  
  
  
自2023年9月以来，朝鲜APT组织已将韩国、美国、中国、日本、德国、新加坡和其他多个国家的组织作为目标。他们的活动包括针对韩国和日本的网络钓鱼活动，以及自2023年10月以来对韩国软件、能源和金融部门的攻击。  
  
  
ASEC 研究人员还发布了此次活动的攻击检测指标 (IoC)。  
  
  
Kimsuky 网络间谍组织 （又名 ARCHIPELAGO、Black Banshee、  
   
Thallium、Velvet Chollima、  
    
APT43）于 2013 年首次被卡巴斯基研究人员发现 。  
  
  
该APT组织主要针对韩国的智库和组织，其他受害者位于美国、欧洲和俄罗斯。  
  
  
今年 2 月，ASEC 研究人员发现朝鲜的 Kimsuky  
    
APT 组织发起了鱼叉式网络钓鱼攻击，以传播 forceCopy 信息窃取恶意软件。  
  
  
受政府支持的黑客发送鱼叉式网络钓鱼邮件，传播伪装成Office文档的恶意*.LNK快捷方式文件。打开后，他们会执行PowerShell或Mshta脚本，下载 PebbleDash 和RDP Wrapper等恶意软件，以控制受感染的系统。  
  
  
攻击者使用定制的 RDP Wrapper 来实现远程桌面访问，并可能修改导出功能以逃避检测。  
  
  
研究人员注意到，威胁组织还安装了代理恶意软件，以实现对位于私人网络中的受感染系统的外部访问。  
  
  
Kimsuky 组织使用多种文件格式的键盘记录器，包括 PowerShell 脚本。  
  
  
Kimsuky 还使用 forceCopy 窃取恶意软件来捕获击键并从浏览器目录中提取文件。  
  
  
技术报告：  
  
https://asec.ahnlab.com/en/87554/  
  
  
新闻链接：  
  
https://securityaffairs.com/176756/apt/kimsuky-apt-exploited-bluekeep-rdp-flaw-in-attacks-against-south-korea-and-japan.html  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/McYMgia19V0WHlibFPFtGclHY120OMhgwDUwJeU5D8KY3nARGC1mBpGMlExuV3bibicibJqMzAHnDDlNa5SZaUeib46xSzdeKIzoJA/640?wx_fmt=svg "")  
  
**今日安全资讯速递**  
  
  
  
**APT事件**  
  
  
Advanced Persistent Threat  
  
RedGolf 黑客与 Fortinet 零日漏洞和网络攻击工具有关  
  
https://gbhackers.com/redgolf-hackers-linked-to-fortinet-zero-day-exploits/  
  
  
黑客利用反向 SSH 工具发起新一轮组织攻击  
  
https://gbhackers.com/chinese-hackers-leverage-reverse-ssh-tool/  
  
  
Kimsuky  
 APT  
组织利用 BlueKeep RDP 漏洞对韩国和日本发起攻击  
  
https://securityaffairs.com/176756/apt/kimsuky-apt-exploited-bluekeep-rdp-flaw-in-attacks-against-south-korea-and-japan.html  
  
  
朝鲜 IT 工作者利用实时 Deepfakes 通过远程工作渗透目标  
  
https://gbhackers.com/north-korean-it-workers-use-real-time-deepfakes-to-infiltrate-organizations/  
  
  
  
**一般威胁事件**  
  
  
General Threat Incidents  
  
FortiGuard 实验室发现一个通过 TOTOLINK 设备传播的新型僵尸网络“RustoBot”  
https://www.fortinet.com/blog/threat-research/new-rust-botnet-rustobot-is-routed-via-routers  
  
  
Greenshift WordPress 插件中的任意文件上传漏洞影响 5 万个 WordPress 网站  
  
https://www.wordfence.com/blog/2025/04/50000-wordpress-sites-affected-by-arbitrary-file-upload-vulnerability-in-greenshift-wordpress-plugin/  
  
  
朝鲜加密货币窃贼劫持Zoom“远程控制”功能  
  
https://www.securityweek.com/north-korean-cryptocurrency-thieves-caught-hijacking-zoom-remote-control-feature/  
  
  
新型网络钓鱼技术将武器化的 HTML 文件隐藏在 SVG 图像中  
  
https://gbhackers.com/new-phishing-technique-hides-weaponized-html-files/  
  
  
ResolverRAT通过网络钓鱼传播至医疗保健领域  
  
https://hackread.com/native-language-phishing-resolverrat-healthcare/  
  
  
Booking.com 网络钓鱼诈骗利用虚假验证码安装 AsyncRAT  
  
https://hackread.com/booking-com-phishing-scam-fake-captcha-asyncrat/  
  
  
美国肾病护理和透析服务提供商  
  
DaVita 遭遇勒索软件攻击，部分业务中断  
  
https://www.cysecurity.news/2025/04/davita-faces-ransomware-attack.html  
  
  
通过钓鱼邮件进行的信息窃取攻击每周交付量比上一年增加 84%  
  
https://cybersecuritynews.com/attack-via-infostealers-increased/  
  
  
黑客利用俄罗斯防弹托管主机 Proton66 发起广泛的网络攻击  
  
https://www.esecurityplanet.com/cybersecurity/hackers-exploit-russian-proton66/  
  
  
一种可绕过  
EDR  
和  
AV  
安全软件的“Baldwin Killer”复杂恶意工具正在暗网推销  
  
https://cybersecuritynews.com/baldwin-killer-bypasses-av-edr/  
  
  
**漏洞事件**  
  
  
Vulnerability Incidents  
  
关键基础设施中使用的 Lantronix 设备使系统面临远程黑客攻击  
  
https://www.securityweek.com/lantronix-device-used-in-critical-infrastructure-exposes-systems-to-remote-hacking/  
  
  
华硕确认 AiCloud 路由器存在严重缺陷；敦促用户更新固件  
  
https://securityaffairs.com/176697/security/asus-warns-of-a-router-authentication-bypass-flaw.html  
  
  
CVE-2025-24054 遭受主动攻击——文件下载时窃取 NTLM 凭证  
  
https://thehackernews.com/2025/04/cve-2025-24054-under-active.html  
  
  
CISA 警告称，多个 Apple   
0day  
漏洞正被利用于攻击  
  
https://cybersecuritynews.com/apple-0-day-vulnerabilities-exploited/  
  
  
AnythingLLM 漏洞致系统面临远程代码执行风险  
  
https://gbhackers.com/critical-anythingllm-vulnerability/  
  
  
WordPress插件安全漏洞曝光数小时后遭黑客利用  
  
https://www.cysecurity.news/2025/04/hackers-target-wordpress-plugin-just.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
