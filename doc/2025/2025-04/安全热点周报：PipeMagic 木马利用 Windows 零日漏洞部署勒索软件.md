#  安全热点周报：PipeMagic 木马利用 Windows 零日漏洞部署勒索软件   
 奇安信 CERT   2025-04-14 09:15  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">《数据安全技术 政务数据处理安全要求》等6项网络安全国家标准发布</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">摩洛哥国家社保基金遭网络攻击，近200万民众敏感数据或泄露</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">美国工业传感器上市公司森萨塔遭勒索攻击，生产运营被迫中断</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Foxmail for Windows远程代码执行漏洞安全风险通告**  
  
  
4月11日，奇安信威胁情报中心红雨滴团队于2025年初在威胁情报狩猎过程中观测到客户网络中的异常行为，协助应急响应时溯源到最初的邮件攻击来源，提取到了相关邮件，分析显示攻击者组合利用了Foxmail客户端存在的高危漏洞(QVD-2025-13936)，受害者仅需点击邮件本身即可触发远程命令执行，最终执行落地的木马。情报中心第一时间复现确认了所发现的新漏洞，并将其上报给腾讯Foxmail业务团队。目前该漏洞已经被修复，最新版的Foxmail 7.2.25 (2025-03-28)不受影响，Foxmail团队给以了致谢。  
  
  
**2.Vite任意文件读取漏洞(CVE-2025-32395)安全风险通告**  
  
  
4月11日，奇安信CERT监测到官方修复Vite任意文件读取漏洞(CVE-2025-32395)，该漏洞源于Vite开发服务器在处理特定URL请求时，没有对请求的路径进行严格的安全检查和限制，导致攻击者可以绕过保护机制，非法访问项目根目录外的敏感文件。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为47506个，关联IP总数为10961个。目前该漏洞技术细节与PoC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
**3.Vite任意文件读取漏洞(CVE-2025-31486)安全风险通告**  
  
  
4月7日，奇安信CERT监测到官方修复Vite任意文件读取漏洞(CVE-2025-31486)，该漏洞源于Vite开发服务器在处理特定URL请求时，没有对请求的路径进行严格的安全检查和限制，导致攻击者可以绕过保护机制，非法访问项目根目录外的敏感文件。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为47363个，关联IP总数为10948个。目前该漏洞技术细节与PoC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Linux Kernel 越界访问漏洞(CVE-2024-53197)&Linux Kernel 越界读取漏洞(CVE-2024-53150)******  
  
  
4月9日，Google 已经修补了 Android 中的 62 个漏洞，其中包括两个在攻击中被积极利用的零日漏洞，分别被跟踪为 CVE-2024-53197 和 CVE-2024-53150。  
  
CVE-2024-53197 是在 Linux 内核的 USB 音频子组件中发现的权限提升缺陷。本地攻击者能够利用该漏洞访问设备上的敏感信息，而无需任何用户交互。它还没有 CVSS 评级，但据 Malwarebytes Labs 的研究人员称，这是另外两个漏洞（CVE-2024-50302 和 CVE-2024-53104）之间的联系，使得塞尔维亚的执法部门能够在尝试安装间谍软件之前使用 Cellebrite 取证工具解锁学生活动家的设备。  
  
同样，CVE-2024-53150 是 Linux 内核的 USB 子组件中的越界缺陷，也可能导致信息泄露。同样，不需要用户交互。NVD 将此漏洞的 CVSS 评级为 7.1，但没有关于此漏洞如何被攻击利用或由谁利用的详细信息。  
  
针对这些漏洞的补丁以及最新一轮更新中的其他 60 个漏洞均适用于 Android 13。14 和 15，但这些修复程序可能无法立即适用于所有设备，因为各个手机制造商必须将它们推广到特定的客户群。用户可以转到“关于手机”或“关于设备”来检查可能适用于其手机品牌和型号的软件更新。  
  
  
参考链接：  
  
https://www.darkreading.com/vulnerabilities-threats/android-zero-day-bugs-active-exploit  
  
**2.********Gladinet CentreStack 反序列化漏洞(CVE-2025-30406)******  
  
  
4月9日，美国网络安全和基础设施安全局 (CISA)将 CVE-2025-30406 添加到其已知可利用漏洞目录中。  
  
自3月份以来，托管服务提供商 (MSP) 广泛使用的文件共享平台中的一个严重零日漏洞一直受到攻击。该漏洞编号为 CVE-2025-30406，是 Gladinet 旗下企业文件共享平台 CentreStack 中的一个反序列化漏洞。根据 CVE.org 和国家漏洞数据库 (NVD) 的记录，该 CentreStack 漏洞于4月3日公开披露，3月份以来一直处于被利用状态。Gladinet 在其安全公告中还表示，已观察到有人在野利用该漏洞。  
  
Gladinet 的安全公告指出，该漏洞源于“IIS web.config 文件中一个硬编码或保护不当的 machineKey，该文件负责保护 ASP.NET ViewState 数据”。如果威胁行为者获取或猜测到加密密钥，他们就可以制作能够通过完整性检查的恶意 ViewState 负载。  
  
CVE.org 和 NVD 均表示，该漏洞是由于“使用硬编码的 machineKey”造成的。Picus Security 联合创始人兼 Picus Labs 副总裁 Süleyman Özarslan 表示，这表明密钥在某种程度上已被泄露。Özarslan 在一封电子邮件中表示：“如果威胁行为者获得此密钥，他们就可以制作通过完整性检查的恶意负载，从而导致服务器端反序列化，并最终导致远程代码执行 (RCE)。  
  
或许更重要的是，CentreStack 被 MSP 和解决方案提供商广泛使用，这可能会危及许多下游客户。攻陷 MSP 的 CentreStack 可能会让威胁行为者获得访问客户网络和数据的特权。  
  
Gladinet 是一家位于佛罗里达州博卡拉顿的私营软件公司。根据该公司网站，CentreStack 被 1,000 多家 IT 解决方案提供商用作安全、无需 VPN 的文件共享平台。近年来，威胁行为者瞄准了托管服务提供商 (MSP) 广泛使用的工具和平台，以危害其客户。例如，2024 年，网络犯罪分子利用 ConnectWise ScreenConnect 软件中的关键漏洞，进行了大规模攻击活动，向下游客户发送了勒索软件。  
  
Gladinet 在其安全公告中敦促用户升级到 16.4.10315.56368 版本，该版本会为每个安装自动生成唯一的 machineKey。公告中指出：对于无法立即更新的用户，建议更换 machineKey 值作为临时缓解措施。  
  
  
参考链接：  
  
https://www.darkreading.com/vulnerabilities-threats/zero-day-centrestack-platform-under-attack  
  
**3.****Windows 通用日志文件系统驱动程序权限提升漏洞(CVE-2025-29824)**  
  
  
4月8日，微软透露，影响 Windows 通用日志文件系统 (CLFS) 的一个现已修补的安全漏洞被利用作为针对少数目标的零日勒索软件攻击。微软表示，RansomEXX 勒索软件团伙一直在利用 Windows 通用日志文件系统中的高严重性零日漏洞来获取受害者系统的系统权限。  
  
该漏洞编号为 CVE-2025-29824 ，已于本月的补丁日进行修补，且仅在有限数量的攻击中被利用。CVE-2025-29824 是由于存在使用后释放漏洞而导致的，该漏洞允许具有低权限的本地攻击者在不需要用户交互的低复杂度攻击中获得系统权限。  
  
虽然该公司已经针对受影响的 Windows 版本发布了安全更新，但它推迟了针对运行 Windows 10 LTSB 2015 的系统的补丁发布，并表示将尽快发布。  
  
微软透露：“目标包括美国信息技术 (IT) 和房地产行业的组织、委内瑞拉的金融行业、西班牙的软件公司以及沙特阿拉伯的零售业。”即使存在漏洞，运行 Windows 11 版本 24H2 的客户也不会受到观察到的漏洞的影响。敦促客户尽快应用这些更新。  
  
微软将这些攻击与 RansomEXX 勒索软件团伙联系起来，该团伙被追踪为 Storm-2460。攻击者首先在受感染的系统上安装了 PipeMagic 后门恶意软件，该恶意软件用于在加密文件后部署 CVE-2025-29824 漏洞、勒索软件负载和 !_READ_ME_REXX2_!.txt 勒索信。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/microsoft-windows-clfs-zero-day-exploited-by-ransomware-gang/  
  
  
**4.****CrushFTP 服务器端认证绕过漏洞(CVE-2025-31161)**  
  
  
4月7日，针对 CrushFTP 文件传输软件中一个严重漏洞的攻击活动仍在继续，该软件一直深陷持续不断的披露争议之中。  
  
安全供应商 Huntress 详细介绍了其于4月3日检测到的 CVE-2025-31161 的在野利用活动。该网络安全供应商表示，早在3月30日就发现了潜在的入侵证据，尽管该活动似乎只是在测试对易受攻击实例的访问。   
  
Huntress 警告称，近年来，文件传输产品和服务已成为攻击者的重灾区。该公司在一篇博客文章中指出：“这些平台通常面向外部，存储敏感的企业数据，因此成为威胁行为者的宠儿。因此，及时修补至关重要。”  
  
CrushFTP 漏洞于3月21日首次曝光，当时该公司通过电子邮件私下通知了客户。CrushFTP 当天还发布了简短的安全公告，敦促客户更新至 11.3.1 版本。但不久之后，CrushFTP 和其他几家公司因 CVE 重叠而陷入了一场信息披露纠纷。  
  
本周针对易受攻击的 CrushFTP 实例的攻击仍在继续。近年来，文件传输产品和服务已成为攻击者的热门目标。分析人员表示，攻击活动似乎在4月1日至4月3日之间达到顶峰，但针对CrushFTP用户的攻击仍在持续。“影响将会很严重，因为很多用户并没有意识到自己被黑了，所以他们得等很久才能发现，”他说道。“现在攻击少了，很多用户都更新了，但仍有一些用户更新速度慢，导致更新延迟。”  
  
Huntress 在近期发布的博客文章更新中表示，漏洞利用活动仍在继续。该公司表示：“4月7日，我们观察到一名威胁行为者利用 CrushFTP（版本 10）的一个易受攻击的实例，在主机上安装 SimpleHelp RMM 作为持久化机制。”  
  
建议 CrushFTP 用户尽快将其软件更新至 11.3.1+ 和 10.8.4+ 版本。如果无法更新，建议企业在 CrushFTP 中启用 DMZ 边界网络选项作为替代方案。  
  
  
参考链接：  
  
https://www.darkreading.com/vulnerabilities-threats/crushftp-exploitation-disclosure-dispute  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.美国工业传感器上市公司森萨塔遭勒索攻击，生产运营被迫中断**  
  
  
4月10日Bleeping Computer消息，美国上市公司、知名传感器生产商森萨塔科技（Sensata Technologies）遭遇勒索软件攻击，公司网络内的部分设备遭到加密，致使业务运营中断。森萨塔在SEC披露文件中表示，此次攻击发生于4月6日（星期日），涉及数据被窃取的情况。此次事件已对森萨塔的运营造成暂时影响，包括发货、收货、制造生产以及其他多个支持职能。森萨塔表示，公司已立即采取措施，加快受此次网络攻击影响的关键功能的恢复工作，不过目前尚无法提供完整的恢复时间表。公司表示，预计本季度的财务业绩不会受到实质性影响。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/sensata-technologies-hit-by-ransomware-attack-impacting-operations/  
  
**2.摩洛哥国家社保基金遭网络攻击，近200万民众敏感数据或泄露**  
  
  
4月9日Yabiladi消息，摩洛哥国家社保基金疑似发生重大数据泄露事件，超过5.4万份文件被盗，近200万企业员工的敏感数据泄露，其中涉及姓名、身份证号码、公司关系、邮件地址、电话号码、银行账户、工资申报记录等。该机构声明称，初步调查显示，此次泄密是由于攻击者绕过了安全系统。声明未透露攻击者的身份，但表示对方发布的许多文件具有误导性、不准确或不完整。此前，疑似阿尔及利亚黑客组织JabaRoot DZ在Telegram和暗网泄露论坛上发布了相关数据。  
  
  
原文链接：  
  
https://en.yabiladi.com/articles/details/163560/algerian-hackers-leak-sensitive-data.html  
  
**3.山东一在校大学生非法获取超2万条个人信息，滥用AI群发骚扰短信**  
  
  
4月7日公安部网安局消息，山东公安网安部门侦破一起非法获取计算机信息系统数据案，犯罪嫌疑人非法获取两万余条学生个人信息，后利用AI技术向其中的两千余名学生发送骚扰短信。犯罪嫌疑人胡某是一名在校大学生，非法入侵了学校某系统并获取两万余条该校学生个人信息。为寻求刺激、炫耀技术，胡某通过之前发现的某小程序存在的技术漏洞，利用AI编写程序，把其中盗取的上千余名学生的手机号码在该小程序上批量注册账户，后将短信验证码篡改为淫秽内容发送至学生本人，对其进行短信骚扰。目前，犯罪嫌疑人对非法获取计算机信息系统数据罪供认不讳，案件正在进一步侦办中。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/zDDYvs2E4B_A1FzgkndNZg  
  
**4.澳大利亚多家大型养老基金超2万个账号遭入侵，数百万元养老储蓄金被盗**  
  
  
4月5日路透社消息，据知情人士透露，黑客对澳大利亚主要的养老金基金发起了一系列协同攻击。在3月29日至30日（周末）期间，多家大型养老基金超过2万个用户账号遭到入侵，其中仅AustralianSuper基金用户就有至少50万澳元（约合人民币220万元）的资金被转出。目前整体损失规模尚不确定，AustralianSuper、Australian Retirement Trust、Rest、Insignia及Hostplus等知名基金均确认受到影响。澳大利亚国家网络安全协调员Michelle McGuinness发布声明称，网络犯罪分子正以澳大利亚4.2万亿澳元退休储蓄领域的账号为目标，目前正协调政府、监管机构及相关行业作出应对。  
  
  
原文链接：  
  
https://www.reuters.com/technology/cybersecurity/multiple-australian-pension-funds-hit-by-coordinated-hacking-media-reports-say-2025-04-04/  
  
  
**5.美国巴尔的摩市政府遭社工攻击，超1100万元供应商合同款被盗**  
  
  
4月3日StateScoop消息，美国马里兰州首府巴尔的摩市审计长办公室透露，3月份发生的一起网络攻击事件导致该市遭遇身份盗窃欺诈，损失超过150万美元（约合人民币1100万元）。副审计长Erika McClammy表示，3月13日，该市收到通知称，一名网络犯罪分子攻击了市政府的应付账款部门，并通过身份盗窃手段获取了超过150万美元的资金，这笔款项原计划支付给一名市政供应商。  McClammy表示：“我们目前尚未确定幕后黑手的身份。显然，对方很可能使用了多个身份。他们成功绕过了巴尔的摩市的地理围栏系统，使用了（星链）IP地址。”官方报告指出，犯罪分子从去年秋季开始与市政府建立联系，利用网络上公开的信息，冒充一名现有供应商的员工，与多个市政部门建立了联系，从而逐步渗透进市政系统。  
  
  
原文链接：  
  
https://statescoop.com/city-of-baltimore-reportedly-lost-1-5m-in-id-theft-cyberattack/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.欧盟EDPB发布《人工智能隐私风险和缓解指南：大语言模型》**  
  
  
4月10日，欧洲数据保护委员会（EDPB）发布了由第三方专家撰写的《人工智能隐私风险和缓解指南：大语言模型》报告。该文件提出了一套全面的大语言模型系统风险管理方法，以系统地识别、评估和缓解隐私与数据保护风险，并针对大语言模型系统的常见隐私风险提出了一系列可实践的缓解措施。该文件还提供了三个具体场景的应用案例，包括用于客户询问的聊天机器人、监控和支持学生改进的大语言模型系统、旅行和日程管理AI助手。  
  
原文链接：  
  
https://www.edpb.europa.eu/system/files/2025-04/ai-privacy-risks-and-mitigations-in-llms.pdf  
  
  
**2.《数据安全技术 政务数据处理安全要求》等6项网络安全国家标准发布**  
  
  
4月9日，根据2025年3月28日国家市场监督管理总局、国家标准化管理委员会发布的中华人民共和国国家标准公告（2025年第6号），全国网络安全标准化技术委员会归口的6项国家标准正式发布。具体包括《网络安全技术 运维安全管理产品技术规范》《数据安全技术 政务数据处理安全要求》《数据安全技术 基于个人信息的自动化决策安全要求》《数据安全技术 数据安全评估机构能力要求》《数据安全技术 大型互联网企业内设个人信息保护监督机构要求》《网络关键设备安全技术要求 可编程逻辑控制器（PLC）》。  
  
  
原文链接：  
  
https://www.tc260.org.cn/upload/2025-04-09/1744186665582029457.pdf  
  
  
**3.欧盟发布《数字欧洲计划2025-2027年工作规划》**  
  
  
3月28日，欧盟委员会发布了《数字欧洲计划2025-2027年工作规划》。该文件重点关注人工智能、云计算、数据、网络安全等领域，支持欧盟成为“人工智能大陆”的战略目标。该文件将投入4560万欧元用于网络安全领域，包括建立欧盟网络安全储备、开发《网络弹性法案》单一报告平台及发展网络安全技能学院等。该文件还将投入3.672亿欧元用于欧洲网络安全能力中心，重点投资人工智能、后量子转型等网络安全新技术。该文件反映了欧盟在技术主权、民主和安全方面的政治优先事项，将为欧洲数字化转型提供强有力的支持，推动欧洲在全球数字创新舞台上的领先地位。  
  
  
原文链接：  
  
https://ec.europa.eu/newsroom/dae/redirection/document/114219  
  
  
**往期精彩推荐**  
  
  
[Foxmail 官方致谢！Foxmail for Windows 远程代码执行漏洞(QVD-2025-13936)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503309&idx=1&sn=7a1ece2cfde74c26341f4eba4ff36737&scene=21#wechat_redirect)  
  
  
[【已复现】Vite 任意文件读取漏洞(CVE-2025-32395)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503309&idx=2&sn=d2d68c02256db122161080d7fe2713f9&scene=21#wechat_redirect)  
  
[微软4月补丁日多个产品安全漏洞风险通告：1个在野利用、11个紧急漏洞](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503290&idx=1&sn=a8392249522b3dfdf21eb6cd1a34ac57&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
