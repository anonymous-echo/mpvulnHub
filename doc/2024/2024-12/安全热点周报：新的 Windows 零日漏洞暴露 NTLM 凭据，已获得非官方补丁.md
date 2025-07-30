#  安全热点周报：新的 Windows 零日漏洞暴露 NTLM 凭据，已获得非官方补丁   
 奇安信 CERT   2024-12-09 10:04  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 中共中央办公厅、国务院办公厅公布《关于推进新型城市基础设施建设打造韧性城市的意见》</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 欧洲理事会通过两项新法案加强网络安全</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 严重损害数据安全，湖南一IT公司被罚20万元</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.SonicWall SMA100 SSLVPN多个高危漏洞安全风险通告**  
  
  
12月6日，奇安信CERT监测到官方修复SonicWall SMA100 SSLVPN Web管理页面栈缓冲区溢出漏洞(CVE-2024-45318)和SonicWall SMA100 mod_httprp栈缓冲区溢出漏洞(CVE-2024-53703)，SonicWall SMA100 SSLVPN的Web管理界面和Apache Web服务器加载的mod_httprp库分别存在两个栈缓冲区溢出漏洞，这些漏洞可能允许远程攻击者执行任意代码，造成系统敏感数据泄露甚至服务器被接管等严重安全威胁。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.ProFTPD权限提升漏洞安全风险通告**  
  
  
12月4日，奇安信CERT监测到官方修复ProFTPD权限提升漏洞(CVE-2024-48651)。ProFTPD是一款流行的FTP服务器软件。在Linux系统中，每个用户都有一个主组和零个或多个附加组，主组是用户登录时默认分配的组，而附加组是用户可以随时加入的其他组。此漏洞是由于在受影响的版本中，如果用户没有任何明确分配的附加组，则会继承GID为0(root)的附加组。这将允许攻击者获得对目标系统的root访问权限，最终可能会导致系统完全受损。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为21447个，关联IP总数为20019个。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.Zabbix SQL注入漏洞安全风险通告**  
  
  
12月2日，奇安信CERT监测到官方修复Zabbix SQL注入漏洞(CVE-2024-42327)，Zabbix的addRelatedObjects函数中的CUser类中存在SQL注入，此函数由CUser.get函数调用，具有API访问权限的用户可利用造成越权访问高权限用户敏感信息以及执行恶意SQL语句等危害。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为31748个，关联IP总数为6852个。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Windows 资源管理器 NTLM 凭证泄露漏洞(QVD-2024-49630)**  
  
  
12月6日，发现了一个新的零日漏洞，攻击者只需诱骗目标查看 Windows 资源管理器中的恶意文件即可捕获 NTLM 凭据。该漏洞由为 Windows 旧版本提供非官方支持的平台 0patch 团队发现，并已报告给微软。但目前尚未发布官方修复程序。  
  
据 0patch 称，该问题目前没有 CVE ID，影响从 Windows 7 和 Server 2008 R2 到最新的 Windows 11 24H2 和 Server 2022 的所有 Windows 版本。0patch 一直隐瞒该零日漏洞的技术细节，直至微软提供官方修复程序，以防止引发大规模恶意利用。  
  
研究人员解释说，攻击只需在文件资源管理器中查看特制的恶意文件即可进行，因此无需打开该文件。  
  
0patch 解释道：“该漏洞允许攻击者通过让用户在 Windows 资源管理器中查看恶意文件来获取用户的 NTLM 凭据 - 例如，打开包含此类文件的共享文件夹或 USB 磁盘，或者查看之前从攻击者的网页自动下载此类文件的下载文件夹。”  
  
虽然 0Patch 没有分享有关该漏洞的更多细节，但它会强制将 NTLM 连接传出到远程共享。这会导致 Windows 自动向登录用户发送 NTLM 哈希，然后攻击者就可以窃取这些哈希。这些哈希可以被破解，从而使威胁行为者能够访问登录名和纯文本密码。微软一年前宣布计划在未来的 Windows 11 中取消 NTLM 身份验证协议。  
  
0patch 指出这是他们最近向微软报告的第三个零日漏洞，但该供应商尚未立即采取行动解决。0patch 将向其平台上注册的所有用户提供最新 NTLM 零日漏洞的免费微补丁，直到微软提供官方修复为止。  
  
   
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/new-windows-zero-day-exposes-ntlm-credentials-gets-unofficial-patch/  
  
  
**2.********CyberPanel 权限提升漏洞(CVE-2024-51378)******  
  
  
12月4日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加 CyberPanel 权限提升漏洞(CVE-2024-51378)  
  
CVE-2024-51378 是 CyberPanel 版本 2.3.6 和 2.3.7 中的一个严重漏洞，CVSS 评分为 9.8，允许未经身份验证的远程代码执行 (RCE)。据报道，威胁行为者（包括 PSAUX 勒索软件组织）利用此漏洞加密服务器文件并部署勒索软件负载。公开的概念验证可用。CVE-2024-51378 的利用已导致全球范围内大量 CyberPanel 实例受到攻击，其中大部分集中在美国。成功的攻击会导致完全控制服务器、未经授权访问敏感域以及潜在的数据泄露。强烈建议受影响的 CyberPanel 版本的用户更新到最新版本以减轻这些风险。  
  
攻击者可以利用此漏洞通过向位于 dns/views.py 和 ftp/views.py 中的 /dns/getresetstatus 和 /ftp/getresetstatus 端点发送精心设计的 OPTIONS HTTP 请求来获得根级访问权限。这可能是由于缺乏适当的输入验证。因此，攻击者可以使用“;”突破预期的代码路径，并在无需向服务器进行身份验证的情况下执行他们选择的命令。  
  
威胁情报搜索引擎 LeakIX报告称，有21,761个存在漏洞的CyberPanel实例在网上曝光，其中近一半（10,170个）位于美国。然而，一夜之间，实例数量神秘地下降到仅剩约 400 个，受影响的服务器不再可访问。网络安全研究员 Gi7w0rm 在 X 上发推文称，这些实例管理着超过 152,000 个域和数据库，而 CyberPanel 充当了其中的中央访问和管理系统。威胁行为者大规模利用暴露的 CyberPanel 服务器来安装PSAUX 勒索软件。  
  
由于 CyberPanel 漏洞遭到积极利用，强烈建议用户尽快升级到GitHub 上的最新版本。  
  
  
参考链接：  
  
https://www.sonicwall.com/blog/critical-cyberpanel-vulnerability-cve-2024-51378-how-to-stay-protected  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.百年伏特加知名品牌因勒索软件攻击宣布破产**  
  
  
12月3日华尔街日报消息，在美国子公司遭勒索软件攻击和俄罗斯政府没收其最后两家酒厂的双重打击下，Stoli集团美国公司被迫申请破产保护。Stoli集团在烈酒行业有着悠久历史，旗下品牌斯托利伏特加（Stolichnaya）是全球最知名的伏特加品牌之一。2024年8月，Stoli集团遭遇勒索软件攻击，公司ERP系统瘫痪，包括财务、供应链在内的核心业务全面转入手动操作模式。Stoli美国子公司总裁克里斯·考德威尔透露，这一事件不仅造成运营中断，还导致公司无法向贷方提供财务报告，因而被指控违约债务达7800万美元。“我们预计，完全恢复IT系统至少要到2025年初，”考德威尔在破产文件中写道。他还表示，这次攻击的影响超出了Stoli集团的美国业务，还波及到集团的全球运营。  
  
  
原文链接：  
  
https://www.wsj.com/articles/cyberattack-and-financial-troubles-force-stolis-u-s-arm-to-file-for-bankruptcy-230f32f8  
  
  
**2.勒索攻击致重要能源数字系统瘫痪，哥国政府安抚民众燃油供应稳定**  
  
  
12月2日The Record消息，北美洲国家哥斯达黎加的国家石油公司（RECOPE）近期遭遇勒索软件攻击，被迫转为手动操作并寻求国际援助。该公司表示，11月27日清晨发现了勒索软件攻击，攻击导致所有用于支付的数字系统瘫痪，他们不得不转而手动处理燃料销售。对此，油轮码头在11月27日将运营时间延长至深夜，并于次日进一步扩大运营时间。RECOPE补充道，公司正在与哥斯达黎加科学、创新、技术和电信部合作解决这一问题，同时多次在社交媒体上向全国公众保证，燃料供应充足。哥斯达黎加科学、创新、技术和电信部发布了独立声明，称其安全团队正全力协助恢复工作，并再次强调全国的燃料供应未受影响。自事件发生以来，该部门还多次发布公告，澄清有关其他国家机构遭遇网络攻击的谣言。  
  
  
原文链接：  
  
https://therecord.media/costa-rica-state-energy-company-ransomware  
  
  
**3.乌干达央行被黑：超1.2亿元被盗 近半或损失**  
  
  
11月29日路透社消息，东非内陆国家乌干达财政部的一名高级官员证实，该国中央银行的账户遭到了黑客攻击。乌干达银行在11月28日晚间发布声明称，警方正对一篇新闻报道进行调查。该报道指出，离岸黑客从中央银行窃取了620亿乌干达先令（约合人民币1.22亿元）。当地国有媒体《新愿景报》报道，自称为“Waste”的东南亚黑客组织侵入了乌干达银行的IT系统，并在本月早些时候非法转移了资金至他国，目前乌干达已追回超过一半的被盗资金，官方称需等待审计工作完成后才能公布细节信息。负责财政事务的国务部长亨利·穆萨西齐确认了此次黑客事件，并表示警方刑事调查局和审计长办公室正在对此事展开深入调查。  
  
  
原文链接：  
  
https://www.reuters.com/world/africa/hackers-steal-17-mln-uganda-central-bank-state-paper-2024-11-28/  
  
  
**4.严重损害数据安全，湖南一IT公司被罚20万元**  
  
  
11月29日网信湖南公众号消息，湖南省互联网信息办公室依法查明，湖南某信息技术有限公司存在不履行网络安全、数据安全保护义务行为，其相关系统未采取技术措施和其他必要措施保障数据安全，存在未授权访问漏洞，造成部分数据多次泄露，严重损害数据安全。湖南省互联网信息办公室依据《中华人民共和国数据安全法》和《湖南省网络安全和信息化条例》对该公司责令改正，给予警告，并处对该公司、主管人员和直接责任人员分别罚款二十万元、三万元和二万元的行政处罚。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/BfXOiNZ1ivn3BpWiKcNKNw  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.《政务计算机终端核心配置规范》等2项网络安全国家标准获批发布**  
  
  
12月6日，根据2024年11月28日国家市场监督管理总局、国家标准化管理委员会发布的中华人民共和国国家标准公告（2024年第29号），全国网络安全标准化技术委员会归口的2项网络安全国家标准正式发布。具体包括《网络安全技术 网络安全产品互联互通 第1部分：框架》《网络安全技术 政务计算机终端核心配置规范》。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/5AZDL959P0LhzWwkDuIsNQ  
  
  
**2.中共中央办公厅、国务院办公厅公布《关于推进新型城市基础设施建设打造韧性城市的意见》**  
  
  
12月5日，中共中央办公厅、国务院办公厅公布《关于推进新型城市基础设施建设打造韧性城市的意见》。该文件部署了11项重点任务，其中包括保障网络和数据安全。该重点任务要求严格落实网络和数据安全法律法规和政策标准，强化信息基础设施、传感设备和智慧应用安全管控，推进安全可控技术和产品应用，加强对重要数据资源的安全保障。强化网络枢纽、数据中心等信息基础设施抗毁韧性，建立健全网络和数据安全应急体系，加强网络和数据安全监测、通报预警和信息共享，全面提高新型城市基础设施安全风险抵御能力。  
  
  
原文链接：  
  
https://www.gov.cn/zhengce/202412/content_6991171.htm  
  
  
**3.美国消费者金融保护局发布提案，限制“数据经纪人”出售个人信息**  
  
  
12月3日，美国消费者金融保护局发布了一项拟议规则，计划针对“数据经纪人”出售美国人个人信息的行为，出台更加严格的监管措施。拟议规则利用已有的《公平信用报告法》第五条“关于消费者报告中包含信息的要求”来限制敏感数据的出售，保护美国人免受犯罪和非法外国监视。拟议规则将贯彻《公平信用报告法》中对消费者报告和消费者报告机构的定义，以及《公平信用报告法》中有关消费者报告机构何时可以提供消费者报告，以及用户何时可以获得消费者报告的部分规定，以确保《公平信用报告法》的保护措施适用于该法规，控制出售美国人敏感个人和财务信息的数据经纪人。  
  
  
原文链接：  
  
https://www.consumerfinance.gov/rules-policy/notice-opportunities-comment/open-notices/protecting-americans-from-harmful-data-broker-practices-regulation-v/  
  
  
**4.欧洲理事会通过两项新法案加强网络安全**  
  
  
12月2日，欧洲理事会通过两项关于网络安全的法案，旨在进一步加强欧盟抵御网络威胁的能力和网络团结合作。这两项法律分别为《网络团结法案》和《网络安全法案》修正案，属于欧盟网络安全立法“一揽子计划”的一部分。欧洲理事会声明称，《网络团结法案》构建了欧盟在应对网络威胁方面的能力，同时加强了合作机制。如欧盟将建立一个由国家和跨境网络中心组成的“网络安全警报系统”，以实现信息共享、检测并应对网络威胁。该法案还提出建立网络安全应急机制，以提高欧盟的突发事件响应能力。《网络安全法案》修正案承认托管安全服务在预防、检测、响应和恢复网络安全事件方面的重要性日益增加，该修正案将有助于提高托管安全服务的质量，培养值得信赖的网络安全服务商。  
  
  
原文链接：  
  
http://www.news.cn/world/20241203/6e57f6719e2b471bb3f82832d345b881/c.html  
  
  
**5.《网络安全技术 基于互联网电子政务信息安全实施指南 第1部分：总则》等2项国家标准公开征求意见**  
  
  
12月2日，全国网络安全标准化技术委员会归口的《网络安全技术 基于互联网电子政务信息安全实施指南 第1部分：总则》和《信息技术 安全技术 网络安全 第6部分：无线网络访问安全》2项国家标准现已形成标准征求意见稿，现公开征求意见。据介绍，第一项标准给出了基于互联网电子政务的参考模型、网络安全技术体系、体系实施原则以及两种安全体系实施架构；第二项标准描述了与无线网络相关的威胁、安全要求、安全控制和设计技术，为使用无线网络进行安全通信提供所需的技术选择、实施和监控指导。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/9ldhVVEgZOQrb2DQD3ss7g  
  
  
**6.工信部《国家智能制造标准体系建设指南 (2024)》公开征求意见**  
  
  
12月2日，工业和信息化部科技司组织编制形成《国家智能制造标准体系建设指南（2024版）》（征求意见稿），现公开征求社会各界意见。该文件提出，智能制造标准体系结构包括基础共性、关键技术、行业应用等3个部分，其中基础共性标准包括通用、安全、可靠性等6大类，位于体系结构的最底层。安全标准主要包括功能安全、网络安全、数据安全等3个部分。功能安全标准主要包括智能制造中功能安全系统的设计、实施、测试等标准。网络安全标准指以确保智能制造中相关终端设备、控制系统、工业互联网平台、工业数据等可用性、机密性、完整性为目标的标准，重点包括企业网络安全分类分级管理、安全管理、安全成熟度评估和密码应用等标准。数据安全标准主要包括工业数据质量管理、加密、脱敏及风险评估等标准。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/filemanager/1226211233/attach/202410/4168de2daabb4c1faca7aba6b67738cd.pdf  
  
  
**往期精彩推荐**  
  
  
[SonicWall SMA100 SSLVPN 多个高危漏洞安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502571&idx=1&sn=c30e1d47ae1059542d59b52c7c4ddfd5&token=277618526&lang=zh_CN&scene=21#wechat_redirect)  
[ProFTPD 权限提升漏洞(CVE-2024-48651)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502512&idx=1&sn=6f8aba628a7b2bfe2bcf2403541b375e&token=1318803137&lang=zh_CN&scene=21#wechat_redirect)  
  
[【已复现】Zabbix SQL注入漏洞(CVE-2024-42327) 安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502546&idx=1&sn=e301f3d4f389baa4e9e448b7cdefb1e8&token=277618526&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
