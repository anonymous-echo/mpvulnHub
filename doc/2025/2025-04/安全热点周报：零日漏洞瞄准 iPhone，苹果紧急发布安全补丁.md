#  安全热点周报：零日漏洞瞄准 iPhone，苹果紧急发布安全补丁   
 奇安信 CERT   2025-04-21 10:12  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">六部门联合印发《促进和规范金融业数据跨境流动合规指南》</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">哈尔滨市公安局公开通缉3名美国国家安全局特工</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">超1.4万台Fortinet设备长期被黑客入侵，约1100台位于中国</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Apple iOS与iPadOS多个在野高危漏洞安全风险通告**  
  
  
4月17日，奇安信CERT监测到官方修复Apple iOS/iPadOS内存破坏漏洞(CVE-2025-31200)以及Apple iOS/iPadOS指针认证绕过漏洞(CVE-2025-31201)，Apple iOS/iPadOS内存破坏漏洞(CVE-2025-31200)产生的原因是操作系统处理音频流时存在内存边界检查不足，导致内存破坏；Apple iOS/iPadOS指针认证绕过漏洞(CVE-2025-31201)产生的原因是系统中存在易受攻击的代码，导致指针认证机制可以被绕过。目前已经发现上述两个漏洞存在在野利用，鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Microsoft Windows NTLM 哈希泄露欺骗漏洞(CVE-2025-24054)******  
  
  
4月17日，黑客正在积极利用 Windows 中存在的一个漏洞，它会利用 .library-ms 文件暴露 NTLM 哈希值，针对政府实体和私营公司进行网络钓鱼活动。  
  
该漏洞编号为CVE-2025-24054 ，已于微软2025年3月补丁发布后修复。最初，该漏洞并未被标记为被主动利用，且评估为“不太可能”被利用。然而，Check Point 研究人员报告称，在补丁发布后仅几天就观察到了针对 CVE-2025-24054 的活跃利用活动，并在2025年3月20日至25日之间达到顶峰。  
  
尽管这些攻击背后的一个 IP 地址之前被关联到俄罗斯国家支持的威胁组织 APT28（“Fancy Bear”），但这并不足以证明其归因可靠。  
  
在 Check Point 发现的攻击中，网络钓鱼电子邮件被发送到波兰和罗马尼亚的实体，其中包含指向 ZIP 存档的 Dropbox 链接，其中包含 .library-ms 文件。library-ms 文件是一种合法的文件类型，打开时会显示一个Windows 库或虚拟容器，其中包含来自不同配置源的文件和文件夹。 在这次网络钓鱼攻击中，创建了 library-ms 文件，其中包含攻击者控制的远程 SMB 服务器的路径。当解压包含 .library-ms 文件的 ZIP 文件时，Windows 资源管理器将自动与其交互，从而触发 CVE-2025-24054 漏洞，并导致 Windows 与文件中指定的 URL 建立 SMB 连接。当 Windows 连接到远程 SMB 服务器时，它将尝试通过 NTLM 进行身份验证，从而允许攻击者捕获用户的 NTLM 哈希。  
  
在后续的攻击活动中，Check Point 发现了包含 .library-ms 附件（不含存档）的网络钓鱼邮件。只需下载 .library-ms 文件即可触发远程服务器的 NTLM 身份验证，这表明无需存档即可利用此漏洞。  
  
捕获 NTLM 哈希可能会为绕过身份验证和提升权限打开大门，因此尽管 CVE-2025-24054 仅被评估为“中等”严重性问题，但其潜在后果却十分严重。  
  
由于利用此漏洞所需的交互较少，组织应将此问题视为高风险问题。建议所有组织安装2025年3月更新，并在不需要时关闭 NTLM 身份验证。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/windows-ntlm-hash-leak-flaw-exploited-in-phishing-attacks-on-governments/  
  
**2.********Apple iOS/iPadOS 内存破坏漏洞(CVE-2025-31200)&Apple iOS/iPadOS 指针认证绕过漏洞(CVE-2025-31201)******  
  
  
4月16日，苹果已向其整个生态系统（包括 iOS、macOS、iPadOS、tvOS 和 visionOS）发布了紧急安全更新，以修补两个零日漏洞，该公司称这是针对特定 iPhone 用户的“极其复杂的攻击”。  
  
这两个漏洞的编号分别为 CVE-2025-31200 和 CVE-2025-31201，是由苹果内部团队与谷歌威胁分析小组 (TAG) 合作发现的。这两个漏洞已被用于有针对性的攻击，但苹果尚未透露攻击的幕后黑手或影响范围。苹果公司在周三发布的安全公告中表示，该问题可能已被利用来针对 iOS 上特定目标用户的极其复杂的攻击。  
  
第一个漏洞存在于苹果的低级音频处理框架 CoreAudio 中。该漏洞编号为 CVE-2025-31200，可通过处理恶意制作的音频流（可能嵌入在媒体文件中）来触发，从而允许远程攻击者在目标设备上执行任意代码。此漏洞影响多个 Apple 平台，并且可以被悄悄利用，使其成为以间谍活动为重点的威胁行为者的理想攻击媒介。  
  
第二个漏洞 CVE-2025-31201 是在 RPAC（远程过程身份验证组件）中发现的，它允许具有读或写权限的对手绕过指针身份验证代码 (PAC) - 这是 Apple 芯片中的一种安全机制，通过验证函数指针来帮助缓解内存损坏攻击。  
  
绕过 PAC 可能允许攻击者提升权限或在受感染设备上保持隐秘持久性——这引发了人们对长期监视和数据泄露能力的严重担忧。  
  
苹果一直对攻击者的身份和攻击手法守口如瓶。该公司尚未透露这些漏洞是如何实施的，以及是否有用户被成功入侵。  
  
这两个漏洞均已在 iOS 18.4.1、iPadOS 18.4.1、tvOS 18.4.1、macOS Sequoia 15.4.1 和 visionOS 2.4.1中修复，强烈建议用户尽快更新补丁版本。  
  
  
参考链接：  
  
https://securityonline.info/urgent-apple-security-patch-zero-day-exploits-target-iphones/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.个人信息3毛/条！物流公司负责人倒卖12.9万条客户数据被判刑**  
  
  
4月17日交汇点消息，宿迁经开区人民法院近日审结的一起侵犯公民个人信息案，揭开了物流行业非法交易客户信息的隐秘链条。某物流公司负责人段某为拓展业务，与网点商家张某达成特殊协议：每提供一条客户收件信息可获0.3至0.6元报酬，同时以每条0.3元价格向快递公司陈某购买数据。经查，段某联络快递公司负责人陈某后，形成由陈某统筹指挥，郑某、陈某某、潘某某、蒋某某分工配合的6人团伙，专门从事信息归纳、汇总、定价工作。据法院审理查明，2024年4月1日至5月14日期间，该团伙通过物流系统非法导出公民个人信息12.9万余条，其中售出部分非法获利4.4万元。这些精准的收件人姓名、电话、住址等信息，最终成为商家“精准营销”的工具，去年4月30日，因市民察觉信息泄露报警，该案东窗事发。法院结合各被告人犯罪情节，最终对段某、陈某等6人判处有期徒刑3年、缓刑4年并处罚金等刑罚。  
  
  
原文链接：  
  
https://www.xhby.net/content/s6800fe3fe4b0e37860aec499.html  
  
**2.哈尔滨市公安局公开通缉3名美国国家安全局特工**  
  
  
4月15日新华社消息，黑龙江省哈尔滨市公安局宣布，为依法严厉打击境外势力对我网络攻击窃密犯罪，切实维护国家网络空间安全和人民生命财产安全，决定对3名隶属于美国国家安全局（NSA）的犯罪嫌疑人凯瑟琳·威尔逊（Katheryn A. Wilson）、罗伯特·思内尔（Robert J. Snelling）、斯蒂芬·约翰逊（Stephen W. Johnson）进行通缉。前期，“2025年哈尔滨第九届亚冬会”遭受境外网络攻击事件经媒体报道后，引发广泛关注。国家计算机病毒应急处理中心和亚冬会赛事网络安全保障团队，及时向哈尔滨市公安局提交了亚冬会遭受网络攻击的全部数据。哈尔滨市公安局立即组织技术专家组成技术团队开展网络攻击溯源调查。在相关国家支持下，经技术团队持续攻坚，成功追查到NSA的3名特工和两所美国高校，参与实施了针对亚冬会的网络攻击活动。调查发现，NSA意图利用网络攻击窃取参赛运动员的个人隐私数据，并妄图破坏系统，扰乱影响亚冬会赛事的正常运行。同时，NSA针对黑龙江省内能源、交通、水利、通信、国防科研院校等重要行业开展网络攻击，意图破坏我关键信息基础设施引发社会秩序混乱和窃取我相关领域重要机密信息。进一步调查发现，该3名特工曾多次对我国关键信息基础设施实施网络攻击，并参与对华为公司等企业的网络攻击活动。技术团队同时发现，具有美国国家安全局（NSA）背景的美国加利福尼亚大学、弗吉尼亚理工大学也参与了本次网络攻击。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/XCazIoSGTRu5-qyZGuSVAg  
  
**3.英国软件厂商关键数据库公网暴露，泄露近800万条医护职工敏感信息**  
  
  
4月15日Hackread消息，安全研究员Jeremiah Fowler披露，英国人力资源软件厂商Logezy的员工管理数据库配置错误，导致该国800万条医护人员的敏感信息被泄露，涉及身份证明、财务数据等。据了解，该数据库无密码保护且未加密，存储数据总量达1.1TB，包括7975438个文件，里边包括工作许可文件、国家报治安好吗、电子签名、证书、身份证明文件、工时记录等大量敏感信息。Fowler通知Logezy公司后该数据库随即被限制公开访问，但不确定此前公网暴露的时长、数据有无被访问等。  
  
  
原文链接：  
  
https://hackread.com/uk-software-firm-exposed-healthcare-worker-records/  
  
**4.知名论坛4chan遭黑客攻击下线，管理员信息及源代码疑泄露**  
  
  
4月15日Bleeping Computer消息，老牌匿名论坛4chan遭遇了一次严重的网络安全事件。该网站在4月14日早些时候突然无法访问，随后长时间处于下线状态。一个名为Soyjak.party的网络社群的成员宣称发动了此次攻击，其宣称已渗透4chan系统长达一年，并公布了多张据称是4chan管理后台界面的截图。截图内容显示，攻击者可能获得了访问管理员工具的权限，这些工具或可用于查看用户IP地址、地理位置信息、管理论坛版块、查看日志、访问数据库（通过phpMyAdmin面板）等。此外，攻击者还泄露了一份据称包含4chan管理员、版主及协助维护人员（Janitors）电子邮件地址的列表。同日晚些时候，又有用户在另一个匿名论坛Kiwi Farms上发布了据称是4chan网站的PHP源代码。4chan官方尚未就此次攻击事件发布声明。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/infamous-message-board-4chan-taken-down-following-major-hack/  
  
  
**5.美国血液透析上市公司达维塔遭勒索攻击，部分运营中断**  
  
  
4月14日路透社消息，美国上市公司、血液透析服务商达维塔（DaVita）披露，日前遭遇勒索软件攻击，导致部分网络系统被加密，有业务运营受影响中断服务，不过公司明确表示仍在继续提供病患护理服务。达维塔表示，4月12日发现此次网络攻击，目前正与第三方网络安全专业专家同评估事件，并已向执法部门报告事件。该公司正在采取部分功能恢复措施，并继续提供病患护理，但目前“无法估计此次中断的持续时间或影响程度”。达维塔年报显示，公司去年在美国为约20万名病患提供了透析服务，并在约760家医院开展业务。  
  
  
原文链接：  
  
https://www.reuters.com/technology/cybersecurity/dialysis-firm-davita-hit-by-ransomware-attack-2025-04-14/  
  
  
**6.超1.4万台Fortinet设备长期被黑客入侵，约1100台位于中国**  
  
  
4月14日Cybernews消息，美国网络安全公司Fortinet发布警告称，攻击者利用已知漏洞（CVE-2024-21762、CVE-2023-27997和CVE-2022-42475）并采取新型后渗透攻击，获取了Fortinet部分型号设备的只读权限，即使受害者更新系统修复漏洞，该权限依然保留，使得攻击者可以长期访问目标设备窃取敏感配置信息等。Shadowserver基金会扫描发现，约14300台受感染的Fortinet设备暴露在互联网上，其中美国、中国、日本数量位列前三。  
  
  
原文链接：  
  
https://cybernews.com/security/fortinet-hackers-maintaining-access-despite-patches/  
  
  
**7.勒索攻击扰乱电商运营，欧洲家居零售公司Fourlis损失超1.6亿元**  
  
  
4月11日Bleeping Computer消息，欧洲老牌家居零售公司、宜家多国代理商Fourlis集团发布财报披露，2024年11月27日“黑色星期五”促销活动前夕遭遇勒索软件攻击，预计损失达2000万欧元（约合人民币1.66亿元）。该事件于2024年12月3日公开，Fourlis集团当时承认宜家线上商店出现的技术问题源于“恶意的外部行为”。财报显示，该事件导致门店补货短暂受影响，电商运营受影响近3个月，对销售运营造成了巨额损失。Fourlis集团并未向勒索软件攻击者支付赎金，而是在外部网络安全专家的协助下，完成了受影响系统的恢复工作。后续调查未发现此次事件中有数据被盗或泄露的证据。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/ransomware-attack-cost-ikea-operator-in-eastern-europe-23-million/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.《可信数据空间 技术架构》技术文件公开征求意见**  
  
  
4月18日，全国数据标准化技术委员会秘书处组织编制了《可信数据空间 技术架构（征求意见稿）》技术文件，现公开征求意见。该文件规范了可信数据空间技术架构，明确可信数据空间在国家数据基础设施中的定位，可信数据空间的核心技术特征、最小功能集合以及关键业务流程，适用于地方数据基础设施试点及可信数据空间试点的规划、建设和运营、管理。该文件专设单章规定了安全要求，包括数字合约安全、数据产品安全、空间运营安全三部分。  
  
原文链接：  
  
https://www.nda.gov.cn/form-files-sjj/2c99e457-8f9edeed-018f-b8a7537c-0243/2c99e457-8f9edeed-018f-b8ad7daf-0256/fileupload_scfj/2025/04/19/ff808081-95c633c9-0196-4c64126d-1a4f.pdf  
  
  
**2.《全国网络安全标准化技术委员会2025年度工作要点》印发**  
  
  
4月18日，《全国网络安全标准化技术委员会2025年度工作要点》已经2025年4月14日全国网络安全标准化技术委员会全体委员会议审议通过。该文件要求加快推动重点领域网络安全国家标准研制，包括推动关键信息基础设施边界确定方法、安全保护能力指标体系等急需标准试点及报批，研制出台生成式人工智能服务安全基本要求、训练数据安全、数据标注安全等标准，研制电子产品信息清除技术要求强制性国家标准，研制出台数据安全保护、数据安全风险评估等标准并推动标准实施应用，加快开展网络安全产品互联互通功能接口、行为信息格式、威胁信息格式等标准研制和试点工作等。  
  
  
原文链接：  
  
https://www.tc260.org.cn/upload/2025-04-18/1744968133800080004.pdf  
  
  
**3.六部门联合印发《促进和规范金融业数据跨境流动合规指南》**  
  
  
4月17日，中国人民银行、金融监管总局、中国证监会、国家外汇局、国家网信办、国家数据局近期联合印发《促进和规范金融业数据跨境流动合规指南》。该文件旨在促进中外资金融机构金融业数据跨境流动更加高效、规范，进一步明确数据出境的具体情形以及可跨境流动的数据项清单，便利数据跨境流动。该文件要求金融机构采取必要的数据安全保护管理和技术措施切实保障数据安全。  
  
  
原文链接：  
  
http://www.pbc.gov.cn/goutongjiaoliu/113456/113469/5675551/index.html  
  
  
**4.九部门印发《关于加快推进教育数字化的意见》**  
  
  
4月16日，教育部、中央网信办、国家发改委等九部门联合印发《关于加快推进教育数字化的意见》。该文件共7章，其中第6章单章要求筑牢教育数字化安全屏障。该章节提出保障重点平台高质量运行、构建网络安全防护体系、强化人工智能安全保障三部分要求，包括提升关键信息基础设施、平台体系保障能力；构建多部门协同的重点时期保障机制，定期组织开展安全评估和检测；依托国家网络身份认证公共服务，建立教育领域身份和数据可信体系，强化实名管理；全面落实教育数据全生命周期安全防护，强化核心和重要数据防篡改、防泄露、防滥用能力；建立“人工智能+教育”安全保障制度；落实人工智能算法与大模型备案机制，探索建立算法安全评估制度，有效规避网络攻击、信息茧房、算法霸权、依赖成瘾等问题。  
  
  
原文链接：  
  
http://www.moe.gov.cn/srcsite/A01/s7048/202504/t20250416_1187476.html  
  
  
**5.《香港生成式人工智能技术及应用指引》发布**  
  
  
4月15日，香港特区政府数字政策办公室（数字办）公布《香港生成式人工智能技术及应用指引》，为技术开发者、服务提供商和使用者提供实务操作指引，内容涵盖生成式人工智能的应用范围和局限、潜在风险与治理原则，包括数据泄露、模型偏见和错误等技术风险。该文件提出，生成式人工智能治理应遵循遵守法律、安全透明、准确可靠、公平客观、实用高效五大原则，并从个人隐私、知识产权、犯罪防治、真实可信、系统安全五大维度展开。该文件还针对技术开发者、服务提供者、服务使用者三类角色给出了实操指南。  
  
  
原文链接：  
  
https://www.digitalpolicy.gov.hk/tc/our_work/data_governance/policies_standards/ethical_ai_framework/doc/HK_Generative_AI_Technical_and_Application_Guideline_tc.pdf  
  
  
**6.美国NIST隐私框架1.1版公开征求意见**  
  
  
4月14日，美国国家标准与技术研究院（NIST）发布隐私框架1.1版草案公开征求意见。与1.0版相比，1.1版草案增加了有关人工智能和隐私风险管理的章节，明确概述了人工智能与隐私的关系，以及如何使用隐私框架来管理人工智能隐私风险。1.1版草案指出，人工智能系统可能因数据处理方式（如未经同意收集数据、隐私保护不足）或技术特性引发各类隐私风险，包括从尊严损害到具体危害（如经济损失、人身伤害）的多层次隐私问题，并可能波及群体或社会层面。当前，人工智能与隐私风险的关系高度依赖具体应用场景，隐私保护措施可能与用户控制需求冲突。因此，各组织应当进行隐私风险评估量化风险，实施包括缓解、转移、避免等方法在内的响应策略。  
  
  
原文链接：  
  
https://csrc.nist.gov/pubs/cswp/40/nist-privacy-framework-11/ipd  
  
  
**7.欧盟EDPB《通过区块链技术处理个人数据指南》公开征求意见**  
  
  
4月14日，欧洲数据保护委员会（EDPB）发布了《关于通过区块链技术处理个人数据的指南》公开征求意见。该文件旨在为计划使用区块链技术处理个人数据的组织提供合规框架，分析了区块链技术的分布式特性、去中心化治理以及加密机制与GDPR要求的相互作用，阐述了其在个人数据处理中可能引发的合规风险和对数据主体权利与自由的潜在威胁。该文件指出，应用区块链技术处理个人数据具有复杂性和不确定性，数据控制者需通过数据保护影响评估识别风险，并优先采用技术措施（如数据最小化、链外存储）来降低对数据主体的威胁。该文件通过提供技术与组织措施的具体建议，帮助数据控制者在设计和实施区块链解决方案时确保符合GDPR的要求。  
  
  
原文链接：  
  
https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-022025-processing-personal-data_en  
  
  
**8.美司法部发布《数据安全计划合规指南》，以防止敏感数据外流至外国对手**  
  
  
4月11日，美国司法部根据《关于防止受关注国家获取美国人大量敏感个人数据和美国政府相关数据的行政命令》（EO 14117），发布三份文件推进实施数据安全计划，分别为《数据安全计划：2025年7月8日前的实施与执行政策》《数据安全计划：合规指南》《数据安全计划：常见问题》。合规指南文件是司法部公布的最佳实践，该文件建立了有效的出口管制措施，以防止外国对手及其控制、管辖、所有权和指挥下的人员访问与美国政府相关的数据以及大量基因组、地理位置、生物特征、健康、财务和其他敏感个人数据。此前，EO 14117自4月8日生效。  
  
  
原文链接：  
  
https://www.justice.gov/opa/pr/justice-department-implements-critical-national-security-program-protect-americans-sensitive  
  
  
**往期精彩推荐**  
  
  
[CVE计划停摆：全球漏洞治理体系面临协同危机](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503338&idx=1&sn=156adf75bc9f1344112970fb946cc863&scene=21#wechat_redirect)  
  
  
[【已发现在野利用】Apple iOS 与 iPadOS 多个在野高危漏洞安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503328&idx=1&sn=5b2547c083206cfdcc72084fb45a3894&scene=21#wechat_redirect)  
  
[Oracle 2025年4月补丁日多产品高危漏洞安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503319&idx=1&sn=c50ec2d0659d1177bf4a7569ff7920f6&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
