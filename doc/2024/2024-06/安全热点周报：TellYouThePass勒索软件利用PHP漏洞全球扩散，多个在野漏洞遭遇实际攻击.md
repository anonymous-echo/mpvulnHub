#  安全热点周报：TellYouThePass勒索软件利用PHP漏洞全球扩散，多个在野漏洞遭遇实际攻击   
 奇安信 CERT   2024-06-11 18:53  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 国家能源局印发《电力网络安全事件应急预案》</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 安徽一单位遭入侵3.54亿条个人信息被盗，公检联合督促整改</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 国内知名电器集团售后系统遭入侵，涉案金额高达1.2亿元</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.PHP CGI Windows平台远程代码执行漏洞安全风险通告**  
  
  
6月7日，奇安信CERT监测到官方修复PHP CGI Windows平台远程代码执行漏洞(CVE-2024-4577)，未经身份认证的远程攻击者可以通过特定的字符序列绕过此前CVE-2012-1823的防护，通过参数注入攻击在远程PHP服务器上执行任意代码，从而导致远程代码执行、敏感信息泄露或造成服务器崩溃。目前该漏洞技术细节已在互联网上公开，鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.Apache OFBiz路径遍历漏洞安全风险通告**  
  
  
6月6日，奇安信CERT监测到Apache OFBiz路径遍历漏洞(CVE-2024-36104)在互联网上公开，未授权的攻击者可以通过构造恶意请求绕过认证，进而访问系统中的敏感接口，造成任意代码执行。目前该漏洞技术细节与EXP已在互联网上公开，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.Check Point安全网关任意文件读取漏洞安全风险通告**  
  
  
5月30日，奇安信CERT监测到Check Point Security Gateways任意文件读取漏洞(CVE-2024-24919)存在在野利用，远程攻击者可以通过构造恶意请求读取服务器上的任意文件，造成敏感信息的泄漏。目前，此漏洞已检测到在野利用。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****PHP CGI Windows平台远程代码执行漏洞(CVE-2024-4577)**  
  
  
6月 10 日，在 PHP（一种广泛用于 Web 开发的脚本语言）中发现一个严重漏洞(CVE-2024-4577)后，网络安全界处于高度警惕状态。恶意行为者目前正在积极利用此漏洞发起名为“TellYouThePass”的勒索软件活动。  
  
该漏洞由 Devcore 首席安全研究员 Orange Tsai 于 2024 年 5 月 7 日首次发现，源于 Windows 系统字符编码转换的疏忽。利用此漏洞，攻击者可以绕过先前的安全措施并在易受攻击的 PHP 服务器上执行任意代码。此漏洞影响 Windows 的所有 PHP 版本，包括不再受支持的版本。Imperva Threat Research 报告称，早在 6 月 8 日，该漏洞就被用于传播 TellYouThePass 勒索软件。  
  
TellYouThePass 自 2019 年以来一直是一个针对企业和个人持续的威胁。这种勒索软件随着时间的推移不断演变，利用各种漏洞来感染系统。  
  
攻击者利用 CVE-2024-4577 漏洞在目标系统上执行任意 PHP 代码。此代码使用“system”函数通过 mshta.exe 二进制文件运行托管在攻击者控制的 Web 服务器上的 HTML 应用程序文件。Mshta.exe 是一个原生 Windows 二进制文件，允许执行远程负载，突显了攻击者的“靠土地生活”策略。  
  
对于使用 PHP 的组织和个人来说，使用受支持 PHP 版本的用户应升级到最新的补丁版本：PHP 8.3.8、PHP 8.2.20 或 PHP 8.1.29。对于无法立即升级的系统或使用终止版本的系统，临时缓解措施包括应用 mod_rewrite 规则来阻止攻击。  
  
参考链接：  
  
https://securityonline.info/php-vulnerability-cve-2024-4577-actively-exploited-in-tellyouthepass-ransomware-attacks/  
  
  
**2.Oracle WebLogic Server OS命令注入漏洞(CVE-2017-3506)**  
  
  
6月 4 日，CISA 将影响 Oracle WebLogic Server 的安全漏洞添加到已知利用漏洞 ( KEV ) 目录中，并指出有证据表明存在主动利用。该漏洞被标记为CVE-2017-3506，涉及操作系统 (OS) 命令注入漏洞，可导致对易受攻击的服务器的未授权访问并完全控制。  
  
CISA 表示：“Fusion Middleware 套件中的一款产品 Oracle WebLogic Server 存在操作系统命令注入漏洞，允许攻击者通过包含恶意 XML 文档的特制 HTTP 请求执行任意代码。”  
  
虽然该机构没有透露利用该漏洞的攻击性质，但加密劫持组织 8220 Gang（又名 Water Sigbin）自去年年初以来就一直利用该漏洞将未修补的设备纳入加密挖掘僵尸网络。  
  
根据趋势科技最近发布的报告，8220 Gang 被发现利用 Oracle WebLogic 服务器中的漏洞（CVE-2017-3506 和CVE-2023-21839）通过 shell 或 PowerShell 脚本（具体取决于目标操作系统）在内存中无文件地启动加密货币挖掘程序。  
  
安全研究员 Sunil Bharti 表示：“该团伙采用了混淆技术，例如对 URL 进行十六进制编码以及通过端口 443 使用 HTTP，从而实现隐秘的有效载荷传递。PowerShell脚本和生成的批处理文件涉及复杂的编码，使用环境变量将恶意代码隐藏在看似良性的脚本组件中。”  
  
鉴于 CVE-2017-3506 的活跃利用，建议联邦机构在 2024 年 6 月 24 日之前应用最新修复程序，以保护其网络免受潜在威胁。  
  
参考链接：  
  
https://thehackernews.com/2024/06/oracle-weblogic-server-os-command.html  
  
  
**3.****Check Point Security Gateways 任意文件读取漏洞(CVE-2024-24919)**  
  
  
5 月 30 日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加Check Point Security Gateways 任意文件读取漏洞(CVE-2024-24919)。自 4 月 30 日以来，威胁行为者一直在利用高严重性的 Check Point 远程访问 VPN 零日漏洞，窃取在成功攻击中横向移动受害者网络所需的 Active Directory 数据。  
  
Check Point 警告客户，攻击者正在使用具有不安全的纯密码身份验证的旧 VPN 本地账户攻击他们的安全网关。该公司随后发现黑客在这些攻击中利用了信息泄露漏洞（追踪为CVE-2024-24919 ），并发布了修补程序来帮助客户阻止针对易受攻击的 CloudGuard Network、Quantum Maestro、Quantum Scalable Chassis、Quantum Security Gateways 和 Quantum Spark 设备的攻击尝试。  
  
威胁行为者可以提取使用仅密码身份验证的传统本地用户的密码哈希值，包括用于连接到 Active Directory 的服务帐户。弱密码可能会被破解，导致进一步的滥用和网络内潜在的横向移动。该漏洞还被利用来提取信息，允许攻击者在受害者的网络中横向移动并滥用 Visual Studio Code 来传输恶意流量。  
  
建议 Check Point 客户立即将受影响的系统更新至修补版本，并删除存在漏洞的安全网关上的任何本地用户。  
  
还建议管理员将 LDAP 连接的密码/帐户从网关轮换到 Active Directory，在日志中进行补丁后搜索以查找入侵迹象，例如异常行为和可疑登录，并且更新 Check Point IPS 签名以检测利用尝试。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/check-point-vpn-zero-day-exploited-in-attacks-since-april-30/  
  
  
**4.Linux kernel netfilter释放后重用漏洞(CVE-2024-1086)**  
  
  
5 月 30 日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加 Linux kernel netfilter释放后重用漏洞(CVE-2024-1086)。  
  
该漏洞是由于nft_verdict_init() 函数允许将正值作为 hook verdict 中的 drop 错误，因此当使用类似于 NF_ACCEPT 的 drop 错误发出 NF_DROP 命令时，nf_hook_slow() 函数可能会导致双重释放漏洞。利用 CVE-2024-1086 可让具有本地访问权限的攻击者在目标系统上实现权限提升，并可能获得 root 级访问权限。  
  
该问题已通过2024 年 1 月的提交得到修复，该提交拒绝 QUEUE/DROP 判决参数，从而防止被利用。  
  
2024 年 3 月下旬，一位使用别名“Notselwyn”的安全研究人员在 GitHub 上发布了详细的PoC，展示了如何利用 Linux 内核版本 5.14 到 6.6 之间的漏洞来实现本地特权提升。  
  
虽然大多数 Linux 发行版都很快推出了修复程序，但 Red Hat直到 3 月份才推出修复程序，这使得威胁行为者有可能在受感染的系统上使用公开漏洞。  
  
CISA 并未透露该漏洞如何被利用的具体细节，但 BleepingComputer 在黑客论坛上看到了有关公开漏洞利用的帖子。  
  
现已要求联邦机构必须在 2024 年 6 月 20 日之前安装可用的补丁。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-of-actively-exploited-linux-privilege-elevation-flaw/  
  
  
**5.Justice AV Solutions Viewer Setup 代码执行漏洞(CVE-2024-4978)**  
  
  
5 月 22 日，Justice AV Solutions Viewer Setup 代码执行漏洞(CVE-2024-4978)公开在野利用。Justice AV Solutions (JAVS) Viewer 安装程序包含恶意版本的 ffmpeg.exe。运行时，它会创建与恶意 C2 服务器的后门连接。  
  
攻击者在广泛使用的 Justice AV Solutions (JAVS) 法庭视频录制软件的安装程序中植入了恶意软件，从而可以接管受感染的系统。  
  
该软件背后的公司也称为 JAVS，该公司表示，这种数字录音工具目前已在全球许多法庭、法律办公室、惩教机构和政府机构中安装超过 10,000 个。  
  
JAVS 随后从其官方网站上删除了受感染的版本，并称包含恶意 fffmpeg.exe 二进制文件的木马软件“并非源自 JAVS 或与 JAVS 相关的任何第三方”。  
  
该公司还对所有系统进行了全面审核，并重置了所有密码，以确保即使被盗，也不会在未来的入侵中被利用。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/javs-courtroom-recording-software-backdoored-in-supply-chain-attack/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.涉中跨境电商熊猫购支付赎金后被撕票，上千万用户数据泄露**  
  
  
6月6日Bleeping Computer消息，主打全球用户海淘中国商品的跨境电商平台Pandabuy（熊猫购）近期曝出数据泄露事件。黑客“Sanggiero”3月底与6月初两次在数据泄露论坛销售Pandabuy数据，第一次公布了300万条数据，其中包括客户姓名、电话、邮箱、登录IP、住址及订单详情等；第二次以4万美元售价兜售1700万条数据。Pandabuy发言人表示，曾向黑客支付了一笔未公开金额的赎金，试图阻止数据泄露，但黑客可能已将数据共享给其他人，公司决定不再与其合作。根据Pandabuy发言人自相矛盾的陈述，专家猜测Pandabuy并未一次性支付所有赎金。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/pandabuy-pays-ransom-to-hacker-only-to-get-extorted-again/  
  
  
**2.安徽一单位遭入侵3.54亿条个人信息被盗，公检联合督促整改**  
  
  
6月6日检察日报正义网消息，2023年6月29日，安徽省某单位信息中心向公安机关报案称遭到网络攻击。在司法程序中，当地检察院承办检察官审查发现，嫌疑人利用黑客工具扫描存在漏洞的服务器，攻击目标服务器非法获取了包含姓名、身份证号、联系电话、不动产信息等内容的公民个人信息3.54亿余条。值得庆幸的是，嫌疑人还没来得及出售这些个人信息，就被抓获归案了。经进一步分析，检察官了解到被入侵的近20台服务器存在防火墙过期、采用弱口令、未定期修改登录密码、疏于对外包服务单位管理等情况。对此，检察院联合公安机关向被入侵服务器所属单位通报并督促整改。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/4QahklubSg-NO8v1j5yWaw  
  
  
**3.国内知名电器集团售后系统遭入侵，涉案金额高达1.2亿元**  
  
  
6月5日封面新闻消息，四川南充仪陇警方成功打掉开发、销售和使用黑客破坏软件的4个犯罪团伙。据悉，当地警方在办案过程中，发现两款黑客软件都攻破了一家知名企业的电器售后服务系统，伪造电器安装服务工单，骗取售后安装服务费。经分析发现，国内某知名电器集团官方APP存在源代码未进行强制权限检查、后台服务器数据交互未加密等40余项安全漏洞，被犯罪嫌疑人利用，开发出了能够控制官方APP，轻易侵入售后服务系统并非法控制进行数据修改的黑客工具。据了解，这两款“黑客”软件是这家电器集团售后服务人员内外勾结，合力研发出来的，研发人员熟悉公司流程和系统规则。警方梳理出北京、浙江、广东等全国29省市共有802人使用这两款软件，涉及售后合作网点786个。涉案总金额高达1.2亿余元。  
  
  
原文链接：  
  
https://baijiahao.baidu.com/s?id=1801031597253357905  
  
  
**4.美国发生超大规模电信网络攻击，60万台路由器集体变砖**  
  
  
5月30日Lumen消息，美国电信公司Lumen Technologies旗下黑莲花实验室发布报告称，2023年底美国发生一起超大规模电信网络破坏事件，黑客在72小时内瘫痪了互联网接入服务商Windstream的超过60万台家庭/家庭办公路由器（型号为ActionTec T3200），这些“变砖”的路由器无法修复，导致大量用户被迫进行硬件更换。公共扫描数据显示，在事件期间，Windstream的自主系统号（ASN）下接近半数（49%）的路由器被攻击下线。这次攻击对农村和偏远社区影响尤其严重，导致紧急服务中断、农业监控信息丢失和远程医疗服务中断等。  
  
  
原文链接：  
  
https://blog.lumen.com/the-pumpkin-eclipse/  
  
  
**5.加拿大老牌药店遭勒索攻击闭店，被索要超1.8亿元赎金**  
  
  
5月22日The Register消息，加拿大连锁药店伦敦药房已确认，勒索软件团伙窃取了一些包含员工信息的公司文件，并表示“不愿意也无力向这些网络罪犯支付赎金。”该公司在声明中称，4月28日的入侵事件是一场“由一帮组织严密的全球网络罪犯策划的攻击”。这次攻击导致伦敦药房所有门店全部关闭约10天，期间药房员工被迫在店外填写重要处方。LockBit勒索软件团伙在5月21日声称对此次攻击负责，要求伦敦药房在5月30日前支付2500万美元（约合人民币1.81亿元），并威胁如果这家连锁药店不付款，将泄露窃取的数据。   
  
  
原文链接：  
  
https://www.theregister.com/2024/05/22/london_drugs_ransomware/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.国家能源局印发《电力网络安全事件应急预案》**  
  
  
6月7日，国家能源局公布《电力网络安全事件应急预案》，要求完善电力网络安全事件应对工作机制，有效预防、及时控制和最大限度消除电力网络安全事件带来的危害和影响，保障电力系统安全稳定运行和电力可靠供应。本文件所指电力网络安全事件是指由计算机病毒或网络攻击、网络侵入等危害网络安全行为导致的，对电力网络和信息系统造成危害，可能影响电力系统安全稳定运行或者影响电力正常供应的事件。电力网络安全事件预警等级分为四级：由高到低依次用红色、橙色、黄色和蓝色表示，分别对应发生或可能发生特别重大、重大、较大和一般电力网络安全事件。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/FqOVARgJQ4t9SCkhzipF-Q  
  
  
**2.美国防部发布《零信任覆盖》政策指南**  
  
  
6月4日，美国国防部发布《零信任覆盖》文件，作为帮助国防部实现拜登总统签署的2021年行政命令中设定目标的路线图和实施指南。该文件首次统一国防部在整个防务界实施零信任的方式，规定分阶段实施零信任控制的方法，并为系统架构师和授权官员开发零信任差距分析。零信任不仅应在国防部内部实施，还应在国防部和各军种的系统及人员队伍中实现，这将是一项挑战。目前零信任尚未在整个国防部体系实施，预计2027财年可达到“目标水平”。  
  
  
原文链接：  
  
https://dodcio.defense.gov/Portals/0/Documents/Library/ZeroTrustOverlays-2024Feb.pdf  
  
  
**3.国家标准《网络安全技术 关键信息基础设施边界确定方法》公开征求意见**  
  
  
5月31日，全国网络安全标准化技术委员会归口的国家标准《网络安全技术 关键信息基础设施边界确定方法》已形成标准征求意见稿，现公开征求意见。该文件给出了关键信息基础设施边界确定的方法，包括基本信息梳理、关键信息基础设施功能识别、关键业务链与关键业务信息识别、关键业务信息流识别和资产识别、关键信息基础设施要素识别和边界确定的流程、步骤等内容，适用于指导关键信息基础设施运营者确定关键信息基础设施边界，也可为关键信息基础设施安全保护的其他相关方使用。  
  
  
原文链接：  
  
https://www.tc260.org.cn/file/2024-05-31/489176b0-b82a-41a6-b972-38001664781e.doc  
  
  
**4.美国家情报总监办公室发布情报界IT能力建设路线图**  
  
  
5月30日，美国家情报总监办公室发布首份信息技术能力建设路线图文件《美情报界信息环境展望：一个信息技术路线图》，这份融合了美情报界一百余名资深技术专家所提建议的文件，就美情报界各成员机构在2025至2030财年期间如何开展IT能力建设，尤其是涉及云计算环境、网络安全、先进计算、数据分析及人工智能等方面提出了前瞻性的技术指导意见。美情报界在2025至2030财年期间需重点推进五大聚焦领域的19个关键举措落地，包括以可靠而具有弹性的数字底座强化任务、以稳健的网络安全保障任务、以现代化的实践和合作关系赋能任务、以数据中心化增强任务、以先进技术和人员技能发展加速任务。  
  
  
原文链接：  
  
https://www.dni.gov/files/documents/CIO/IC-IT-Roadmap-Vision-For-the-IC-Info-Environment-May2024.pdf  
  
  
**5.中央网信办等三部门印发《信息化标准建设行动计划（2024—2027年）》**  
  
  
5月29日，中央网信办、市场监管总局、工业和信息化部联合印发《信息化标准建设行动计划（2024—2027年）》。该文件共六章，包括总体要求、创新信息化标准工作机制、推进重点领域标准研制、推进信息化标准国际化、提升信息化标准基础能力、组织保障。该文件提出，完善人工智能标准，强化安全、隐私等标准研制；推进脑机接口标准研究，加强脑信息安全与隐私保护等关键技术和应用标准研制；加快IPv6在检测、安全等方向的标准研制；推进数据密码保护、数据分类分级、数据脱敏脱密、数据跨境传输等数据安全相关标准研制；加强公共安全视频图像、公共安全大数据等标准建设，提升数字化社会管理能力。  
  
  
原文链接：  
  
https://www.cac.gov.cn/pdf/web/viewer.html?file=//www.cac.gov.cn/rootimages/uploadimg/1718660302978083/1718660302978083.pdf  
  
  
**往期精彩推荐**  
  
  
[PHP CGI Windows平台远程代码执行漏洞(CVE-2024-4577)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501265&idx=1&sn=113d8f380673723f53d9c0b06f9f2fc4&chksm=fe79e149c90e685f02814a0c15dd3a94527f01b5c592f312e9be04e2eb6c288401a64574b358&token=104754157&lang=zh_CN&scene=21#wechat_redirect)  
[【已复现】Apache OFBiz 路径遍历漏洞(CVE-2024-36104)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501249&idx=1&sn=b8105f3bf1ef2554314d204e9f57ed2c&chksm=fe79e159c90e684ff68547160b11ec15b0cb71bc2b36b108454acf6d1eafe6c72227a10cf280&token=104754157&lang=zh_CN&scene=21#wechat_redirect)  
  
[攻防演练收敛已知漏洞攻击面，请更新这些软件到最新版本！](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501231&idx=1&sn=149d1942b6b9dc0a4a08fa5c0017d674&chksm=fe79e137c90e6821d88edaddc6d43597ffa50884b713eeb254e6a1f589e01df88a151bcd2383&token=104754157&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
