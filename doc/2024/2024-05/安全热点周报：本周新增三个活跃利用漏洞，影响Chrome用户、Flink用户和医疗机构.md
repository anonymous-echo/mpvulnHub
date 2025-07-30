#  安全热点周报：本周新增三个活跃利用漏洞，影响Chrome用户、Flink用户和医疗机构   
 奇安信 CERT   2024-05-27 17:41  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 中央网信办等四部门发布《互联网政务应用安全管理规定》</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 强制性国家标准《智能网联汽车时空数据传感系统安全基本要求》公开征求意见</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 日本公开首例光伏电场网络攻击事件，超800台设备遭劫持</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Google Chrome V8类型混淆漏洞(CVE-2024-5274)安全风险通告**  
  
  
5月24日，奇安信CERT监测到Google 发布公告称Google Chrome V8类型混淆漏洞(CVE-2024-5274)存在在野利用，远程攻击者可通过诱导用户打开恶意链接来利用此漏洞，从而获取敏感信息或代码执行。目前，此漏洞已检测到在野利用。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.Sonatype Nexus Repository 3路径遍历漏洞安全风险通告**  
  
  
5月23日，奇安信CERT监测到官方修复Sonatype Nexus Repository 3 路径遍历漏洞(CVE-2024-4956)，未经身份认证的远程攻击者通过构造特殊的请求可以下载读取远程目标系统上的任意文件，对机密性造成很高的影响。目前该漏洞技术细节与EXP已在互联网上公开，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.Atlassian Confluence 远程代码执行漏洞安全风险通告**  
  
  
5月22日，奇安信CERT监测到Atlassian官方发布新版本修复高危漏洞Atlassian Confluence Data Center and Server 远程代码执行漏洞(CVE-2024-21683)。经过身份认证的远程攻击者通过构造特殊的请求，利用该漏洞可以执行任意代码，对目标系统的机密性、完整性和可用性造成很高的影响。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**4.GitHub Enterprise Server身份认证绕过漏洞安全风险通告**  
  
  
5月21日，奇安信CERT监测到GitHub Enterprise Server身份认证绕过漏洞(CVE-2024-4985)细节已公开在互联网。GitHub Enterprise Server(GHES)中存在身份验证绕过漏洞，该漏洞与SAML SSO身份验证机制有关。当利用具有可选加密断言功能的SAML SSO身份验证时，攻击者可以利用此漏洞伪造SAML响应，从而绕过身份验证机制，这可能允许攻击者配置或获取具有站点管理员权限的用户访问权限。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**5.Fluent Bit任意代码执行漏洞安全风险通告**  
  
  
5月21日，奇安信CERT监测到Fluent Bit 任意代码执行漏洞(CVE-2024-4323)细节已公开在互联网。未经身份验证的远程攻击者可以通过构造特殊请求，利用此漏洞使服务崩溃或远程执行任意代码。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**6.Zabbix Server SQL注入漏洞安全风险通告**  
  
  
5月21日，奇安信CERT监测到Zabbix zbx_auditlog_global_script SQL注入漏洞(CVE-2024-22120)在互联网上公开。在Zabbix系统中，具有Detect operating system 权限的用户可以通过时间注入获取管理员凭证，进一步利用可以结合后台功能执行代码。目前该漏洞技术细节与PoC已在互联网上公开，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**7.Git远程代码执行漏洞安全风险通告**  
  
  
5月20日，奇安信CERT监测到官方修复Git 远程代码执行漏洞(CVE-2024-32002)，由于Git在支持符号链接的不区分大小写的文件系统上的递归克隆容易受到大小写混淆的影响，未经身份认证的远程攻击者利用该漏洞使受害者克隆操作期间执行刚刚克隆的代码，从而导致远程代码执行。目前该漏洞技术细节与EXP已在互联网上公开，鉴于该漏洞影响范围较大，只影响Windows和Mac系统，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Google Chrome V8 类型混淆漏洞(CVE-2024-5274)**  
  
  
谷歌发布了一个新的紧急安全更新，以解决 Chrome 浏览器中已确认在野利用的第八个零日漏洞。该安全问题由 Google 内部的 Clément Lecigne 发现，编号为 CVE-2024-5274。这是 Chrome 负责执行 JS 代码的 JavaScript 引擎 V8 中严重的“类型混淆”。  
  
最近的这次漏洞利用是通过一个钓鱼邮件活动发现的，攻击者在邮件中嵌入了恶意的HTML文件，当用户打开这些文件时，漏洞就会被触发。这个漏洞允许攻击者在受害者的设备上执行任意代码，这可能导致数据泄露、恶意软件感染或其他安全问题。谷歌的安全团队迅速响应了这一问题，并发布了一个更新来修复这个漏洞。用户被强烈建议尽快应用这个安全更新，以保护他们的设备不受威胁。  
  
安全研究人员指出，这种类型的攻击表明网络犯罪分子正在不断寻找新的方法来利用软件中的漏洞。因此，用户应该保持警惕，及时更新他们的软件，避免点击不明链接或打开可疑的附件。  
  
谷歌表示，他们将继续努力提高Chrome浏览器的安全性，并通过其漏洞奖励计划鼓励安全研究人员帮助识别和修复潜在的安全问题。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/google-fixes-eighth-actively-exploited-chrome-zero-day-this-year/  
  
  
**2.Apache Flink 目录遍历漏洞(CVE-2020-17519)**  
  
  
美国 CISA 将影响 Apache Flink（一个开源、统一的流处理和批处理框架）的安全漏洞添加到已知被利用的漏洞目录中，并引用了积极利用的证据。编号为 CVE-2020-17519 的漏洞是一种不正确的访问控制，可能允许攻击者通过 JobManager 的 REST 接口读取 JobManager 本地文件系统上的任何文件。未经身份验证的远程攻击者可以发送特制的目录遍历请求，从而允许对敏感信息进行未经授权的访问。  
  
Apache 在三年多前发布 1.11.3 和 1.12.0 版本解决了该问题。不久之后，安全研究人员发布了漏洞代码 。现在，2024 年 5 月，联邦机构和其他组织仍在使用不安全的版本，犯罪分子仍在 CVE 周围徘徊。  
  
由于其活跃的利用状态，建议在 2024 年 6 月 13 日之前应用最新的修复程序，以保护其网络免受主动威胁。  
  
参考链接：  
  
https://www.theregister.com/2024/05/24/apache_flink_flaw_cisa/?&web_view=true  
  
  
**3.NextGen Healthcare Mirth Connect 反序列化漏洞(CVE-2023-43208)**  
  
  
Mirth Connect 是一种广泛使用的跨平台界面引擎，医疗保健组织将其用于信息管理。  
  
编号为 CVE-2023-43208 的漏洞是一个数据反序列化问题，可能允许未经身份验证的远程代码执行。随着 4.4.1 版本的发布，补丁也随之推出。  
  
该漏洞于 2023 年 10 月曝光，当时网络安全公司 Horizon3.ai 警告其对医疗保健公司的潜在影响。CVE-2023-43208 是 CVE-2023-37679 的变体，Mirth Connect 开发人员之前已在 4.4.0 版本发布时修补了该漏洞。  
  
2024 年 1 月中旬其 PoC 代码发布。当时，它很容易遭受攻击并且容易被利用，攻击者很可能利用此漏洞进行初始访问或破坏敏感的医疗数据和 1,200 多个互联网暴露的 NextGen Mirth Connect 的实例数据。  
  
CISA 已将 CVE-2023-43208 添加到其 KEV 目录中，并指示政府机构在 6 月 10 日之前解决该问题。  
  
参考链接：  
  
https://thecyberthrone.in/2024/05/21/cisa-adds-cve-2023-43208-to-its-catalog/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.大型医疗服务商被黑！澳大利亚政府警告发生“大规模勒索软件数据泄露”**  
  
  
5月17日The Register消息，澳大利亚电子处方提供商MediSecure于16日发表声明称，发现一起影响个人和健康信息的网络安全事件，初步迹象表明事件可能源自一家第三方供应商。该公司后续表示，“该事件影响了MediSecure系统截至2023年11月保存的数据。”澳大利亚联邦警察正在调查这起入侵事件。澳大利亚国家网络安全协调员发布警告称，这是一次“大规模勒索软件数据泄露事件”，表示政府“继续帮助MediSecure”，并正在努力了解数据泄露事件的规模和性质。澳大利亚政府正在向卫生部门行业团体通报数字入侵和应对情况，通报对象包括澳大利亚医学协会、澳大利亚药剂师协会和主要私立医院服务商。  
  
  
原文链接：  
  
https://www.theregister.com/2024/05/17/medisecure_ransomware_attack/  
  
  
**2.日本公开首例光伏电场网络攻击事件，超800台设备遭劫持**  
  
  
5月1日日本产经新闻消息，黑客劫持了一个大型光伏电网中的800台远程监控设备，用于银行账户盗窃，这些设备型号为日本工控厂商Contec生产的SolarView Compact。Contec确认了最近对远程监控设备的攻击，并提醒光伏发电设施运营商将设备软件更新至最新版本。这可能是全球首例公开确认的针对光伏发电基础设施的网络攻击。据悉，攻击者利用了Palo Alto Networks在2023年6月发现的SolarView Compact漏洞（CVE-2022-29303）传播Mirai僵尸网络，并在Youtube上发布了如何SolarView系统上利用漏洞的“教学视频”。Contec随后在2023年7月18日修补了该漏洞。  
  
  
原文链接：  
  
https://www.sankei.com/article/20240501-ZSOLVFVJZZL6BLQJR6S6SJ23GM/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.工信部印发《工业和信息化领域数据安全风险评估实施细则（试行）》**  
  
  
5月24日，工业和信息化部印发《工业和信息化领域数据安全风险评估实施细则（试行）》，以落实《工业和信息化领域数据安全管理办法（试行）》有关要求，引导工业和信息化领域数据处理者规范开展数据安全风险评估工作，提升数据安全管理水平。该文件适用于境内工业和信息化领域重要数据和核心数据处理者数据处理活动开展的数据安全风险评估。该文件提出，重要数据和核心数据处理者每年至少开展一次数据安全风险评估，评估报告应当包括数据处理者基本情况、评估团队基本情况、重要数据的种类和数量、开展数据处理活动的情况、数据安全风险评估环境，以及数据处理活动分析、合规性评估、安全风险分析、评估结论及应对措施等。细则自6月1日起施行。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/demo/pdfjs/web/viewer.html?file=/cms_files/filemanager/1226211233/attach/20244/1e8f671034ea40a796ca155145c86081.pdf  
  
  
**2.国家标准《网络安全技术 生成式人工智能服务安全基本要求》公开征求意见**  
  
  
5月23日，全国网络安全标准化技术委员会归口的国家标准《网络安全技术 生成式人工智能服务安全基本要求》已形成标准征求意见稿，现公开征求意见。该文件规定了生成式人工智能服务在安全方面的基本要求，包括训练数据安全、模型安全、安全措施等，并给出了安全评估参考要点，适用于服务提供者开展安全评估，也可为相关主管部门提供参考。  
  
  
原文链接：  
  
https://www.tc260.org.cn/file/2024-05-17/9e2853d0-99a0-49c2-9df7-ccaada842ac5.pdf  
  
  
**3.中央网信办等四部门发布《互联网政务应用安全管理规定》**  
  
  
5月22日，中央网络安全和信息化委员会办公室、中央机构编制委员会办公室、工业和信息化部、公安部发布《互联网政务应用安全管理规定》。该文件共八章四十四条，包括总则、开办和建设、信息安全、网络和数据安全、电子邮件安全、监测预警和应急处置、监督管理、附则。该文件所称互联网政务应用，是指机关事业单位在互联网上设立的门户网站，通过互联网提供公共服务的移动应用程序（含小程序）、公众账号等，以及互联网电子邮件系统。该文件要求，建设运行互联网政务应用应当落实网络安全与互联网政务应用“三同步”原则，采取技术措施和其他必要措施，防范内容篡改、攻击致瘫、数据窃取等风险，保障互联网政务应用安全稳定运行和数据安全。  
  
  
原文链接：  
  
https://www.cac.gov.cn/2024-05/22/c_1718054910848581.htm  
  
  
**4.强制性国家标准《智能网联汽车时空数据传感系统安全基本要求》公开征求意见**  
  
  
5月21日，自然资源部编制了《智能网联汽车时空数据传感系统安全基本要求》的征求意见稿，现公开征求意见。该文件规定了智能网联汽车安装、集成涉及时空数据感知与处理等功能的安全要求、检测要求、同一型式判定条件以及实施过渡期，适用于搭载了时空数据传感系统、面向社会销售且在中国境内运行的智能网联汽车。该文件要求，时空数据传感器应具备独立的、可检测的关闭功能，时空数据传感系统的存储模块和向车外传输模块在运行时，应具备地理信息保密处理功能，并应符合国家认定的地理信息保密处理技术要求。  
  
  
原文链接：  
  
https://std.samr.gov.cn/dcpspTools/gbPlan/download?path=%2Fzxd%2F2022004445%2F20_%E6%A0%87%E5%87%86%E8%B5%B7%E8%8D%89%2F20_WD_2022004445_%20%E6%99%BA%E8%83%BD%E7%BD%91%E8%81%94%E6%B1%BD%E8%BD%A6%E6%97%B6%E7%A9%BA%E6%95%B0%E6%8D%AE%E4%BC%A0%E6%84%9F%E7%B3%  
  
  
**5.欧洲理事会正式批准《人工智能法案》**  
  
  
5月21日，欧盟理事会正式批准《人工智能法案》。这是一项旨在协调整个欧盟人工智能规则的开创性立法。该法案采用基于风险的方法，即对社会的潜在危害越大的人工智能系统，法规要求越严格，如被认定构成系统性风险的通用人工智能模型。作为全球首部全面的人工智能法规，它为人工智能治理设定了新标准。该法案在经欧洲议会和欧洲理事会主席签署后，将于近日在欧盟官方公报上公布，并在公布20天后生效。  
  
  
原文链接：  
  
https://www.consilium.europa.eu/en/press/press-releases/2024/05/21/artificial-intelligence-ai-act-council-gives-final-green-light-to-the-first-worldwide-rules-on-ai/  
  
  
**6.四部门印发《关于深化智慧城市发展 推进城市全域数字化转型的指导意见》**  
  
  
5月20日，国家发展改革委、国家数据局、财政部、自然资源部联合印发《关于深化智慧城市发展 推进城市全域数字化转型的指导意见》。该文件提出提升城市安全韧性水平，包括加强物理空间安全管理和安全风险态势感知、数字空间安全管理、数据安全体系、个人隐私保护、数据可信流通体系五部分。该文件要求，健全完善网络安全监测预警和应急处置机制，构建城市网络运行安全管理体系，落实数据分类分级保护制度，健全数据要素流通领域数据安全实时监测预警、数据安全事件通报和应急处理机制等。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/XpBz56FgDGilPCWXaFIJGA  
  
  
**7.美国证交会通过新规，受监管机构发现数据违规后需在30天内披露**  
  
  
5月15日，美国证券交易委员会（SEC）通过修正案，对管理消费者个人信息处理工作的《S-P条例》进行了修改。修正案要求，机构在发现未经授权的网络访问或客户数据使用后，必须“尽快在不超过30天”内通知受影响个人。新规将对美国证券市场的经纪交易商（包括融资门户）、投资公司、注册投资顾问和转账代理人等受监管机构具有约束力。  
  
  
原文链接：  
  
https://www.sec.gov/news/press-release/2024-58  
  
  
**往期精彩推荐**  
  
  
[【在野利用】Google Chrome V8 类型混淆漏洞(CVE-2024-5274)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501184&idx=1&sn=6ef011b0a502294c7cc9a5e94c18f9b5&chksm=fe79e118c90e680e9c8dad5834623ed6b42d668cb79e0afbea68b1b4fdd6ce0e537afa15fa36&token=802407879&lang=zh_CN&scene=21#wechat_redirect)  
[【已复现】Sonatype Nexus Repository 3 路径遍历漏洞(CVE-2024-4956)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501174&idx=1&sn=ca7c460d094e96aaefc7cf3f05bcb31f&chksm=fe79e1eec90e68f81460b4c8227f7eb9b7b4d714e8723c837061e6209b52d1b152744597867d&token=802407879&lang=zh_CN&scene=21#wechat_redirect)  
  
[Atlassian Confluence 远程代码执行漏洞(CVE-2024-21683)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501160&idx=1&sn=bbca83e44eca687fce84ed143277fe00&chksm=fe79e1f0c90e68e6dadfba1a2e10010c1a635b1cbea29185a3f3a57b2fe95492fe182838c445&token=802407879&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
