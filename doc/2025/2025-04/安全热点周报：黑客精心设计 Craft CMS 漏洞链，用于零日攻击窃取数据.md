#  安全热点周报：黑客精心设计 Craft CMS 漏洞链，用于零日攻击窃取数据   
 奇安信 CERT   2025-04-28 10:01  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">金融监管总局拟制定《银行业保险业网络安全管理办法》</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">远程控制、窃密、挖矿！我国境内捕获“银狐”木马病毒变种</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">马来西亚多家券商系统遭境外攻击，大量交易账户被操纵买卖股票</span></p></td></tr></tbody></table>  
  
  
**PART****0****1**  
  
  
**新增在野利用**  
  
  
**1.****Craft CMS 远程代码执行漏洞(CVE-2025-32432)&Yii 2 框架远程代码执行漏洞(CVE-2024-58136)******  
  
  
4月25日，CERT Orange Cyberdefense 称，影响 Craft CMS 的两个漏洞被串联起来进行零日攻击，以入侵服务器并窃取数据，并且攻击仍在持续进行。  
  
这些漏洞是由 Orange Cyberdefense 的 CSIRT 发现的，当时该组织被要求调查一台被入侵的服务器。作为调查的一部分，他们发现影响 Craft CMS 的两个零日漏洞被利用来入侵服务器：CVE-2025-32432： Craft CMS 中的远程代码执行 (RCE) 漏洞。CVE-2024-58136： Craft CMS 使用的 Yii 框架中存在输入验证缺陷。根据 Orange Cyberdefense 道德黑客团队 SensePost 的报告，威胁行为者将这两个漏洞结合在一起，以破坏服务器并上传 PHP 文件管理器。  
  
此次攻击始于 CVE-2025-32432 漏洞的利用，该漏洞允许攻击者发送一个特制的请求，其中包含一个“返回 URL”作为参数，该参数保存在 PHP 会话文件中。此会话名称作为 HTTP 请求响应的一部分发送给访问者。攻击的第二阶段利用了 Craft CMS 所使用的 Yii 框架 (CVE-2024-58136) 中的一个漏洞。为了利用此漏洞，攻击者发送了一个恶意的 JSON 负载，导致会话文件中的 PHP 代码在服务器上执行。这使得攻击者可以在服务器上安装基于 PHP 的文件管理器，从而进一步破坏系统。  
  
Yii 开发人员最终在4月9日发布的 Yii 2.0.52 版本中修复了 CVE-2024-58136 漏洞。  
  
Craft CMS 还于4月10日修复了 3.9.15、4.14.15 和 5.6.17 版本中的CVE-2025-32432 漏洞。虽然他们没有将 Craft CMS 中的 Yii 更新到最新版本，但 Orange 表示攻击链仍然已修复。  
  
如果管理员认为他们的网站已被入侵，Craft CMS 建议执行以下步骤：  
  
如果安全密钥已被捕获，请刷新。可以运行 php craft setup/security-key 命令，并将更新后的 CRAFT_SECURITY_KEY 环境变量复制到所有生产环境。如果有任何其他私钥存储为环境变量（例如 S3 或 Stripe），也请刷新。  
  
出于谨慎考虑，可能需要强制所有用户重置密码，以防数据库被盗。可以运行 php craft resave/users --set passwordResetRequired --to "fn() => true" 来执行此操作。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/craft-cms-rce-exploit-chain-used-in-zero-day-attacks-to-steal-data/  
  
**2.********SAP NetWeaver 任意文件上传漏洞(CVE-2025-31324)******  
  
  
4月25日，SAP 发布了 NetWeaver 紧急更新，以修复疑似被积极利用来劫持服务器的远程代码执行 (RCE) 零日漏洞。  
  
该漏洞编号为 CVE-2025-31324，评级为严重（CVSS v3 评分：10.0），是 SAP NetWeaver Visual Composer（具体来说是 Metadata Uploader 组件）中的一个未经身份验证的文件上传漏洞。它允许攻击者无需登录即可上传恶意可执行文件，从而可能导致远程代码执行和整个系统受到损害。  
  
虽然供应商的公告尚未公开，但 ReliaQuest 本周早些时候报告了 SAP NetWeaver Visual Composer 中一个被积极利用的漏洞，特别是“/developmentserver/metadatauploader”端点，该漏洞与 CVE-2025-31324 一致。ReliaQuest报告称，多名客户因 SAP NetWeaver 上未经授权的文件上传而受到攻击，攻击者将 JSP webshell 上传到可公开访问的目录。这些上传通过对 JSP 文件的简单 GET 请求实现了远程代码执行，允许从浏览器执行命令、文件管理操作（上传/下载）等。在后利用阶段，攻击者部署了“Brute Ratel”红队工具、“Heaven's Gate”安全绕过技术，并将 MSBuild 编译的代码注入 dllhost.exe 以实现隐身。  
  
ReliaQuest 在报告中指出，漏洞利用不需要身份验证，并且受感染的系统已完全修补，这表明它们已成为零日漏洞利用的目标。安全公司 watchTowr 也证实，他们发现与 CVE-2025-31324 相关的积极漏洞利用。未经身份验证的攻击者可以滥用内置功能将任意文件上传到 SAP NetWeaver 实例，这意味着完全远程代码执行和整个系统受损，”watchTowr 首席执行官 Benjamin Harris 表示。watchTowr 看到威胁行为者积极利用，他们利用此漏洞将 Web Shell 后门投放到暴露的系统并获得进一步的访问权限。  
  
该漏洞影响 Visual Composer Framework 7.50，建议的操作是应用最新的补丁。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/sap-fixes-suspected-netweaver-zero-day-exploited-in-attacks/  
  
**PART****0****2**  
  
  
**安全事件**  
  
  
**1.远程控制、窃密、挖矿！我国境内捕获“银狐”木马病毒变种**  
  
  
4月25日央视新闻消息，国家计算机病毒应急处理中心在我国境内连续捕获一系列针对我国网络用户，特别是财务和税务工作人员用户的木马病毒。这些病毒的文件名称与2025年“税务稽查”“所得税汇算清缴”“放假安排”等诱饵主题相关，实际为恶意可执行程序，全部针对Windows平台用户，主要通过社交媒体中转发的钓鱼网页链接进行传播。经过分析后发现这些病毒均为“银狐”（又名：“游蛇”“谷堕大盗”等）家族木马病毒变种，如果用户运行相关恶意程序文件，将被攻击者实施远程控制、窃密、挖矿等恶意操作，并可能被利用充当进一步实施电信网络诈骗活动的“跳板”。  
  
  
原文链接：  
  
https://news.cctv.com/2025/04/25/ARTImRQthoBuCLhaQxRyYKZL250425.shtml  
  
**2.马来西亚多家券商系统遭境外攻击，大量交易账户被操纵买卖股票**  
  
  
4月24日TheEdge消息，马来西亚证券交易所（Bursa Malaysia）披露，已与马拉西亚证券委员会接到多家券商上报，部分用户交易账户出现未授权访问与交易活动。据业内人士透露，被入侵的账户大多未启用预授权的互联网交易功能，境外IP的攻击者入侵了券商系统，操纵用户交易账户买卖股票以操纵股价，相关股票和衍生品包括高峰控股及其B类认股权证、马来西亚邮政、若干香港结构性认股权证等。大约六周前曾发生过一次规模较小的类似事件，该人士推测攻击者当时可能是在进行试探性攻击，为本次更大规模的行动做准备。马来西亚主要股票经纪直接市场接入平台服务商N2N Connect Bhd表示，已封禁高风险IP与境外IP。  
  
  
原文链接：  
  
https://theedgemalaysia.com/node/752877  
  
**3.280万人健康数据被盗，两家美国大型医疗集团赔偿超4700万元**  
  
  
4月23日HIPAA Journal消息，美国健康管理公司Navvis与SSM健康医疗集团已同意支付650万美元（约合人民币4742万元），以解决2023年发生的一起数据泄露事件相关的索赔事项。2023年7月，Navvis遭勒索软件团伙攻击，致使敏感数据失窃、部分文件被加密，SSM健康等多家医疗机构约280万人身份信息、健康信息、医保信息等泄露。根据和解条款，将设立一个总额为650万美元的和解基金，用于支付集体成员的索赔、律师费用、集体代表的服务奖励金及相关法律费用。  
  
  
原文链接：  
  
https://www.hipaajournal.com/navvis-ssm-health-data-breach-settlement/  
  
**4.俄军士兵作战规划App被植入后门，专门窃取通信、位置等信息**  
  
  
4月23日Bleeping Computer消息，俄罗斯网络安全公司Doctor Web研究员发现，有攻击者在Alpine Quest App中植入木马，并以付费版破解包等噱头在Telegram频道和俄罗斯境内应用商店内分发。Alpine Quest是一款正规的GPS与地形图绘制安卓App，俄罗斯士兵经常使用该应用进行战区作战规划。安装该App后，用户的通信聊天、实时位置等敏感信息均会遭到窃取，可能会泄露俄军行动的关键细节。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/russian-army-targeted-by-new-android-malware-hidden-in-mapping-app/  
  
  
**5.英国零售巨头马莎百货疑遭网络攻击，门店支付和订单自取服务中断**  
  
  
4月22日TheRecord消息，英国零售商巨头马莎百货（M&S）披露，最近几天一直在应对一起网络事件，对部分门店的运营进行了轻微且临时的调整。此前，许多客户在社交媒体上抱怨称，门店支付系统无法使用，包括刷卡支付、礼品卡使用以及该公司提供的“网购自取”服务等。马莎百货表示，已聘请外部网络安全专家进行调查和处理，并已向相关监管机构及国家网络安全中心进行了报告。公司正采取更多措施来加强网络安全，确保能够持续为客户提供服务。  
  
  
原文链接：  
  
https://therecord.media/british-retailer-MS-confirms-cyber-incident-store-delays  
  
  
**6.韩国SK电讯用户USIM卡数据大规模泄露，官方宣布提供免费换卡服务**  
  
  
4月22日Bleeping Computer消息，韩国最大电信运营商SK电讯遭受网络攻击，黑客通过植入恶意软件，成功访问了部分用户的USIM卡（通用用户身份模块）相关敏感信息。事件发生后，SK电讯已加强了对SIM卡更换与异常认证行为的防护机制，并宣布将对出现可疑活动的账户立即暂停服务。SK电讯后续召开新闻发布会表示，将为2300万用户提供免费SIM卡更换服务，以缓解此次安全问题。截至目前，尚无任何网络犯罪组织对该攻击事件宣称负责。值得注意的是，USIM数据的潜在价值不仅限于金融与诈骗用途，其在情报获取、国家安全监控等方面的利用空间，引发外界对国家级黑客背景的猜测。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/sk-telecom-warns-customer-usim-data-exposed-in-malware-attack/  
  
  
**7.泄露近50万患者健康信息，美国知名眼科医疗集团赔偿超2600万元**  
  
  
4月16日HIPAA Journal消息，美国知名眼科护理机构Retina Group of Washington已同意支付360万美元（约合人民币2626万元）达成和解，以解决一起涉及2023年3月数据泄露的集体诉讼案件。此次数据泄露事件导致455935人的受保护健康信息遭到未经授权的访问。此前2023年该机构遭遇勒索软件攻击，导致约45万患者的个人隐私、健康信息、支付和保险信息等遭到窃取。根据和解协议，将设立一个360万美元的基金，用于支付索赔、律师费用以及其他与法律相关的成本和开支。  
  
  
原文链接：  
  
https://www.hipaajournal.com/retina-group-of-washington-data-breach-settlement/  
  
  
**PART****0****3**  
  
  
**政策法规**  
  
  
**1.《网络安全技术 移动终端安全技术规范》等9项国家标准公开征求意见**  
  
  
4月27日，全国网络安全标准化技术委员会归口的9项国家标准现已形成标准征求意见稿，现公开征求意见。9项国家标准包括《网络安全技术 移动终端安全技术规范》《网络安全技术 具有中央处理器的IC卡芯片安全规范》《网络安全技术 SM2密码算法加密和签名消息格式》《网络安全技术 SM9密码算法加密签名消息格式》《网络安全技术 密码应用标识》《网络安全技术 秘密分享技术机制》《网络安全技术 二元序列随机性检测方法》《网络安全技术 量子密钥分发的安全要求、测试和评估方法 第1部分：要求》《网络安全技术 量子密钥分发的安全要求、测试和评估方法 第2部分：测试和评估方法》。  
  
原文链接：  
  
https://mp.weixin.qq.com/s/P92oogQILEL3ypuDWtXObA  
  
  
**2.工信部印发《智能制造典型场景参考指引（2025年版）》**  
  
  
4月26日，工业和信息化部组织编制了《智能制造典型场景参考指引（2025年版）》。该文件从工厂建设、产品研发、生产管理、生产作业等8个重点环节，凝练出40个典型场景。在工厂建设环节数字基础设施建设场景，该文件建议面向数据中心、工业网络、安全基础设施建设等业务活动，针对工厂算力和网络能力不足、安全防护能力弱等问题，建设数字基础设施，推动IT和OT深度融合，部署安全防护设备，应用算力资源动态调配、负载均衡、异构网络融合、高带宽实时通信、5G、动态身份验证、安全态势感知、多层次纵深防御等技术，建设高性能的算力和网络基础设施，以及全方位监测防护的安全基础设施，提升工厂算力、网络和安全防护能力。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/filemanager/1226211233/attach/20253/3ddfcafcac6d410f990d75b85b508b22.pdf  
  
  
**3.市场监管总局《商业秘密保护规定》公开征求意见**  
  
  
4月25日，市场监管总局起草形成了《商业秘密保护规定（征求意见稿）》，现公开征求意见。该文件所称商业秘密，是指不为公众所知悉、具有商业价值并经权利人采取相应保密措施的技术信息、经营信息等商业信息。该文件要求，经营者应当落实商业秘密保护主体责任，强化自我保护意识和能力建设，根据自身行业特点、技术要求、竞争优势，积极采取有效措施加强涉密信息、涉密区域、涉密人员、涉密载体等商业秘密保护内部控制和合规管理，自觉抵制侵权行为。  
  
  
原文链接：  
  
https://www.samr.gov.cn/cms_files/filemanager/1647978232/attach/20254/2a3d95637b4842b8a1a361dee4ce7854.pdf  
  
  
**4.七部门联合印发《医药工业数智化转型实施方案（2025—2030年）》**  
  
  
4月24日，工业和信息化部、商务部、国家卫生健康委、国家医保局、国家数据局、国家中医药局、国家药监局等七部门联合印发《医药工业数智化转型实施方案（2025—2030年）》。该文件聚焦数智技术赋能行动、数智转型推广行动、数智服务体系建设行动、数智监管提升行动等四个方面系统提出14项具体工作任务。该文件要求，指导医药企业开展工业操作系统和企业信息系统的网络安全防护，落实安全管理、技术防护、安全运营等防护措施，提升网络安全风险防御和处置能力；支持相关单位建立医药大模型创新平台，协同开展医药大模型技术产品研发、监管科学研究等，强化标准规范、科技伦理、应用安全和风险管理等规则建设。  
  
  
原文链接：  
  
https://www.miit.gov.cn/zwgk/zcwj/wjfb/tz/art/2025/art_13998d1c720e41438c5d25a943101f76.html  
  
  
**5.工信部、国家标准委联合印发《国家智能制造标准体系建设指南（2024版）》**  
  
  
4月23日，工业和信息化部、国家标准化管理委员会联合印发《国家智能制造标准体系建设指南（2024版）》。该文件提出，智能制造标准体系结构包括基础共性、关键技术、行业应用等3个部分，基础共性标准包括通用、安全、可靠性、检测、评价、人员能力等6大类。其中，安全标准主要包括功能安全、网络安全、数据安全等3个部分。功能安全标准主要包括智能制造中功能安全系统的设计、实施、测试等标准；网络安全标准指以确保智能制造中相关终端设备、控制系统、工业互联网平台、边缘计算、工业数据等可用性、机密性、完整性为目标的标准，重点包括企业网络安全分类分级管理、安全管理、安全成熟度评估和密码应用等标准；数据安全标准主要包括工业数据质量管理、加密、脱敏及风险评估等标准。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/demo/pdfjs/web/viewer.html?file=/cms_files/filemanager/1226211233/attach/20253/694cbeb17a9b45b580c3602a6345723b.pdf  
  
  
**6.韩国PIPC发布《个人信息处理政策制定指南》**  
  
  
4月21日，韩国个人信息保护委员会（PIPC）公布了修订版《个人信息处理政策制定指南》。依据韩国《个人信息保护法》第30条规定，个人信息处理者应当制定个人信息处理政策，并以适当、透明的方式公开。此次修订版旨在帮助个人信息处理者在2025年处理政策评估实施之前制定有效的处理政策。此次修订的方向是切实保障数据主体的权利，同时减轻个人信息处理者的负担，包括明确无需数据主体同意即可处理的个人信息处理项目和需要同意的个人信息处理项目、放宽了个人信息处理场景及保存/使用期限的具体要求、记录直接受理数据主体个人信息投诉部门的联系方式、完善披露方式以适应移动应用环境的多样性等。  
  
  
原文链接：  
  
https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS217&mCode=G010030000&nttId=11134  
  
  
**7.金融监管总局拟制定《银行业保险业网络安全管理办法》**  
  
  
4月18日，金融监管总局发布《金融监管总局2025年规章制定工作计划》显示，年度计划修订规章11部，制定规章9部。其中，9部拟制定规章包括《银行业保险业网络安全管理办法》。  
  
  
原文链接：  
  
https://www.nfra.gov.cn/cn/view/pages/governmentDetail.html?docId=1205226&itemId=861&generaltype=1  
  
  
**8.乌克兰总统泽连斯基签署法律，加强国家网络和关基安全保护**  
  
  
4月17日，乌克兰总统泽连斯基签署了第4336-IX号法律《乌克兰关于国家信息资源和关键信息基础设施对象的信息保护与网络安全的若干法律修正案》，以大规模改革国家网络战略。该法律引入了多项重大变化，包括建立国家网络事件响应系统、网络安全危机应急机制框架、网络事件信息交换系统、基于风险管理的关基保护体系、网络安全评估系统、网络安全人员队伍等。该法律要求关基保护放弃传统框架CIPS，转向风险管理模式。  
  
  
原文链接：  
  
https://zakon.rada.gov.ua/laws/show/4336-20?lang=en#Text  
  
  
**往期精彩推荐**  
  
  
[安全热点周报：零日漏洞瞄准 iPhone，苹果紧急发布安全补丁](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503342&idx=1&sn=2e5b04fa739192fac3232716a4ffedda&scene=21#wechat_redirect)  
  
  
[CVE计划停摆：全球漏洞治理体系面临协同危机](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503338&idx=1&sn=156adf75bc9f1344112970fb946cc863&scene=21#wechat_redirect)  
  
[【已发现在野利用】Apple iOS 与 iPadOS 多个在野高危漏洞安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503328&idx=1&sn=5b2547c083206cfdcc72084fb45a3894&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
