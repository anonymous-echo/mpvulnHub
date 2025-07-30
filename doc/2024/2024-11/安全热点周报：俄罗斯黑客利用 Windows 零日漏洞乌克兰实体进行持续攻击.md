#  安全热点周报：俄罗斯黑客利用 Windows 零日漏洞乌克兰实体进行持续攻击   
 奇安信 CERT   2024-11-18 10:20  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 国家密码管理局《关键信息基础设施商用密码使用管理规定》公开征求意见</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 欧盟发布《通用人工智能实践准则草案（初稿）》</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 国际石油巨头哈里伯顿因网络攻击损失超2.5亿元</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Ivanti Endpoint Manager SQL注入漏洞安全风险通告**  
  
  
11月13日，奇安信CERT监测到官方修复Ivanti Endpoint Manager SQL注入漏洞(CVE-2024-50330)，在Ivanti EPM的代理门户中，存在一个SQL注入漏洞。该漏洞允许远程未经身份验证的攻击者执行远程代码，从而控制受影响的系统，造成敏感信息泄露甚至获取系统权限等危害。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Palo Alto Networks Expedition SQL注入漏洞(CVE-2024-9465)&****Palo Alto Networks Expedition 远程命令执行漏洞(CVE-2024-9463)**  
  
  
11月14日，CISA 警告称，Palo Alto Networks 的 Expedition 迁移工具中两个严重的安全漏洞目前正在被积极利用。  
  
攻击者可以利用两个未经身份验证的命令注入（CVE-2024-9463）和 SQL 注入（CVE-2024-9465）漏洞入侵运行该公司 Expedition 迁移工具的未修补系统，该工具可帮助从 Checkpoint、Cisco 和其他受支持的供应商迁移配置。  
  
CVE-2024-9463 允许攻击者以 root 身份运行任意 OS 命令，暴露 PAN-OS 防火墙的用户名、明文密码、设备配置和设备 API 密钥，而第二个漏洞可被利用来访问 Expedition 数据库内容（包括密码哈希、用户名、设备配置和设备 API 密钥）并在易受攻击的系统上创建或读取任意文件。  
  
Palo Alto Networks 正在发布安全更新，以解决 Expedition 1.2.96 及更高版本中的这些问题。该公司建议无法立即更新软件的管理员将 Expedition 网络访问权限限制为授权用户、主机或网络。  
  
“升级到 Expedition 修复版本后，所有 Expedition 用户名、密码和 API 密钥都应轮换。更新后，Expedition 处理的所有防火墙用户名、密码和 API 密钥都应轮换。”该公司补充道，并表示这些安全漏洞不会影响其防火墙、Panorama、Prisma Access 和 Cloud NGFW 产品。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-of-more-palo-alto-networks-bugs-exploited-in-attacks/  
  
  
**2.****Windows 任务计划程序权限提升漏洞(CVE-2024-49039)**  
  
  
11月12日，微软共发布了89个漏洞的补丁程序，修复了Windows Kerberos、Windows DWM、Microsoft Exchange Server等产品中的漏洞。CVE-2024-49039是 Microsoft Windows 任务计划程序中的一个 EoP 漏洞。它的 CVSSv3 评分为 8.8，被评为重要。对易受攻击的系统具有本地访问权限的攻击者可以通过运行特制应用程序来利用此漏洞。成功利用此漏洞将允许攻击者访问他们原本无法使用的资源以及执行代码，例如远程过程调用 (RPC) 函数。  
  
微软表示：“在这种情况下，攻击者可以从低权限的AppContainer发起成功的攻击 。攻击者可以提升权限，以比 AppContainer 执行环境更高的完整性级别执行代码或访问资源。”  
  
谷歌威胁分析小组发现并向微软报告了这一漏洞，这表明当前利用该漏洞的攻击者要么是受国家支持的组织，要么是其他高级持续威胁行为者。  
  
Immersive Labs 首席网络安全工程师 Ben McCarthy 通过电子邮件补充道：“攻击者可以以低权限 AppContainer 的身份执行此漏洞，并有效执行仅对特权任务可用的 RPC。”“目前尚不清楚这里受影响的 RPC 是什么，但它可能使攻击者能够提升权限并在远程机器以及他们正在执行漏洞的机器上执行代码。”  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.darkreading.com/cloud-security/2-zero-day-bugs-microsoft-nov-update-active-exploit  
  
  
**3.****Windows NTLM 哈希泄露欺骗漏洞(CVE-2024-43451)**  
  
  
11月12日，微软共发布了89个漏洞的补丁程序，修复了Windows Kerberos、Windows DWM、Microsoft Exchange Server等产品中的漏洞。CVE-2024-43451是 Microsoft Windows 中的一个 NTLM 哈希欺骗漏洞。它的 CVSSv3 评分为 6.5，被评为重要。攻击者可以通过诱使用户打开特制文件来利用此漏洞。成功利用此漏洞将导致未经授权泄露用户的 NTLMv2 哈希，然后攻击者可以使用该哈希以用户身份向系统进行身份验证。据 Microsoft 称，CVE-2024-43451 被广泛利用为零日漏洞。  
  
疑似俄罗斯黑客被发现利用最近修复的 Windows 漏洞作为零日漏洞对乌克兰实体进行持续攻击。该安全漏洞（CVE-2024-43451）是 ClearSky 安全研究人员报告的 NTLM Hash Disclosure 欺骗漏洞，可通过强制连接到远程攻击者控制的服务器来利用该漏洞窃取登录用户的 NTLMv2 哈希。  
  
ClearSky 在 6 月份观察到旨在利用该攻击活动的钓鱼电子邮件后发现了该攻击活动。这些电子邮件包含超链接，可下载互联网快捷方式文件，该文件托管在之前被入侵的服务器 (osvita-kp.gov[.]ua) 上，该服务器属于卡缅涅茨-波多利斯基市议会教育和科学部。ClearSky 表示：“当用户通过右键单击、删除或移动 URL 文件进行交互时，就会触发漏洞。”当发生这种情况时，就会创建与远程服务器的连接以下载恶意软件负载，包括 SparkRAT 开源和多平台远程访问工具，使攻击者能够远程控制受感染的系统。  
  
在调查该事件时，研究人员还收到警告，有人试图通过服务器消息块 (SMB) 协议窃取 NTLM 哈希。这些密码哈希可用于“传递哈希”攻击或破解以获取用户的明文密码。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/microsoft-patches-windows-zero-day-exploited-in-attacks-on-ukraine/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.美国知名律所因泄露用户个人信息赔偿超5700万元**  
  
  
11月12日GovinfoSecurity消息，美国加利福尼亚北区联邦地区法院8日最终批准了针对奥睿律师事务所（Orrick, Herrington & Sutcliffe）的集体诉讼和解协议，总金额达800万美元（约合人民币5782万元）。根据和解协议，集体诉讼成员人均最高赔偿现金7.2万元及额外三年的信用监控服务，该律所还承诺部署持续漏洞扫描、EDR、MDR等数据安全整改措施。该诉讼涉及一起2023年3月的黑客攻击事件，奥睿多个医疗保健客户受影响，泄露数据包括个人姓名、地址、出生日期、社会安全号码、健康信息等，涉及超过63.8万名个人。  
  
  
原文链接：  
  
https://www.govinfosecurity.com/court-finalizes-8m-settlement-in-orrick-data-breach-case-a-26793  
  
  
**2.以色列支付龙头遭DDoS攻击，各地超市加油站等POS机瘫痪**  
  
  
11月11日TheRecord消息，以色列各地的信用卡刷卡设备在10日出现故障，疑似由于网络攻击影响了支撑这些设备运行的通信服务。超市和加油站的顾客因设备故障无法进行支付，事件持续了大约一个小时。据《耶路撒冷邮报》报道，故障原因是当地支付网关公司Hyp旗下产品CreditGuard遭到DDoS攻击，导致各地的POS机终端与线上支付服务断联，任何信息或支付数据均未受影响。据《以色列时报》报道，以色列第12频道新闻和陆军电台声称，一个与伊朗有关的黑客组织声称对此次攻击负责，但未提供具体信源。  
  
  
原文链接：  
  
https://therecord.media/cyberattack-causes-credit-card-readers-in-israel-to-malfunction  
  
  
**3.25家跨国企业数据泄露，MOVEit漏洞引发重大安全危机**  
  
  
11月11日Infostealers消息，网络犯罪情报厂商HudsonRock发布报告称，一名昵称为“Nam3L3ss”的黑客8日在地下论坛发布了利用MOVEit漏洞（CVE-2023-34362）获取的大量企业员工数据，据称来自麦当劳、汇丰、亚马逊、联想、惠普等多家知名跨国企业，比如涉及亚马逊超286万条记录、大都会人寿超58万条记录、汇丰银行超28万条记录等。此次被公开泄漏的被盗数据包括来自25家跨国企业的员工详细信息，如姓名、邮箱地址、电话号码、成本中心代码和组织结构等。这次泄密事件再次凸显了MOVEit漏洞的深远影响以及未迅速应用安全补丁所带来的风险。  
  
  
原文链接：  
  
https://www.infostealers.com/article/massive-moveit-vulnerability-breach-hacker-leaks-employee-data-from-amazon-mcdonalds-hsbc-hp-and-potentially-1000-other-companies/  
  
  
**4.国际石油巨头哈里伯顿因网络攻击损失超2.5亿元**  
  
  
11月8日Cybersecurity Dive消息，美国石油巨头哈里伯顿（Halliburton）首席执行官Jeff Miller在季度财报电话会议上表示，8月的网络攻击及墨西哥湾风暴导致收入损失或延迟，致使公司调整后每股收益减少了2美分。公司财报显示，此次网络攻击直接带来了约3500万美元（约合人民币2.51亿元）相关费用。公司表示，此次入侵迫使其推迟账单和收款，对当季现金流造成了影响，但不构成重大影响。这次攻击被怀疑与RansomHub威胁组织有关，该组织是今年全球最为活跃的黑客团体之一。  
  
  
原文链接：  
  
https://www.cybersecuritydive.com/news/halliburton-35-million-cyberattack/732397/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.国家密码管理局《关键信息基础设施商用密码使用管理规定》公开征求意见**  
  
  
11月15日，国家密码管理局研究起草了《关键信息基础设施商用密码使用管理规定（征求意见稿）》，现公开征求意见。该文件共26条。该文件要求，关键信息基础设施运营者应当加强关键信息基础设施商用密码使用的制度保障、人员保障、经费保障。该文件明确了商用密码使用具体要求，包括商用密码技术、产品、服务使用要求，数据安全保护、个人信息保护要求，规划、建设、运行等阶段要求以及过渡安排，商用密码应用安全性评估要求。  
  
  
原文链接：  
  
https://www.oscca.gov.cn/sca/hdjl/2024-11/15/1061217/files/f3a4bd2f91714ae580ac93c10198e86e.doc  
  
  
**2.欧盟发布《通用人工智能实践准则草案（初稿）》**  
  
  
11月14日，欧盟人工智能办公室发布了《通用人工智能实践准则草案（初稿）》，并对外征求意见。该文件由四个工作组的独立专家共同编写，包括透明度与版权规则、系统性风险识别与评估、系统性风险技术缓解、系统性风险治理缓解，旨在为未来可信、安全的通用AI模型的开发与部署提供指导框架。该文件提出，具有系统性风险的通用人工智能模型提供者，应采用、落实并公开其安全保障框架（Safety and Security Framework，SSF），详细说明各类风险、缓解措施、映射过程及局限性。  
  
  
原文链接：  
  
https://ec.europa.eu/newsroom/dae/redirection/document/109946  
  
  
**3.美国NIST发布后量子密码迁移路线图公开草案**  
  
  
11月12日，美国国家标准与技术研究院（NIST）发布了《过渡到后量子密码学标准》初始公开草案，包含迁移的路线与时间表。根据草案，NIST希望到2035年将政府机构的加密系统转变为后量子加密，该机构将在2030年前弃用112位及以下安全强度的加密算法，于2035年前禁用这些算法。NIST指出，向后量子密码学迁移的初期可能会采用混合解决方案，这些方案在建立加密密钥或生成数字签名时结合了抗量子算法和易受量子攻击算法的使用，以确保至少一个算法安全时整体系统的安全性。  
  
  
原文链接：  
  
https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf  
  
  
**往期精彩推荐**  
  
  
[【已复现】Fortinet FortiManager 身份认证绕过漏洞(CVE-2024-47575)安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502432&idx=1&sn=d3405bf69adda60e3be13962d038b6aa&chksm=fe79eef8c90e67eead814333282edff4d7e247d6ba9e9ba1895fff6354e808e4fa84048a0cd1&token=378560052&lang=zh_CN&scene=21#wechat_redirect)  
[奇安信集团2024年11月补丁库更新通告第一次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502419&idx=1&sn=0f428998b6afbde7b8f9bb36368f4400&chksm=fe79eecbc90e67dd896bd9e2e5d9dd814079af71d3b1ca2181e70d456a6b5dad59bbad3ddc51&token=378560052&lang=zh_CN&scene=21#wechat_redirect)  
  
[Ivanti Endpoint Manager SQL注入漏洞(CVE-2024-50330)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502418&idx=1&sn=0eb02a0cd4e956002411e0d7ec486bcf&chksm=fe79eecac90e67dc1f0d6bfaa6ca031761fca7ed42b4a815f9cea602d7d9aec5b0b990fb4c0e&token=378560052&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
