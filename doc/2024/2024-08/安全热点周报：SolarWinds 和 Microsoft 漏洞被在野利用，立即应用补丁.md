#  安全热点周报：SolarWinds 和 Microsoft 漏洞被在野利用，立即应用补丁   
 奇安信 CERT   2024-08-19 17:30  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 美国NIST正式发布首批3项后量子加密标准</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 伊朗遭遇大规模网络攻击，银行系统瘫痪</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 巴黎奥运会期间共发生超140起网络攻击事件</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Windows TCP/IP IPv6远程拒绝服务/代码执行漏洞安全风险通告**  
  
  
8月15日，奇安信CERT监测到微软发布8月补丁日安全更新修复Windows TCP/IP远程代码执行漏洞(CVE-2024-38063)，Windows TCP/IP组件中发现了一个整数下溢漏洞，可能会触发缓冲区溢出。未经身份验证的远程攻击者可以通过发送特制的IPv6数据包到目标Windows系统机器导致目标蓝屏崩溃，精心构造请求理论上存在远程代码执行的可能性。该漏洞影响了所有受IPv6支持的Windows版本，包括即将发布的Windows 11版本24H2。禁用IPv6的系统不受此漏洞的影响，但对于启用IPv6的系统，存在很大的利用风险。该漏洞被微软标记较大可能被利用，鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。强烈建议马上安装补丁。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****SolarWinds Web Help Desk 反序列化漏洞(CVE-2024-28986)**  
  
  
8月 15 日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加SolarWinds Web Help Desk 反序列化漏洞(CVE-2024-28986)，SolarWinds Web Help Desk 被发现存在 Java 反序列化远程代码执行漏洞，如果该漏洞被利用，攻击者便可在主机上运行命令。  
  
Web Help Desk (WHD) 是一种 IT 帮助台软件，被世界各地的大型企业、政府机构、医疗保健和教育组织广泛使用，以集中、自动化和简化帮助台管理任务。  
  
SolarWinds 于周三发布了针对该漏洞的补丁程序，不过，该公司并未透露有关该漏洞在野利用的任何信息，尽管它建议所有管理员对易受攻击的设备应用补丁程序。  
  
SolarWinds表示：“虽然它被报告为未经身份验证的漏洞，但 SolarWinds 经过彻底测试后仍无法在未经身份验证的情况下重现该漏洞。不过，出于谨慎考虑，建议所有 Web Help Desk 客户应用现已推出的补丁”。如果使用 SAML 单点登录 (SSO)，则不应应用 WHD 12.8.3 Hotfix 1。官方承诺将很快发布新补丁来解决此问题。  
  
SolarWinds 还发布了一篇支持文章，其中包含有关应用和删除补丁程序的详细说明，并警告管理员必须在安装补丁程序之前将易受攻击的服务器升级到 Web Help Desk 12.8.3.1813。  
  
该公司建议在安装过程中替换原始文件之前创建备份，以避免补丁程序部署失败或补丁程序未正确应用时出现潜在问题。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-critical-solarwinds-rce-bug-is-exploited-in-attacks/  
  
  
**2.Microsoft Project 远程代码执行漏洞(CVE-2024-38189)**  
  
  
8月 13 日，微软共发布了91个漏洞的补丁程序，修复了Windows WinSock、 Microsoft Project、Windows Power Dependency Coordinator和Azure等产品中的漏洞。据微软称，Microsoft Project 远程代码执行漏洞(CVE-2024-38189)已发现在野利用。  
  
CVE-2024-38189是一个影响项目管理工具 Microsoft Project 的 RCE 漏洞。此漏洞的 CVSSv3 评分为 8.8，并已被广泛利用。根据微软的发布的8月份安全更新公告，利用该漏洞需要毫无戒心的受害者打开精心设计的 Microsoft Office Project 文件。此外，为了成功攻击，必须将系统配置为禁用“阻止宏在 Internet 策略中的 Office 文件中运行”，并禁用 VBA 宏通知设置。微软的公告确实澄清了预览窗格不是此漏洞的攻击媒介，并在无法立即执行修补时提供缓解选项来保护系统。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-august-2024-patch-tuesday-addresses-88-cves  
  
  
**3.Microsoft 脚本引擎内存损坏漏洞(CVE-2024-38178)**  
  
  
8月 13 日，微软共发布了91个漏洞的补丁程序，修复了Windows WinSock、 Microsoft Project、Windows Power Dependency Coordinator和Azure等产品中的漏洞。据微软称，Microsoft 脚本引擎内存损坏漏洞(CVE-2024-38178)已被发现在野利用。  
  
CVE-2024-38178是 Windows 脚本中的脚本引擎内存损坏漏洞。此漏洞的 CVSSv3 评分为 7.5，Microsoft 指出已发现利用漏洞的情况。据 Microsoft 称，在未经身份验证的攻击者说服受害者单击特制的 URL 以获取 RCE 之前，经过身份验证的受害者必须拥有 Internet Explorer 模式下的 Edge，这是利用漏洞的先决条件。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-august-2024-patch-tuesday-addresses-88-cves  
  
  
**4.Windows Mark of the Web 安全特性绕过漏洞(CVE-2024-38213)**  
  
  
8月 13 日，微软共发布了91个漏洞的补丁程序，修复了Windows WinSock、 Microsoft Project、Windows Power Dependency Coordinator和Azure等产品中的漏洞。据微软称，Windows Mark of the Web 安全特性绕过漏洞(CVE-2024-38213)已被发现在野利用。  
  
CVE-2024-38213是一个安全功能绕过漏洞，其 CVSSv3 评分为 6.5。要利用此漏洞，用户必须打开一个特制文件，该文件可能托管在文件服务器、网站上或通过钓鱼电子邮件发送。如果攻击者成功说服受害者打开此文件，他们就可以绕过 Windows SmartScreen 用户体验。微软已将此标记为“漏洞已遭利用”，因为他们已经发现了在野利用行为。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-august-2024-patch-tuesday-addresses-88-cves  
  
  
**5.Windows 辅助功能驱动程序的 WinSock 权限提升漏洞(CVE-2024-38193)**  
  
  
8月 13 日，微软共发布了91个漏洞的补丁程序，修复了Windows WinSock、 Microsoft Project、Windows Power Dependency Coordinator和Azure等产品中的漏洞。据微软称，Windows 辅助功能驱动程序的 WinSock 权限提升漏洞(CVE-2024-38193)已被作为零日漏洞在野利用。  
  
CVE-2024-38193是影响 Windows 辅助功能驱动程序（用于 Winsock） (afd.sys) 的 EoP 漏洞。该漏洞允许本地用户提升系统权限。该漏洞是由于 WinSock 辅助功能驱动程序中的释放后使用错误而产生的。本地用户可以触发释放后使用错误并以提升的权限执行任意代码。该漏洞的 CVSSv3 评分均为 7.8，请注意，该漏洞正在被广泛利用。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-august-2024-patch-tuesday-addresses-88-cves  
  
  
**6.Windows 内核权限提升漏洞(CVE-2024-38106)**  
  
  
8月 13 日，微软共发布了91个漏洞的补丁程序，修复了Windows WinSock、 Microsoft Project、Windows Power Dependency Coordinator和Azure等产品中的漏洞。据微软称，Windows 内核权限提升漏洞(CVE-2024-38106)已被作为零日漏洞在野利用。  
  
CVE-2024-38106是影响 Windows 内核的 EoP 漏洞。该漏洞允许本地用户提升系统权限。该漏洞是由于 Windows 内核中的竞争条件而存在的。本地用户可以利用该竞争条件并以 SYSTEM 权限执行任意代码。CVE-2024-38106 的 CVSSv3 评分为 7。尽管 CVE-2024-38106 的严重性较低且攻击者需要赢得竞争条件才能成功利用，但是已发现在野利用行为。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-august-2024-patch-tuesday-addresses-88-cves  
  
  
**7.Windows Power Dependency Coordinator 权限提升漏洞(CVE-2024-38107)**  
  
  
8月 13 日，微软共发布了91个漏洞的补丁程序，修复了Windows WinSock、 Microsoft Project、Windows Power Dependency Coordinator和Azure等产品中的漏洞。据微软称，Windows Power Dependency Coordinator 权限提升漏洞(CVE-2024-38107)已被作为零日漏洞在野利用。  
  
CVE-2024-38107是一个 EoP 漏洞，影响 Windows 电源依赖性协调器 (pdc.sys)，该驱动程序负责 Windows 系统上的电源管理。此漏洞被广泛利用为零日漏洞，但尚未提供有关利用的具体细节。Microsoft 为该漏洞提供的 CVSSv3 评分为 7.8，并且所有受支持的 Windows 和 Windows Server 版本均提供修补程序。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-august-2024-patch-tuesday-addresses-88-cves  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.伊朗遭遇大规模网络攻击，银行系统瘫痪**  
  
  
8月15日财联社消息，伊朗央行和该国多家银行14日遭受了一次重大网络攻击，导致伊朗银行系统大面积中断。初步评估表明，这可能是针对伊朗国家基础设施的最大网络攻击之一。据悉，黑客还窃取了伊朗多家银行客户的信息。此次网络攻击正值中东地缘政治风险加剧之际，因此受到了高度关注。很多伊朗人认为，此次网络攻击是以色列情报部门实施的，然而这些指控并没有实质性证据。以色列媒体也报道了针对伊朗银行系统的重大网络攻击，但伊朗官方至今尚未证实这一消息，该国媒体也保持了沉默。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/hqDFTDhm8sUoubkA58GhHA  
  
  
**2.巴黎奥运会期间共发生超140起网络攻击事件**  
  
  
8月14日法新社消息，法国当局表示，在巴黎奥运会期间，共报告了超过140起网络攻击，但均未对比赛造成干扰。在奥运会筹备期间和整个比赛期间，法国的网络安全机构一直保持高度警戒，防范可能破坏组委会、票务或交通的攻击。从7月26日到8月11日，法国政府网络安全机构ANSSI记录了119起影响较低的“安全事件”，以及22起“恶意行为者”成功攻击受害者信息系统的事件。该机构表示，这些攻击主要针对政府实体以及体育、交通和电信基础设施。根据ANSSI的数据，三分之一的事件是宕机事件，其中一半是通过拒绝服务攻击压垮服务器造成的。其他网络事件则与既遂或未遂系统入侵和数据泄露等相关。  
  
  
原文链接：  
  
https://www.france24.com/en/live-news/20240814-france-reports-over-140-cyberattacks-linked-to-olympics  
  
  
**3.特朗普竞选团队在大选期间被黑，部分敏感数据外泄**  
  
  
8月10日Politico消息，美国前总统唐纳德·特朗普的竞选团队日前确认，其部分内部通信资料已被黑客获取。特朗普竞选团队引用微软8月9日发布的一份报告的说法，将此归咎于“对美国怀有敌意的外国势力”。该报告称，伊朗黑客“在2024年6月向一名美国总统竞选的高级官员发送了一封鱼叉式网络钓鱼邮件，成功入侵其邮箱账号。”微软并未确认邮件针对的是哪一家竞选团队，也拒绝发表评论。此前，多家知名媒体收到来自一个匿名账号发送的电子邮件，其中包含了特朗普竞选团队内部的文件。  
  
  
原文链接：  
  
https://www.politico.com/news/2024/08/10/trump-campaign-hack-00173503  
  
  
**4.美国金融巨头因勒索攻击损失近2亿元，超1600万用户数据泄露**  
  
  
8月7日SecurityWeek消息，美国抵押贷款巨头LoanDepot通过SEC报告披露，今年1月曝光的勒索软件攻击相关的费用总计2690万美元（约合人民币1.92亿元）。公司当时遭受勒索软件攻击后，为了应对攻击导致数据被加密的情况，选择将一些系统下线。几周后，LoanDepot通知当局，超过1600万人的个人信息可能已被泄露，泄露信息包括姓名、地址、电子邮件地址、电话号码、出生日期、社会保障号码和金融账号。LoanDepot最新财报显示，该事件给公司造成了2690万美元损失，包括“调查和补救网络安全事件的成本、客户通知和身份保护的成本、专业费用（包括法律费用、诉讼和解费用以及佣金担保）”。  
  
  
原文链接：  
  
https://www.securityweek.com/ransomware-attack-cost-loandepot-27-million/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.美国NIST正式发布首批3项后量子加密标准**  
  
  
8月13日，美国NIST正式发布首批3项后量子密码标准，以应对即将到来的量子威胁。3项标准分别如下：ML-KEM（基于CRYSTALS-Kyber）是基于模块格的密钥封装机制，速度很快，适用于快速加密操作，如安全访问网站；ML-DSA（基于CRYSTALS-Dilithium）是用于数字签名的标准，能够确保文件或软件在传输过程中的完整性和真实性；SLH-DSA（基于SPHINCS+）也是一种数字签名标准，但其安全性更强，代价是需要更大的签名或更长的签名生成时间。  
  
  
原文链接：  
  
https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards  
  
  
**2.美国议员提出《联邦承包商网络安全漏洞消减法案》**  
  
  
8月9日，美国民主党参议员Mark R. Warner和共和党参议员James Lankford联合推出一项立法提案《联邦承包商网络安全漏洞消减法案》，旨在加强联邦承包商的漏洞披露规则。该立法提案要求美国联邦和国防供应商全部强制实施漏洞披露政策（VDP），执行和联邦机构一致的漏洞披露要求，以实现漏洞消减目标。对于实施漏洞披露政策的组织，研究人员如在这些组织的软件产品中发现漏洞，将有途径进行报告，以便在漏洞被利用进行攻击之前进行处理。参议员们认为，接收漏洞报告能够让开发人员和服务提供商意识到问题。目前，美国要求联邦民事行政部门实施漏洞披露政策，联邦承包商却不受约束。  
  
  
原文链接：  
  
https://www.warner.senate.gov/public/index.cfm/2024/8/warner-lankford-announce-legislation-to-strengthen-federal-cybersecurity-measures-implement-mandatory-vulnerability-disclosure-policies  
  
  
**3.旅游行业标准《旅游大数据安全与隐私保护要求》公开征求意见**  
  
  
8月9日，全国旅游标准化技术委员会组织编制了《旅游大数据安全与隐私保护要求（征求意见稿）》，现公开征求意见。该文件规定了旅游大数据的通用安全目标、安全与隐私保护生命周期管理、安全与隐私保护运维管理、安全与隐私保护监控管理以及典型旅游应用场景大数据安全等方面的内容。该文件适用于旅游管理和服务机构开展旅游大数据收集、传输、存储、提供与公开、使用与加工、退役等过程中的安全管理组织、人员安全管理、相关系统建设等，也可为有关部门对旅游大数据相关活动进行监管管理提供参考。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/dmyrVs41UY89JbbruJ1wzg  
  
  
**往期精彩推荐**  
  
  
[【利用场景更新】Windows TCP/IP IPv6远程拒绝服务/代码执行漏洞(CVE-2024-38063)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501938&idx=1&sn=d0ffecf00a33d91609cea098c7d70a9f&chksm=fe79eceac90e65fc7a71b961d6d526d1e00a06cd9940fde42fde602b4626bc5209d64573394b&token=1124892821&lang=zh_CN&scene=21#wechat_redirect)  
[【已复现】Windows TCP/IP IPv6远程拒绝服务/代码执行漏洞(CVE-2024-38063)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501929&idx=1&sn=f5f4d0cd06570b68b527e10c3fa80b77&chksm=fe79ecf1c90e65e7f03fc258b83ed5f0d964172db2126e225933235831e75accb9632d22047e&token=1124892821&lang=zh_CN&scene=21#wechat_redirect)  
  
[微软8月补丁日多个产品安全漏洞风险通告：5个在野利用、7个紧急漏洞](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501900&idx=1&sn=9dac68515903944fde3fb17660e0d4da&chksm=fe79ecd4c90e65c2f4785b7b90197aa0503883839f59b127a77bdae244e58dd7ed921b24633b&token=1124892821&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
