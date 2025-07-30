#  安全热点周报：Fortinet 修复了 FortiVoice 攻击中利用的关键零日漏洞   
 奇安信 CERT   2025-05-19 09:58  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">国务院2025年预备制定网络安全等级保护条例</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">美国最大钢铁公司纽柯因网络攻击被迫停产</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">迪奥中国客户信息遭泄露，官方群发短信通知客户</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Google Chrome跨源数据泄露漏洞安全风险通告**  
  
  
5月15日，奇安信CERT监测到Google发布公告称Google Chrome跨源数据泄露漏洞(CVE-2025-4664)存在在野利用，该漏洞源于Google Chrome加载程序中的策略执行不足，远程攻击者利用此漏洞可使浏览器发起请求时携带完整的URL，导致敏感信息泄露。目前该漏洞已发现在野利用，奇安信威胁情报中心安全研究员已成功复现。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.Fortinet FortiOS身份认证绕过漏洞安全风险通告**  
  
  
5月15日，奇安信CERT监测到官方修复Fortinet FortiOS身份认证绕过漏洞(CVE-2025-22252)，FortiOS、FortiProxy和FortiSwitchManager TACACS+中存在一个身份认证绕过漏洞，当其配置为使用ASCII认证的远程TACACS +服务器进行认证时（非默认配置），未经身份验证的远程攻击者可以绕过设备的正常认证机制，成功利用此漏洞可使攻击者获得设备的管理员权限。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.Ivanti Endpoint Manager Mobile多个漏洞安全风险通告**  
  
  
5月14日，奇安信CERT监测到官方修复Ivanti Endpoint Manager Mobile身份认证绕过漏洞(CVE-2025-4427)以及Ivanti Endpoint Manager Mobile代码执行漏洞(CVE-2025-4428)，这两个漏洞都是由于Ivanti Endpoint Manager Mobile的API组件未能正确验证输入的数据而造成的漏洞。攻击者可以利用这两个漏洞绕过身份认证，并通过受影响的API执行任何代码，对系统安全造成严重损害。目前该漏洞POC和技术细节已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Google Chrome 跨源数据泄露漏洞(CVE-2025-4664)******  
  
  
5月16日，Google 发布了 Chrome 桌面版关键稳定通道更新，Windows 和 macOS 版本升级至 136.0.7103.113/.114，Linux 版本升级至 136.0.7103.113。此更新将在未来几天和几周内陆续推出，包含四个安全修复程序，其中两个被评为高危漏洞，其中一个已确认被在野利用。  
  
此版本中最重要的修复是 CVE-2025-4664，该漏洞是由于 Google Chrome 加载器组件的策略执行不足造成的，成功利用该漏洞可让远程攻击者通过恶意制作的 HTML 页面泄露跨域数据。该漏洞被归类为高危漏洞。该漏洞最初由安全研究员 @slonser_ 于5月5日通过 X 帖子披露。  
  
该漏洞允许攻击者绕过 Chrome 加载器逻辑中的安全策略，可能导致未经授权的代码执行或沙盒逃逸。现实场景中的可利用性显著增加了修补的紧迫性。查询参数可能包含敏感数据——例如，在 OAuth 流程中，这可能会导致帐户接管。开发人员很少考虑通过来自第三方资源的图像窃取查询参数的可能性。  
  
虽然谷歌没有透露该漏洞是否曾被滥用于攻击或是否仍在被利用，但它在安全公告中警告称，该漏洞已被公开利用，这通常暗示该漏洞正在被积极利用。建议受影响用户尽快更新至 Chrome 136.0.7103.113/.114（Windows/macOS）、Chrome 136.0.7103.113（Linux），可以通过导航到检查版本 chrome://settings/help，这也会触发更新检查并安装任何待处理的更新。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-tags-recently-patched-chrome-bug-as-actively-exploited-zero-day/  
  
  
**2.****SAP NetWeaver Visual Composer Metadata Uploader 反序列化漏洞(CVE-2025-42999)******  
  
  
5月15日，SAP 已发布补丁来解决最近针对 SAP NetWeaver 服务器的零日攻击中利用的第二个漏洞。  
  
该公司于5月12日发布了针对此安全漏洞 CVE-2025-42999 的安全更新，称该漏洞是在调查涉及 SAP NetWeaver Visual Composer 中另一个未经身份验证的文件上传漏洞（追踪为 CVE-2025-31324）的零日攻击时发现的，该漏洞已于4月份修复。  
  
Shadowserver 基金会目前正在追踪超过 204 台暴露在互联网上且易受攻击的 SAP Netweaver 服务器。  
  
虽然 SAP 尚未确认 CVE-2025-42999 是否已被利用，但 Onapsis 首席技术官 Juan Pablo Perez-Etchegoyen 称威胁行为者自1月份以来就一直在利用这两个漏洞进行攻击。Perez-Etchegoyen 说“在2025年3月观察到的攻击实际上滥用了 CVE-2025-31324 以及 CVE-2025-42999。这种组合允许攻击者远程执行任意命令，而无需任何系统权限。这种残留风险本质上是一个反序列化漏洞，只有 SAP 目标系统上具有 VisualComposerUser 角色的用户才能利用。  
  
建议 SAP 管理员立即修补其 NetWeaver 实例，并考虑禁用 Visual Composer 服务，以及限制对元数据上传器服务的访问并监控其服务器上的可疑活动。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/sap-patches-second-zero-day-flaw-exploited-in-recent-attacks/  
  
  
**3.****Fortinet 多产品栈缓冲区溢出漏洞(CVE-2025-32756)******  
  
  
5月14日，Fortinet 发布了安全更新，以修补针对 FortiVoice 企业电话系统攻击中被利用为零日漏洞的严重远程代码执行漏洞。  
  
该安全漏洞是一个基于堆栈的溢出漏洞，编号为 CVE-2025-32756，还会影响 FortiMail、FortiNDR、FortiRecorder 和 FortiCamera。正如该公司发布的安全公告中所解释的那样，成功利用该漏洞可以允许远程未经身份验证的攻击者通过恶意制作的 HTTP 请求执行任意代码或命令。  
  
Fortinet 的产品安全团队根据攻击者的活动发现了 CVE-2025-32756，包括网络扫描、删除系统崩溃日志以掩盖其踪迹以及打开“fcgi 调试”以记录系统或 SSH 登录尝试的凭据。威胁行为者从六个 IP 地址发起了攻击，包括 198.105.127[.]124、43.228.217[.]173、43.228.217[.]82、156.236.76[.]90、218.187.69[.]244 和 218.187.69[.]59。Fortinet 在攻击分析过程中发现的入侵指标包括在受感染系统上启用的“fcgi 调试”设置（默认情况下未启用）。要检查此设置是否在您的系统上打开，运行以下命令后您应该看到“general to-file ENABLED” diag debug application fcgi：。  
  
在调查这些攻击时，Fortinet 发现威胁行为者在被黑客入侵的设备上部署恶意软件、添加旨在收集凭证的 cron 作业以及删除脚本以扫描受害者的网络。该公司还为无法立即安装安全更新的客户分享了缓解建议，要求他们禁用易受攻击的设备上 HTTP/HTTPS 管理界面。  
  
上个月，Shadowserver 基金会发现超过 16,000 台暴露在互联网上的 Fortinet 设备因使用新的符号链接后门而遭到入侵，该后门为威胁行为者提供了对先前攻击中被黑客入侵的现已修补的设备上敏感文件的只读访问权限。  
  
建议 FortiVoice、FortiMail、FortiNDR、FortiRecorder 和 FortiCamera 的用户应用必要的修复程序，以保护其设备免受主动攻击。如果无法立即修复，建议禁用 HTTP/HTTPS 管理界面作为临时解决方法。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/fortinet-fixes-critical-zero-day-exploited-in-fortivoice-attacks/  
  
  
**4.****Microsoft DWM 核心库权限提升漏洞(CVE-2025-30400)******  
  
  
5月14日，微软共发布了78个漏洞的补丁程序，修复了Windows 通用日志文件系统驱动程序、Windows 脚本引擎、Microsoft SharePoint Server等产品中的漏洞。  
  
CVE-2025-30400是 Windows 桌面窗口管理器 (DWM) 核心库中的一个 EoP 漏洞。该漏洞的 CVSSv3 评分为 7.8，并被评为“重要”。微软指出，该漏洞已被利用为零日漏洞。成功利用该漏洞，攻击者可以通过利用“释放后使用”漏洞来提升权限。这是今年修复的 DWM 核心库中的第七个 EoP 漏洞。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-may-2025-patch-tuesday-addresses-71-cves-cve-2025-32701-cve-2025-32706  
  
  
**5.****Windows 通用日志文件系统驱动程序权限提升漏洞(CVE-2025-32701、CVE-2025-32706)******  
  
  
5月14日，微软共发布了78个漏洞的补丁程序，修复了Windows 通用日志文件系统驱动程序、Windows 脚本引擎、Microsoft SharePoint Server等产品中的漏洞。  
  
CVE-2025-32701 和 CVE-2025-32706 是 Windows 通用日志文件系统 (CLFS) 驱动程序中的 EoP 漏洞。漏洞的 CVSSv3 评分均为 7.8，并被评为重要漏洞。CVE-2025-32701 和 CVE-2025-32706 均已在野以零日漏洞的形式被利用。Windows CLFS 仍然是攻击者常用的攻击媒介，并且已被勒索软件团伙利用。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-may-2025-patch-tuesday-addresses-71-cves-cve-2025-32701-cve-2025-32706  
  
  
**6.****Windows 脚本引擎内存损坏漏洞(CVE-2025-30397)******  
  
  
5月14日，微软共发布了78个漏洞的补丁程序，修复了Windows 通用日志文件系统驱动程序、Windows 脚本引擎、Microsoft SharePoint Server等产品中的漏洞。  
  
CVE-2025-30397 是 Microsoft 脚本引擎中的一个内存损坏漏洞，可导致目标机器上任意代码执行。该漏洞的 CVSSv3 评分为 7.5，级别为“重要”。攻击复杂度被评为“高”，Microsoft 指出目标必须首先在 Internet Explorer 模式下运行 Microsoft Edge。成功利用该漏洞需要用户点击一个精心设计的 URL。据报道，该漏洞已被广泛利用，并被用作零日漏洞。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-may-2025-patch-tuesday-addresses-71-cves-cve-2025-32701-cve-2025-32706  
  
  
**7.****Windows Ancillary Function Driver for WinSock 权限提升漏洞(CVE-2025-32709)******  
  
  
5月14日，微软共发布了78个漏洞的补丁程序，修复了Windows 通用日志文件系统驱动程序、Windows 脚本引擎、Microsoft SharePoint Server等产品中的漏洞。  
  
CVE-2025-32709 是 Windows 辅助功能驱动程序 (WinSock) 中的一个 EoP 漏洞。该漏洞的 CVSSv3 评分为 7.8，并被评为“重要”。经过身份验证的攻击者可以利用此漏洞，通过利用用户在空闲状态下的漏洞，将权限提升至管理员。微软指出，该漏洞已被广泛利用，是一个零日漏洞，也是 2025 年内第二个被利用的漏洞，之前一个是 CVE-2025-21418 ，该漏洞已在二月份的补丁星期二版本中得到修复。  
  
建议管理员和家庭用户尽快测试和部署微软官方发布的补丁，以避免已知漏洞的攻击。  
  
  
参考链接：  
  
https://www.tenable.com/blog/microsofts-may-2025-patch-tuesday-addresses-71-cves-cve-2025-32701-cve-2025-32706  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.Coinbase遭网络攻击泄露客户敏感数据，预计损失高达28亿元**  
  
  
5月15日Bleeping Computer消息，知名加密货币交易所Coinbase披露称，有网络犯罪团伙收买了一批公司海外客服人员，窃取约百万客户（占比1%）的敏感数据用以实施社会工程攻击，试图诱骗对方转账汇款，目前客户损失规模尚未公布。据悉，此次泄漏数据包括客户姓名、地址、电话、电子邮箱、打码社会安全号码、打码银行账户、身份证/护照/驾照照片、账户金额及交易记录、公司客服内部资料等。官方称客户密码、私钥等信息未泄露。Coinbase表示将对被骗汇款的客户进行赔偿，并设立2000万美元基金用于悬赏攻击者线索，预计该事件的补救措施和客户赔偿总支出最高需要28.8亿元。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/coinbase-discloses-breach-faces-up-to-400-million-in-losses/  
  
**2.美国最大钢铁公司纽柯因网络攻击被迫停产**  
  
  
5月14日Bleeping Computer消息，美国最大的钢铁生产商纽柯（Nucor）发布SEC公告披露，近日遭遇网络安全事件，第三方未经授权访问了公司的部分信息技术系统。发现该事件后，公司立即启动了应对措施，包括启动事件响应计划，主动将可能受影响的系统下线，并实施其他遏制、修复及恢复措施。此次事件导致纽柯公司多个生产基地部分运营暂停，目前正在逐步恢复中，尚不清楚该事件对公司整体业务造成了多大影响。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/steel-giant-nucor-corporation-facing-disruptions-after-cyberattack/  
  
**3.迪奥中国客户信息遭泄露，官方群发短信通知客户**  
  
  
5月13日中国新闻社消息，迪奥官方客服表示，有未经授权的外部方获取含客户信息的部分数据，但涉事数据库中未存储任何金融信息。迪奥品牌5月12日向用户发布短信，表示该品牌发生数据泄露事件，已采取措施以避免此次恶意访问事件的事态扩大。根据目前调查进展，在中国收集的受影响的客户个人信息的最大范围可能包括姓名、性别、手机号码、电子邮箱地址、邮寄地址、消费水平、偏好，以及客户可能已向迪奥提供的其他信息。被访问的数据库中不包含诸如银行账户详情、国际银行账户号码（IBAN）或信用卡信息等财务信息。迪奥建议客户对任何可疑通信（短信、电话、电子邮件）都要保持警惕，不要打开或点击来自不明来源的通信或链接，也不要透露验证码、密码等敏感信息。若收到任何以迪奥名义发送的可疑信息或联系，请客户咨询迪奥官方客服中心。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/9toojbXPycmNctEZMN8VvA  
  
**4.日本逾十家券商大量用户账户遭盗取：被操纵买卖股票 涉金额约20亿美元**  
  
  
5月10日The Record消息，日本金融厅发布警告称，有攻击者通过伪造券商官方网站实施网络钓鱼攻击，窃取了十余家券商大量用户证券账户，并大肆操作买卖股票，涉及金额约20亿美元。据悉，其中多数欺诈交易是在4月发生，有9家券商报告了2746笔欺诈交易，涉及近5000个证券账户。日本金融厅称，攻击者通常将被盗取账户的资金，大举购买国内外的小盘股及其他证券资产，试图推高股价，待股价上涨后再将其出售，从中获取高价差利润。  
  
  
原文链接：  
  
https://therecord.media/hackers-hijack-japan-finance-accounts  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.财政部、金融监管总局发布《关于加快推动银行函证数字化发展的通知》**  
  
  
5月16日，财政部、金融监管总局发布《关于加快推动银行函证数字化发展的通知》，要求建设安全、便捷、高效、经济的银行函证体系。该文件提出，压实各方责任，统筹保障银行函证平台运营的安全性、连续性、稳定性；掌握平台知识产权，确保平台核心底层技术的独立、自主、可控；提升平台安全性，中国注册会计师协会会商银行函证平台建设方制定、发布银行函证平台信息安全标准，相关银行函证平台建设方组织第三方机构对相关银行函证平台统一实施评估认证，并将结果提供给平台用户。  
  
原文链接：  
  
https://kjs.mof.gov.cn/gongzuotongzhi/202505/t20250516_3963932.htm  
  
  
**2.美国消费者金融保护局撤回关于数据经纪人监管的拟议规则**  
  
  
5月15日，美国消费者金融保护局（CFPB）在《联邦公报》发布公告，撤回其《保护美国人免受有害数据经纪行为侵害》拟议规则。CFPB认为，目前进行规则制定“既无必要也不合适”，预计本届政府任期内不太可能有进一步的发展。CFPB于2024年12月提出该规则，计划将《公平信用报告法》的适用范围扩大至涵盖数据经纪等行业，要求数据共享需获得消费者的明确同意，并限制此类数据的销售或使用目的，旨在解决国家安全、监控和消费者权益受损等担忧。  
  
  
原文链接：  
  
https://www.federalregister.gov/documents/2025/05/15/2025-08644/protecting-americans-from-harmful-data-broker-practices-regulation-v-withdrawal-of-proposed-rule  
  
  
**3.国务院2025年预备制定网络安全等级保护条例**  
  
  
5月14日，国务院办公厅印发《国务院2025年度立法工作计划》，其中多项内容和网络与信息安全相关，包括制定政务数据共享条例，预备制定网络安全等级保护条例、终端设备直连卫星服务管理条例，预备修订政府信息公开条例、互联网信息服务管理办法、反间谍法实施细则，推进人工智能健康发展立法工作。此前公安部于2018年6月公布《网络安全等级保护条例（征求意见稿）》对外公开征求意见，时隔7年后，该文件终于迎来新进展。  
  
  
原文链接：  
  
https://www.gov.cn/zhengce/content/202505/content_7023697.htm  
  
  
**4.《儿童手表安全技术要求》强制性国家标准公开征求意见**  
  
  
5月13日，工业和信息化部组织完成了《儿童手表安全技术要求》强制性国家标准（征求意见稿）的编制工作，现公开征求意见。该文件规定了儿童手表的安全技术要求，描述了相应的试验方法。在网络安全方面，该文件对信息安全、数据安全和个人信息保护、内容安全三方面做出要求，包括儿童智能手表应具备产品维保周期内操作系统安全升级的功能、应具备应用程序被预置或安装时的安全管理机制、应支持开机和锁屏时的密码保护、应制定专门的儿童个人信息处理规则、应建立儿童专属内容池、应具备阻断生成式语音问答应用程序安装的功能、应建立对儿童智能手表向儿童提供信息内容进行持续内容安全监测机制等。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/filemanager/1226211233/attach/20255/79a07e6f5ee8466cac065d70bf45ee6b.rar  
  
  
**往期精彩推荐**  
  
  
[【已复现】Ivanti Endpoint Manager Mobile 多个漏洞安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503407&idx=1&sn=bc577b527b31ff7b989f2b804f447771&scene=21#wechat_redirect)  
  
  
[【已复现】Google Chrome 跨源数据泄露漏洞(CVE-2025-4664)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503400&idx=1&sn=a3ed07a0c534855161deb71b6a0642e4&scene=21#wechat_redirect)  
  
[Fortinet FortiOS 身份认证绕过漏洞(CVE-2025-22252)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503400&idx=2&sn=80467da7de6cbd94b86630f8ee95874a&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
