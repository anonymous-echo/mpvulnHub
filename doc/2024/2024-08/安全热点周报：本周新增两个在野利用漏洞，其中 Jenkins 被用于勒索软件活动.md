#  安全热点周报：本周新增两个在野利用漏洞，其中 Jenkins 被用于勒索软件活动   
 奇安信 CERT   2024-08-26 19:15  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 强制性国家标准《汽车整车信息安全技术要求》正式发布</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 九国网络安全机构联合发布《事件日志记录和威胁检测最佳实践指南》</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 国内某上市公司疑遭勒索攻击泄漏2.3TB数据</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Google Chrome V8类型混淆漏洞安全风险通告**  
  
  
8月22日，奇安信CERT监测到Google发布公告称Google Chrome V8类型混淆漏洞(CVE-2024-7971)存在在野利用，远程攻击者可通过诱导用户打开恶意链接来利用此漏洞，从而获取敏感信息或代码执行。目前，此漏洞已检测到在野利用。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Versa Director 危险文件类型上传漏洞(CVE-2024-39717)**  
  
  
8月 23 日，美国网络安全和基础设施安全局 (CISA)根据主动利用的证据，将影响 Versa Director 的安全漏洞列入其已知被利用漏洞 ( KEV )目录。  
  
该中等严重性漏洞的编号为 CVE-2024-39717（CVSS 评分：6.6），是影响“更改图标”功能的文件上传错误，可能允许黑客通过将其伪装成看似无害的 PNG 图像文件来上传恶意文件。  
  
CISA 在一份公告中表示：Versa Director GUI 包含一个不受限制的危险类型文件上传漏洞，允许具有 Provider-Data-Center-Admin 或 Provider-Data-Center-System-Admin 权限的管理员自定义用户界面。更改收藏夹图标 (Favorite Icon) 可以上传 .png 文件，攻击者可以利用该文件上传伪装成图像的带有 .PNG 扩展名的恶意文件。  
  
但是，只有具有 Provider-Data-Center-Admin 或 Provider-Data-Center-System-Admin 权限的用户成功通过身份验证并登录后，才有可能成功利用该漏洞。  
  
虽然 CVE-2024-39717 被利用的具体情况尚不清楚，但 Versa Networks 知道一个已确认的客户报告的实例，该实例利用了此漏洞，因为该客户未实施 2015 年和 2017 年发布的防火墙指南。这种不实施导致不良行为者无需使用 GUI 即可利用此漏洞。  
  
建议受影响客户通过应用供应商提供的修复程序来防止该漏洞。  
  
  
参考链接：  
  
https://thehackernews.com/2024/08/cisa-urges-federal-agencies-to-patch.html  
  
  
**2.Jenkins任意文件读取漏洞(CVE-2024-23897)**  
  
  
8 月 19 日，CISA 在其已知可利用漏洞 (KEV) 目录中添加了一个新漏洞。该漏洞编号为CVE-2024-23897，CVSS 评分为 9.8，可用于启用远程代码执行 (RCE) 和数据盗窃，并影响 Jenkins 开源 CICD 自动化服务器。这是一个文件读取漏洞，影响 Jenkins 2.441 和 LTS 2.426.2 之前的版本。该漏洞位于用于解析 Jenkins Controller 命令行界面 (CLI) 中的命令参数的 args4j 库中，允许未经身份验证的用户读取文件系统上的部分文件。  
  
该漏洞与“expandAtFiles”功能有关，其中参数中的“@”字符后跟文件路径会被替换为文件的内容。它会带来严重的安全风险，有可能造成远程代码执行 (RCE)。攻击媒介是“任意文件读取”，允许攻击者使用控制器进程的默认字符编码读取任意文件。它于 2024 年 1 月首次被发现并修补。  
  
日本安全巨头趋势科技表示，该漏洞最早于 2024 年 3 月发现在野利用，并指出“根据Shadowserver数据，我们的分析发现了来自不同地区的多起攻击事件，其中大多数攻击的源 IP 地址来自荷兰。同时，大多数目标来自南非。” 当时，他们还报告说，他们已经发现了一些团体出售和交易该漏洞以换取 BTC。  
  
最近，CloudSEK 发布了一份报告，称跨国公司 BORN 集团显然是供应链攻击的受害者，该攻击利用此漏洞窃取了多个客户账户的数据。此事仍在调查中，但似乎是一个名为 Intelbroker 的组织所为，该组织以针对知名政府、公司和组织而闻名。  
  
8 月中旬，瞻博网络披露勒索软件团伙 RansomEXX 利用该漏洞进入了印度 Brontoo Technology 解决方案的网络。此次攻击发生在 2024 年 7 月，影响了整个印度的支付技术。根据瞻博网络的报告，Brontoo 是“ C-Edge Technologies 的合作伙伴，C-Edge Technologies 是 TCS（塔塔咨询服务公司）和 SBI（印度国家银行）的合资企业，据 NPCI（印度国家支付公司）称，该公司受到了勒索软件攻击的影响。C-Edge 主要为合作和地区农村银行提供技术服务。”   
  
客户可以通过检查 Jenkins 版本来验证系统是否受到影响。易受攻击的版本包括 Jenkins 2.441 和 LTS 2.426.2 之前的版本。此步骤对于了解潜在安全风险的暴露程度至关重要。强烈建议将 Jenkins 安装更新到最新版本。更新到修复漏洞的修补版本是保护系统免受潜在攻击的重要措施。作为临时缓解措施，用户可以选择禁用对命令行界面 (CLI) 功能的访问。通过限制或暂时阻止 CLI 访问，您可以防止未经授权的活动并降低漏洞利用风险，直到应用全面的解决方案。  
  
  
参考链接：  
  
https://xmcyber.com/blog/cve-2024-23897-jenkins-rce-exploited-in-ransomware-attacks/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.美国知名军工芯片厂商因网络攻击生产能力受损**  
  
  
8月21日The Register消息，美国半导体制造公司微芯科技（Microchip Technology）通过SEC文件披露，“未经授权的第三方破坏了公司对某些服务器的使用以及部分业务操作。”该公司在8月17日“检测到可能涉及其信息技术系统的可疑活动。”随后展开调查，19日调查结果确认存在未经授权的访问。该公司采取了隔离相关系统、关闭其他系统等多项措施，并聘请了外部网络安全顾问来确定问题范围。“由于该事件，公司某些制造设施的运营低于正常水平，公司目前履行订单的能力受到影响。”文件没有提及事件原因、对芯片制造商造成的破坏程度，或是否涉及勒索软件。微芯科技的产品被设计用于军事关键任务，常用于汽车、飞机、导弹等高速移动的设备，或在恶劣的偏远地区运行的设备。  
  
  
原文链接：  
  
https://www.theregister.com/2024/08/21/microchip_technology_security_incident/  
  
  
**2.国内某上市公司疑遭勒索攻击泄漏2.3TB数据**  
  
  
8月20日GoUpSec消息，据FalconFeeds、Ransomlook等多家威胁情报平台报道，某A股上市建筑公司某集团疑似发生大规模数据泄漏，勒索软件组织The Ransom House Group在数据泄漏论坛发帖称窃取了该公司2.3TB数据，并宣称如果未来2-3天内不支付赎金将撕票（公布数据）。此次针对某集团的攻击事件未得到官方确认，也未公布具体被窃数据的种类和数量，但报道该事件的威胁情报平台预计可能涉及公司内部敏感信息。RansomHouse是近年来新兴的数据勒索团伙之一，自2021年末开始活跃，曾成功攻击过包括半导体巨头AMD、非洲零售巨头Shoprite在内的多家大型公司。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/-e-uFQGGQ0h1Uz79YtLPXQ  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.强制性国家标准《汽车整车信息安全技术要求》正式发布**  
  
  
8月23日，由工业和信息化部归口的强制性国家标准《汽车整车信息安全技术要求》正式发布，于2026年1月1日起实施。该标准文本目前尚未公布，根据此前的征求意见稿，该标准规定了汽车信息安全管理体系要求、车辆信息安全一般要求、车辆信息安全技术要求、审核评估及测试验证方法，适用于M类、N类及至少装有1个电子控制单元的O类车辆，其他类型车辆可参考执行。  
  
  
原文链接：  
  
https://std.samr.gov.cn/gb/search/gbDetailed?id=208DEC46F6B347EEE06397BE0A0AA4A0  
  
  
**2.九国网络安全机构联合发布《事件日志记录和威胁检测最佳实践指南》**  
  
  
8月21日，澳大利亚、美国等五眼联盟国家及日本、韩国、新加坡、荷兰九国网络安全机构联合发布《事件日志记录和威胁检测最佳实践指南》，针对恶意攻击者常使用的离地攻击手法（如无文件攻击），给出了事件记录的最佳实践，以捕获高质量的安全日志，帮助网络防御者正确识别安全事件。该指南适用于IT、OT环境，可作为关键基础设施提供商的参考指南。  
  
  
原文链接：  
  
https://www.cyber.gov.au/sites/default/files/2024-08/best-practices-for-event-logging-and-threat-detection.pdf  
  
  
**3.美国海军部发布《信息优势愿景》2.0版**  
  
  
8月15日，美国海军部发布《信息优势愿景2.0》，对2020年发布的首个信息优势愿景进行更新，强调向“以数据为中心”、“数据优先”机构的转变，并明确数据管理的重要性，旨在指导海军的IT发展规划，将海军部转变为一个数据运转更加流畅的现代化组织，从而在执行作战和商业任务时能够更加快速高效地生成和使用数据。该文件要求构建一个以保密数据为中心的生态系统，以实现更广泛、更安全地机密信息共享能力，包括与海军以外的授权用户共享；基于零信任原则实施支持所有涉密数据的单一结构；加快美军和任务伙伴对不同分类数据的访问速度以提高美军决策优势。  
  
  
原文链接：  
  
https://www.doncio.navy.mil/FileHandler.ashx?id=22154  
  
  
**4.美国联邦航空管理局发布《人工智能安全保障路线图》**  
  
  
7月25日，美国联邦航空管理局发布《人工智能安全保障路线图》第一版，概述了如何将人工智能技术安全整合至航空领域的方法。该文件提出在现有航空生态系统内运行、聚焦安全保证和安全增强、避免拟人化、采取渐进式方法等7项指导原则，协作、监管人员准备、确保AI安全、利用AI提高安全性、航空安全研究等5项关键领域行动计划。该文件要求，在近期研究人工智能风险建模、异常行为监测、软件运行时保障、软件验证、系统安全审查等一系列项目。  
  
  
原文链接：  
  
https://www.faa.gov/aircraft/air_cert/step/roadmap_for_AI_safety_assurance  
  
  
**往期精彩推荐**  
  
  
[【在野利用】Google Chrome V8 类型混淆漏洞(CVE-2024-7971)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501953&idx=1&sn=132f57d74ad27b44fc64a22b6f3c081b&chksm=fe79ec19c90e650f6fc4cdbadd1d11b32abe1cebf4128b9c74a56acbe9bbdabb4039e5c11b91&token=969516558&lang=zh_CN&scene=21#wechat_redirect)  
[网络安全威胁2024年中报告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501943&idx=1&sn=c2fac45ea8a3d1b4666767e47e1393cf&chksm=fe79ecefc90e65f9f007f3e34d48772153b3b92d51e064c1bd27d6bd059942be98ab6b96a258&token=969516558&lang=zh_CN&scene=21#wechat_redirect)  
  
[安全热点周报：SolarWinds 和 Microsoft 漏洞被在野利用，立即应用补丁](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501943&idx=2&sn=1ec9ac2abad8584c8efff6a62fe43010&chksm=fe79ecefc90e65f9aeefc1efcc71100ea27711bba70d5c0200319ceae32c618c575f97564ada&token=969516558&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
