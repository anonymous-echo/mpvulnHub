#  安全热点周报：Apache Tomcat RCE 漏洞遭两步利用   
 奇安信 CERT   2025-04-07 17:44  
  
#   
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="">• </span><span leaf="">《关键信息基础设施安全测评要求》公安行业标准发布</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="">• </span><span leaf="">哈尔滨亚冬会赛事信息系统遭境外网络攻击超27万次，攻击源大部来自美国</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="">• </span><span leaf="">俄乌黑客展开铁路大战，运营系统瘫痪殃及百万民众</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Zabbix groupBy SQL注入漏洞安全风险通告**  
  
  
4月3日，奇安信CERT监测到官方修复Zabbix groupBy SQL注入漏洞(CVE-2024-36465)，该漏洞源于include/classes/api/CApiService.php文件对参数校验不当，导致具有API访问权限的Zabbix用户可以通过groupBy参数执行任意SQL命令。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为21139个，关联IP总数为6156个。目前奇安信威胁情报中心安全研究员已成功复现，鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.Vite任意文件读取漏洞安全风险通告**  
  
  
4月1日，奇安信CERT监测到官方修复Vite任意文件读取漏洞(CVE-2025-31125)，该漏洞源于Vite开发服务器在处理特定URL请求时，没有对请求的路径进行严格的安全检查和限制，导致攻击者可以绕过保护机制，非法访问项目根目录外的敏感文件。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为47578个，关联IP总数为10830个。目前该漏洞技术细节与POC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
**3.CrushFTP身份验证绕过漏洞安全风险通告**  
  
  
3月31日，奇安信CERT监测到官方修复CrushFTP身份验证绕过漏洞(CVE-2025-2825)，该漏洞源于处理身份验证标头不当，攻击者可绕过认证机制获取管理员权限，进而可能获取敏感信息、篡改数据或执行其他恶意操作。奇安信鹰图资产测绘平台数据显示，该漏洞关联的全球风险资产总数为19882个，关联IP总数为6101个。目前该漏洞技术细节与POC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Ivanti 多款产品堆缓冲区溢出漏洞(CVE-2025-22457)******  
  
  
4月4日，Ivanti 发布了安全更新，以修补一个严重的 Connect Secure 远程代码执行漏洞，该漏洞至少自 2025 年 3 月中旬以来被黑客利用来部署恶意软件。  
  
该严重安全漏洞编号为 CVE-2025-22457，是由基于堆栈的缓冲区溢出漏洞引起的。它影响 Pulse Connect Secure 9.1x（已于 12 月终止支持）、Ivanti Connect Secure 22.7R2.5 及更早版本、Policy Secure 和 Neurons for ZTA 网关。  
  
根据 Ivanti 的建议，远程威胁行为者可以利用该漏洞进行高复杂度攻击，而无需身份验证或用户交互。Ivanti 表示该漏洞是一种缓冲区溢出漏洞，其字符仅限于句点和数字，经过评估，确定其不能被利用为远程代码执行，也不符合拒绝服务的要求。  
  
虽然 Ivanti 尚未披露有关 CVE-2025-22457 攻击的更多细节，但 Mandiant 和谷歌威胁情报集团 (GTIG) 的安全研究人员透露，威胁行为者至少从2025年3月中旬就开始利用被追踪为 UNC5221 的漏洞。  
  
Mandiant 表示：“成功利用该漏洞后，我们观察到两个新发现的恶意软件家族的部署，即 TRAILBLAZE 内存中唯一植入程序和 BRUSHFIRE 被动后门。此外，我们还观察到了之前报告的归因于 UNC5221 的 SPAWN 恶意软件生态系统的部署 。 ”评估威胁行为者很可能研究了 ICS 22.7R2.6 中的漏洞补丁，并通过复杂的过程发现，可以利用 22.7R2.5 及更早版本来实现远程代码执行。  
  
虽然 ZTA 和 Ivanti Policy Secure 网关的安全补丁仍在开发中，并将分别于4 月19日和4月21日发布，但 Ivanti 表示“尚未发现针对这些网关的任何攻击”，这些网关也“显著降低了此漏洞的风险”。Ivanti 还建议管理员监控其外部完整性检查工具 (ICT) 并查找 Web 服务器崩溃情况。如果发现任何受感染迹象，管理员应将受影响的设备恢复出厂设置，并使用软件版本 22.7R2.6 将其恢复生产。  
  
   
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/ivanti-patches-connect-secure-zero-day-exploited-since-mid-march/  
  
  
**2.********Apache Tomcat 远程代码执行漏洞(CVE-2025-24813)******  
  
  
4月1日，Apache Tomcat 中的一个严重漏洞已被攻击者积极利用，在易受攻击的服务器上可以实现远程代码执行 (RCE )。  
  
漏洞利用过程很简单，只需两个步骤：首先，攻击者通过 PUT 请求上传序列化的 Java 会话文件，然后攻击者通过在 GET 请求中引用恶意会话 ID 来触发反序列化。  
  
该漏洞最初由名为 iSee857 的中国论坛用户发布；但第一次攻击是在 3 月 12 日由 Wallarm 研究人员在波兰检测到的，而当时第一个漏洞尚未在 GitHub 上公开发布。  
  
虽然 Apache 没有提供 CVSS 评分，但 Red Hat 团队给出了8.6 分（满分 10 分），严重程度为中等。但 Wallarm 研究人员警告称，该漏洞非常危险，因为大多数 Web 应用程序防火墙 (WAF) 完全没有发现这种攻击，因为 PUT 请求看起来很正常，有效载荷是 base64 编码的，而且攻击分为两步，攻击的有害部分只在最后执行。  
  
研究人员表示：“这种攻击执行起来非常简单，不需要身份验证。唯一的要求是 Tomcat 使用基于文件的会话存储，这在许多部署中很常见。更糟糕的是，base64 编码允许漏洞绕过大多数传统的安全过滤器，使检测变得具有挑战性。”  
  
主动利用尝试已在全球范围内观察到，攻击者主要针对美国、日本、印度、韩国和墨西哥的系统。  
  
他们建议实施实时 API 安全，确保每个请求都“经过深入分析，而不仅仅是模式匹配”，有效载荷被解码和解包，并且多步骤攻击被阻止，即使使用了混淆。   
  
为了减轻与 CVE-2025-24813 相关的风险，组织应尽快升级到 Apache Tomcat 的修补版本（9.0.99、10.1.35 或 11.0.3）。对于无法立即升级的情况，实施网络级控制来限制对 Tomcat 服务器的访问可以提供临时保护。此外，禁用不必要的 HTTP 方法并实施严格的访问控制可以进一步降低被利用的风险。为了检测和阻止恶意流量，还建议持续监控威胁指标并使用 Web 应用程序防火墙 (WAF)。  
  
  
参考链接：  
  
https://cybersecuritynews.com/apache-tomcat-vulnerability-exploited/  
  
**3.****Cisco Smart License Utility 静态凭证漏洞(CVE-2024-20439)&Cisco Smart License Utility 信息泄露漏洞(CVE-2024-20440)**  
  
  
3月31日，据 SANS 互联网风暴中心称，影响思科智能许可实用程序的两个安全漏洞目前已得到修补，但有人正在积极尝试利用这些漏洞。所涉及的两个严重漏洞如下：  
  
CVE-2024-20439（CVSS 评分：9.8）- 存在未记录的管理帐户静态用户凭证，攻击者可利用该凭证登录受影响的系统；CVE-2024-20440（CVSS 评分：9.8）- 由于调试日志文件过于冗长而产生的漏洞，攻击者可以利用该漏洞通过精心设计的 HTTP 请求访问此类文件并获取可用于访问 API 的凭据。  
  
成功利用这些漏洞可以使攻击者以管理员权限登录受影响的系统，并获取包含敏感数据的日志文件，包括可用于访问 API 的凭据。也就是说，这些漏洞仅在程序正在运行的情况下才会被利用。  
  
这些缺陷影响 2.0.0、2.1.0 和 2.2.0 版本，思科已于 2024 年 9 月对其进行了修补。思科智能许可证实用程序 2.3.0 版本不会受到这两个漏洞的影响。  
  
SANS 技术研究所研究主任 Johannes B. Ullrich 表示，截至 2025 年 3 月，已经观察到威胁行为者试图积极利用这两个漏洞，并补充说身份不明的威胁行为者还在利用其他漏洞作为武器。  
  
目前尚不清楚该活动的最终目标是什么，也不清楚谁是幕后黑手。鉴于该活动正在肆虐，用户必须安装必要的补丁才能获得最佳保护。  
  
   
  
参考链接：  
  
https://thehackernews.com/2025/03/ongoing-cyber-attacks-exploit-critical.html  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.哈尔滨亚冬会赛事信息系统遭境外网络攻击超27万次，攻击源大部来自美国**  
  
  
4月3日央视新闻消息，国家计算机病毒应急处理中心发布“2025年哈尔滨第九届亚冬会”赛事信息系统及黑龙江省内关键信息基础设施遭境外网络攻击情况监测分析报告，全面总结了网络安全保障团队监测处置的本届赛事各类网络安全威胁情况。相关统计数据表明，赛事期间，各赛事信息系统、黑龙江省域范围内的关键信息基础设施遭到来自境外的大量网络攻击。攻击源大部分来自美国、荷兰等国家和地区。在赛事网络安全保障团队的共同努力下，这些网络攻击未能对赛事造成严重影响，但却进一步凸显了我国网络频繁遭受境外攻击的严峻形势。  
  
  
原文链接：  
  
https://news.cctv.com/2025/04/03/ARTIBoBzJBBJdGTMr2y2j5j9250403.shtml  
  
  
**2.英国皇家邮政144GB数据泄露，供应商Spectos疑似“罪魁祸首”**  
  
  
4月2日Hackread消息，英国皇家邮政集团日前遭遇了一起严重的数据泄露事件，144GB的敏感数据被黑客公开，包括客户个人信息、内部通讯记录、运营数据以及营销基础设施数据等。一位名为GHNA的黑客在地下论坛Breach Forum上发布了相关数据，并声称是通过皇家邮政的供应商Spectos获取的这些信息。泄露的数据包包含293个文件夹和16,549个文件，涉及客户个人身份信息、内部通讯记录、运营数据、营销基础设施数据等，Spectos的名字多次出现在泄露材料中，包括内部文件和录制的视频通话。皇家邮政已承认此事，并表示正在与Spectos合作调查。  
  
  
原文链接：  
  
https://hackread.com/hacker-leaks-royal-mail-group-data-supplier-spectos/  
  
  
**3.俄乌黑客展开铁路大战，运营系统瘫痪殃及百万民众**  
  
  
4月1日综合消息，俄乌数字战争近期在交通行业升级，导致数以百万计的民众出行受阻。3月下旬，乌克兰国有铁路运营商Ukrzaliznytsia遭遇了一场“系统性、复杂且多层次”的网络攻击。这次攻击直接导致在线售票系统宕机，网站和移动应用瘫痪。虽然火车运行时间表未受影响，但乘客不得不涌向车站窗口排队购票，场面-度混乱。为了应对危机，ukrzaliznytsia紧急加倍增开售票窗口，并在89小时的不懈努力后恢复了在线服务。3月31日，莫斯科地铁系统的网站和应用突然宕机。根据俄罗斯用户在 Downdetector上的反馈，这次故障不仅让在线服务中断，连数字交通卡都无法正常使用，数百万民众出行受到影响。更戏剧性的是，在莫斯科地铁网站被重新定向到了乌克兰国有铁路运营商Ukrzaliznvtsia的网站(下图)，页面上赫然出现了一条ukrzaliznytsia网站被攻击后黑客留下的消息:"你们打我们的铁路，我们就瘫痪你们的地铁。”  
  
  
原文链接：  
  
https://www.secrss.com/articles/77287  
  
  
**4.疑似NSA网攻行动曝光：神秘零日漏洞利用链 目标针对俄媒体科研机构**  
  
  
3月27日The Record消息，卡巴斯基披露了一起尖端网络攻击行动，受害者点击定向钓鱼邮件中的链接，该页面暗藏了零日漏洞（CVE-2025-2783）利用代码，可远程绕过Chrome浏览器的沙盒保护机制，结合另一个未知漏洞即可实现远程代码执行，控制受害者的设备。根据该行动非常隐蔽和技艺高超的特征，卡巴斯基认为攻击者具有国家背景，参考此前披露的三角行动，这起事件也很可能是NSA的网络间谍活动。  
  
  
原文链接：  
  
https://therecord.media/russian-media-academia-targeted-in-espionage-campaign  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.《中华人民共和国卫星导航条例》公开征求意见**  
  
  
4月3日，国家发展改革委牵头会同有关部门研究起草了《中华人民共和国卫星导航条例（公开征求意见稿）》，现向社会公开征求意见。该文件共7章52条，分为总则、建设运行、运营服务、应用推广、安全保护、法律责任和附则。该文件提出，国家建立健全卫星导航安全体系，加强卫星导航运行安全、网络安全、应用安全、数据安全保护，确保卫星导航安全。国家有关部门负责监测、防御、处置来源于境外的风险和威胁，保护相关系统免受攻击、侵入、干扰和破坏；国家网信部门负责卫星导航应用的网络安全和数据安全统筹协调；国务院有关部门和县级以上地方人民政府，应当按照职责分工，负责本部门、本行政区域卫星导航应用的网络安全和数据安全管理工作，督促落实网络安全和数据安全有关制度。  
  
原文链接：  
  
https://yyglxxbs.ndrc.gov.cn/file-submission/20250403173857128265.pdf  
  
  
**2.《工业和信息化部关于开展号码保护服务业务试点的通知》公开征求意见**  
  
  
4月3日，工业和信息化部信息通信管理局编制了《工业和信息化部关于开展号码保护服务业务试点的通知（征求意见稿）》，现公开征求意见。该文件指出，号码保护服务是互联网平台等企业为保护用户的个人电话号码信息而提供的一项服务，也称“中间号”或“隐私号”。该文件明确了业务定义和业务参与方，明晰了应用平台提供方、基础电信业务经营者、业务使用方等三方参与主体的责任边界和相关要求，强化合规经营、防范治理电信网络诈骗、加强商业营销电话和商业营销信息防控等业务管理要求，限制应用平台提供方“转租转售”。该文件规划了15位长的700专用号码，并开展为期两年半的试点行动，试点过渡阶段结束后，将全部使用700专用号码开展号码保护服务业务。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/filemanager/1226211233/attach/20253/600fd4907ba04a57ab3d05b64b6c7bc1.pdf  
  
  
**3.《网络安全标准实践指南——移动互联网未成年人模式技术要求》发布**  
  
  
4月3日，全国网络安全标准化技术委员会秘书处组织编制了《网络安全标准实践指南——移动互联网未成年人模式技术要求》。该文件规定了移动互联网未成年人模式的技术要求，适用于移动互联网应用程序提供者、移动智能终端制造商和移动互联网应用程序分发平台提供者开展未成年人模式的研发和应用，也可为监管部门、第三方评估机构对未成年人网络保护的监督、管理、评估提供参考。  
  
  
原文链接：  
  
https://www.tc260.org.cn/upload/2025-04-02/1743581174222099189.pdf  
  
  
**4.英国政府发布《网络安全与弹性法案》政策声明**  
  
  
4月1日，英国政府发布网络安全与弹性政策声明，详细介绍了将于今年提交议会的《网络安全与弹性法案》的内容。该政策声明显示，《网络安全与弹性法案》主要内容包括：对接欧盟NIS2指令要求，扩大关基行业覆盖范围，提高关基网络安全事件上报标准；将约一千家托管服务商纳入管控范围，要求遵循必要的网络安全标准，以提高IT基础设施的安全性；加强供应链安全，可对基础服务运营商、相关数字服务提供商及监管机构单独给出的指定关键供应商，设置更严格的供应链安全责任。  
  
  
原文链接：  
  
https://assets.publishing.service.gov.uk/media/67ec11d053fa8521c3248b70/Cyber_Security_and_Resilience_Policy_Statement_Command_Paper.pdf  
  
**5.《关键信息基础设施安全测评要求》公安行业标准发布**  
  
  
3月31日，公安部技术监督委员会2024年12月26日批准发布了公安部网络安全保卫局组织起草的《关键信息基础设施安全测评要求》（GA/T2182-2024）行业标准，自2025年5月1日起实施。该标准规定了针对关键信息基础设施开展安全测评的要求和方法，适用于规范关基运营者及网络安全服务机构开展关基安全测评工作。关基测评的目标是发现关基现存的或潜在的安全风险，为运营者开展建设整改、提升其关基安全保护水平及安全管控能力提供指导。关基测评由单元测评、关联测评和整体评估三部分组成。关基测评在开展整体评估时复用相关等级测评结果。该标准是推动关基安全保护、建立全面安全防护体系的重要手段，是各级公安机关推进关基安全保护工作的重要依托。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/cfVXba0cu583OFkcbZoj0Q  
  
  
**6.中共中央办公厅、国务院办公厅印发《关于健全社会信用体系的意见》**  
  
  
3月31日，中共中央办公厅、国务院办公厅印发《关于健全社会信用体系的意见》。该文件专设单章加强信用信息安全保护。要求建立信用信息安全管理追溯和侵权责任追究机制，明确信息传输链条各环节安全责任。严格落实安全保护责任，规范信用信息处理程序。提高信用信息基础设施安全管理水平。建立健全信用信息安全应急处理机制。  
  
  
原文链接：  
  
https://www.gov.cn/zhengce/202503/content_7016535.htm  
  
  
**7.英国信息专员办公室发布匿名化指南**  
  
  
3月28日，英国信息专员办公室（ICO）发布了《匿名化指南》，旨在帮助组织有效实施匿名化技术，确保个人数据在共享、发布或再利用时，符合英国GDPR、2018年数据保护法等数据保护法规。该文件指出，将个人数据应用匿名化技术转化为匿名信息的行为，算作处理个人数据。虽然最终结果（匿名信息）不受数据保护法约束，但该过程（匿名化）是受约束的。该文件提出了“有动机的闯入者”测试作为评估匿名化有效性的方法，即模拟具备中等技术能力、资源支持且存在明确动机（如经济利益、社会关注或学术研究）的攻击者，通过综合运用公开数据源（如社交媒体、政府开放数据）、技术手段（如数据关联分析、算法攻击）及社会工程学方法，尝试破解匿名化数据集以重新识别个体身份。  
  
  
原文链接：  
  
https://ico.org.uk/media2/aahlfdke/anonymisation-all-1-0-21.pdf  
  
  
**8.美国NIST发布《对抗性机器学习：攻击和缓解的分类和术语》**  
  
  
3月24日，美国国家标准与技术研究所（NIST）正式发布保护AI系统免受对抗性攻击的最新指南《对抗性机器学习：攻击和缓解的分类和术语》（NIST AI 100-2e2025）。该文件描述了对抗性机器学习的分类法和术语，介绍了预测性人工智能系统和生成式人工智能系统及与两类系统相关的攻击，有助于保护AI应用免受对抗性操纵和攻击。该文件分五个维度对攻击进行分类：一是人工智能系统类型；二是发起攻击的机器学习生命周期过程阶段；三是攻击者试图破坏的系统属性方面的目标和目的；四是攻击者的能力和访问权限；五是攻击者对学习过程及其他方面的了解。该文件还提供了在AI系统生命周期中缓解和管理相关攻击后果的相应方法，并概述了广泛使用的缓解技术的局限性，以提高认识并帮助提高AI风险缓解工作的有效性。  
  
  
原文链接：  
  
https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf  
  
  
**往期精彩推荐**  
  
  
[【已复现】Zabbix groupBy SQL注入漏洞(CVE-2024-36465)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503262&idx=1&sn=144ab53fe27ab9e6774fd2b64009cb84&scene=21#wechat_redirect)  
  
  
[【已复现】Vite 任意文件读取漏洞(CVE-2025-31125)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503253&idx=1&sn=4097b8627e1a4e2b99e50ae829dae77a&scene=21#wechat_redirect)  
  
[安全热点周报：Google 紧急修复被 APT 攻击的 Chrome 零日漏洞](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503245&idx=1&sn=963cffbc8c064b0da2ae6c9e2eaf6c92&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
