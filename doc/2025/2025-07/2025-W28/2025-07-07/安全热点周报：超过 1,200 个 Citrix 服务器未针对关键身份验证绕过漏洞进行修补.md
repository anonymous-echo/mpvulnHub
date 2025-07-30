> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503557&idx=1&sn=b46dcfec1d66e735b4c53d7ae9633c0c

#  安全热点周报：超过 1,200 个 Citrix 服务器未针对关键身份验证绕过漏洞进行修补  
 奇安信 CERT   2025-07-07 09:58  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• 三部门印发《关于进一步加强医疗机构电子病历信息使用管理的通知》</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">黑客入侵挪威一水坝运营系统，私自完全打开阀门数小时</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">江西鹰潭某公司视频监控数据遭境外窃取被罚</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Google Chrome V8类型混淆漏洞安全风险通告**  
  
  
7月2日，奇安信CERT监测到Google发布公告称Google Chrome V8 类型混淆漏洞(CVE-2025-6554)存在在野利用，该漏洞源于V8引擎在执行JavaScript代码时，对某些数据类型的边界检查和类型转换处理不当，导致浏览器无法正确区分不同类型的内存数据。远程攻击者可通过诱导用户打开恶意链接来利用此漏洞，从而获取敏感信息或代码执行。目前该漏洞POC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞已发现在野利用，建议客户尽快做好自查及防护。  
  
  
**2.Linux sudo本地提权漏洞安全风险通告**  
  
  
7月2日，奇安信CERT监测到Linux sudo修复两个相互关联的本地提权漏洞(CVE-2025-32462、CVE-2025-32463)，Linux sudo host权限提升漏洞(CVE-2025-32462)源于sudo的-h（--host）选项错误应用远程主机规则到本地，攻击者可绕过权限提升至root并执行任意代码。Linux sudo chroot权限提升漏洞(CVE-2025-32463)源于本地低权限用户通过特制的恶意chroot环境触发动态库加载，从而以root权限执行任意代码。目前该漏洞技术细节与PoC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.WinRAR目录穿越漏洞安全风险通告**  
  
  
7月1日，奇安信CERT监测到WinRAR目录穿越漏洞(CVE-2025-6218)POC已公开，该漏洞存在于WinRAR处理压缩文件中文件路径的过程中。攻击者可以利用精心构造的文件路径，使WinRAR进程遍历到任意目录，从而造成敏感信息泄露等危害。此漏洞POC已公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.Google Chrome V8 类型混淆漏洞(CVE-2025-6554)******  
  
  
7月2日，在发现一个高严重性零日漏洞（CVE-2025-6554）后，Google 紧急发布了其 Chrome 稳定频道的更新，该漏洞已被广泛利用。该漏洞在 V8 JavaScript 引擎中被归类为类型混淆漏洞，对 Windows、macOS 和 Linux 平台上的用户构成严重威胁。  
  
该公司警告称，谷歌知道 CVE-2025-6554 的漏洞正在被广泛利用。CVE-2025-6554 是 V8 中的一个类型混淆漏洞，V8 是 Chrome 渲染引擎的核心 JavaScript 引擎。该漏洞由 Google 威胁分析小组 （TAG） 的 Clément Lecigne 于 2025年6月25日发现，该漏洞可能允许攻击者通过诱骗浏览器误解内存类型（一种通常用于远程代码执行 （RCE） 的漏洞利用方法）来执行任意代码。  
  
零日漏洞（尤其是影响 Chrome 等浏览器的漏洞）是民族国家行为者、高级持续性威胁 （APT） 和出于经济动机的网络犯罪分子的主要目标。V8 中的类型混淆缺陷以前曾被用于路过式下载攻击、沙箱逃逸和通过看似无害的网站进行恶意负载传递。  
  
该补丁在 Windows 的版本 138.0.7204.96/.97、Mac 的 138.0.7204.92/.93 和 Linux 的 138.0.7204.96 下发布。由于该漏洞的敏感性及其潜在影响，在大多数用户受到保护之前，完整的技术细节仍然受到限制。  
  
  
参考链接：  
  
https://securityonline.info/google-patches-actively-exploited-chrome-zero-day-cve-2025-6554/  
  
  
**2.Citrix NetScaler 输入验证不足漏洞(CVE-2025-5777)&Citrix NetScaler ADC 和 Gateway 内存溢出漏洞(CVE-2025-6543)******  
  
  
6月30日，在线公开的 1,200 多台 Citrix NetScaler ADC 和 NetScaler Gateway 设备未针对据信被积极利用的关键漏洞进行修补，从而允许威胁行为者通过劫持用户会话来绕过身份验证。  
  
此越界内存读取漏洞被跟踪为 CVE-2025-5777，称为 Citrix Bleed 2，它是由于输入验证不足造成的，使未经身份验证的攻击者能够访问受限内存区域。成功利用 CVE-2025-5777 可能允许威胁行为者从面向公众的网关和虚拟服务器窃取会话令牌、凭证和其他敏感数据，从而使他们能够劫持用户会话并绕过多因素身份验证 （MFA）。  
  
在6月17日的公告中，Citrix 警告客户在将所有 NetScaler 设备升级到修补版本以阻止潜在攻击后，终止所有活动的 ICA 和 PCoIP 会话。互联网安全非营利组织 Shadowserver Foundation 的安全分析师在周末发现，仍有 2,100 台设备容易受到 CVE-2025-5777 攻击。  
  
虽然 Citrix 尚未确认该安全漏洞正在被广泛利用，并表示“目前没有证据表明利用 CVE-2025-5777”，但网络安全公司 ReliaQuest 称该漏洞已经在针对性攻击中被滥用。  
  
Shadowserver 还发现，超过 2,100 个 NetScaler 设备未针对另一个严重漏洞（CVE-2025-6543）进行修补，该漏洞现在在拒绝服务 （DoS） 攻击中被积极利用。  
  
由于这两个漏洞都被标记为严重性漏洞，建议管理员尽快从 Citrix 部署最新补丁。公司还应审查其访问控制并监控 Citrix NetScaler 设备是否存在可疑的用户会话和活动。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/over-1-200-citrix-servers-unpatched-against-critical-auth-bypass-flaw/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.俄罗斯大型国防承包商遭入侵，海军机密文件疑似泄露**  
  
  
7月2日Cybernews消息，有犯罪团伙在知名数据泄露论坛发帖称，从俄罗斯主要国防承包商NPO Mars窃取了250GB数据。据分析，其提供的数据样本包含大量PDF和技术手册，涉及NPO Mars为俄军开发的系统，部分文件名暗示为协议、证书等文件，其他文件使用军事技术术语命名。攻击者制作宣传视频，声称获取了SIGMA、TRASSA、DIEZ等多个俄海军关键系统权限。NPO Mars是“联邦科研生产中心”，为俄军提供自动化控制系统、舰艇作战信息与指挥系统、装甲运兵车、坦克等装备。  
  
  
原文链接：  
  
https://cybernews.com/security/russian-defense-contractor-mars-breach-navy/  
  
  
**2.澳洲航空遭遇重大网络攻击，约600万客户信息或泄露**  
  
  
7月2日，澳大利亚澳洲航空公司披露，黑客入侵了澳航一个存有大约600万客户隐私信息的数据系统，恐致大规模数据泄露。澳航在一份声明中说，该公司6月30日发现其第三方客户服务平台出现“异常活动”，显示黑客入侵了一个客户联络中心系统，可获取约600万客户的姓名、电子邮件地址、手机号码、生日等隐私信息。“我们仍在调查具体有多少数据被盗，但预计泄露规模较大。”目前，澳航正在联系受影响客户，通报事件详情，并说明公司可提供的具体支持方案。澳航首席执行官瓦妮萨·赫德森代表澳航“真诚地向受影响客户道歉”，表示公司正就此事与澳大利亚政府网络安全专家“密切合作”。  
  
  
原文链接：  
  
https://content-static.cctvnews.cctv.com/snow-book/index.html?item_id=4103047984007139562  
  
  
**3.黑客入侵挪威一水坝运营系统，私自完全打开阀门数小时**  
  
  
6月30日GBHackers消息，挪威布雷芒厄市里瑟湖区某座水坝的运营系统遭到入侵，攻击者掌握了水流控制系统的指令权限，并成功访问了水坝的阀门关闭机制，导致阀门被完全开启。直到数小时后，水坝运营方发现了该事件并进行处置。据悉由于水流量不大，并未造成实际风险。这座水坝是当地水资源管理和水力发电系统中的关键组成部分。目前案件已正式由挪威国家刑事调查局主导刑事调查，相关部门正努力确认攻击者身份，并评估此次事件的整体影响范围。  
  
  
原文链接：  
  
https://gbhackers.com/hackers-breach-norwegian-dam/  
  
  
**4.江西鹰潭某公司视频监控数据遭境外窃取被罚**  
  
  
6月30日，鹰潭市互联网信息办公室接上级转办线索，某新型材料集团有限公司所属IP向境外多个IP传输数据，行为异常。经过立案调查、现场勘验、远程勘验（采样技术分析）、笔录问询等工作，查明：该公司未采取相应的技术措施和其他必要措施保障数据安全，未在开展数据处理活动时加强数据安全缺陷、漏洞等风险监测，导致其所属的视频监控系统多次被境外黑客组织登录并窃取视频监控数据，相关行为违反了《中华人民共和国数据安全法》第二十七条、第二十九条规定。鹰潭市网信办依据《中华人民共和国数据安全法》、《中华人民共和国行政处罚法》等法律法规，责令该公司限期改正，并给予警告。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/e-K1XnjzFcUN4VAZhroZFg  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.《网络安全技术 信息安全管理体系 要求》等3项网络安全国家标准发布**  
  
  
7月4日，国家市场监督管理总局、国家标准化管理委员会近日发布2025年第14号《中华人民共和国国家标准公告》，由全国网络安全标准化技术委员会归口的3项国家标准正式发布。包括GB/T 20988—2025《网络安全技术 信息系统灾难恢复规范》、GB/T 22080—2025《网络安全技术 信息安全管理体系 要求》、GB/T 45909—2025《网络安全技术 数字水印技术实现指南》。  
  
  
原文链接：  
  
https://www.tc260.org.cn/front/postDetail.html?id=20250704092842  
  
  
**2.工信部印发《关于开展号码保护服务业务试点的通知》**  
  
  
7月3日，工业和信息化部印发《关于开展号码保护服务业务试点的通知》，旨在加强个人信息保护，同时规范中间号业务、强化码号资源管理、防范治理电信网络诈骗和非应邀商业营销信息。该文件指出，工信部规划了15位长的700专用号码，并开展为期两年半的试点行动，试点过渡阶段结束后，将全部使用700专用号码开展号码保护服务业务。该文件要求严格管理业务试点和700专用号码申请。强化业务和码号分配的全流程管理，提升技术监管手段，有效支撑违规行为溯源，切实防范700专用号码被滥用。对于试点期间出现严重违法违规行为的业务参与方，将依法依规撤销试点资格，并会同有关部门进行严肃查处。  
  
  
原文链接：  
  
https://www.miit.gov.cn/zwgk/zcwj/wjfb/tz/art/2025/art_1c4a98acc8e641859359181940850634.html  
  
  
**3.工信部印发《2025年护航新型工业化网络安全专项行动方案》**  
  
  
7月2日，工业和信息化部印发《2025年护航新型工业化网络安全专项行动方案》，聚焦突出重点管理、做优服务模式，以推动重点企业、重要系统、关键产品防护能力升级为核心，提出3方面8项重点任务。该文件提出，建立完善工业领域网络安全防护重点企业清单，深入实施工业互联网安全分类分级管理，面向不少于800家工业企业开展网络安全贯标达标试点，更新不少于100个车联网服务平台的定级备案，有效提高重点企业综合防护水平；深化工业控制系统网络安全评估，探索开展工业控制产品安全检测认证；组织全国范围新型工业化网络安全政策标准宣贯，推动各地方宣贯工作覆盖属地不少于20%的规上工业企业，切实增强工业领域网络安全意识和保障能力，以高水平网络安全护航制造业高质量发展。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/demo/pdfjs/web/viewer.html?file=/cms_files/filemanager/1226211233/attach/20256/91c0963b1e5a40a0bbac8cf0883f5fc2.pdf  
  
  
**4.欧盟EDPB发布简化GDPR合规声明**  
  
  
7月2日，欧洲数据保护委员会（EDPB）发布《关于增强透明度、支持与参与的赫尔辛基声明》。该文件公布了多项新举措，旨在使 GDPR 合规变得更加容易，特别是对于微型、小型和中型组织，加强一致性并促进跨监管合作。该文件提出，开发“即用型”合规模板（基于并统一各国已有工作），减轻企业负担；制定通用模板供各国数据保护机构使用，旨在简化流程并探索跨监管的统一通知方案；推出易于获取和应用的检查清单、操作指南和常见问题解答，帮助企业理解关键义务。  
  
  
原文链接：  
  
https://www.edpb.europa.eu/news/news/2025/helsinki-statement-enhanced-clarity-support-and-engagement_en  
  
  
**5.越南颁布《重要数据和核心数据清单》法令**  
  
  
7月1日，越南副总理阮志勇签署了第20/2025/QD-TTg号决定，公布了重要数据和核心数据清单，以配合该国《数据法》的实施。据悉，核心数据包括尚未公开的国界与领土主权相关数据、未公开的国防安全工业活动数据、未公开的政党活动数据等28类，重要数据包括核心数据类别及其他17类，如国家机构手机管理且未公开的监察申诉举报及反腐数据、内政数据、交通运输数据等。  
  
  
原文链接：  
  
https://vanban.chinhphu.vn/?pageid=27160&docid=214354  
  
  
**6.三部门印发《关于进一步加强医疗机构电子病历信息使用管理的通知》**  
  
  
6月30日，国家卫生健康委办公厅、国家中医药局综合司、国家疾控局综合司印发《关于进一步加强医疗机构电子病历信息使用管理的通目前案件已正式由挪威国家刑事调查局主导刑事调查，相关部门正努力确认攻击者身份，并评估此次事件的整体影响范围。  知》。该文件要求加强医疗机构内部管理。医疗机构需明确电子病历范围，压实主体责任，依法依规严格保护患者隐私，将电子病历信息规范使用管理情况纳入绩效评价。健全管理制度，建立电子病历使用长效监管机制和应急处置制度。落实分级管理要求，遵循最小可用原则，明确临床诊疗、教学、管理等相关人员分级访问权限和时限。该文件明确规范电子病历信息使用。医疗机构需规范相关人员使用权限和行为，不得违规收集、传输或泄露患者信息。加强短期人员培训与管理，确保权限与职责匹配，并与外部服务商签订保密协议。保障全流程可追溯，采用数字水印等技术，确保使用过程留痕。确保数据安全，建立电子病历信息安全防护体系，防范潜在安全风险。  
  
  
原文链接：  
  
https://www.nhc.gov.cn/yzygj/c100068/202506/c68abee7c54b4651a774cd533761780b.shtml  
  
  
**7.伊朗立法禁止使用“星链”互联网服务，违者可能面临监禁或鞭刑**  
  
  
6月29日，伊朗伊斯兰议会已通过一项新立法，对未经许可使用电子通讯工具，包括使用马斯克旗下SpaceX公司运营的“星链”卫星互联网服务将被定为犯罪行为，违者可能面临罚款、鞭刑或最高两年的监禁。该法律共包含九条内容，对一系列被视为威胁国家安全的行为将进行严厉处罚。根据该法律，任何与以色列或其他敌对国家的“情报或行动合作”都将被视为犯罪，依据伊朗法律，此项罪名可判处死刑。此外，若个人参与生产、运输或使用致命或非常规武器、军用级无人机或机器人、实施网络攻击或破坏关键基础设施，且其行为意图协助敌对实体，同样可能被判死刑。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/7ehwf-dX25wwDGV9thACcQ  
  
  
**8.国家知识产权局印发《关于开展“人工智能+”知识产权信息公共服务应用场景建设的通知》**  
  
  
6月27日，国家知识产权局办公厅印发《关于开展“人工智能+”知识产权信息公共服务应用场景建设的通知》，以充分释放知识产权数据要素价值。该文艺要求强化数据安全保障水平。挖掘“人工智能+”支撑知识产权数据安全建设，进一步加强自主可控数据库建设和应用；提高数据合规高效流通利用水平，解决不同类型数据资源提供方、使用方、服务方、监管方等主体间的安全与信任问题等应用场景。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/gKButBO-BSeiCY8PrCbjSg  
  
  
**往期精彩推荐**  
  
  
[【已复现】Google Chrome V8 类型混淆漏洞(CVE-2025-6554)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503550&idx=1&sn=403675d7942468c56b29a05e37f625fc&scene=21#wechat_redirect)  
  
  
[【已复现】Linux sudo 本地提权漏洞(CVE-2025-32462、CVE-2025-32463)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503550&idx=2&sn=2f98d1c24d7cacca9fa9bfac2fb1adb8&scene=21#wechat_redirect)  
  
  
[【已复现】WinRAR 目录穿越漏洞(CVE-2025-6218)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503538&idx=1&sn=5439ec7c9b1446ac237be77feab8fcd0&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
