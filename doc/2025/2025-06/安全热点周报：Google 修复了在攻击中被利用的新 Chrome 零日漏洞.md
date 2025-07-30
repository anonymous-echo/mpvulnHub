#  安全热点周报：Google 修复了在攻击中被利用的新 Chrome 零日漏洞  
 奇安信 CERT   2025-06-09 09:32  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">李强签署国务院令，公布《政务数据共享条例》</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">阿里云核心域名遭“劫持”，域名安全引担忧</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">国家安全部：境外间谍对我实施网络攻击窃密愈演愈烈</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Roundcube Webmail后台代码执行漏洞安全风险通告**  
  
  
6月6日，奇安信CERT监测到官方修复Roundcube Webmail后台代码执行漏洞(CVE-2025-49113)，该漏洞是Roundcube Webmail的自定义反序列化函数在处理包含特定分隔符时存在逻辑错误，允许认证攻击者通过构造恶意文件名触发反序列化，最终实现远程命令执行从而完全接管服务器。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为57430个，关联IP总数为7345个。目前该漏洞技术细节与PoC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.DataEase多个远程代码执行漏洞安全风险通告**  
  
  
6月5日，奇安信CERT监测到官方修复DataEase远程代码执行漏洞(CVE-2025-49001、CVE-2025-49002)，CVE-2025-49001是由于JWT校验机制错误导致攻击者可伪造JWT令牌绕过身份验证流程，CVE-2025-49002 是由于H2数据库模块没有严格过滤用户输入的JDBC连接参数，可使用大小写绕过补丁。攻击者可利用这些漏洞实现未授权代码执行，威胁用户数据和系统的安全。目前该漏洞技术细节与PoC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.vBulletin远程代码执行漏洞安全风险通告**  
  
  
6月4日，奇安信CERT监测到vBulletin远程代码执行漏洞(CVE-2025-48827)存在在野利用，攻击者可以利用这个漏洞调用受保护的API控制器执行未授权的操作，从而执行任意代码。目前该漏洞已发现在野利用，奇安信威胁情报中心安全研究员已成功复现。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**4.Google Chrome越界读写漏洞安全风险通告**  
  
  
6月3日，奇安信CERT监测到Google发布公告称Google Chrome越界读写漏洞(CVE-2025-5419)存在在野利用，该漏洞源于V8引擎中的越界读写问题，攻击者通过恶意网页触发漏洞，可绕过沙箱防护实现远程代码执行，完全控制用户设备。目前该漏洞已发现在野利用。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Google Chrome 越界读写漏洞(CVE-2025-5419)******  
  
  
6月5日，Google 发布了紧急安全更新，以修复自今年年初以来在攻击中被利用的第三个 Chrome 零日漏洞。  
  
该公司在周一发布的安全公告中警告到其知道 CVE-2025-5419 的漏洞正在广泛被利用。  
  
这个高严重性漏洞是由 Chrome V8 JavaScript 引擎中的越界读写引起的，谷歌威胁分析小组的 Clement Lecigne 和 Benoît Sevens 一周前报告了该漏洞。谷歌表示，一天后，该公司在所有 Chrome 平台上将配置更改推送到稳定频道，从而缓解了这个问题。  
  
虽然 Google 已经确认 CVE-2025-5419 正在被广泛利用，但在更多用户修补他们的浏览器之前，该公司不会分享有关这些攻击的其他信息。谷歌表示：“在大多数用户更新修复程序之前，对错误详细信息和链接的访问可能会受到限制。如果该错误存在于其他项目类似依赖但尚未修复的第三方库中，我们也将保留限制。”  
  
这是谷歌自今年年初以来的第三个 Chrome 零日漏洞，另外两个漏洞分别在3月和5月修补。  
  
谷歌发布了适用于 Windows/Mac 的 137.0.7151.68/.69 和适用于 Linux 的 137.0.7151.68，这些版本将在未来几周内向稳定桌面频道中的用户推出。Chrome 会在新的安全补丁可用时自动更新，用户可以通过转到 Chrome 菜单> 帮助 >关于 Google Chrome“，让更新完成，然后单击“重新启动”按钮立即安装它来加快该过程。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/google-patches-new-chrome-zero-day-bug-exploited-in-attacks/  
  
  
**2.********Qualcomm 多芯片组授权不当漏洞(CVE-2025-21479、CVE-2025-21480)&Qualcomm Adreno GPU 驱动内存破坏漏洞(CVE-2025-27038)******  
  
  
6月3日，Qualcomm 发布了针对 Adreno 图形处理单元 （GPU） 驱动程序中三个零日漏洞的安全补丁，这些漏洞影响了数十个芯片组，并在针对性攻击中被积极利用。  
  
该公司表示，Google Android 安全团队于1月下旬报告了两个严重漏洞（跟踪为 CVE-2025-21479 和 CVE-2025-21480），第三个高严重性漏洞（CVE-2025-27038）于3月报告。  
  
前两个都是图形框架不正确的授权，由于在执行特定命令序列时在 GPU 微节点中未经授权的命令执行，可能导致内存损坏，而 CVE-2025-27038 是一个释放后使用，在 Chrome 中使用 Adreno GPU 驱动程序渲染图形时导致内存损坏。  
  
高通在周一的公告中警告称，谷歌威胁分析小组有迹象表明，CVE-2025-21479、CVE-2025-21480、CVE-2025-27038 可能受到有限的针对性利用。在调查这些攻击时，谷歌的威胁分析小组（TAG）发现的证据表明，设备也感染了 NoviSpy 间谍软件，这些间谍软件使用漏洞利用链绕过 Android 的安全机制，并在内核级别持续安装自身。近年来，该公司修补了各种其他芯片组安全漏洞，这些漏洞可能让攻击者访问用户的短信、通话记录、媒体文件和实时对话。  
  
影响 Adreno 图形处理单元 （GPU） 驱动程序的问题的补丁已于5月提供给 OEM，并强烈建议尽快在受影响的设备上部署更新。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/qualcomm-fixes-three-adreno-gpu-zero-days-exploited-in-attacks/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.阿里云核心域名遭“劫持”，域名安全引担忧**  
  
  
6月6日IDC圈消息，今日凌晨约2点，阿里云核心域名aliyuncs.com的NS记录被修改，解析指向了国际非营利网络安全组织Shadowserver的服务器（sinkhole.shadowserver.org）。这一异常操作导致阿里云的DNS解析服务受阻，对象存储（OSS）、CDN以及其他依赖该域名的云服务出现中断，影响包括博客园在内的多个知名网站和平台的正常访问。事件发生后，阿里云迅速响应，于今日上午8点11分完成修复工作，逐步恢复了受影响的服务。然而，由于DNS变更的滞后性，部分用户可能在修复后仍感受到持续影响。有分析认为，aliyuncs.com可能被Shadowserver转移解析或者域名注册局VeriSign下架，目前尚无官方层面的消息。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/dL5Tj5wspCKPyjOWeNpydQ  
  
  
**2.奢侈品牌卡地亚发生数据泄露，中国客户收到泄露通知**  
  
  
6月4日北京商报消息，历峰集团旗下奢侈品品牌卡地亚向部分客户发出邮件称，其系统遭入侵后发生数据泄露事件，导致客户个人信息外泄。邮件内容显示，“未经授权者曾短暂进入我方系统并获取了少量客户信息。我们已控制事态，并进一步强化了系统及数据的防护措施。”泄露信息包括客户姓名、电子邮箱地址、所在国家/地区及出生日期，卡地亚强调，此次泄露不涉及密码、信用卡号或其他银行账户详情等敏感数据，但鉴于数据性质，建议客户警惕任何未经请求的通信及其他可疑信函。卡地亚表示已通报相关部门，并正与外部网络安全专家合作处理漏洞。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/6nJK9TZ1yBIH2cOy9itRLQ  
  
  
**3.国家安全部：境外间谍对我实施网络攻击窃密愈演愈烈**  
  
  
6月4日国家安全部消息，国家安全部公众号发文称，近年来，境外间谍情报机关对我实施网络攻击窃密愈演愈烈，各种手段层出不穷，对我国家安全构成威胁，需引起警惕。某国家级重点实验室工作人员王某，为了盲目追求工作的方便快捷，故意绕开审批监管手续，在其个人联网计算机内违规存储了1000余份涉密文件和敏感资料。某天，王某收到一封主题为“会议通知”的电子邮件，邀请其参加所属研究领域的一场学术会议。王某未作甄别就直接下载并阅读了该邮件的附件，导致其使用的个人计算机被境外间谍情报机关植入特种木马程序，并被秘密控制长达三个月。王某个人计算机内违规存储的文件资料全部被窃取，造成重大失泄密事件。境外间谍情报机关试图利用境内个别OA系统漏洞，对我党政机关、科研院所、重点企业和关键基础设施实施网络攻击窃密活动。国家安全机关工作掌握，某科研单位使用的OA系统由于长期未进行漏洞修补和杀毒软件更新，导致其服务器被境外黑客攻击并植入木马病毒，最终造成该单位重要数据被窃取倒卖。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/__w_cH58CvzmXkW4zc8_4w  
  
  
**4.俄罗斯军工巨头遭乌克兰网军攻击，4.4GB机密数据失窃**  
  
  
6月4日Bleeping Computer消息，乌克兰国防部情报总局（GUR）宣布，其网络战部队成功渗透俄罗斯军工企业图波列夫设计局，获取包括图160（白天鹅战略轰炸机）在内的4.4GB机密数据。据乌克兰媒体报道，GUR的网络专家在长时间内潜伏于图波列夫的网络系统中，期间获取了大量敏感信息，包括高层内部通信记录、员工个人信息、采购合同与技术文档、闭门会议纪要等。GUR匿名消息人士表示：“此次行动的成果难以估量。对于乌克兰情报部门而言，图波列夫的运营几乎已无任何秘密可言。”他还补充道：“我们现在掌握了直接参与维护俄罗斯战略航空的人员的全面信息。这一行动的影响将在地面和空中同时显现。”  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/ukraine-claims-it-hacked-tupolev-russias-strategic-warplane-maker/  
  
  
**5.俄罗斯国家黑客组织服务器暴露，内部架构、攻击行动等遭揭秘**  
  
  
6月1日The Insider消息，美国媒体The Insider俄语版记者声称，近日获得了一台神秘服务器的访问权限，由此揭示了一个俄罗斯国家黑客组织的内部组织架构和大量敏感行动信息。据称，该组织与俄罗斯第29155部队有关。第29155部队隶属于俄罗斯总参谋部情报总局，并以其旧称“格鲁乌（GRU）”广为人知。记者通过对电话记录、出行数据以及内部通信的分析，识别出数十名该黑客小组的成员，包括诈骗前科人员、应届生、非IT背景的格鲁乌老兵等。其攻击目标清单涵盖广泛，涉及乌克兰国有企业、欧洲重要基础设施、卡塔尔一家银行及全球多家医疗机构。  
  
  
原文链接：  
  
https://theins.press/inv/281701  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.特朗普政府发布加强国家网络安全的行政命令**  
  
  
6月6日，美国总统特朗普签署了新的网络安全行政命令，重点关注针对外国网络威胁的关键保护措施并加强安全技术实践，以加强国家网络安全。重点内容包括：修正了奥巴马政府13694号行政命令和拜登政府第14144号行政命令；指示美国联邦政府推进安全软件开发；指示各部门和机构在边界网关安全方面采取行动，以阻止网络互连劫持行为；指示部门和机构在后量子密码方面采取行动，以确保防范可能利用下一代计算架构的威胁；要求采用最新的加密协议；将人工智能网络安全工作的重点重新转向识别和管理漏洞，而非审查；指示采取技术措施颁布网络安全政策，包括机器可读的政策标准和“物联网”的正式信任指定，以确保美国民众了解其个人和家用设备符合基本的安全工程原则。  
  
  
原文链接：  
  
  
https://www.whitehouse.gov/presidential-actions/2025/06/sustaining-select-efforts-to-strengthen-the-nations-cybersecurity-and-amending-executive-order-13694-and-executive-order-14144/  
  
  
  
**2.欧洲数据保护委员会发布《关于GDPR第48条的指南》**  
  
  
6月5日，欧洲数据保护委员会（EDPB）通过了《关于GDPR第48条的指南》最终版本。该文件明确了个人数据传输至第三国的规范，阐述了在何种条件下可以合法响应来自第三国当局的个人数据传输请求的最佳评估方法，为欧洲数据控制者和处理者提供实操建议，帮助其应对跨境数据请求，确保数据传输的合规性和安全性。该文件主要针对第三方国家机构与欧盟内的私人实体之间的直接合作请求，欧盟内部公共机构与第三国公共机构之间直接交换个人数据的情况，如基于相互法律协助条约的情报共享等，不属于指南的覆盖范畴。  
  
  
原文链接：  
  
https://www.edpb.europa.eu/system/files/2025-06/edpb_guidelines_202402_article48_v2_en.pdf  
  
  
**3.李强签署国务院令，公布《政务数据共享条例》**  
  
  
6月3日，《政务数据共享条例》已经5月9日国务院第59次常务会议通过，现予公布，自2025年8月1日起施行。该文件共8章44条，包括总则、管理体制、目录管理、共享使用、平台支撑、保障措施、法律责任、附则。该文件要求，政务数据共享主管部门应当会同同级网信、公安、国家安全、保密行政管理、密码管理等部门，根据数据分类分级保护制度，推进政务数据共享安全管理制度建设，按照谁管理谁负责、谁使用谁负责的原则，明确政务数据共享各环节安全责任主体，督促落实政务数据共享安全管理责任。政务数据需求部门在使用依法共享的政务数据过程中发生政务数据篡改、破坏、泄露或者非法利用等情形的，应当承担安全管理责任。  
  
  
原文链接：  
  
https://www.gov.cn/zhengce/content/202506/content_7026294.htm  
  
  
**4.澳大利亚支付勒索软件赎金强制报告规则正式生效**  
  
  
5月30日，澳大利亚信号局旗下网络安全中心发布指导文件称，支付勒索软件和网络勒索赎金强制报告规则已于5月30日起生效。这使其成为全球首个强制要求受害者报告支付赎金情况的国家。该规则出自《2024年网络安全法案》，要求年营收为300万澳元及以上的大型组织和特定关键基础设施实体，必须在勒索软件或网络勒索赎金支付后72小时内，向澳大利亚网络安全中心报告。未能及时报告的组织将面临约1.8万澳元的罚款。据悉，年营收超300万澳元的组织约占澳大利亚所有注册企业的约6.56%。  
  
  
原文链接：  
  
https://www.homeaffairs.gov.au/cyber-security-subsite/files/how-to-make-a-report-ransomware-payment-reporting.pdf  
  
  
**往期精彩推荐**  
  
  
[【已复现】Roundcube Webmail 后台代码执行漏洞(CVE-2025-49113)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503459&idx=1&sn=087027a577be1dc41e697c2c19c5b6d6&scene=21#wechat_redirect)  
  
  
[【已复现】DataEase 远程代码执行漏洞(CVE-2025-49001、CVE-2025-49002)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503451&idx=1&sn=838415cece549ae052cced3f736997b1&scene=21#wechat_redirect)  
  
  
[【新安全事件】vBulletin 远程代码执行漏洞(CVE-2025-48827)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503443&idx=1&sn=763f543a4089f1b08833ccbac7059be5&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
