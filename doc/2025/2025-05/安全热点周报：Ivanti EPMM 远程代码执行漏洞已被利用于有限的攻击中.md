#  安全热点周报：Ivanti EPMM 远程代码执行漏洞已被利用于有限的攻击中   
 奇安信 CERT   2025-05-26 09:45  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">零售巨头马莎百货因勒索攻击运营中断数月，预计损失近30亿元</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">超1.84亿条账号密码泄露，涉苹果、谷歌、小米等众多知名公司</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">国内一打印机品牌官方软件感染窃密木马超半年</span></p></td></tr></tbody></table>  
  
  
  
**PART****0****1**  
  
  
**新增在野利用**  
  
  
**1.****MagicINFO 任意文件上传漏洞(CVE-2025-4632)******  
  
  
5月22日，美国网络安全和基础设施安全局(CISA) 将三星 MagicINFO 9 服务器漏洞（编号为CVE-2025-4632，CVSS 评分为 9.8）添加到其已知被利用漏洞 (KEV) 目录中。运行 Samsung MagicINFO（一个用于管理三星商用数字显示器上内容的平台）的公司应升级到其 v9 分支的最新可用版本，以修复被攻击者利用的漏洞。  
  
由于三星没有回应标记漏洞并发布 PoC 的研究人员，也没有回应媒体询问，因此对于哪个漏洞被利用以及哪个版本的服务器组件容易受到攻击，人们产生了混淆。研究人员声称 MagicINFO 9 Server 21.1050（当时最新的可用版本）受到影响，Huntress 研究人员随后证实了这一点，因为一些被破坏的系统确实在运行它。在5月7日，三星推出了 MagicINFO 9 服务器（修补程序）21.1052。  
  
该公司的安全更新页面表示，他们已经修补了 CVE-2025-4632，这是一个将路径名不当限制为受限目录漏洞，允许攻击者以系统权限写入任意文件。不过，MagicINFO 9 服务器修补程序 21.1052 的发行说明没有提到 CVE-2025-4632，只提到了 CVE-2024-7399。  
  
MagicINFO V9（修补程序）21.1052 确实缓解了这个问题，正如 Huntress 研究人员最近证实的那样。MagicINFO v8 没有修补程序，因此用户应该切换到 v9 并以特定方式进行：首先升级到 v9 21.1050，然后更新到 v9（修补程序）21.1052。  
  
  
参考链接：  
  
https://www.helpnetsecurity.com/2025/05/15/samsung-patches-magicinfo-9-server-vulnerability-exploited-by-attackers/  
  
  
**2.****Ivanti Endpoint Manager Mobile身份认证绕过漏洞(CVE-2025-4427)&Ivanti Endpoint Manager Mobile代码执行漏洞(CVE-2025-4428)******  
  
  
5月19日，美国网络安全和基础设施安全局(CISA)将 CVE-2025-4427、CVE-2025-4428 添加到其已知可利用漏洞目录中。Wiz 的研究人员于周二发布了一篇博客文章，警告称 Ivanti 漏洞的利用活动仍在持续，并详细说明了这些漏洞与其他边缘设备（尤其是 Palo Alto Networks 防火墙）攻击之间的关联。威胁活动的模式加剧了企业面临的风险，并进一步表明边缘设备仍然是各种威胁行为者的热门且有利可图的目标。  
  
Ivanti 上周披露，其 Endpoint Manager Mobile (EPMM) VPN 产品中存在两个漏洞，可引发远程代码执行 (RCE) 攻击。这两个漏洞分别为 CVE-2025-4427（一个中等严重程度的身份验证绕过漏洞）和 CVE-2025-4428（一个高严重程度的 EPMM RCE 漏洞）。本月初利用两个 Ivanti 零日漏洞的威胁行为者也是之前针对其他边缘设备发动零日攻击的幕后黑手。  
  
Wiz 从5月16日开始观察到针对两个 Ivanti 漏洞的利用活动，该云安全供应商表示，这与 watchTowr 和 Project Discovery 等多个来源发布的概念验证漏洞同时发生。更重要的是，Wiz 研究人员 Merav Bar、Shahar Dorfman 和 Gili Tikochinski 发现 Ivanti 攻击与其他攻击有相似之处。例如，他们发现用于命令和控制 (C2) 的 IP 地址 77.221.158[.]154 在过去的攻击中也曾被使用过。  
  
Wiz 研究人员表示，与该 IP 地址关联的数字证书自2024年11月以来一直没有改变。他们称，这种连续性使我们得出结论，同一个攻击者一直在机会主义地瞄准 PAN-OS 和 Ivanti EPMM 设备。Tikochinski 表示，Wiz 仍在积极调查 Ivanti 的后漏洞利用活动，目前尚未发现任何勒索软件或数据泄露。然而证据表明，Wiz 观察到的两组零日攻击背后都有同一个威胁行为者。在最近针对 Ivanti 零日漏洞的攻击中，威胁行为者使用了 Sliver，这是一种受到红队和网络犯罪分子青睐的 C2 框架。  
  
建议 Ivanti 客户升级到 EPMM 版本 11.12.0.5、12.3.0.2、12.4.0.2 或 12.5.0.1，并优先考虑面向互联网的设备。同时建议客户对所有 EPMM 端点实施网络级限制，直到修复漏洞为止。企业还应监控其网络上的 Sliver 活动并阻止来自 77.221.158[.]154 的流量。  
  
  
参考链接：  
  
https://www.darkreading.com/cyberattacks-data-breaches/ivanti-epmm-exploitation-previous-zero-day-attacks  
  
**PART****0****2**  
  
  
**安全事件**  
  
  
**1.河南某公司办公系统遭篡改挂恶意标语被罚3万元**  
  
  
5月23日网信郑州消息，郑州市网信办工作中发现，我市某公司未履行网络安全保护义务，引发网络安全事件。郑州市网信办依据《网络安全法》对该公司作出责令改正，给予警告，并处以人民币三万元罚款的行政处罚。现向社会公开通报该起典型案例如下：经调查，该公司在网络安全方面意识淡薄，未建立健全网络安全等级保护制度，其网络办公系统存在部分未选择记录日志功能、防火墙未禁用高危端口、未对账户进行重命名、未及时修复漏洞隐患、未对数据库加密处理、应用程序版本过低等9个问题，境外不法分子利用该系统存在的漏洞，上传恶意标语，引发网络安全事件，造成严重恶劣影响，违反《网络安全法》第二十一条规定，违法情节严重。针对以上违法情况，郑州市网信办依据《网络安全法》第五十九条，对该公司作出责令改正，给予警告，并处人民币三万元罚款的行政处罚。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/x4jcyW6vZVwMCT4BydsbLw  
  
**2.CNCERT发布风险提示：“游蛇”黑产近期攻击活动频繁**  
  
  
5月23日国家互联网应急中心CNCERT消息，CNCERT和安天近期监测到“游蛇”黑产团伙（又名“银狐”、“谷堕大盗”、“UTG-Q-1000”等）组织活动频繁，攻击者采用搜索引擎SEO推广手段，伪造Chrome浏览器下载站。伪造站与正版官网高度相似，极具迷惑性。用户一旦误信并下载恶意安装包，游蛇远控木马便会植入系统。实现对目标设备的远程操控，盗取敏感数据等操作。通过跟踪监测发现其每日上线境内肉鸡数（以IP数计算）最多已超过1.7万。  
  
  
原文链接：  
  
https://www.cert.org.cn/publish/main/upload/File/Colubrid%20Black%20Market%20New.pdf  
  
**3.超1.84亿条账号密码泄露，涉苹果、谷歌、小米等众多知名公司**  
  
  
5月22日连线消息，知名数据安全研究员Jeremiah Fowler发现，一个神秘的Elastic数据库在公网暴露，总数据量超过47GB，里边包括1.84亿条账号密码记录，涉及美澳中等数十国家各类主流互联网服务账号、政府邮箱、银行账号等，如互联网服务账号包括苹果、谷歌、微软、脸书、小米等。该数据库涉及的各国网络服务过于广泛，缺乏识别所有者的线索，经分析疑似信息窃取软件收集而来。经联系服务器托管商，对方称可能是欺诈用户上传的非法内容。  
  
  
原文链接：  
  
https://www.wired.com/story/mysterious-database-logins-governments-social-media/  
  
**4.零售巨头马莎百货因勒索攻击运营中断数月，预计损失近30亿元**  
  
  
5月21日天空新闻消息，英国零售巨头马莎百货（也称玛莎百货、M&S）披露，4月遭遇的勒索软件攻击致使其数字支付、电商等在线业务持续中断数月，预计7月才能完全恢复。受该事件受冲击，公司市值已蒸发约百亿元，预估损失高达3亿英镑（约合人民币29亿元）。公司将通过成本控制措施尽量降低损失金额。马莎百货首席执行官Stuart Machin在分析师电话会议中表示，此次攻击源于“人为错误”，并指出公司目前“正处于恢复过程中”，“正在重新步入正轨”。马莎百货拒绝对是否已向黑客支付赎金一事发表评论。  
  
  
原文链接：  
  
https://news.sky.com/story/mands-warns-of-300m-profit-hit-due-to-hacking-crisis-13371908  
  
  
**5.韩国SK电讯2700万用户SIM卡机密数据泄露**  
  
  
5月20日Bleeping Computer消息，韩国最大电信运营商SK电讯披露了4月数据泄漏事件的调查细节。SK电讯于4月19日在内部网络检测到恶意软件活动，但最初攻击可追溯至2022年6月15日，当时黑客通过WebShell入侵并悄无声息植入恶意负载，横向扩散至23台服务器，长达将近三年未被发现。调查显示，黑客获取了大量用户敏感数据，包括IMSI、USIM身份认证密钥、SIM卡中储存的短信和联系人、网络使用记录等。SK电讯称，将尽快通知2695万用户数据泄露及处置措施，为所有用户更换SIM卡。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/sk-telecom-says-malware-breach-lasted-3-years-impacted-27-million-numbers/  
  
  
**6.我国某科技公司遭境外组织网络攻击，分析称技术水平较低**  
  
  
5月20日央视新闻消息，广东省广州市公安局天河区分局发布警情通报称，广州某科技公司自助设备的后台系统遭受网络攻击并被上传多份恶意代码。接警后，公安机关立即开展调查，提取相关样本，依法固定电子证据。经对网络攻击手法和相关恶意代码样本开展技术分析，现已初步判定该事件为境外黑客组织发起的网络攻击活动。据悉，攻击者利用技术手段绕过该公司的网络防护装置，非法进入自助设备的后台系统，通过横向移动渗透控制多台网络设备，向这些设备中的后台系统非法上传多份攻击程序，使其官方网站和部分业务系统受到影响，导致网络服务中断数小时，给公司造成了重大损失，部分用户隐私信息疑遭泄露。  
  
据警方透露，此次网络攻击是境外黑客组织的一次有组织、有预谋的大规模网络攻击行动，带有明显的网络战痕迹，并非普通个人黑客所能完成。初步追踪溯源发现，该黑客组织长期使用开源工具对我重要部门、敏感行业和科技公司开展网络资产扫描探测，广泛搜寻攻击目标，通过技术手段挖掘目标单位网络防护薄弱环节和攻击点位，伺机入侵控制目标系统，窃取、破坏重要数据，干扰相关机构正常运营。技术团队分析认为，攻击者的作案手法及相关技术水平较低，攻击过程中暴露出大量网络线索，公安机关正在对相关线索开展技术分析和侦查调查。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/06fEE8rh32b82ji9zNVEVw  
  
  
**7.全球最大有机乳品生产商Arla Foods遭黑，德国工厂被迫中断生产**  
  
  
5月19日Bleeping Computer消息，丹麦乳业巨头Arla Foods确认，公司位于德国Upahl的工厂IT网络遭受网络攻击，后续采取安全措施导致生产暂时受到影响，可能导致产品交付延迟或取消。该公司已启动应急措施恢复系统，预计在该周末重启。Arla Foods的其他工厂未受影响。尚不明确是否涉及数据窃取或勒索软件，目前暂无组织宣称对此次事件负责。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/arla-foods-confirms-cyberattack-disrupts-production-causes-delays/  
  
  
**8.英国官方首次披露：医院患者因网络攻击遭受临床伤害**  
  
  
5月19日The Record消息，英国国家医疗服务体系（NHS）官方数据显示，2024年有两起网络攻击事件达到第三级损害，即可能对50名以上患者造成临床伤害，这是首次由官方机构披露网络攻击造成临床伤害的数据。两起事件中，前一起事件可能是针对病理服务供应商Synnovis的勒索软件攻击，该事件严重干扰了伦敦多家NHS医院和护理机构的正常服务，导致手术和预约被延迟或取消。后一起攻击则针对威勒尔大学教学医院NHS信托机构，造成癌症治疗出现延误，据媒体报道，该事件同样对医疗服务造成干扰。  
  
  
原文链接：  
  
https://therecord.media/uk-nhs-data-two-cyberattacks-clinical-harm-2024  
  
  
**9.国内一打印机品牌官方软件感染窃密木马超半年**  
  
  
5月16日Bleeping Computer消息，德国网络安全公司G Data发现，中国打印机品牌Procolored存放在Mega网盘的官方驱动和配套软件，感染了远控木马和加密货币窃取木马，时间至少半年以上。数据显示，该加密货币窃取木马已经收到9.308枚比特币，按当前汇率价值近百万美元。Procolored于5月8日下架了相关软件，后续更新软件并启动内部调查。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/printer-maker-procolored-offered-malware-laced-drivers-for-months/  
  
  
**PART****0****3**  
  
  
**政策法规**  
  
  
**1.六部门联合公布《国家网络身份认证公共服务管理办法》**  
  
  
5月23日，公安部、国家互联网信息办公室、民政部、文化和旅游部、国家卫生健康委员会、国家广播电视总局等六部门联合公布《国家网络身份认证公共服务管理办法》，自2025年7月15日起施行。该文件共16条，主要规定了四个方面内容：一是明确了国家网络身份认证公共服务及网号、网证的概念、申领方式；二是明确了使用国家网络身份认证公共服务的效力、应用场景；三是强调了国家网络身份认证公共服务平台、互联网平台等对数据安全和个人信息保护的责任；四是对未成年人申领、使用国家网络身份认证公共服务作出特殊规定。  
  
原文链接：  
  
https://www.mps.gov.cn/n6557558/c10087550/content.html  
  
  
**2.美国NSA等多国网络安全机构联合发布AI数据安全指南**  
  
  
5月22日，美国国家安全局（NSA）、网络安全与基础设施安全局、联邦调查局联合澳大利亚、新西兰、英国等国网络安全机构发布《人工智能数据安全：保护用于训练和运行人工智能系统的数据的最佳实践》指南文件。该文件强调数据安全对于确保AI结果的准确性和完整性的重要性，介绍了数据供应链、数据恶意篡改、数据漂移三种主要的AI数据安全风险及其在AI系统生命周期的影响，并就开发、测试和运行AI系统过程中数据的安全提供通用最佳实践。  
  
  
原文链接：  
  
https://media.defense.gov/2025/May/22/2003720601/-1/-1/0/CSI_AI_DATA_SECURITY.PDF  
  
  
**3.国家密码管理局《电子印章管理办法》公开征求意见**  
  
  
5月21日，国家密码管理局会同有关部门研究起草了《电子印章管理办法(征求意见稿)》,现向社会公开征求意见。该文件共8章38条，围绕规范政务活动及相关社会化服务领域电子印章管理工作，重点明确了电子印章法律效力、管理主体、管理要求、互信互认和安全管理等方面内容。该文件要求，电子印章管理全过程应当建立完善的信息保护制度，采取必要措施确保电子印章相关信息的安全，并对收集的单位（组织）和个人的信息严格保密。电子印章相关信息系统的建设、使用和运行维护应当符合国家密码管理、网络安全、数据安全等相关法律法规和标准规范。  
  
  
原文链接：  
  
https://www.oscca.gov.cn/sca/hdjl/2025-05/21/1061253/files/4c8ad51318144db588f3d26c8a63d064.doc  
  
  
**4.中央网信办等三部门印发《2025年深入推进IPv6规模部署和应用工作要点》**  
  
  
5月20日，中央网信办、国家发展改革委、工业和信息化部联合印发《2025年深入推进IPv6规模部署和应用工作要点》。该文件明确了2025年工作目标：到2025年末，全面建成全球领先的IPv6技术、产业、设施、应用和安全体系，IPv6安全能力持续改进，各类安全产品的IPv6功能进一步丰富、防护能力进一步提高。该文件部署了9个方面42项重点任务，其中强化网络安全保障方面包括加强IPv6网络安全防护和管理监督、提升IPv6安全风险研判及技术实践能力、推动IPv6安全产品研发应用。  
  
  
原文链接：  
  
https://www.cac.gov.cn/2025-05/20/c_1749446498560205.htm  
  
  
**往期精彩推荐**  
  
  
[蝉联获奖数量第一！奇安信斩获8项CNNVD重磅大奖](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503422&idx=1&sn=d615ef697127cc8ce320ab0a75bc4063&scene=21#wechat_redirect)  
  
  
[安全热点周报：Fortinet 修复了 FortiVoice 攻击中利用的关键零日漏洞](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503417&idx=1&sn=e3066a86595352998f8e826f3a2435cf&scene=21#wechat_redirect)  
  
  
[【已复现】Ivanti Endpoint Manager Mobile 多个漏洞安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503407&idx=1&sn=bc577b527b31ff7b989f2b804f447771&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
