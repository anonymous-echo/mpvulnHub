> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503502&idx=2&sn=ffe84150213eff7c9c03e074b80d7c59

#  安全热点周报：黑客利用 Windows WebDav 零日漏洞来投放恶意软件  
 奇安信 CERT   2025-06-16 08:30  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• 《汽车数据出境安全指引（2025版）》公开征求意见</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">北京2家公司个人信息数据遭境外IP窃取被罚</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">首个AI Agent零点击漏洞曝光揭示其深层次风险</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.契约锁电子签章系统远程代码执行漏洞安全风险通告**  
  
  
6月12日，奇安信CERT监测到官方修复契约锁电子签章系统远程代码执行漏洞(QVD-2025-23408)，该漏洞源于管理控制台存在未授权JDBC注入漏洞，攻击者通过构造恶意数据库连接参数，在dbtest接口触发远程代码执行。目前该漏洞技术细节与PoC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**2.Apache Kafka多个高危漏洞安全风险通告**  
  
  
6月10日，奇安信CERT监测到Kafka官方修复多个安全漏洞。Apache Kafka客户端任意文件读取漏洞(CVE-2025-27817)是由于在SASL/OAUTHBEARER和SASL JAAS配置中未对URL和登录模块进行严格限制，从而造成的客户端的敏感数据和内网信息泄露；Apache Kafka远程代码执行漏洞(CVE-2025-27818、CVE-2025-27819)则分别因允许使用LdapLoginModule和JndiLoginModule，可能触发Java反序列化漏洞，进而导致远程代码执行或拒绝服务攻击。奇安信威胁情报中心安全研究员已成功复现CVE-2025-27817。鉴于上述漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.Wazuh 平台远程代码执行漏洞(CVE-2025-24016)******  
  
  
6月11日，两个独立的 Mirai 僵尸网络活动正在利用一个不太可能的目标中的严重缺陷。  
  
Akamai 安全情报与响应团队最近观察到开源 Wazuh 网络安全平台中存在远程代码执行漏洞 CVE-2025-24016 的利用。该漏洞的 CVSS 评分为 9.9，源于一个不安全的反序列化问题，影响该平台 4.4.0 至 4.9.1 版本。  
  
CVE-2025-24016 于2月10日公开披露，并于当月晚些时候在 GitHub 上发布了概念验证 (PoC) 漏洞利用代码。Akamai 研究人员从3月初就开始观察到此类漏洞利用活动。  
  
Akamai 研究人员 Kyle Lefton 和 Daniel Messing 在6月9日的一篇博客文章中写道：“这是僵尸网络运营商针对新发布的 CVE 所采用的不断缩短的利用时间线的最新例子。”  
  
研究小组后来将利用活动追溯到两个活动，这些活动涉及 Mirai 僵尸网络的变体。  
  
Wazuh 反驳了 Akamai 的报告，并否认 CVE-2025-24016 已被利用。该公司强调，利用需要有效的管理 API 凭证和对 Wazuh 服务器 API 的访问权限。因此，被利用的可能性很低，总体风险也很有限。据 Lefton 和 Messing 称，虽然这些活动表明 Mirai 变体的持续传播，但僵尸网络也显示了公开发布已知漏洞 PoC 的风险。  
  
Akamai 敦促各组织升级到 Wazuh 4.9.1 或更高版本。研究人员还警告称，僵尸网络运营商密切关注公开的漏洞披露，并会迅速利用任何可用的 PoC 代码进行攻击，因此及时修补应成为所有组织的首要任务。  
  
  
参考链接：  
  
https://www.darkreading.com/vulnerabilities-threats/mirai-botnets-exploit-wazuh-security-platform  
  
  
**2.Web 分布式创作和版本控制 (WEBDAV) 远程代码执行漏洞(CVE-2025-33053)******  
  
  
6月11日，微软共发布了66个漏洞的补丁程序，修复了Windows 通用日志文件系统驱动程序、Windows Installer、Microsoft Office等产品中的漏洞。  
  
自2025年3月以来，一个名为“Stealth Falcon”的 APT 黑客组织利用 Windows WebDav RCE 漏洞对土耳其、卡塔尔、埃及和也门的国防和政府组织发动了零日攻击。Stealth Falcon（又名“FruityArmor”）是一个 APT 组织，以对中东组织进行网络间谍攻击而闻名。  
  
CVE-2025-33053 是一个远程代码执行（RCE）漏洞，该漏洞是由于某些合法系统可执行文件对工作目录的不当处理而引起的。具体来说，当 .url 文件将其 WorkingDirectory 设置为远程 WebDAV 路径时，内置的 Windows 工具可能会被诱骗从该远程位置而不是合法位置执行恶意可执行文件。这允许攻击者强制设备从其控制的 WebDAV 服务器远程执行任意代码，而不会在本地放置恶意文件，从而使他们的作变得隐蔽和规避。  
  
该漏洞由 Check Point Research 发现，Microsoft 在发布的最新补丁公告更新中修复了该漏洞。  
  
根据 Check Point 的说法，尽管漏洞是有效的并确认已被利用，但未遂的攻击可能没有成功。威胁行为者使用一种以前未公开的技术，通过纵合法内置 Windows 工具的工作目录，执行托管在他们控制的 WebDAV 服务器上的文件。伪装成 PDF 的欺骗性 URL 文件，通过网络钓鱼电子邮件发送给目标。Check Point 检索了攻击者服务器上托管的文件和后续负载，以分析未遂的攻击。  
  
在这次攻击中，恶意 .url 漏洞将工作目录设置为攻击者的 WebDAV 服务器，导致 iediagcmd.exe 工具直接从远程 WebDav 共享运行命令。这会导致 iediagcmd.exe 从远程服务器运行攻击者的假 route.exe 程序，该程序会安装一个名为“Horus Loader”的自定义多阶段加载程序。然后，加载程序会丢弃主要有效负载“Horus Agent”，这是一个自定义的 C++ Mythic C2 植入程序，支持系统指纹识别、配置更改、shellcode 注入和文件作的命令执行。以前，威胁行为者使用定制的 Apollo 代理，而他们最新的 Horus 工具更先进、更规避和模块化，提供作隐蔽性和灵活性。  
  
鉴于 CVE-2025-33053 在间谍活动中被积极利用，建议关键组织尽快应用最新的 Windows 更新。如果无法升级，建议阻止或密切监控 WebDAV 流量，以发现到未知终端节点的可疑出站连接。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/stealth-falcon-hackers-exploited-windows-webdav-zero-day-to-drop-malware/  
  
  
**3.****Erlang/OTP SSH未认证远程代码执行漏洞(CVE-2025-32433)******  
  
  
6月9日，美国网络安全和基础设施安全局(CISA) 将 Erlang Erlang/OTP SSH 服务器漏洞添加到其已知利用漏洞 (KEV) 目录中。CVE-2025-32433 是一个严重漏洞，影响 Erlang/OTP（用于 Erlang 编程语言的工具包）的旧版本。如果运行的是 OTP-27.3.3、OTP-26.2.5.11 或 OTP-25.3.2.20 之前的版本，系统可能存在通过其内置 SSH 服务器进行远程代码执行(RCE) 的漏洞。这意味着攻击者无需登录或输入任何凭证即可在目标系统上运行代码。此问题已在上述版本中得到修复。  
  
4月16日，德国波鸿鲁尔大学的 Fabian Bäumer、Marcus Brinkmann、Marcel Maehren 和 Jörg Schwenk 向OpenWall漏洞邮件列表披露了 Erlang/OTP SSH 中的一个高危漏洞。此外，Erlang/OTP 的GitHub 项目上也发布了官方公告，对研究人员的披露表示感谢。4月17日，Platform Security 的研究人员发布了针对 CVE-2025-32433 的公开概念验证 (PoC) 漏洞。报告指出，该 PoC 是在 ChatGPT 和 Cursor 的帮助下生成的，使用这些 AI 工具生成 PoC 相当简单。该 PoC 会像普通客户端一样发起 SSH 协议协商。但是，在对用户进行身份验证之前，客户端会发送一条包含任意命令的意外消息。存在漏洞的服务器会处理这些消息并执行这些命令。已修补的服务器在身份验证之前看到这些消息后会立即断开连接。  
  
目前尚未发现任何已知的利用情况，但是由于利用的容易程度和严重性，预计攻击将很快发生。  
  
Erlang/OTP 已发布补丁来解决此漏洞。如果无法立即修复，Erlang/OTP 提供的缓解措施包括通过防火墙限制访问或禁用 SSH 服务器。但强烈建议尽快升级以完全修复此漏洞。  
  
  
参考链接：  
  
https://www.tenable.com/blog/cve-2025-32433-erlangotp-ssh-unauthenticated-remote-code-execution-vulnerability  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.北京2家公司个人信息数据遭境外IP窃取被罚**  
  
  
6月13日网信北京公众号消息，北京市网信办持续加强数据安全领域执法力度，披露了2起违法典型案例。北京某科技公司在开展业务过程中，因技术人员缺乏数据安全保护意识，未对后台业务系统的接口配置访问控制和身份认证等安全措施，导致该系统存在未授权访问漏洞，使储存于其中的姓名、身份证号、手机号等个人信息数据暴露于互联网，并被境外IP访问窃取。该公司未依法履行数据安全保护义务，未建立健全全流程数据安全管理制度，相关系统未采取技术措施和其他必要措施保障数据安全，造成部分个人信息数据遭窃取，违反《中华人民共和国数据安全法》第二十七条规定。针对以上违法情况，北京市网信办依据《中华人民共和国数据安全法》第四十五条，对北京某科技公司作出警告，并处五万元罚款的行政处罚。北京某有限公司在开展业务过程中，为方便系统测试，将ES数据库的9200端口对外开放且未限制访问，导致ES数据库存在未授权访问漏洞，使储存于其中的姓名、手机号等个人信息数据暴露于互联网，并被境外IP访问窃取。该公司数据安全保护意识淡薄，未依法履行数据安全保护义务，未建立健全全流程数据安全管理制度，相关系统未采取技术措施和其他必要措施保障数据安全，造成部分个人信息数据遭窃取，违反《中华人民共和国数据安全法》第二十七条规定。针对以上违法情况，北京市网信办依据《中华人民共和国数据安全法》第四十五条，对北京某有限公司作出警告，并处五万元罚款的行政处罚。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/Fzt00_CXsooCHWtWGutL7g  
  
  
**2.工信部风险提示：AI绘图工具ComfyUI多个安全漏洞已被用于实施网络攻击**  
  
  
6月13日网络安全威胁和漏洞信息共享平台公众号消息，工业和信息化部网络安全威胁和漏洞信息共享平台（NVDB）监测发现，ComfyUI工具存在任意文件读取、远程代码执行等5个安全漏洞，已被用于实施网络攻击。ComfyUI是一款开源的人工智能绘图工具，用于人工智能驱动的图像生成、视频制作、3D建模与音频创作等。由于其组件存在代码注入、任意文件读取、跨站脚本、远程代码执行等安全漏洞，可被攻击者利用执行远程恶意代码，获取服务器权限，进而窃取系统数据。受影响的ComfyUI组件包括ComfyUI-Ace-Nodes、Comfyanonymous/comfyui、ComfyUI-Bmad-Node、ComfyUI-Impact-Pack、ComfyUI-Manager。上述漏洞均已修复，建议相关单位和用户立即开展全面排查，及时升级至最新安全版本，通过限制互联网访问、设置IP白名单、增强身份验证机制等方式做好类似人工智能应用的安全加固，防范网络安全风险。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/4N60-U9bhuvbt8hx_ocoHA  
  
  
**3.韩国知名票务平台Yes24遭勒索攻击，多场明星活动被迫中断**  
  
  
6月12日The Record消息，韩国知名票务及图书平台Yes24在6月9日遭遇勒索软件攻击，导致网站及App连续瘫痪了四天，线上图书订购、演唱会票务、电子书服务全部中断。此次攻击迫使朴宝剑、ENHYPEN、ATEEZ等韩国明星的演唱会及粉丝活动推迟或取消，《廊桥遗梦》《阿拉丁》等音乐剧制作方要求观众出示纸质门票或邮件确认函入场，部分观众因无法提供可验证票务信息被拒绝入场。Yes24表示尚未确认个人信息外泄，但已向韩国数据隐私机构报告涉及客户数据未授权访问的可疑活动。  
  
  
原文链接：  
  
https://therecord.media/yes24-south-korea-ransomware-attack  
  
  
**4.美国航空巨头爆出“数据后门”，所有乘客数据被秘密出售给政府**  
  
  
6月10日404 Media消息，美国政府内部文件显示，由达美航空、美国航空、联合航空等美国主要航空公司共同拥有的数据代理商航空公司报告公司，一直在系统性地收集美国国内旅客的飞行记录，并将其打包出售给美国海关和边境保护局（CBP）。根据内部文件，CBP购买的数据包内容详尽得令人不安，远超普通安检所需，包括乘客姓名、航班行程细节、订单及支付细节等信息。采购合同中还包含一项“封口”条款，明确指示政府机构不得透露数据的真实来源。美国公民自由联盟等组织的专家指出，这实质上是对全体国内旅客建立了一个“无证监控”系统。  
  
  
原文链接：  
  
https://www.404media.co/airlines-dont-want-you-to-know-they-sold-your-flight-data-to-dhs/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.《汽车数据出境安全指引（2025版）》公开征求意见**  
  
  
6月13日，工业和信息化部、国家网信办、国家发展改革委、国家数据局、公安部、自然资源部、交通运输部、市场监管总局起草了《汽车数据出境安全指引（2025版）（征求意见稿）》，拟以规范性文件印发，现面向社会公开征求意见。该文件旨在引导规范汽车数据处理者高效便利安全开展汽车数据出境活动，提升汽车数据出境流动便利化水平。该文件所称汽车数据是指汽车设计、生产、销售、使用、运维等过程中涉及的个人信息和重要数据。汽车数据处理者是指开展汽车数据处理活动的组织，包括汽车制造商、零部件和软件供应商、电信运营企业、自动驾驶服务商、平台运营企业、经销商、维修机构以及出行服务企业等。  
  
  
原文链接：  
  
https://www.miit.gov.cn/cms_files/demo/pdfjs/web/viewer.html?file=/cms_files/filemanager/1226211233/attach/20256/acada4bb4d694c61adf4f390d0631380.pdf  
  
  
**2.工信部等七部门印发《食品工业数字化转型实施方案》**  
  
  
6月10日，工业和信息化部、教育部、人力资源社会保障部、中国人民银行、市场监管总局、国家粮食和储备局、国家数据局联合印发《食品工业数字化转型实施方案》，加快新一代信息技术在食品工业全链条、全方位深度应用，推动食品工业转型升级和高质量发展。该文件部署了4方面18项重点任务，其中一项为“强化网络和数据安全保障”，具体内容包括鼓励企业开展工业互联网安全分类分级管理，研究制定食品工业重要数据识别指南，强化重要数据识别和目录备案、数据安全风险评估、事件应急处置等工作，加强网络和数据安全防护能力建设，提升网络和数据安全防护水平。  
  
  
原文链接：  
  
https://www.miit.gov.cn/zwgk/zcwj/wjfb/tz/art/2025/art_5b1d644caf3f44549a53361a996bc3eb.html  
  
  
**3.美国NIST发布《硬件安全构造的指标和方法》**  
  
  
6月5日，美国国家标准与技术研究所（NIST）发布《硬件安全构造的指标和方法》白皮书，旨在评估硬件威胁。该文件提出了一种全面的方法论，用于评估与各类硬件弱点相关的威胁及可利用这些弱点的攻击方式。该方法论引入了两个关键指标：威胁指标，用于量化单一攻击可利用的硬件弱点数量；敏感性指标，衡量带有特定弱点的硬件系统可能受到的不同攻击数量。这些指标及其分析旨在为硬件安全防护提供指导，并在安全性与成本之间实现最优权衡。  
  
  
原文链接：  
  
https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.45.pdf  
  
  
**往期精彩推荐**  
  
  
[【已复现】契约锁电子签章系统远程代码执行漏洞(QVD-2025-23408)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503493&idx=1&sn=0810b8ac4e0360b1135b0ff03117cf88&scene=21#wechat_redirect)  
  
  
[【已复现】Apache Kafka 多个高危漏洞安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503484&idx=1&sn=e9cb94f0ad7c963ed06257db90f92834&scene=21#wechat_redirect)  
  
  
[微软6月补丁日多个产品安全漏洞风险通告：1个在野利用、9个紧急漏洞](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503477&idx=1&sn=1410a653474bbb82b32dadab97a47c7b&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
