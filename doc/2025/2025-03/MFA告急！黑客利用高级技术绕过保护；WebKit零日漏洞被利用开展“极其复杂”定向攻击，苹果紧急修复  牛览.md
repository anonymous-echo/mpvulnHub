#  MFA告急！黑客利用高级技术绕过保护；WebKit零日漏洞被利用开展“极其复杂”定向攻击，苹果紧急修复 | 牛览   
 安全牛   2025-03-13 18:36  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**新闻速览**  
  
  
  
  
•英国网络安全行业收入增长12%突破130亿英镑  
  
•机器身份数量超过人类用户4万倍，风险增加7.5倍  
  
•MFA告急！黑客利用高级技术绕过保护  
  
•微软修复6个零日漏洞和10个高风险漏洞  
  
•新型Ebyte勒索软件来袭，采用先进加密策略攻击Windows用户  
  
•WebKit零日漏洞被利用开展“极其复杂”定向攻击，苹果紧急修复  
  
•MirrorFace组织利用Windows内置功能进行APT攻击  
  
•NVIDIA Riva语音AI平台曝高危漏洞，攻击者可提升权限  
  
  
  
**热点观察**  
  
  
  
**英国网络安全行业收入增长12%突破130亿英镑**  
  
  
根据最新政府报告，英国网络安全行业在上一财年表现出色，总收入增长12%，达到132亿英镑。该报告基于公司注册处数据和电话调查等多个数据源编制而成。  
  
  
报告显示，目前英国有约2165家网络安全公司在运营，比前一年增加74家。其中59%提供服务、26%注册为产品公司、12%是托管安全服务提供商、3%为经销商。虽然大多数(56%)被归类为微型企业，但网络安全行业中中型(16%)和大型(10%)企业的比例远高于英国整体水平(分别为3%和1%)。  
  
  
仅有四分之一(26%)的2165家英国网安公司拥有国际业务，主要覆盖欧盟(52%)和美国(43%)市场。除了令人印象深刻的12%收入增长外，英国网络安全企业的总增加值也增长21%，达到78亿英镑。总增加值衡量了一个行业对经济的贡献，扣除了生产商品和服务所使用的投入价值。  
  
  
报告还揭示，缺乏技术人才(47%)和无法承受的薪酬要求(46%)是该领域面临的两大主要挑战，其次是来自竞争对手的压力(39%)。根据ISC2的一项研究，英国网络安全人才缺口去年增长27%，达到93000人。  
  
  
原文链接：  
  
https://www.infosecurity-magazine.com/news/uk-cybersecurity-sector-revenue/  
  
  
**机器身份数量超过人类用户4万倍，风险增加7.5倍**  
  
  
根据Sysdig今天发布的一份新报告，机器身份的激增、威胁检测加快以及漏洞数量大幅下降，正在重塑云安全的未来。Sysdig报告强调了自动化和实时响应的需求，以有效应对不断出现的新安全风险。  
  
  
报告显示，机器身份现在比人类用户多出4晚倍，并带来7.5倍的风险。随着组织扩大云运营，管理这些身份变得越来越困难。与此同时，人工智能(AI)和机器学习(ML)的采用在过去一年中激增了500%。尽管增长如此迅速，但组织还是提高了安全性，公开暴露的AI工作负载减少了38%。  
  
  
Sysdig表示，云威胁环境正在演变，但安全团队正在跟上步伐。成熟组织能在5秒内检测到威胁，并在3.5分钟内启动响应行动——远远低于攻击者通常利用的10分钟窗口期。漏洞管理也有了显著改善，组织正将重点转移到只修复真正构成威胁的漏洞上。生产工作负载中使用的漏洞百分比已降至6%以下，较两年前改善了64%。  
  
  
原文链接：  
  
https://www.infosecurity-magazine.com/news/machine-identities-outnumber/  
  
  
**MFA告急！黑客利用高级技术绕过保护**  
  
  
研究人员近期发现一种令人不安的趋势：黑客正在使用专门设计的复杂攻击手段来规避多因素认证（MFA）保护。这些先进技术利用认证工作流程中的漏洞，而非攻击认证因素本身，使攻击者能够在启用MFA的情况下未经授权访问受保护的账户。  
  
  
Quarkslab的研究人员分析显示，攻击者正在利用系统验证和跟踪MFA完成状态时的时序漏洞和实现缺陷，有效地欺骗应用程序认为二次验证已成功完成。最令人担忧的技术涉及在验证流程中精心操纵认证响应数据。当用户启动认证时，主要因素（通常是密码）生成一个初始会话令牌，然后等待二次验证。攻击者发现了在MFA挑战完成之前拦截并修改此令牌状态标志的方法。攻击通常使用JavaScript代码注入来修改认证响应。  
  
  
这种漏洞主要影响在认证服务器和资源服务器之间实现单独会话状态跟踪的系统。安全专家建议组织在整个会话生命周期内持续验证MFA状态，并采用无法在不被检测的情况下修改的加密签名令牌。  
  
  
原文链接：  
  
https://cybersecuritynews.com/hackers-using-advanced-mfa-bypassing-techniques/  
  
  
**微软修复6个零日漏洞和10个高风险漏洞**  
  
  
微软最新发布的2025年3月星期二补丁更新修复了 6 个正在被积极利用的零日漏洞和 10 个被评估为更有可能被利用的高风险漏洞。此次更新共修复了 57 个微软 CVE，并重新发布了 10 个非微软 CVE，其中包括 9 个 Chrome 漏洞和 1 个 Synaptics 漏洞。  
  
  
六个零日漏洞的严重程度从 4.6 到 7.8（CVSS:3.1）不等，包括：  
- CVE-2025-24983：Windows Win32 内核子系统权限提升漏洞（严重度 7.0）  
  
- CVE-2025-24984：Windows NTFS 信息泄露漏洞（严重度 4.6）  
  
- CVE-2025-24985：Windows Fast FAT 文件系统驱动程序远程代码执行漏洞（严重度 7.8）  
  
- CVE-2025-24991：Windows NTFS 信息泄露漏洞（严重度 5.5）  
  
- CVE-2025-24993：Windows NTFS 远程代码执行漏洞（严重度 7.8）  
  
- CVE-2025-26633：Microsoft 管理控制台安全功能绕过漏洞（严重度 7.0）  
  
  
除了这六个正在被积极利用的零日漏洞外，微软还报告了 10 个 "更有可能" 被利用的漏洞。这些漏洞的严重程度从 4.3 到 8.1 不等，涉及 Windows exFAT 文件系统、远程桌面服务、内核流媒体服务驱动程序等多个组件。安全专家建议用户和组织尽快应用这些补丁，特别是针对零日漏洞和高风险漏洞的修复。同时，也应关注其他供应商发布的补丁更新，以全面保护系统安全。  
  
  
原文链接：  
  
https://thecyberexpress.com/patch-tuesday-march-2025-six-zero-days/  
  
  
  
**网络攻击**  
  
  
  
**新型Ebyte勒索软件来袭，采用先进加密策略攻击Windows用户**  
  
  
近期，复杂新型勒索软件Ebyte正在北美和欧洲地区针对Windows系统发起攻击。自三周前被发现以来，该勒索软件已经入侵了数千个系统，其采用的先进加密策略给安全专家带来了巨大挑战。  
  
  
Ebyte主要通过钓鱼邮件传播，这些邮件包含恶意Office文档，利用最新的Windows漏洞（CVE-2025-0142）。钓鱼邮件伪装成来自可信业务伙伴的发票提醒或发货通知。一旦执行，恶意软件通过注册表修改和计划任务建立持久性，然后禁用安全工具和备份解决方案。勒索软件会在加密前进行全面的系统扫描，优先处理数据库和财务记录等关键业务文件。  
  
  
Ebyte采用了复杂的混合加密系统，结合ChaCha20文件加密和4096位RSA算法，为每个受害者生成唯一的256位密钥。这使得在没有赎金密钥的情况下几乎不可能解密。Ebyte还实施了安全密钥管理系统，为每个文件生成唯一的加密密钥，这些密钥被加密并存储在自定义文件结构中，防止开发通用解密工具。  
  
  
Ebyte要求从5万到200万美元不等的赎金，以Monero加密货币支付。安全专家建议及时修补系统、实施邮件过滤、维护离线备份，并部署高级终端保护以缓解这一新兴威胁。  
  
  
原文链接：  
  
https://cybersecuritynews.com/new-ebyte-ransomware-attacking-windows-users/  
  
  
**WebKit零日漏洞被利用开展“极其复杂”定向攻击，苹果紧急修复**  
  
  
Apple近日发布紧急安全更新，修复了WebKit跨平台网络浏览器引擎中一个零日漏洞（CVE-2025-24201）。该漏洞是一个越界写入问题，已被用于针对特定目标个人的"极其复杂"的网络攻击中。  
  
  
攻击者可利用精心制作的网页内容来突破Web Content沙箱。Apple表示，这是对iOS 17.2中已阻止攻击的补充修复。为解决这一漏洞，Apple通过改进检查机制发布了iOS 18.3.2、iPadOS 18.3.2、macOS Sequoia 15.3.2、visionOS 2.3.2和Safari 18.3.1更新。受影响的设备包括iPhone XS及更新机型、多代iPad Pro、iPad Air、iPad和iPad mini，以及运行macOS Sequoia的Mac和Apple Vision Pro。  
  
  
这是Apple今年修复的第三个零日漏洞。此前，公司在1月修复了影响Core Media框架的权限提升漏洞（CVE-2025-24085），2月修复了可禁用锁定设备上USB限制模式的漏洞（CVE-2025-24200）。  
  
  
尽管Apple未披露攻击细节或归因于任何威胁行为者，但安全专家强烈建议用户立即更新设备，以防范潜在的安全威胁。  
  
  
原文链接：  
  
https://securityaffairs.com/175269/hacking/apple-third-zero-day-2025.html  
  
  
**MirrorFace组织利用Windows内置功能进行APT攻击**  
  
  
日本国家警察厅（NPA）和国家网络安全事件准备和战略中心（NISC）近日发布安全公告，警告APT10旗下的MirrorFace威胁组织正在针对日本组织进行高级持续性威胁（APT）攻击活动。攻击者利用Windows Sandbox和Visual Studio Code执行恶意活动，同时规避主机系统上运行的安全工具的检测。  
  
  
MirrorFace使用了一个定制版的开源Lilith RAT "LilimRAT"，专门设计用于在Windows Sandbox内运行。该恶意软件包含特定代码，通过检查WDAGUtilityAccount用户文件夹的存在来验证其是否在Windows Sandbox内运行。攻击方法包括在目标机器上启用Windows Sandbox，创建自定义WSB配置文件，并在隔离环境中执行恶意软件。攻击者首先需要启用默认禁用的Windows Sandbox功能并重启受感染系统。攻击过程涉及在受感染主机上放置三个关键文件：批处理文件、归档实用程序和包含恶意软件的存档。然后创建一个Windows Sandbox配置（WSB）文件，启用网络连接，共享主机和沙盒环境之间的文件夹，并在登录时执行命令。  
  
  
安全专家建议除非特别需要，否则保持Windows Sandbox禁用状态，监控相关进程，限制管理权限，并在企业环境中实施AppLocker策略以防止未经授权执行Windows Sandbox。  
  
  
原文链接： https://cybersecuritynews.com/mirrorface-apt-hackers-exploited-windows-sandbox-visual-studio-code/#google_vignette  
  
  
  
**安全漏洞**  
  
  
  
**NVIDIA Riva语音AI平台曝高危漏洞，攻击者可提升权限**  
  
  
NVIDIA近日发布了Riva语音AI平台的重要软件更新，版本2.19.0修复了两个高危漏洞。这两个漏洞涉及不当的访问控制机制，影响所有运行Riva 2.18.0及以下版本的Linux部署。  
  
  
其中，CVE-2025-23242漏洞（CVSS 7.3）暴露了系统中的权限提升向量。攻击者可能执行任意代码、操纵实时语音处理管道或从AI推理工作负载中窃取敏感对话日志。其攻击向量（AV:N/AC:L/PR:N/UI:N/S:U）表明可通过网络利用且无需用户交互，对暴露的API端点尤其危险。CVE-2025-23243（CVSS 6.5）可能导致拒绝服务条件或篡改神经机器翻译（NMT）服务的文本规范化输出。两个漏洞都源于Riva微服务架构中gRPC请求头的验证不足。  
  
  
NVIDIA建议立即升级到Riva 2.19.0，该版本引入了增强的基于角色的访问控制（RBAC）策略和强化的gRPC身份验证协议。对于无法立即修补的组织，NVIDIA建议：将Riva服务置于API网关后，实施严格的IP白名单；为所有服务间通信启用相互TLS（mTLS）审核自定义应用中riva-speech-client库的使用。  
  
  
NVIDIA计划在2025年第二季度为Riva模型存储库引入自动漏洞扫描，作为其增强安全路线图的一部分。  
  
  
原文链接：  
  
https://cybersecuritynews.com/nvidia-riva-vulnerabilities/  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkAibeib6HUSIXJ4IhpazTYic3uwicySgIEk8ZeMC7X5evYXoNPHxoUlibqgo6Ilq0dRkGrMKibWtfcibYwsg/640?wx_fmt=jpeg "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
