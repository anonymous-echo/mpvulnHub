#  网安瞭望台第10期：开源机器学习框架存在漏洞、GammaDrop 恶意软件   
原创 扬名堂  东方隐侠安全团队   2024-12-07 13:35  
  
网安资讯分享  
  
DAILY NEWS AND KNOWLEDGE  
  
  新鲜资讯&知识 抢先了解    
  
隐侠安全客栈  
  
**国内外要闻**  
  
  
**研究人员发现流行开源机器学习框架存在漏洞**  
  
      
网络安全研究人员披露了多个影响开源机器学习（ML）工具和框架（如 MLflow、H2O、PyTorch 和 MLeap）的安全漏洞，这些漏洞可能导致代码执行。这些漏洞由 JFrog 发现，是该供应链安全公司上个月首次披露的 22 个安全缺陷的一部分。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGVG5IDw43AhMz705n8maqnJHF2Th47At54ksfu8icpZUpDllciaTicaAlQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    与第一批涉及服务器端漏洞的缺陷不同，新发现的漏洞存在于处理 SafeTensors 等安全模型格式的库中，可被用于攻击 ML 客户端。该公司表示：“劫持组织中的 ML 客户端可能使攻击者在组织内进行广泛的横向移动。ML 客户端很可能有权访问重要的 ML 服务，如 ML 模型注册中心或 MLOps 管道。” 这进而可能会暴露模型注册凭证等敏感信息，实际上允许恶意行为者在存储的 ML 模型中植入后门或实现代码执行。  
  
    具体漏洞如下：  
1. CVE - 2024 - 27132（CVSS 评分：7.2）：MLflow 中存在净化不充分问题，在 Jupyter Notebook 中运行不受信任的配方时会导致跨站脚本（XSS）攻击，最终导致客户端远程代码执行（RCE）。  
  
1. CVE - 2024 - 6960（CVSS 评分：7.5）：H2O 在导入不受信任的 ML 模型时存在不安全的反序列化问题，可能导致 RCE。  
  
1. PyTorch 的 TorchScript 功能存在路径遍历问题，可能因任意文件覆盖导致拒绝服务（DoS）或代码执行，可用于覆盖关键系统文件或合法的 pickle 文件（无 CVE 标识符）。  
  
1. CVE - 2023 - 5245（CVSS 评分：7.5）：MLeap 在加载压缩格式的保存模型时存在路径遍历问题，可能导致 Zip Slip 漏洞，造成任意文件覆盖和潜在的代码执行。  
  
    JFrog 指出，即使是从 SafeTensors 等安全类型加载 ML 模型，也不应盲目加载，因为它们有可能实现任意代码执行。JFrog 安全研究副总裁 Shachar Menashe 在一份声明中表示：“人工智能和机器学习（ML）工具具有巨大的创新潜力，但也可能为攻击者打开大门，对任何组织造成广泛损害。为防范这些威胁，重要的是要了解正在使用的模型，即使是从‘安全’的 ML 存储库中也绝不要加载不受信任的 ML 模型。在某些情况下，这样做可能导致远程代码执行，对组织造成广泛伤害。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGQAvicCKbHFkBDEYJtDAIVAPicKLZMM4ZgrBvicXc80DpDbq6pV2qkza5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**黑客利用 Cloudflare 隧道和 DNS 快速变换隐藏 GammaDrop 恶意软件**  
  
      
已知的威胁行为体 Gamaredon 被发现利用 Cloudflare 隧道来隐藏托管 GammaDrop 恶意软件的中转基础设施。Recorded Future 的 Insikt Group 在一项新分析中表示，这种活动是自 2024 年初以来针对乌克兰实体的持续性鱼叉式网络钓鱼活动的一部分，其目的是投放 Visual Basic Script 恶意软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGRnAjwYibWpESaH4PVyicCSbf0kr0steyGyia2tR4qqibA2iclRh6nQQTrHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    网络安全公司将该威胁行为体追踪为 BlueAlpha，它还有 Aqua Blizzard、Armageddon、Hive0051、Iron Tilden、Primitive Bear、Shuckworm、Trident Ursa、UAC - 0010、UNC530 和 Winterflounder 等别名。该组织据信自 2014 年起就处于活跃状态，与俄罗斯联邦安全局（FSB）有关联。  
  
    Insikt Group 指出：“BlueAlpha 最近开始使用 Cloudflare 隧道来隐藏 GammaDrop 所使用的中转基础设施，这是网络犯罪威胁团体用来部署恶意软件的一种日益流行的技术。BlueAlpha 还继续对 GammaLoad 命令与控制（C2）基础设施使用域名系统（DNS）快速变换，以使对 C2 通信的跟踪和阻断变得复杂，从而保持对受感染系统的访问。”  
  
    斯洛伐克网络安全公司 ESET 在 2024 年 9 月就记录了该威胁行为体对 Cloudflare 隧道的使用，这是针对乌克兰和北约多个国家（包括保加利亚、拉脱维亚、立陶宛和波兰）攻击的一部分。ESET 还指出，该威胁行为体的作案手法较为鲁莽，并不特别注重隐蔽性，尽管他们努力 “避免被安全产品拦截并极力维持对受感染系统的访问”。Gamaredon 试图通过同时部署多个简单下载器或后门来维持其访问权限。其工具缺乏复杂性，但通过频繁更新和使用不断变化的混淆手段来弥补。  
  
    这些工具主要用于从互联网浏览器、电子邮件客户端和即时通讯应用程序（如 Signal 和 Telegram）内运行的网络应用程序中窃取有价值的数据，以及下载额外的有效载荷并通过连接的 USB 驱动器传播恶意软件。  
  
Recorded Future 强调的最新一轮攻击包括发送带有 HTML 附件的钓鱼邮件，这些附件利用 HTML 走私技术通过嵌入的 JavaScript 代码激活感染过程。当 HTML 附件被打开时，会释放一个 7 - Zip 压缩文件（“56 - 27 - 11875.rar”），其中包含一个恶意 LNK 文件，该文件利用 mshta.exe 来传递 GammaDrop，这是一个负责将名为 GammaLoad 的自定义加载器写入磁盘的 HTA 释放器，随后 GammaLoad 与 C2 服务器建立联系以获取更多恶意软件。GammaDrop 文件从位于 amsterdam - sheet - veteran - aka.trycloudflare [.] com 域名上的 Cloudflare 隧道后的中转服务器获取。GammaLoad 在传统 DNS 失效时利用谷歌和 Cloudflare 等 DNS - over - HTTPS（DoH）提供商来解析 C2 基础设施。如果首次与服务器通信失败，它还会采用快速变换 DNS 技术来获取 C2 地址。  
  
    Recorded Future 表示：“BlueAlpha 可能会继续通过利用像 Cloudflare 这样广泛使用的合法服务来完善逃避检测技术，这将使传统安全系统的检测变得更加复杂。对 HTML 走私和基于 DNS 的持久性技术的持续改进可能会带来不断演变的挑战，特别是对于威胁检测能力有限的组织而言。”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGAEmvABooiatd2CZyy2UxCfQeRiciaM2v6VKaCYwIEVkORZCQQdPObcDpw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**More_eggs MaaS 借助 RevC2 后门与 Venom 加载器扩张业务**  
   
  
      
More_eggs 恶意软件背后的威胁行为体与两个新的恶意软件家族有关联，这表明其恶意软件即服务（MaaS）业务有所扩张。其中包括一种名为 RevC2 的新型信息窃取后门和一个代号为 Venom Loader 的加载器，两者均通过 VenomLNK 进行部署，VenomLNK 是一种主要工具，作为后续有效载荷部署的初始访问向量。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGWlbry7xykAtFOdaNXEaEAxBQFZYic48dVmTN8sYRIYkhOcmNOuOrSKQ/640?wx_fmt=png&from=appmsg "")  
  
    Zscaler ThreatLabz 研究员 Muhammed Irfan V A 表示：“RevC2 使用 WebSockets 与它的命令与控制（C2）服务器进行通信。该恶意软件能够窃取 Cookie 和密码、代理网络流量并实现远程代码执行（RCE）。Venom Loader 是一种新的恶意软件加载器，它为每个受害者定制，使用受害者的计算机名对有效载荷进行编码。”  
  
    这两个恶意软件家族都是在该网络安全公司于 2024 年 8 月至 10 月期间观察到的活动中被分发的。该电子犯罪产品背后的威胁行为体被追踪为 Venom Spider（又名 Golden Chickens）。目前确切的分发机制尚不清楚，但其中一个活动的起点是 VenomLNK，它除了显示一个 PNG 诱饵图像外，还会执行 RevC2。该后门能够从 Chromium 浏览器窃取密码和 Cookie、执行 shell 命令、截取屏幕截图、使用 SOCKS5 代理流量以及以不同用户身份运行命令。  
  
    第二个活动同样以 VenomLNK 开始，用于传递诱饵图像，同时秘密执行 Venom Loader。该加载器负责启动 More_eggs lite，这是 JavaScript 后门的一个轻量级变体，仅提供 RCE 功能。  
  
    新的发现表明，尽管去年来自加拿大和罗马尼亚的两名个人被揭露运营该 MaaS 平台，但恶意软件作者仍在继续用新的恶意软件更新和完善他们的定制工具集。此次披露正值 ANY.RUN 详细介绍一种此前未记录的无文件加载器恶意软件 PSLoramyra，该软件已被用于投递开源的 Quasar RAT 恶意软件之际。ANY.RUN 称：“这种先进的恶意软件利用 PowerShell、VBS 和 BAT 脚本来将恶意有效载荷注入系统，在内存中直接执行它们，并建立持久访问。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGiaLXiabcRUSZia4yOaffHv4HgS05WzReuibpbnTaYCfyHV1Xic1iaqcARZDA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识分享**  
  
  
《东方隐侠网络安全指导课》序章 1.网络安全基础概论  
  
    东方隐侠为提升少侠们的安全技能，带领更多人加入网安武林，并为以后从粉丝群体中持续选拔正式成员，发布《东方隐侠网络安全指导课》，从2024年12月5日开始陆续更新课程中，暂未上架，敬请期待。     
  
    课程大纲为：  
  
**一、网络安全基础概论**  
1. 网络安全的定义与范畴  
  
1. 网  
络安全在数字化时代的重要性  
  
1. 网  
络安全事故案例剖析  
  
**二、网络安全基础知识**  
1. API 测试方法（黑盒、白盒、灰盒测试应用）  
  
1. API 测试工具（Postman、SoapUI 等使用）  
  
1. API 安全漏洞类型与应对策略  
  
**三、Web 漏洞知识与攻击剖析**  
1. GraphQL API vulnerabilities（GraphQL API 漏洞）  
  
1. Cross-origin resource sharing (CORS)（跨域资源共享）  
  
1. SQL injection（SQL 注入）  
  
1. NoSQL injection（NoSQL 注入）  
  
1. CSRF（跨站请求伪造）  
  
1. Clickjacking (UI redressing)（点击劫持）  
  
1. Server-side vulnerabilities（服务器端漏洞）  
  
1. File upload vulnerabilities（文件上传漏洞）  
  
1. Path traversal（路径遍历）  
  
1. WebSockets vulnerabilities（WebSockets 漏洞）  
  
1. Web cache deception（Web 缓存欺骗）  
  
**四、常见程序缺陷与防御策略进阶**  
1. Race conditions（竞争条件）  
  
1. Authentication vulnerabilities（认证漏洞）  
  
1. Server-side request forgery (SSRF) attacks（服务器端请求伪造攻击）  
  
1. Logical Vulnerability（逻辑漏洞）  
  
**五、新兴与特定场景安全威胁应对**  
1. Web LLM attacks（Web 大语言模型攻击）  
  
1. Prototype pollution（原型污染）  
  
1. ……  
  
**六、企业网络安全运营**  
1. 企业网络安全架构与策略规划  
  
1. 网络安全监控与应急响应机制  
  
1. 企业网络安全合规性管理  
  
1. 网络安全团队建设与人员培训要点  
  
  
  
知识大陆：内部交流群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4KWicH7M2NcAgNUJdibJ9CFGdhWeFkycicJF6LAVib76109ICK9C1icqchxnEArWt9G0z0ibdNPwZetibGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
