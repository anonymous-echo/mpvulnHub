#  量子计算破解RSA加密难度降低20倍，后量子密码学迫在眉睫；国家网络安全通报中心提醒：ComfyUI存在多个高危漏洞 | 牛览   
 安全牛   2025-05-27 08:54  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**新闻速览**  
  
  
  
•国家网络安全通报中心提醒：ComfyUI存在多个高危漏洞  
  
•国家互联网应急中心提醒防范 “游蛇”黑产攻击活动的风险  
  
•量子计算破解RSA加密难度降低20倍，后量子密码学迫在眉睫  
  
•SilverRAT远控木马源代码泄露，安全专家警告风险激增  
  
•合法远程访问工具成为网络攻击新宠，ConnectWise ScreenConnect使用率最高  
  
•开源生态系统告急：超70个恶意npm和VS Code包被发现窃取数据和加密货币  
  
•CISA警告Commvault零日漏洞成为更广泛SaaS攻击活动的一部分  
  
•Zimbra协作套件XSS漏洞被武器化，影响全球超12.9万服务器  
  
•PoC代码已被公开，专家敦促尽快修补Fortinet严重漏洞  
  
  
  
**特别关注**  
  
  
  
**国家网络安全通报中心提醒：ComfyUI存在多个高危漏洞**  
  
  
国家网络安全通报中心5月27日发布微信公众号文章，提醒ComfyUI存在多个高危漏洞。  
  
  
ComfyUI是一款AI绘图工具，专为图像生成任务设计，通过将深度学习模型的工作流程简化为图形化节点，使用户操作更加直观和易于理解。近期，北京市网络与信息安全信息通报中心发现，ComfyUI存在任意文件读取、远程代码执行等多个历史高危漏洞（CVE-2024-10099、CVE-2024-21574、CVE-2024-21575、CVE-2024-21576、CVE-2024-21577），攻击者可利用上述漏洞实施远程代码执行攻击，获取服务器权限，进而窃取系统数据。目前已有境外黑客组织利用ComfyUI漏洞对我网络资产实施网络攻击，伺机窃取重要敏感数据。  
  
  
建议相关用户在确保安全的前提下，及时下载升级官方补丁堵塞漏洞，同时做好类似人工智能大模型应用的安全加固，确保网络和数据安全，发现遭攻击情况第一时间向当地公安机关报告。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/hqnxF5J3RDmleRdjULPnKw  
  
  
**国家互联网应急中心提醒：防范 “游蛇”黑产攻击活动的风险**  
  
  
国家互联网应急中心（CNCERT）与安天科技集团股份有限公司近期联合监测发现，"游蛇"黑产团伙（又名"银狐"、"谷堕大盗"、"UTG-Q-1000"等）组织活动频繁，通过搜索引擎SEO推广手段伪造Chrome浏览器下载站进行攻击。这些钓鱼网站与正版官网高度相似，极具迷惑性。  
  
  
攻击者搭建多个以"Chrome浏览器"为诱饵的钓鱼网站，诱导用户下载名为"chromex64.zip"的恶意安装包。该安装包包含一个文件解压程序和一个正常的dll文件。安装后，程序会在C:\Chr0me_12.1.2目录释放旧版Chrome浏览器相关文件，并在桌面创建伪装的Chrome快捷方式。实际上，该快捷方式启动的是恶意文件，采用dll侧加载形式执行，在内存中解密并执行shellcode，最终加载Gh0st远控木马家族变种。  
  
  
该木马连接C2地址duooi.com:2869等多个域名，攻击者基于任务持续注册新域名并更换IP地址。通过监测分析，2025年4月23日至5月12日期间，该黑产团伙使用的Gh0st远控木马日上线肉鸡数最高达到1.7万余台，C2日访问量最高达到4.4万条，累计已有约12.7万台设备受其感染。  
  
  
防范建议包括：通过官方网站下载正版软件；不打开来历不明的链接；加强口令强度；及时修复系统漏洞；安装终端防护软件；发现感染后立即清理受害主机。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/Rx9MVhztkfGHQkcuXcxiMg  
  
  
  
**热点观察**  
  
  
  
**量子计算破解RSA加密难度降低20倍，后量子密码学迫在眉睫**  
  
  
根据Google Quantum AI的最新研究，一台拥有100万噪声量子比特的量子计算机只需运行一周即可理论上破解RSA-2048位加密，所需量子比特数量比Google 2019年的估计减少了20倍。这一发现大大缩短了当前加密标准可能被攻破的时间表，迫使企业加速采用后量子密码学(PQC)。  
  
  
研究人员Craig Gidney和Sophie Schmieg指出，三项技术突破显著降低了实际密码学威胁的门槛：更高效的算法、先进的错误校正和优化的量子操作。具体而言，团队采用了2024年的近似模幂方法，将开销从1000倍降至仅2倍；通过分层错误校正将逻辑量子比特密度提高了3倍；并引入"魔法态培养"来简化量子处理过程。  
  
  
对于安全领导者，研究强调了两个紧迫优先事项：首先，使用RSA或类似算法的加密通信面临"现在存储，以后解密"的风险；其次，数字签名实施带来更复杂的挑战，尤其是嵌入在硬件安全模块中或设计为多年使用的签名密钥。  
  
  
NIST建议的时间表：到2030年弃用易受攻击的算法，到2035年完全移除，现在看来越来越确定。安全团队应采取具体步骤，包括加密审计以识别最脆弱的系统，优先考虑包含敏感长期数据的高价值资产的过渡计划，并与技术供应商讨论其后量子实施路线图。  
  
  
原文链接：  
  
https://www.csoonline.com/article/3995036/breaking-rsa-encryption-just-got-20x-easier-for-quantum-computers.html  
  
  
**SilverRAT远控木马源代码泄露，安全专家警告风险激增**  
  
  
近日，臭名昭著的远程访问木马SilverRAT完整源代码在GitHub上短暂泄露，虽然该仓库"SilverRAT-FULL-Source-Code"很快被删除，但已被安全研究人员通过Wayback Machine存档。此次泄露包含了完整项目代码、功能列表、构建说明及控制面板截图。  
  
  
SilverRAT是一款用C#开发的远控木马，于2023年底首次出现，据信由叙利亚的"Anonymous Arabic"组织开发。该工具在地下论坛中作为恶意软件即服务(MaaS)出售，具备多种强大功能，包括：加密货币钱包监控、隐藏应用和进程、通过Discord webhooks窃取数据、多种文件类型的漏洞利用生成器、反病毒绕过、隐藏RDP和VNC会话，以及从浏览器、应用、游戏、银行卡、Wi-Fi和系统凭证中窃取密码等。  
  
  
此次泄露的GitHub仓库由用户Jantonzz发布，声称分享"最新版本"的SilverRAT。项目包含Visual Studio解决方案文件、构建说明和代码模块，任何具备基本.NET知识的人都能轻松编译。尽管仓库描述声称该工具"仅供学习和实验目的"，但其武器化功能清单明显指向犯罪应用。  
  
  
安全专家警告，尽管泄露的恶意软件源代码常打着"教育目的"的幌子，但实际上这类泄露会助长网络犯罪。现在，即使是缺乏编程技能的低级网络犯罪分子也能编译自己的副本、修改恶意软件或创建新变种，显著扩大了该恶意软件的影响范围。  
  
  
原文链接：  
  
https://hackread.com/silverrat-source-code-leaked-online-you-need-to-know/  
  
  
**合法远程访问工具成为网络攻击新宠，ConnectWise ScreenConnect使用率最高**  
  
  
Cofense Intelligence最新发布的报告揭示了一个令人担忧的网络攻击趋势：网络犯罪分子正越来越多地劫持合法远程访问工具(RATs)来入侵计算机系统。与专为黑客设计的恶意软件不同，这些工具本是为合法目的而构建，通常被企业IT专业人员使用。其合法性使它们特别危险，能够绕过传统安全措施和用户警惕。  
  
  
ConnectWise ScreenConnect(前身为ConnectWise Control和ScreenConnect)成为2024年攻击者最青睐的选择，在涉及合法RATs的活跃威胁报告中占比56%。该工具在2025年的使用率继续攀升，目前的攻击量已与去年全年持平。另一款工具FleetDeck在2024年夏季使用率激增，主要针对德语和法语用户，使用金融主题诱饵。  
  
  
攻击者采用多种方法诱骗受害者安装这些工具。对于ConnectWise ScreenConnect，典型攻击包括冒充美国社会保障管理局发送虚假福利声明更新邮件。这些邮件通常包含指向假PDF文件或直接链接到RAT安装程序的链接。自2025年2月5日以来，另一种策略是伪装成"filesfm"共享文件通知，诱导受害者下载看似合法的OneDrive客户端，实际上是ConnectWise RAT安装程序。  
  
  
其他被滥用的合法RATs还包括Atera、LogMeIn Resolve、Gooxion RAT、PDQ Connect、Mesh Agent、N-Able和Teramind等。获取这些工具的便捷性和低成本使攻击者能够快速在不同工具间切换，对网络安全防护构成持续挑战。  
  
  
原文链接：  
  
 https://hackread.com/connectwise-screenconnect-tops-abused-rats-2025/  
  
  
**网络攻击**  
  
  
  
**开源生态系统告急：超70个恶意npm和VS Code包被发现窃取数据和加密货币**  
  
  
安全研究人员近期发现了大量恶意软件包在开源生态系统中传播，这些包主要针对npm注册表和VS Code扩展市场，目的是窃取敏感数据和加密货币凭证。这些发现显示了攻击者利用开发者信任来分发恶意代码，同时凸显了开源软件供应链安全的重要性。  
  
  
在npm平台上，研究人员发现了60个恶意包，这些包由三个不同账户发布，总下载量超过3000次。这些恶意包会在安装时触发脚本，收集主机名、IP地址、DNS服务器和用户目录等信息，并将数据发送到Discord控制端点。Socket安全研究人员指出，这些代码专门设计用于对安装包的每台机器进行指纹识别，如果检测到在亚马逊、谷歌等虚拟化环境中运行，则会中止执行。  
  
  
另外，研究人员还发现了8个伪装成React、Vue.js等流行JavaScript框架辅助库的恶意npm包已被下载超过6200次，这些包一旦安装就会部署破坏性负载。  
  
  
在VS Code市场中，Datadog安全研究团队发现了三个针对Solidity开发者的恶意扩展（solaibot、among-eth和blankebesxstnion），这些扩展伪装成合法工具，但实际上会窃取加密货币钱包凭证。攻击者使用复杂的感染链，包括利用存储在Internet Archive上的图像文件中隐藏的恶意负载。  
  
  
原文链接：  
  
https://thehackernews.com/2025/05/over-70-malicious-npm-and-vs-code.html  
  
  
**CISA警告Commvault零日漏洞成为更广泛SaaS攻击活动的一部分**  
  
  
美国网络安全和基础设施安全局(CISA)近日发布警告，威胁行为者正在滥用Commvault的SaaS云应用程序Metallic，以访问其客户的关键应用程序密钥。这一攻击凸显了允许第三方对组织环境进行特权访问所涉及的风险，以及攻击者正从基于端点和网络的攻击转向利用权限过高的SaaS环境和配置错误的云应用程序。  
  
  
攻击者可能通过零日漏洞(CVE-2025-3928)获取了Commvault托管在Microsoft Azure上的Metallic Microsoft 365(M365)备份解决方案中的客户端密钥。这进而使他们能够未经授权访问那些由Commvault存储应用程序密钥的客户M365环境。今年2月，Microsoft曾警告Commvault上一个高危漏洞影响Commvault Web服务器，并且一个国家级黑客组织正积极利用它来访问Azure环境。这个漏洞允许攻击者在被入侵的环境中创建和执行webshell。CISA怀疑对CVE-2025-3928的利用是更广泛攻击活动的一部分，该活动针对具有默认设置和高级权限的SaaS应用程序。根据Commvault的调查，国家级攻击者通过零日漏洞获取了某些Commvault客户用于验证其M365环境的应用程序凭证子集。  
  
  
Commvault已在收到Microsoft警告后迅速修复了该漏洞，修复程序已在Commvault版本11.36.46、11.32.89、11.28.141和11.20.217中推出。CISA建议组织立即应用补丁并采取额外缓解措施，包括监控和审查Microsoft Entra审计日志、实施条件访问策略以限制单租户应用程序内的身份验证，以及轮换Commvault Metallic应用程序上的应用程序密钥和凭证。  
  
  
原文链接：  
  
https://www.csoonline.com/article/3994999/cisa-flags-commvault-zero-day-as-part-of-wider-saas-attack-campaign.html  
  
  
**Zimbra协作套件XSS漏洞被武器化，影响全球超12.9万服务器**  
  
  
Zimbra协作套件(ZCS)近日被发现存在一个严重安全漏洞（CVE-2024-27443），该漏洞已被列入CISA已知被利用漏洞(KEV)目录，并疑似被黑客组织Sednit(又称APT28或Fancy Bear)积极利用中。  
  
  
这个中等严重级别(CVSS评分6.1)的跨站脚本(XSS)漏洞存在于Zimbra经典Web客户端界面的CalendarInvite功能中。漏洞产生的原因是系统未能正确验证电子邮件日历头部中的传入信息，从而创造了存储型XSS攻击的可能性。攻击者可以在精心设计的电子邮件中嵌入恶意代码，当用户通过经典Zimbra界面打开这封邮件时，恶意代码会在其Web浏览器中自动执行，使攻击者能够访问用户会话。受影响的版本包括ZCS 9.0(补丁1-38)和10.0(直至10.0.6)。  
  
  
根据网络安全洞察公司Censys的数据，截至2025年5月22日，全球共有129131个潜在易受攻击的ZCS实例暴露在互联网上，大多数托管在云服务中。此外，还发现了33614个通常与共享基础设施相关的本地Zimbra主机。安全研究公司ESET表示，著名黑客组织Sednit可能正在利用此漏洞作为其"RoundPress行动"的一部分，该行动旨在窃取登录凭据并维持对网络邮件平台的访问权限。  
  
  
Zimbra已在ZCS 10.0.7版本和9.0.0补丁39中修复了这个问题。安全专家强烈建议用户立即将其Zimbra协作套件更新到这些已修补版本。  
  
   
  
原文链接：  
  
https://hackread.com/zimbra-cve-2024-27443-xss-flaw-hit-sednit-servers/  
  
  
**网络攻击**  
  
  
  
**PoC代码已被公开，专家敦促尽快修补Fortinet严重漏洞**  
  
  
安全研究人员近日公开了针对Fortinet产品中严重安全漏洞（CVE-2025-32756）的概念验证(PoC)代码，该漏洞目前正被黑客积极利用。这一基于栈的缓冲区溢出漏洞允许未经身份验证的远程代码执行，影响多款Fortinet产品，包括FortiMail、FortiCamera、FortiNDR、FortiRecorder和FortiVoice。  
  
  
Fortinet产品安全团队基于观察到的威胁活动发现了这一漏洞，这些活动包括网络扫描、凭证记录和日志文件擦除。该漏洞位于共享库中，与系统处理名为APSCOOKIE的会话管理cookie有关，特别是解码和处理该cookie中AuthHash字段的问题。这一漏洞允许远程未认证攻击者通过精心构造的HTTP请求执行任意代码或命令。从技术角度看，这是一个管理API中的漏洞，系统试图将过多数据塞入有限空间，导致数据溢出到不应该的区域，使攻击者能够注入恶意代码  
。  
  
  
该漏洞已于5月14日被添加到CISA已知被利用漏洞(KEV)目录中。鉴于攻击者已在利用此漏洞，且许多易受攻击的Fortinet系统暴露在互联网上，专家强烈建议所有用户尽快更新产品或应用推荐的修复方案。如无法立即修补，可考虑禁用HTTP/HTTPS管理接口作为临时缓解措施。  
  
  
原文链接：  
  
https://hackread.com/researchers-poc-fortinet-cve-2025-32756-quick-patch/  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkAibeib6HUSIXJ4IhpazTYic3uwicySgIEk8ZeMC7X5evYXoNPHxoUlibqgo6Ilq0dRkGrMKibWtfcibYwsg/640?wx_fmt=jpeg "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
  
