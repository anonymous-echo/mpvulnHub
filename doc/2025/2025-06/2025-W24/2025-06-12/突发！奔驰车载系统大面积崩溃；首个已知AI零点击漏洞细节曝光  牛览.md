#  突发！奔驰车载系统大面积崩溃；首个已知AI零点击漏洞细节曝光 | 牛览  
 安全牛   2025-06-12 09:40  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**新闻速览**  
  
  
  
•突发！奔驰车载系统大面积崩溃  
  
•内存泄漏漏洞意外曝光MaaS组织DanaBot内部运作  
  
•650个IP联合暴力攻击瞄准Apache Tomcat管理面板  
  
•Erie保险确认遭受网络攻击，导致业务中断  
  
•Salesforce Industry Cloud曝出20个安全漏洞，包含多个零日漏洞  
  
•Apache CloudStack多个严重漏洞允许攻击者执行特权操作  
  
•**首个已知AI零点击漏洞细节曝光**  
  
•研究揭示："SmartAttack"攻击可用智能手表突破物理隔离防线  
  
•SinoTrack GPS设备存在严重安全漏洞，可被远程控制车辆  
  
  
  
**热点观察**  
  
  
  
**突发！奔驰车载系统大面积崩溃，导航、CarPlay功能失效**  
  
  
6月12日上午，多名奔驰用户反映奔驰系统疑似崩溃，车载大屏导航等功能无法正常使用，车载大屏显示“请插入带地图内容的数据载体以启用导航”字样。除了导航功能无法使用外，还有车主反映音乐和CarPlay等功能也存在问题。  
  
  
有车主表示收到了奔驰的短信，称“由于Mercedes-me后台临时出现故障，导致导航、CARPLAY等多个功能出现无法使用，或类似导航无法显示或没有导航图标。我们奔驰厂家正在加急修复，给您带来不便，敬请谅解！预计今天中午可以恢复使用。”12日下午，记者询问奔驰客服，对方表示有部分车辆的数字化产品和服务功能受到影响，正在紧急排查和修复，但尚未得到何时修复的通知。  
  
  
奔驰4S店一工作人员表示，应该是后台软件的问题，从早上到现在，好多客户都反映导航没法使用，厂家正在紧急处理中，还没有处理好。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/4RaT7YYR_tytH-yACsIdXQ  
  
  
**内存泄漏漏洞意外曝光MaaS组织DanaBot内部运作**  
  
  
安全研究人员发现，臭名昭著的恶意软件即服务(MaaS)组织DanaBot在近三年时间里一直存在一个内存泄漏缺陷"DanaBleed"，导致其命令与控制(C2)服务器持续泄露敏感数据。ThreatLabz发现并监控了这一漏洞，这使研究人员能够前所未有地深入了解DanaBot的内部基础设施、运营和附属组织。  
  
  
DanaBot自2018年首次被发现以来，一直是网络犯罪领域的持续威胁，提供银行凭证窃取、信息窃取等服务，甚至参与DDoS攻击和供应链入侵。DanaBot采用联盟模式运营：开发者负责创建恶意软件、维护命令与控制(C2)基础设施并提供运营支持。其MaaS模式吸引了广泛的客户群。随着2022年6月2380版本的发布，DanaBot开发者对恶意软件的C2协议进行了更改，并意外引入了一个灾难性错误：未初始化的内存被添加到每个C2响应的数据缓冲区中，有效地将高达1,792字节的服务器内存泄露给受感染的客户端。  
  
  
ThreatLabz的研究人员利用这一漏洞提取了大量有价值的情报，包括：威胁行为者用户名和IP地址、C2服务器域名和IP、感染和数据窃取指标、私有加密密钥、恶意软件版本更新日志、受害者凭证和IP、SQL语句和调试日志和C2网络界面的HTML代码片段。最具揭示性的证据包括与DanaBot地下营销材料中发现的宣传内容相匹配的截图和HTML片段，以及显示感染统计数据和数据窃取命令的SQL转储。  
  
  
这一泄漏为安全研究人员提供了了解全球网络犯罪集团运营和财务后台的窗口，也为执法部门提供了关键信息，最终支持了"终局行动"(Operation Endgame)，该行动于2025年5月拆除了DanaBot的基础设施并起诉了16名个人。  
  
  
原文链接：  
  
https://securityonline.info/danableed-flaw-exposes-danabots-inner-workings-for-three-years/  
  
  
**研究揭示："SmartAttack"攻击可用智能手表突破物理隔离防线**  
  
  
以色列大学研究人员发现了一种名为"SmartAttack"的新型攻击方法，该方法利用智能手表作为隐蔽的超声波信号接收器，从物理隔离(air-gapped)系统中窃取数据。  
  
  
物理隔离系统通常部署在政府设施、武器平台和核电站等关键环境中，它们与外部网络物理隔离，以防止恶意软件感染和数据盗窃。SmartAttack由隐蔽攻击渠道领域的专家Mordechai Guri领导的研究团队开发。该攻击方法需要恶意软件首先感染隔离计算机以收集敏感信息，如按键、加密密钥和凭证。然后，它可以使用计算机内置扬声器向环境发射超声波信号。通过使用二进制频移键控(B-FSK)，音频信号频率可以被调制为表示二进制数据，即1和0。18.5 kHz的频率代表"0"，而19.5 kHz代表"1"。这个频率范围对人类来说是不可听见的，但附近人员佩戴的智能手表麦克风可以捕捉到。智能手表中的声音监控应用程序应用信号处理技术来检测频率变化并解调编码信号。最终数据可通过Wi-Fi、蓝牙或蜂窝连接进行窃取。  
  
  
防范SmartAttack的最佳方法是禁止在安全环境中使用智能手表，或从隔离机器中移除内置扬声器。如果这些措施不可行，超声波干扰、基于软件的防火墙和音频隔离仍然可能有效。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/smartattack-uses-smartwatches-to-steal-data-from-air-gapped-systems/  
  
  
  
**网络攻击**  
  
  
  
**650个IP联合暴力攻击瞄准Apache Tomcat管理面板**  
  
  
网络安全公司GreyNoise近日发现，一场协调的暴力破解攻击正在针对暴露在互联网上的Apache Tomcat Manager接口。这些攻击从6月5日开始，使用了近650个独特IP地址，大部分已被标记为恶意地址。  
  
  
Apache Tomcat是一款广泛应用于大型企业和SaaS提供商的开源Web服务器，而Tomcat Manager是随服务器捆绑的基于Web的管理工具，允许管理员通过图形界面管理已部署的Web应用。默认情况下，Tomcat Manager仅允许本地访问(127.0.0.1)，没有预配置凭证，且远程访问被阻止。然而，一旦暴露在互联网上，该应用就可能成为攻击目标。  
  
  
GreyNoise观察到两个协调的攻击活动：第一个使用近300个独特IP地址尝试登录暴露的Tomcat服务；第二个则利用250个恶意IP对Tomcat Manager进行暴力破解，攻击者使用自动化工具测试成千上万种可能的凭证组合。虽然这些攻击未针对特定漏洞，但凸显了对暴露Tomcat服务的持续兴趣。  
  
  
GreyNoise建议拥有Tomcat Manager的组织确保强认证和访问限制，检查安全日志中的可疑登录活动，并及时阻止可能尝试入侵的IP地址。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/brute-force-attacks-target-apache-tomcat-management-panels/  
  
  
**Erie保险确认遭受网络攻击，导致业务中断**  
  
  
Erie保险和Erie Indemnity赔偿公司近日确认，自6月7日（周六）以来的广泛业务中断和平台故障是由网络攻击引起的。  
  
  
Erie赔偿公司是Erie保险集团的管理公司，该集团是一家拥有超过600万有效保单的财产和意外伤害保险公司，通过独立代理商提供汽车、房屋、人寿和商业保险服务。自上6月7日以来，Indemnity保险遭遇了大范围的系统故障和业务中断，客户无法登录客户门户网站，并报告难以提交理赔或接收公司文件。该公司表示正与执法部门合作，并在领先网络安全专家的协助下进行全面的取证分析，以充分了解此事件。当公司遭受网络攻击时，通常的响应是关闭系统以防止攻击扩散到其他设备，但这也会中断用于开展业务的应用程序和网站。  
  
  
Erie保险还警告客户，在此次停机期间，公司不会通过电话或电子邮件要求客户付款，并建议客户不要点击来自未知来源的链接或通过电话或电子邮件提供个人信息。该公司尚未分享有关这是否为勒索软件攻击或数据是否在入侵期间被窃取的信息。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/erie-insurance-confirms-cyberattack-behind-business-disruptions/  
  
  
  
**安全漏洞**  
  
  
  
**Salesforce Industry Cloud曝出20个安全漏洞，包含多个零日漏洞**  
  
  
安全研究公司AppOmni近日发现Salesforce Industry Cloud产品中存在超过20个安全漏洞，其中包括多个被评为高风险的零日漏洞，对用户构成严重威胁。  
  
  
Salesforce Industry Cloud旨在帮助医疗、金融和电信等行业快速构建定制解决方案，其低代码开发方式虽提高效率，但也增加了用户安全配置的责任。AppOmni的研究发现，基本设置错误和不安全实践可能导致未授权访问加密数据、会话劫持以及登录凭证和业务信息泄露。这些安全问题影响Salesforce的FlexCards、Data Mappers和Integration Procedures等核心组件。例如，CVE-2025-43697可能在Data Mapper中暴露加密信息；FlexCard漏洞包括字段级安全被忽略(CVE-2025-43698)、绕过所需权限(CVE-2025-43699)、未授权用户查看加密数据(CVE-2025-43700)和自定义设置数据暴露(CVE-2025-43701)。  
  
  
Salesforce已与AppOmni合作解决部分问题。此次发现的五个关键漏洞中有三个已修复，两个需要客户采取行动解决；另有16个配置风险仍需客户自行修复。AppOmni已  
  
  
原文链接：  
  
https://hackread.com/salesforce-industry-cloud-20-vulnerabilities-0days/  
  
  
**Apache CloudStack多个严重漏洞允许攻击者执行特权操作**  
  
  
Apache CloudStack平台多个流行版本中存在严重安全漏洞，可能允许攻击者执行特权操作并危害云基础设施系统。6月10日发布的安全公告披露的漏洞有两个被归类为严重级别，可能导致资源的机密性、完整性和可用性完全被破坏。  
  
  
最严重的漏洞CVE-2025-26521影响Apache CloudStack项目中的Container Kubernetes Service(CKS)集群。当用户在项目中创建基于CKS的Kubernetes集群时，系统不当地将"kubeadmin"用户的API密钥和密钥暴露给可以访问该集群的其他项目成员。这一设计缺陷允许同一项目中的恶意行为者提取这些凭据并冒充集群创建者的账户，从而执行可能导致完整基础设施被破坏的特权操作。  
  
  
另外两个严重漏洞CVE-2025-47713和CVE-2025-47849允许ROOT域中的Domain Admin用户提升权限并控制更高权限的Admin账户。CVE-2025-47713允许恶意Domain Admin重置Admin角色账户的密码，而CVE-2025-47849则允许未经授权访问同一域内Admin用户的API密钥和密钥。  
  
  
这些漏洞影响Apache CloudStack 4.10.0.0至4.20.0.0版本。攻击者可以冒充Admin账户并访问敏感API，可能导致数据丢失、拒绝服务和基础设施可用性受损。Apache CloudStack已通过4.19.3.0和4.20.1.0版本中的全面修复解决了这些漏洞。  
  
  
原文链接：  
  
https://cybersecuritynews.com/apache-cloudstack-vulnerability-2/  
  
  
**首个已知AI零点击漏洞细节曝光**  
  
  
Aim Security近日公布了首个已知的AI零点击漏洞详情，该漏洞曾影响Microsoft 365 Copilot生成式AI工具，可在无需用户交互的情况下窃取敏感内部数据。  
  
  
这一被命名为"EchoLeak"的漏洞于今年1月被发现并报告给Microsoft，在漏洞修复后Aim Security才公开相关细节。漏洞涉及"LLM范围违规"（LLM Scope Violation），是指攻击者诱导大语言模型越权访问数据的安全漏洞。  
  
  
EchoLeak漏洞的攻击方式是构造包含特定markdown语法的恶意邮件，绕过Microsoft的跨提示注入攻击（Cross-Prompt Injection Attack）防御。恶意邮件中的markdown利用引用式图像和链接格式绕过Copilot的过滤器，确保在AI助手处理邮件时保留有效负载。  
  
  
攻击者可利用SharePoint和Teams等Microsoft受信任域名，嵌入外部链接或图像。当Copilot渲染这些内容时，会自动发出出站请求，攻击者通过精心构造的引用将包含从Copilot上下文中检索的敏感数据重定向到他们控制的服务器。这操作都在后台进行，用户无需打开邮件或点击任何内容，Copilot的自动处理足以触发整个攻击链，因此EchoLeak被归类为零点击漏洞。  
  
  
Microsoft已确认并修复了该问题，并表示未发现该漏洞在野被利用的证据。安全专家警告，这类漏洞对使用企业AI助手的北约、政府、国防和医疗机构等组织构成严重威胁，攻击者无需再依赖凭证窃取或钓鱼攻击，而可直接操纵受信任的AI接口。  
  
  
原文链接：  
  
https://siliconangle.com/2025/06/11/aim-security-details-first-known-ai-zero-click-exploit-targeting-microsoft-365-copilot/  
  
  
**SinoTrack GPS设备存在严重安全漏洞，可被远程控制车辆**  
  
  
美国网络安全和基础设施安全局(CISA)近日披露了SinoTrack GPS设备中的两个安全漏洞，这些漏洞可被黑客利用来控制连接车辆的某些远程功能，甚至追踪车辆位置。  
  
  
CISA在公告中揭示，成功利用这些漏洞可允许攻击者通过常见的Web管理界面未经授权访问设备配置文件，从而对连接的车辆执行某些远程功能，如追踪车辆位置，以及在支持的情况下断开燃油泵电源。这些漏洞影响SinoTrack IoT PC平台的所有版本，其中一个是SinoTrack设备管理界面的弱身份验证源于使用默认密码和印在接收器上的标识符作为用户名，另一个用于Web管理界面身份验证的用户名（即标识符）是不超过10位的数字值。  
  
  
攻击者可以通过物理访问或从公开网站（如eBay）上发布的设备图片中获取设备标识符。此外，攻击者还可以通过递增或递减已知标识符，或通过枚举随机数字序列来寻找潜在目标。  
  
  
目前尚无修复这些漏洞的补丁。CISA建议用户尽快更改默认密码，并采取措施隐藏标  
  
  
原文链接：  
  
https://thehackernews.com/2025/06/sinotrack-gps-devices-vulnerable-to.html  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkAibeib6HUSIXJ4IhpazTYic3uwicySgIEk8ZeMC7X5evYXoNPHxoUlibqgo6Ilq0dRkGrMKibWtfcibYwsg/640?wx_fmt=jpeg "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
