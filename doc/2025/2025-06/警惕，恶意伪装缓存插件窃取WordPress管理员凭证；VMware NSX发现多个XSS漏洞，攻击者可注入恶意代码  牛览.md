#  警惕，恶意伪装缓存插件窃取WordPress管理员凭证；VMware NSX发现多个XSS漏洞，攻击者可注入恶意代码 | 牛览  
 安全牛   2025-06-06 09:04  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**新闻速览**  
  
  
  
•因隐私和安全违规，Vodafone在德国被处以5140万美元罚款  
  
•Passion.io数据库泄露导致360万创作者信息遭曝光  
  
•全球3.5万台太阳能设备管理界面暴露于互联网，引发安全隐患  
  
•新型AMOS恶意软件通过伪造验证页面入侵macOS  
  
•  
AT&T旧泄露数据被重新打包发布  
  
•警惕，恶意伪装缓存插件窃取WordPress管理员凭证  
  
•VMware NSX发现多个XSS漏洞，攻击者可注入恶意代码  
  
•Cisco修复ISE跨实例凭证共享高危漏洞，影响AWS、Azure和Oracle云部署  
  
•Meta开源其AI工具，可自动识别与分类敏感文档  
  
  
  
**热点观察**  
  
  
  
**因隐私和安全违规，Vodafone在德国被处以5140万美元罚款**  
  
  
德国数据保护机构(BfDI)近日对Vodafone GmbH（沃达丰德国子公司）处以4500万欧元（约合5140万美元）的罚款，原因是该公司存在严重的隐私和安全违规行为。  
  
  
据BfDI 6月5日的公告，此次处罚分为两部分：一项1500万欧元的罚款是因为Vodafone未能有效监管其合作代理机构，这些机构的恶意员工未经授权更改客户合同或诱骗客户签署虚假合同；另一项3000万欧元的罚款则针对其"MeinVodafone"（我的沃达丰）应用和公司热线的身份验证漏洞，这些漏洞允许攻击者访问客户的eSIM配置文件。据悉，Vodafone在整个调查过程中持续、无限制地配合，并主动披露了不利于公司的情况。  
  
  
为降低未来风险，Vodafone已更新其流程和系统，并替换了部分系统；同时还更新了选择和审核合作代理机构的程序，并与涉及欺诈活动的合作伙伴终止了合作关系。BfDI透露，这家电信巨头已支付罚款，并向促进数据保护、媒体素养和打击网络欺凌的组织捐赠了数百万欧元。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/germany-fines-vodafone-51-million-for-privacy-security-breaches/  
  
  
**Passion.io数据库泄露导致360万创作者信息遭曝光**  
  
  
网络安全专家Jeremiah Fowler近日发现了一个未受保护的数据库，导致超过360万应用创作者、网红和企业家的个人信息面临风险。这个数据库容量高达12.2TB，未经加密也没有密码保护，包含了3,637,107条记录，其中包括姓名、电子邮件、物理地址，以及用户和应用创作者的支付详情。  
  
  
根据Fowler的报告，数据库属于Passion.io公司。该公司提供无代码平台，允许创作者、教练和名人无需技术技能即可构建自己的移动应用，通过订阅或一次性购买获利。泄露的个人身份信息可能被犯罪分子用于"钓鱼或社会工程攻击"。此外，数据库还包含视频文件和PDF文档，这些似乎是应用创作者销售的高级内容，以及内部财务记录，可能损害创作者收入并让竞争对手了解公司运营情况。  
  
  
Fowler在发现泄露后立即通知了Passion.io。该公司迅速采取行动，当天限制了数据库的公共访问。Passion.io承认了这一发现，表示其"隐私官和技术团队正在修复问题，确保这种情况不再发生"。  
  
  
原文链接：  
  
https://hackread.com/unsecured-database-exposes-passion-io-creators-data/  
  
  
**全球3.5万台太阳能设备管理界面暴露于互联网，引发安全隐患**  
  
  
工业网络安全公司Forescout近日发布的最新报告指出，全球近3.5万台太阳能设备的管理界面可从互联网直接访问，这些设备来自42家不同制造商，包括太阳能基础设施运行所必需的关键设备。  
  
  
虽然部分管理界面可能设有密码保护，但几乎所有这些设备都不需要联网。拥有最多暴露设备的10家供应商在过去十年中都曾披露过漏洞，这进一步增加了它们暴露在公共互联网上的风险。SMA公司的Sunny WebBox是最常见的可远程访问设备，其次是Fronius International逆变器。Sunny WebBox已于2015年停产，但研究人员在同年9月披露了该产品中的硬编码漏洞。这些设备在欧洲和亚洲比其他地区更为普遍，其中四分之三位于欧洲，17%位于亚洲。德国和希腊各占暴露设备总数的五分之一。  
  
  
威胁组织正积极寻找并利用一切机会入侵联网基础设施。Forescout建议运营方应当采取'假设已被入侵'的安全思维，充分认识到这些系统对攻击者的高度吸引力，并据此制定防御策略。  
  
  
原文链接：  
  
https://gbhackers.com/35000-internet-connected-solar-power-systems/  
  
  
  
**网络攻击**  
  
  
  
  
**新型AMOS恶意软件通过伪造验证页面入侵macOS**  
  
  
近日，安全研究人员发现了一场针对macOS用户的复杂恶意软件攻击活动。攻击者利用模仿美国电信提供商Spectrum的域名，分发Atomic macOS Stealer (AMOS)的新变种，以绕过Apple的安全机制。  
  
  
这次攻击利用了日益流行的Clickfix方法，向受害者展示伪造的Cloudflare保护页面。当用户在诸如panel-spectrum.net等域名上遇到这些欺骗性界面时，他们被诱导完成看似例行的人机验证过程。然而，点击"Alternative Verification"按钮会触发一系列恶意命令，同时显示看似标准的安全协议指令。恶意软件使用shell脚本持续提示用户输入系统密码，并利用macOS原生的dscl命令来验证密码的真实性。一旦成功，恶意软件会下载AMOS payload，并使用窃取的密码通过sudo -S xattr -c命令移除隔离属性，有效绕过Gatekeeper保护。  
  
  
这次攻击的影响范围不仅限于个人凭证窃取，还可能导致企业网络渗透和横向移动。通过窃取macOS用户密码，攻击者可以获得对企业系统、虚拟专用网络和内部资源的访问权限，这对拥有Mac用户的组织构成了特别严重的威胁。鉴于此次攻击的复杂性和潜在影响，安全专家呼吁macOS用户和企业提高警惕，加强安全意识培训，并及时更新系统和安全软件。  
  
  
原文链接：  
  
https://cybersecuritynews.com/amos-macos-stealer-distributed-via-clickfix/  
  
  
**AT&T旧泄露数据被重新打包发布**  
  
  
一名威胁行为者重新发布了2021年影响7000万AT&T客户的数据泄露信息，此次泄露将之前分散的文件合并，直接将社会安全号码(SSN)和出生日期与个人用户关联起来。  
  
  
AT&T表示其正在调查这些数据，但认为这些数据源自已知的数据泄露事件，只是被重新包装成新的泄露。该数据首先被HackRead发现，出现在一个俄语黑客论坛上，威胁者声称这是在2024年AT&T Snowflake数据窃取攻击中获取的。然而，BleepingComputer分析表明，这些数据实际上来自2021年由知名威胁行为者ShinyHunters实施的AT&T数据泄露，当时他试图以20万美元出售这些数据。  
  
  
2024年3月，另一名威胁行为者在网络犯罪论坛上免费泄露了全部AT&T数据。当前泄露的数据分析显示，这与2024年泄露的相同，但经过清理，移除了AT&T内部数据，并为每个客户记录添加了未加密的社会安全号码和出生日期。泄露的数据共有88,320,017行，去重后为86,017,088条唯一记录，包含48,896,044个唯一电话号码及相关客户信息。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/old-atandt-data-leak-repackaged-to-link-ssns-dobs-to-49m-phone-numbers/  
  
  
**警惕，恶意伪装缓存插件窃取WordPress管理员凭证**  
  
  
安全研究人员近期发现恶意插件"wp-runtime-cache"正在针对WordPress网站实施攻击，通过伪装成缓存插件来窃取管理员凭证。该恶意软件潜伏在wp-content/plugins目录中，但不会出现在WordPress管理面板的插件列表中，从而逃避检测。  
  
  
与合法缓存插件通常在wp-admin界面提供可见设置不同，这个假插件不提供任何功能。且其目录仅包含一个文件：wp-runtime-cache.php，而非正常插件的多文件结构。技术分析显示，该插件通过add_action('wp_login', 'octopusJson50286', 10, 2)钩子在网站登录期间激活，捕获用户输入。它专门针对具有"manage_options"(管理员级别)和"edit_pages"(编辑级别)权限的高权限用户，这些字符串通过base64编码隐藏。一旦匹配到目标用户，插件会收集包括用户名和密码在内的敏感数据，并通过WordPress内置的wp_remote_post函数将其发送到远程服务器https://woocommerce-check[.]com/report-to 。  
  
  
该插件还使用  add_action ('pre_current_active_plugins',  'pbes2PITR0339')  触发的辅助函数来操纵插件列表，对普通用户保持不可见。代码混淆技术的使用，如随机变量名和base64编码内容，进一步增加了检测难度。  
  
  
安全专家建议，WordPress管理员应定期审核插件和用户账户，使用服务器端扫描器或Sucuri等安全插件检测未授权文件上传。实施双因素认证(2FA)和基于IP的登录限制可以防止未授权访问。如果怀疑遭到入侵，更新wp-config.php文件中的WordPress盐值也至关重要。  
  
  
原文链接：  
  
https://gbhackers.com/wordpress-admins-cautioned-about-fake-cache-plugin/  
  
  
  
**安全漏洞**  
  
  
  
**VMware NSX发现多个XSS漏洞，攻击者可注入恶意代码**  
  
  
VMware于6月4日发布安全公告，披露其NSX网络虚拟化平台存在多个跨站脚本(XSS)漏洞，这些漏洞可能允许恶意攻击者注入并执行有害代码。  
  
  
这些漏洞影响NSX Manager UI、网关防火墙和路由器端口组件，具体情况如下：  
- CVE-2025-22243是NSX Manager用户界面中的存储型XSS漏洞。该漏洞源于网络配置字段中的输入验证不当，允许持久注入恶意JavaScript负载。具有管理权限的攻击者可以在DNS名称或IP地址描述等字段中嵌入恶意脚本，当合法管理员通过NSX Manager UI查看受感染的配置时，这些负载会自动执行；  
  
- CVE-2025-22244影响NSX网关防火墙URL过滤组件。该漏洞允许攻击者在用户尝试访问被阻止网站时显示的自定义响应页面中注入脚本；  
  
- CVE-2025-22245存在于NSX路由器端口管理界面中。端口描述字段的不当净化使脚本注入成为可能。  
  
这三个漏洞影响所有VMware NSX 4.0.x至4.2.x版本，以及依赖平台如VMware Cloud Foundation和Telco Cloud Infrastructure。VMware已发布全面补丁，建议用户立即升级到相应版本：4.2.x安装升级至4.2.2.1，4.2.1.x版本升级至4.2.1.4，4.1.x和4.0.x部署升级至4.1.2.6。值得注意的是，VMware已停止对4.0.x版本的支持，建议迁移到4.1.2.6补丁版本。  
  
  
原文链接：  
  
https://cybersecuritynews.com/vmware-nsx-xss-vulnerability/  
  
  
**Cisco修复ISE跨实例凭证共享高危漏洞，影响AWS、Azure和Oracle云部署**  
  
  
Cisco修复了Identity Services Engine (ISE)中一个严重漏洞(CVE-2025-20286)，该漏洞CVSS评分高达9.9，影响AWS、Microsoft Azure和Oracle Cloud Infrastructure上的ISE云部署。未经身份验证的远程攻击者可利用此漏洞访问敏感数据、执行有限的管理操作、修改配置或中断服务。  
  
  
该漏洞源于Cisco ISE在云平台部署时凭证生成机制存在缺陷，导致使用相同软件版本和云平台(AWS、Azure或OCI)的不同实例生成相同的凭证。攻击者可以从一个Cisco ISE实例中提取凭证，然后通过未受保护的端口访问其他云环境中部署的ISE系统。  
  
  
Cisco  
产品安全事件响应团队已  
确认存在此漏洞的概念验证代码，但表示没有  
证据表明该漏洞已在野攻击中被积极利用。受影响的版本包括ISE 3.1、3.2、3.3、3.4和3.5。Cisco提供了一些重要缓解措施：通过云安全组或直接在ISE界面中仅允许受信任的源IP地址访问；对于新安装，建议在基于云的主节点上运行application reset-config ise命令生成新凭证，但这将重置系统为出厂设置，从备份恢复会带回原始(可能易受攻击的)凭证。  
  
  
原文链接：  
  
https://securityaffairs.com/178659/uncategorized/critical-flaw-in-cisco-ise-impacts-cloud-deployments-on-aws-microsoft-azure-and-oracle-cloud-infrastructure.html  
  
  
  
**行业动态**  
  
  
  
**Meta开源其AI工具，可自动识别与分类敏感文档**  
  
  
Meta近日发布了开源AI工具Automated Sensitive Document Classification。该工具最初为内部使用而开发，旨在自动识别文档中的敏感信息并应用安全标签。  
  
  
该解决方案利用Apache Tika从Google Docs、Sheets和Slides中提取文本，然后使用Llama模型识别敏感内容，并通过Google Drive API为这些文件应用敏感度标签。文档一旦被标记，系统可以防止未授权访问，同时确保这些敏感内容不会被使用检索增强生成(RAG)技术的AI系统所处理。Meta计划未来扩展支持的部署平台(如Ollama)和SaaS文档共享平台，包括Office 365的文档敏感度标签功能。  
  
  
Meta表示，传统的正则表达式等方法无法满足公司海量文件类型和敏感数据的识别需求。为此，Meta开发了基于大语言模型(LLM)的解决方案，该方案不仅可以分类数据，还能绘制组织内数据分布图。系统可以输出包含文件枚举和分类结果的CSV文件，或将所有内容存储到内置的SQLi数据库中。Meta提供了一个多级分类代理，可以配置为匹配公司自己的政策或标准，开发人员可以根据自己的标准标记数据。此外，该工具可以作为Docker容器部署，使任何组织都能根据需要扩展服务。  
  
  
原文链接：  
  
https://www.helpnetsecurity.com/2025/06/05/meta-open-source-automated-sensitive-document-classification-tool/  
  
  
**Accelerate 2025北亚巡展·北京站成功举办**  
  
  
6月5日，网络安全行业的年度盛会——"Accelerate 2025北亚巡展·北京站"成功举办。来自智库、产业界、Fortinet的权威专家，以及来自各行业的企业用户代表，围绕"AI智御全球·引领安全新时代"主题，就AI技术驱动的安全防御体系重构、网络与安全的原生融合实践、全球化场景下的SASE技术落地三大核心议题展开深入研讨。  
  
  
Fortinet北亚区资深区域总监冯玉明强调，AI安全是当前数字化转型的关键议题。Fortinet 25年以创新驱动网络融合安全解决方案持续迭代；构建AI驱动的智能化防御体系，为全球客户提供可落地的安全保障方案是Fortinet的重任。  
  
  
Fortinet中国区技术总监张略以三维辩证视角剖析AI安全格局认为“AI是网络安全的现在和未来”，并深入解析、现场演示Fortinet三大“AI安全智能体”应用：FortiAI-Protect、FortiAI-Assist和FortiAI-SecureAI。不仅如此，Fortinet还通过AI技术实现了威胁情报的自动化收集和分析，为企业提供了更加准确、及时的威胁情报支持。  
  
  
原文链接：  
  
 https://www.aqniu.net/news/details/2025060614015627882938?type=5&from=list  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkAibeib6HUSIXJ4IhpazTYic3uwicySgIEk8ZeMC7X5evYXoNPHxoUlibqgo6Ilq0dRkGrMKibWtfcibYwsg/640?wx_fmt=jpeg "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
