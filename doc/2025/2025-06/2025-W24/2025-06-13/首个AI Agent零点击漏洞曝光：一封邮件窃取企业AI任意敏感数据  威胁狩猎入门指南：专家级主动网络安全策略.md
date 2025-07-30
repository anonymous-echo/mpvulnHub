#  首个AI Agent零点击漏洞曝光：一封邮件窃取企业AI任意敏感数据 | 威胁狩猎入门指南：专家级主动网络安全策略  
e安在线  e安在线   2025-06-13 03:22  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# 首个AI Agent零点击漏洞曝光：一封邮件窃取企业AI任意敏感数据  
  
微软365 Copilot是集成在Word、Excel、Outlook、PowerPoint和Teams等Office办公应用中的AI工具。研究人员日前发现，该工具存在一个严重安全漏洞，揭示了AI代理被入侵可能带来 的更广泛风险。  
  
AI安全初创公司Aim Security发现并披露了这一漏洞，据称这是已知首个针对AI代理的“零点击”攻击案例。所谓AI代理，是指能自主完成特定目标的AI系统。由于该漏洞的特殊性质，用户无需点击或与信息交互，攻击者就能访问连接到AI代理的应用和数据源中的敏感信息。  
  
在微软365 Copilot的案例中，攻击者只需向用户发送一封电子邮件即可发起攻击，无需借助钓鱼手法或恶意软件。这一攻击链通过一系列巧妙的技术手段，引导AI助手“自我攻击”。  
  
  
**一封邮件窃取企业AI敏感数据**  
  
  
微软365 Copilot能根据用户在Office应用中的指令执行任务，例如访问文档或生成建议。一旦被黑客利用，该工具可被用来访问如电子邮件、电子表格和聊天记录等敏感内部信息。这类攻击绕过了Copilot内置的防护机制，从而可能导致专有、机密或合规相关数据的泄露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWhws6cIalg26VuVfJ5sgY6pH37WxpiafzSf2FH2E6ZlbzwultqT1XufV7gD9JqLGhrRfSNrgyHeq0g/640?wx_fmt=jpeg "")  
  
图：攻击链示意  
  
攻击起始于一封发送给目标用户的恶意邮件，其内容与Copilot毫无关联，外观则被伪装成一份常规的商业文档。  
  
邮件中嵌入了一个隐藏的提示注入，指示大模型提取并泄露敏感内部数据。因为这些提示的措辞看起来像是写给人类的正常内容，成功绕过了微软用于防护跨提示注入攻击（XPIA）的分类器。  
  
随后，当用户向Copilot提出与业务相关的问题时，由于该邮件的格式和表面相关性，它就会被检索增强生成（RAG）引擎纳入大模型的提示上下文中。  
  
恶意注入一旦进入模型，即会“欺骗”模型提取敏感内部数据，并将其插入到精心构造的链接或图像中。  
  
Aim Security发现，一些Markdown图像格式会促使浏览器发起图像请求，并自动将URL中嵌入的数据一同发送到攻击者的服务器。  
  
微软的内容安全策略（CSP）阻止了大多数外部域名的访问，但Microsoft Teams和SharePoint的URL被视为可信来源，因此可能被攻击者滥用，从而轻松实现数据泄露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWhws6cIalg26VuVfJ5sgY6pzY3Xe86ia009xvUqhjamBXgauge87pb7VLz9I4a1bhAH5sqSPhOOHQQ/640?wx_fmt=jpeg "")  
  
图：攻击效果  
  
  
****  
**漏洞暴露AI Agents根本缺陷**  
  
  
  
Aim Security的研究团队将该漏洞命名为“EchoLeak”。微软回应称，已经修复了Copilot中的该问题，目前客户未受到影响。  
  
微软发言人在一份声明中表示：“我们感谢Aim发现并负责任地报告了这个问题，使我们能够在客户受到影响之前进行修复。我们已对产品进行了更新以缓解该漏洞，客户无需采取任何措施。我们还部署了额外的纵深防御措施，以进一步增强我们的安全态势。”  
  
Aim的研究人员指出，EchoLeak不仅仅是一个普通的安全漏洞。它的影响超出了Copilot范围，暴露出大模型AI代理在设计上的一个根本性缺陷。这与上世纪90年代的软件漏洞类似。当时，攻击者开始利用这些漏洞控制笔记本电脑和手机等设备。  
  
Aim Security联合创始人兼CTO Adir Gruss表示，他和研究团队花了约三个月时间对微软365 Copilot这款被广泛使用的生成式AI助手进行逆向工程。他们希望确认是否存在类似早期软件漏洞的风险，并开发出相应的防护机制。  
  
Gruss解释称，他们在1月份发现该漏洞后立即联系了微软安全响应中心，该中心负责调查所有影响微软产品和服务的安全问题。他说：“对方确实很重视客户的安全。他们告诉我们，这一发现对他们来说具有突破性意义。”  
  
不过，微软花了5个月才最终修复这个问题。Gruss表示，“对于这种级别的问题来说，这已经算是相当长的修复周期。”他指出，原因之一是漏洞极具新颖性，微软需要时间调动合适的团队，理解问题并制定缓解方案。  
  
Gruss表示，微软曾在4月尝试修复，但在5月又发现了与该漏洞相关的其他安全问题。Aim决定等微软完全解决问题后再发布研究，希望其他可能面临类似风险的厂商能提高警觉。  
  
  
**大型客户感到恐慌，需采取有力防范措施**  
  
  
Gruss强调，EchoLeak的最大隐忧在于其可能适用于其他类型的代理系统，从Anthropic的MCP（模型上下文协议）连接AI助手与其他应用，到Salesforce的Agentforce平台，都可能受到影响。  
  
Gruss说：“如果我是某家正在部署AI代理的公司员工，我此刻会非常恐慌。这是一个非常基础性的设计问题，20到30年前我们曾因系统结构缺陷而长期受安全问题困扰，如今这一幕在AI领域重演。”  
  
他解释说，组织对此风险已有所察觉，这可能也是为什么大多数机构尚未将AI代理大规模投入生产环境的原因。他说：“他们还处在试验阶段，而且非常谨慎。他们确实有理由担忧。但另一方面，作为一个行业，我们也应该构建出合适的系统和防护机制。”  
  
微软曾尝试预防此类问题，特别是针对所谓“大模型作用范围越界”漏洞，即模型被诱导访问或暴露其权限范围以外的数据，从而违反授权。Gruss指出：“他们曾试图在攻击链的多个环节进行阻断，但失败了。原因是AI的行为过于不可预测，攻击面也太广。”  
  
尽管Aim正在为部署可能受EchoLeak漏洞影响的AI代理客户提供临时缓解方案，Gruss强调，从长远来看，必须从根本上重新设计AI代理的构建方式。他解释说：“AI代理在一个‘思考过程’中同时使用可信和不可信数据，这种设计上的基本缺陷导致它容易遭受攻击。这就像一个人对所有读到的内容都全盘接受，那他就很容易被操控。要解决这个问题，要么采用临时控制机制，要么彻底重新设计系统，使可信指令与不可信数据实现明确分离。”  
  
Gruss表示，这种重新设计可以发生在模型本身，比如当前有研究试图增强模型区分指令和数据的能力。或者，也可以在代理构建的应用层引入强制性的安全机制。  
  
他说，“目前我所了解的每一家《财富》500强企业都对将AI代理投入生产环境感到恐惧。”他指出，Aim此前在代码代理相关研究中，曾成功在开发者电脑上运行恶意代码。“虽然仍有用户在测试，但类似漏洞的存在让他们夜不能寐，也阻碍了行业创新。”  
  
# 威胁狩猎入门指南：专家级主动网络安全策略  
  
代网络安全威胁已突破传统边界防御体系，迫使企业必须采用能够预判入侵场景的主动狩猎方法。本指南深入解析高级威胁狩猎策略、技术框架与实施方案，帮助安全专家在重大损害发生前识别复杂威胁。  
  
  
通过假设驱动方法、高级分析平台和MITRE ATT&CK等结构化框架，组织可将安全态势从被动响应转变为主动预测，显著缩短威胁驻留时间并降低潜在攻击影响。  
  
### Part01  
### 威胁狩猎基础认知  
###   
  
威胁狩猎标志着从被动安全响应到主动威胁识别与缓解的范式转变。与传统依赖预定义告警和特征库的安全监控不同，威胁狩猎需要主动搜寻可能绕过现有检测机制的入侵指标（IoC）和恶意活动。其核心原则基于"网络环境中已存在攻击者"的假设，要求持续开展调查分析。  
  
  
成熟的威胁狩猎团队采用基于科学方法的假设驱动方法论，通过逻辑推理和实证证据获取知识，避免偏见和假设影响结果。这种方法始于定义具体攻击场景而非泛泛搜索威胁。安全分析师需考虑可能采用的整体技术，识别网络中的潜在目标，并评估攻击各阶段可能被利用的各类漏洞。  
  
### Part02  
### 技术实施框架  
###   
  
MITRE ATT&CK框架作为现代威胁狩猎的基础要素，提供基于真实数据的标准化战术技术术语库。该框架帮助事件响应人员验证环境中的检测覆盖范围，制定明确的防御能力强化目标。MITRE网络分析知识库（CAR）通过提供针对多种ATT&CK战术技术的检测分析，对该框架形成补充。  
  
  
以APT3（Buckeye）为例的高级持续性威胁（APT）组织，展示了ATT&CK框架在威胁狩猎中的实际应用。APT3通常通过钓鱼邮件（初始访问战术）渗透组织，建立后门（持久化战术）。进入环境后，他们会执行远程命令收集系统网络信息（发现战术），并从受感染设备窃取凭证（凭据访问战术）。  
  
### Part03  
### 基于SIEM的威胁狩猎架构  
###   
  
安全信息与事件管理（SIEM）系统构成高级威胁狩猎的支柱，通过先进关联技术实现历史与实时数据分析。SIEM威胁狩猎通过持续扫描自动化系统可能遗漏的入侵迹象，调查潜伏在网络系统中的潜在威胁。  
  
  
SIEM威胁狩猎的技术实施包含多个关键组件。入侵指标（IoC）作为攻击者留下的数字痕迹，包括IP地址、文件哈希、域名和异常用户行为等。SIEM系统擅长通过关联来自网络设备、终端、服务器和安全设备等多源日志，实现IoC的收集、识别与分析。  
  
### Part04  
### 实战查询与检测分析  
###   
### Splunk为实施复杂威胁狩猎查询提供强大能力，可检测多种攻击向量和恶意活动。以下示例展示不同威胁场景的实践方案：  
```
# 基础登录失败监控
index=main sourcetype="Login_Attempts" status="Failure"
| stats count by user, src_ip
| where count > 5
| sort -count
```  
  
  
该查询通过监控失败登录尝试，识别存在可疑活动模式的用户或源IP地址，从而发现潜在暴力破解攻击。  
  
  
针对更高级的威胁检测，可实施监控终端常见滥用命令的查询：  
```
| tstats count from datamodel=Endpoint.Processes 
where nodename=Processes.process_name IN ("tasklist.exe","ipconfig.exe","systeminfo.exe","net.exe","netstat.exe","whoami.exe") 
by Processes.dest, Processes.process_name, Processes.user
| stats dc(Processes.process_name) as command_count, values(Processes.process_name) as commands by Processes.dest, Processes.user
| where command_count >= 3
| sort -command_count
```  
  
  
该高级查询可识别短时间内执行多个侦察命令的终端，可能表明存在横向移动或系统枚举活动。  
  
### Part05  
### SIGMA规则实施  
###   
### SIGMA规则提供标准化方法创建可跨SIEM平台转换的检测逻辑。以下示例展示检测可疑PowerShell执行的SIGMA规则语法：  
```
title: 可疑PowerShell编码命令
id: f0d1f9c2-3b1a-4c3d-8e9f-1a2b3c4d5e6f
description: 检测包含编码命令的PowerShell执行
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'
      - '-ec'
  condition: selection
falsepositives:
  - 合法的管理脚本
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```  
###   
### 该SIGMA规则在Splunk中转换为：  
```
(Image="*\\powershell.exe" AND (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*" OR CommandLine="*-ec*"))
```  
  
  
该规则能在不同SIEM平台保持一致的检测逻辑，识别潜在的恶意PowerShell活动。  
  
### Part06  
### 高级狩猎方法与自动化  
###   
  
高级威胁狩猎需要结合人类专业知识与自动化能力的结构化方法。TaHiTI（融合威胁情报的目标狩猎）方法论包含三个明确阶段：启动、执行和行动。启动阶段，安全团队从威胁情报报告、异常观察或事件响应洞察中识别触发点，这些触发点转化为捕获调查本质的摘要。  
  
  
PEAK（准备、执行、行动、知识）框架提供另一种复杂方法，包含模型辅助威胁狩猎（M-ATH）等多种狩猎类型。该方法结合人类专业知识与机器学习技术，狩猎者使用机器学习算法建立已知正常和恶意行为模型，通过识别符合或偏离既定模式的活动，实现更精准的威胁识别。  
  
### Part07  
### Osquery终端狩猎实施  
###   
### Osquery通过类SQL查询提供强大的终端威胁狩猎能力，可探查系统状态和活动。以下示例展示Osquery实践方案：  
```
-- 检测从临时目录执行的可疑进程
SELECT p.name, p.path, p.cmdline, p.parent, u.username 
FROM processes p 
JOIN users u ON p.uid = u.uid 
WHERE p.path LIKE '%temp%' OR p.path LIKE '%tmp%' 
OR p.path LIKE '%appdata%local%temp%';
-- 通过注册表运行键识别持久化机制
SELECT r.key, r.name, r.data, r.type 
FROM registry r 
WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run%' 
OR r.key LIKE 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run%';
```  
  
  
这些查询支持全面的终端审查，识别攻击者常用的可疑进程执行模式和持久化机制。  
  
### Part08  
### 威胁情报与机器学习集成  
###   
  
现代威胁狩猎平台越来越多地整合机器学习能力，以提高检测精度并降低误报率。Elastic Security通过实时呈现丰富上下文的高级分析展示这种集成，使分析师能在数秒内查询PB级日志，并将最新入侵指标与多年历史数据进行匹配。  
  
  
威胁情报源的集成通过纳入关于已知和新兴威胁的外部知识，增强SIEM威胁狩猎能力。这些情报源包括恶意软件特征、IP黑名单、已知攻击者技术，以及与恶意活动相关的哈希值、域名和URL等入侵指标。SIEM系统将这些指标与内部日志关联，搜索与已知攻击模式匹配的行为。  
  
### Part09  
### 总结  
###   
### 有效的威胁狩猎需要结合结构化方法、先进技术工具和持续适应不断演变的威胁态势。通过实施假设驱动方法、利用MITRE ATT&CK等框架，以及在Splunk、Osquery和SIGMA等平台上运用复杂查询语言，安全专业人员可显著提升组织的主动安全能力。  
###   
### 机器学习、威胁情报和实时分析的集成，使狩猎团队能够识别传统安全措施可能遗漏的复杂威胁。威胁狩猎的成功最终取决于将自动化检测能力与人类专业知识相结合，构建假设存在入侵场景并持续搜寻企业环境中恶意活动证据的全面防御策略。  
  
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源：安全内参、FreeBuf、  
  
参考来源：  
  
Threat Hunting 101 – Proactive Cybersecurity Strategies for Experts  
  
https://cybersecuritynews.com/threat-hunting-2/  
  
参考资料：fortune.com  
  
   
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
