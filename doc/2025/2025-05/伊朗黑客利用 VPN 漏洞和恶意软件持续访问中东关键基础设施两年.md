#  伊朗黑客利用 VPN 漏洞和恶意软件持续访问中东关键基础设施两年   
会杀毒的单反狗  军哥网络安全读报   2025-05-06 01:01  
  
**导****读**  
  
  
  
一个与伊朗有关的威胁组织被认为对中东地区关键国家基础设施进行了持续近两年的网络入侵。  
  
  
FortiGuard 事件响应 (FGIR) 团队在一份报告中表示，该活动至少从 2023 年 5 月持续到 2025 年 2 月，涉及“广泛的间谍活动和疑似网络预置——这是一种经常用于保持持续访问以获得未来战略优势的策略” 。  
  
  
FortiGuard 指出，此次攻击表现出与已知伊朗威胁组织Lemon Sandstorm（以前称为 Rubidium）的间谍手法重叠，该组织还被追踪为 Parisite、Pioneer Kitten 和 UNC757。  
  
  
据估计，该攻击至少自2017年以来就一直活跃，袭击了美国、中东、欧洲和澳大利亚的航空航天、石油天然气、水利和电力行业。  
  
  
据工业网络安全公司Dragos称，攻击者利用了Fortinet、Pulse Secure和Palo Alto Networks中已知的虚拟专用网络（VPN）安全漏洞，获取了初始访问权限。  
  
  
去年，美国网络安全和情报机构指责Lemon Sandstorm 向美国、以色列、阿塞拜疆和阿拉伯联合酋长国的实体部署勒索软件。  
  
  
Fortinet 分析的针对 CNI 实体的攻击自 2023 年 5 月开始，分为四个阶段，随着受害者采取对策，攻击使用了不断演变的工具库：  
- 2023 年 5 月 15 日至2024 年 4 月 29 日  
  
使用窃取的登录凭据访问受害者的 SSL VPN 系统，在面向公众的服务器上放置 Web Shell，并部署三个后门（Havoc、HanifNet 和 HXLibrary）以实现长期访问，从而建立立足点  
- 2024 年 4 月 30 日至2024 年 11 月 22 日  
  
通过植入更多 Web Shell 和名为 NeoExpressRAT 的附加后门来巩固立足点，使用 plink 和 Ngrok 等工具深入网络，有针对性地窃取受害者的电子邮件，并进行横向移动到虚拟化基础设施  
- 2024 年 11 月 23 日至 2024 年 12 月 13 日  
  
部署更多 Web Shell 和另外两个后门（MeshCentral Agent 和      SystemBC），以响应受害者采取的初步遏制和补救措施  
- 2024 年 12 月 14 日至今  
  
尝试利用已知的 Biotime 漏洞（CVE-2023-38950、CVE-2023-38951 和CVE-2023-38952）再次渗透网络，并针对 11 名员工发起鱼叉式网络钓鱼攻击，在受害者成功删除攻击者的访问权限后获取 Microsoft 365 凭据  
值得注意的是，Havoc和MeshCentral都是开源工具，分别充当命令与控制 (C2) 框架和远程监控与管理 (RMM) 软件。而SystemBC则是一种商业恶意软件，通常充当勒索软件部署的前兆。  
  
  
攻击中使用的其他自定义恶意软件家族和开源工具的简要说明如下：  
- HanifNet：一个未签名的 .NET 可执行文件，可以从 C2 服务器检索和执行命令（首次部署于 2023 年 8 月）  
- HXLibrary： 一个用.NET 编写的恶意 IIS 模块，旨在检索托管在 Google Docs 上的三个相同文本文件，以获取 C2 服务器并向其发送 Web      请求（首次部署于 2023 年 10 月）  
- CredInterceptor：一种基于 DLL 的工具，可以从 Windows 本地安全机构子系统服务 ( LSASS ) 进程内存中获取凭据（首次部署于 2023 年 11      月）  
- RemoteInjector：用于执行下一阶段有效载荷（如 Havoc）的加载器组件（于 2024 年 4 月首次部署）  
- RecShell：用于初步侦察的 Web Shell（首次部署于 2024 年 4 月）  
- NeoExpressRAT：一种从 C2 服务器检索配置并可能使用 Discord 进行后续通信的后门（首次部署于 2024 年 8 月）  
- DropShell：具有基本文件上传功能的 Web Shell（于 2024 年 11 月首次部署）  
- DarkLoadLibrary：用于启动 SystemBC 的开源加载器（于 2024 年 12 月首次部署）  
与 Lemon Sandstorm 相关的链接来自C2 基础设施： apps.gist.githubapp[.]net 和 gupdate[.]net - 之前被标记为与威胁组织在同一时期进行的操作有关。  
  
  
Fortinet 表示，鉴于威胁组织广泛的侦察活动以及对托管 OT 相邻系统网络段的入侵，受害者受限的运营技术 (OT) 网络是此次攻击的关键目标。目前尚无证据表明攻击者已经入侵 OT 网络。  
  
  
鉴于命令错误和一致的工作时间安排，大多数恶意活动被评估为由不同人员执行的手动键盘操作。此外，对该事件的深入调查显示，该威胁组织可能早在 2021 年 5 月 15 日就已访问该网络。  
  
  
该公司表示：“在整个入侵过程中，攻击者利用链式代理和自定义植入程序绕过网络分段，并在环境中横向移动。在后期阶段，他们持续链接四种不同的代理工具来访问内部网络段，展现出一种保持持久性和规避检测的复杂方法。”  
  
  
技术报告：  
  
https://www.fortinet.com/blog/threat-research/fortiguard-incident-response-team-detects-intrusion-into-middle-east-critical-national-infrastructure  
  
  
新闻链接：  
  
https://thehackernews.com/2025/05/iranian-hackers-maintain-2-year-access.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
