#  又一BeyondTrust漏洞遭黑客利用；Fortinet修复已被在野利用零日漏洞，可攻破FortiGate防火墙 | 牛览   
 安全牛   2025-01-15 09:28  
  
点击蓝字·关注我们   
/   
aqniu  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**新闻速览**  
  
  
  
•英国拟禁止赎金支付，剑指勒索软件攻击  
  
•又一BeyondTrust漏洞遭黑客利用  
  
•OWASP发布十大"非人类身份安全风险"清单  
  
•警惕网络犯罪新手法：伪造YouTube链接窃取登录凭证  
  
•Fortinet修复已被在野利用FortiOS零日漏洞，可攻破FortiGate防火墙  
  
•供应链安全警报：Kong  Ingress Controller v.3.4.0 镜像被篡改，系统变成挖矿设备  
  
•PDF文件零日漏洞曝光：Adobe与Foxit  Reader中的NTLM泄露风险  
  
•微软1月周二补丁日：修复159个漏洞，包含8个零日漏洞  
  
  
  
**特别关注**  
  
  
  
**英国拟禁止赎金支付，剑指勒索软件攻击**  
  
  
英国即将实施一项重要政策，正式禁止赎金支付，以应对日益严重的勒索软件攻击。这项禁令将主要针对公共和关键基础设施部门，包括教育、交通、医院（包括国家医疗服务体系）以及银行等金融机构。2025年1月14日，英国内政部发布了一份咨询白皮书，详细说明了这一政策变更，预计不久将正式以行政命令的形式实施。  
  
  
英国此次决定效仿美国，后者已采取措施，劝阻企业和公共部门支付赎金以换取解密密钥。实施这一政策的原因在于削弱网络犯罪分子的经济激励，从而减少这些对全球各行业造成重大干扰的攻击事件。除了禁止支付赎金外，提案还要求遭遇勒索软件攻击的企业和组织在三个工作日内向执法机构报告事件。未能遵守这一报告要求可能会面临法律处罚和其他后果。这一措施旨在确保迅速应对攻击，并使执法机构能够收集关键情报，以追踪和打击勒索软件活动。  
  
  
国家犯罪局（NCA）与国家网络安全中心（NCSC）已开始提升公众对新政策及其影响的认识。尽管面临挑战，英国提议的赎金支付禁令标志着在打击网络犯罪方面迈出了大胆的一步。如果成功，这一政策可能为其他面临勒索软件攻击威胁的国家提供借鉴。  
  
  
原文链接：  
  
https://www.cybersecurity-insiders.com/uk-to-follow-america-in-imposing-a-ransomware-payment-ban/  
  
   
  
**又一BeyondTrust漏洞遭黑客利用**  
  
  
1月13日，美国网络安全与基础设施安全局(CISA)表示，一个影响BeyondTrust特权远程访问(PRA)和远程支持(RS)工具产品的漏洞CVE-2024-12686正在被黑客利用。CISA已将CVE-2024-12686添加到KEV中，并表示防御者应“根据供应商说明应用缓解措施，或在无法缓解时停止使用该产品"。根据KEV的标准补丁期限，联邦机构必须在2月3日之前应用缓解措施或停止使用PRA和RS。  
  
  
CVE-2024-12686是一个中等严重程度的操作系统命令注入漏洞，影响BeyondTrust PRA和RS工具24.3.1及更早版本。该软件供应商上月初在调查客户遭到入侵时发现了这一漏洞，并于12月18日披露。  
  
  
根据BeyondTrust关于CVE-2024-12686的安全公告，所有易受攻击的PRA和RS版本都存在命令注入缺陷，可被拥有管理权限的用户利用来上传恶意文件，"成功利用此漏洞可使远程攻击者在站点用户上下文中执行底层操作系统命令。"该供应商通过为RS和PRA 22.1及更高版本提供补丁来解决此问题。使用旧版本的客户必须升级才能应用相关补丁。  
  
  
原文链接：  
  
https://www.techtarget.com/searchsecurity/news/366618092/CISA-BeyondTrust-flaw-CVE-2024-12686-exploited-in-the-wild  
  
  
**OWASP发布十大"非人类身份安全风险"清单**  
  
  
1月14日，开放式网络应用程序安全项目(OWASP)发布了首个"非人类身份(NHI)十大安全风险"排行榜，旨在提高人们对于软件实体，如应用程序、API、机器人和自动化系统，获取授权访问安全资源时所面临的风险的认识，并提供可操作的指导和缓解漏洞的策略。  
  
  
这10大风险包括：不当的身份注销、秘密泄露、第三方 NHI漏洞、不安全的身份认证、过度授权的 NHI、不安全的云部署配置、长期有效的秘密、环境隔离不足、NHI 重复使用和人为使用 NHI。OWASP的十大风险清单概述了最普遍的NHI风险及相关的缓解措施，帮助组织优先改善其安全态势。  
  
  
报告强调，虽然许多NHI安全实践本身并不复杂，但在现代组织中，NHI的规模使其成为一大挑战。大量的NHI、多个身份提供商(IdP)、混合云环境和容器化工作流，使手动管理几乎不可能，需要借助高级工具。  
  
  
原文链接：  
  
https://cybersecuritynews.com/owasp-nhi-top-10/  
  
  
  
**网络攻击**  
  
  
  
**警惕网络犯罪新手法：伪造YouTube链接窃取登录凭证**  
  
  
网络安全分析师最近发现，网络犯罪分子利用伪造的YouTube链接将用户重定向至钓鱼页面，从而窃取登录凭证。这种攻击手段通过对统一资源标识符（URI）的巧妙操控，掩盖了恶意意图，同时保持了链接的表面可信度。  
  
  
在这一攻击中，网络犯罪分子通过精心设计的URI操控来欺骗用户。这些恶意链接通常以类似http://youtube的合法字符串开头。通过ANY.RUN的互动沙箱进行的分析显示，攻击者通过电子邮件分发恶意链接，受害者收到的邮件提示他们“查看已完成的文档”，邮件中嵌入的链接经过巧妙替换，使用了可识别的域名，使其看起来可信。点击后会将受害者重定向至一个专门设计的钓鱼页面，以窃取他们的登录凭证。攻击者还使用通常涉及多个中间域名的分层重定向技术，以逃避自动检测工具和用户的注意。当用户到达实际网站时，他们的警惕性往往降低，而钓鱼页面几乎与合法页面无异。  
  
  
此次攻击与Storm1747组织有关，该组织依赖于一个组织良好的域名基础设施来实施攻击。他们的设置包括检查器、重定向器和主要钓鱼页面，所有这些都是使用Tycoon 2FA钓鱼工具包的标准化模板构建的。这些现成的组件使攻击者能够快速高效地部署大规模的钓鱼活动。  
  
  
原文链接：  
  
https://hackread.com/hackers-fake-youtube-links-steal-login-credentials/  
  
  
**Fortinet修复已被在野利用FortiOS零日漏洞，可攻破FortiGate防火墙**  
  
  
Fortinet近日修复了一个已经被在野利用数月的FortiOS零日缺陷。该缺陷影响FortiOS防火墙和FortiProxy网络网关，攻击者利用这一缺陷对公开暴露的FortiGate防火墙进行入侵。  
  
  
该缺陷是一个身份验证绕过漏洞，允许远程攻击者通过对Node.js websocket模块的精心构造请求获得超级管理员权限，从而执行未经授权的代码或命令。该缺陷影响FortiOS版本7.0.0至7.0.16，以及FortiProxy版本7.0.0至7.0.19和7.2.0至7.2.12，且可在无需用户交互的情况下被利用。针对该缺陷的攻击始于11月中旬，涉及对防火墙管理接口的未经授权的管理员登录、新账户的创建、通过这些账户进行SSL VPN身份验证以及其他各种配置更改。  
  
  
企业管理员被建议升级到修复版本：FortiOS 7.0.17及以上版本，FortiProxy 7.2.13及以上版本或7.0.20及以上版本，并检查已知的入侵迹象。如果无法立即更新设备，建议采取临时解决方案，例如将防火墙的基于Web的管理接口从公共互联网中移除。  
  
  
原文链接：  
  
https://www.helpnetsecurity.com/2025/01/14/fortinet-fortigate-zero-day-vulnerability-exploited-cve-2024-55591/  
  
  
**供应链安全警报：Kong Ingress Controller v.3.4.0 镜像被篡改，系统变成挖矿设备**  
  
  
近日，攻击者入侵了Kong的DockerHub账户，并将合法的Kong Ingress Controller v.3.4.0镜像替换为恶意版本。  
  
  
这一漏洞源于2024年12月23日上传到DockerHub的未经授权的镜像。受影响的镜像（哈希值：sha256:a00659df0771d076fc9d0baf1f2f45e81ec9f13179f499d4cd940f57afc75d43）包含恶意代码，导致加密劫持。该恶意代码将控制器指向一个名为pool.supportxmr.com的加密货币挖矿网站，意味着该镜像中的代码会在运行受影响镜像的任何系统上秘密进行加密货币挖矿，将这些系统变成了意外的挖矿设备。这可能给组织带来严重后果，包括资源消耗增加、能源成本上升以及多种安全风险。受损镜像还可能引入漏洞或后门，使攻击者获得进一步访问权限。  
  
  
Kong团队于2025年1月2日意识到这一问题，并从DockerHub上移除了版本3.4.0及所有相关标签，并更换了所有用于DockerHub访问的密钥。随后，修复版本3.4.1于2025年1月2日发布，移除了未经授权的加密劫持代码。Kong团队建议在2024年12月22日至2025年1月3日期间部署了Kong Ingress Controller版本3.4.0用户立即采取行动，从所有内部注册表和集群中删除该镜像。  
  
  
原文链接：  
  
https://hackread.com/malicious-kong-ingress-controller-image-dockerhub/  
  
   
  
  
**安全漏洞**  
  
  
  
**PDF文件零日漏洞曝光：Adobe与Foxit Reader中的NTLM泄露风险**  
  
  
网络安全研究人员在EXPMON发现了一个严重的零日漏洞，该漏洞存在于PDF文件中，可能被攻击者利用以泄露敏感的NTLM认证数据。该漏洞涉及Adobe Reader和Foxit Reader在处理特定PDF操作时的安全隐患。  
  
  
这一漏洞源于Adobe Reader和Foxit Reader处理特定/Launch操作的方式。如果被恶意行为者利用，这些行为可能导致NTLM信息的盗取，而NTLM是Windows网络中的关键认证机制。在Adobe Reader中打开该PDF样本时，应用程序会尝试查找名为“Applications”的网络资源。如果成功，它会在用户看到警告消息之前，主动连接并将NTLM凭证发送到服务器。虽然这种行为不允许攻击者使用公共域名，但在私有网络环境中，攻击者可以通过制作恶意PDF并使用攻击者控制的本地服务器，收集受害者的敏感NTLM信息。  
  
  
安全专家建议Adobe Reader用户在Adobe尚未发布针对该行为的补丁之前，通过在Acrobat设置中禁用“自动信任来自Win OS安全区域的网站”功能来降低风险；Foxit Reader用户立即更新至Foxit Reader v2024.4或更高版本。  
  
  
原文链接：  
  
https://cybersecuritynews.com/zero-day-vulnerability-in-pdf-files-leaking-ntlm-data-in-adobe-foxit-reader/  
  
  
**微软1月周二补丁日：修复159个漏洞，包含8个零日漏洞**  
  
  
微软于2025年1月的周二补丁日发布了安全更新，修复了159个漏洞，其中包括：权限提升漏洞40个，安全功能绕过漏洞14个，远程代码执行漏洞58个，信息泄露漏洞24个，拒绝服务漏洞20个，伪造漏洞5个。  
  
  
微软本次修复了3个正在被积极利用的零日漏洞：CVE-2025-21333、CVE-2025-21334、CVE-2025-21335。微软修复了这三个在Windows Hyper-V中被利用的权限提升漏洞，这些漏洞允许攻击者在Windows设备上获取SYSTEM权限。  
  
  
微软本次修复了5个公开披露的零日漏洞：  
- CVE-2025-21275：Windows应用程序包安装程序权限提升漏洞。攻击者若成功利用此漏洞可获得SYSTEM权限；  
  
- CVE-2025-21308：Windows主题伪造漏洞。该漏洞可以通过在Windows资源管理器中显示特制的主题文件来利用。攻击者需要说服用户加载恶意文件，通常通过电子邮件或即时消息的诱惑来实现。  
  
- CVE-2025-21186、CVE-2025-21366、CVE-2025-21395：Microsoft Access远程代码执行漏洞。这三个漏洞是在打开特制的Microsoft Access文档时被利用的远程代码执行漏洞。微软通过阻止访问通过电子邮件发送的特定Microsoft Access文档来缓解此问题。  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2025-patch-tuesday-fixes-8-zero-days-159-flaws/  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkAibeib6HUSIXJ4IhpazTYic3uwicySgIEk8ZeMC7X5evYXoNPHxoUlibqgo6Ilq0dRkGrMKibWtfcibYwsg/640?wx_fmt=jpeg "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
