#  五眼联盟警告：Ivanti网关漏洞已被攻击   
THN  知机安全   2024-03-02 11:15  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfPp3dAJ2kUugdJZicy83I7QIA7icNh4edDLphElvef94DxmcGpE0zwkRfaLhUFHsXnbBr1ymZc0UIzw/640?wx_fmt=png "")  
  
The Five Eyes (FVEY) intelligence alliance has issued a new cybersecurity advisory warning of cyber threat actors exploiting known security flaws in Ivanti Connect Secure and Ivanti Policy Secure gateways, noting that the Integrity Checker Tool (ICT) can be deceived to provide a false sense of security.  
  
五眼（FVEY）情报联盟发布了一项新的网络安全咨询警告，指出网络威胁行为者正在利用Ivanti Connect Secure和Ivanti Policy Secure网关中已知的安全漏洞，并指出完整性检查工具（ICT）可能被欺骗以提供虚假的安全感。  
  
  
"Ivanti ICT is not sufficient to detect compromise and that a cyber threat actor may be able to gain root-level persistence despite issuing factory resets," the agencies said.  
  
"Ivanti ICT无法检测妥协，网络威胁行为者可能会获得根级持久性，尽管进行了出厂复位"，各机构表示。  
  
  
To date, Ivanti has disclosed five security vulnerabilities impacting its products since January 10, 2024, out of which four have come under active exploitation by multiple threat actors to deploy malware -  
  
迄今为止，自2024年1月10日以来，Ivanti已披露了五个影响其产品的安全漏洞，其中四个已被多个威胁行为者积极利用以部署恶意软件。  
  
- CVE-2023-46805 (CVSS score: 8.2) - Authentication bypass vulnerability in web component  
  
CVE-2023-46805（CVSS评分：8.2）- Web组件中的身份验证绕过漏洞  
  
  
- CVE-2024-21887 (CVSS score: 9.1) - Command injection vulnerability in web component  
  
CVE-2024-21887（CVSS评分：9.1）- Web组件中的命令注入漏洞  
  
  
- CVE-2024-21888 (CVSS score: 8.8) - Privilege escalation vulnerability in web component  
  
CVE-2024-21888（CVSS评分：8.8）- Web组件中的特权提升漏洞  
  
  
- CVE-2024-21893 (CVSS score: 8.2) - SSRF vulnerability in the SAML component  
  
CVE-2024-21893（CVSS评分：8.2）- SAML组件中的SSRF漏洞  
  
  
- CVE-2024-22024 (CVSS score: 8.3) - XXE vulnerability in the SAML component  
  
CVE-2024-22024（CVSS评分：8.3）- SAML组件中的XXE漏洞  
  
  
Mandiant, in an analysis published this week, described how an encrypted version of a malware known as BUSHWALK is placed in a directory excluded by ICT in /data/runtime/cockpit/diskAnalysis.  
  
Mandiant在本周发表的一篇分析中描述了一种名为BUSHWALK的恶意软件的加密版本如何被放置在ICT中排除的目录/data/runtime/cockpit/diskAnalysis中。  
  
  
The directory exclusions were also previously highlighted by Eclypsium this month, stating the tool skips a dozen directories from being scanned, thus allowing an attacker to leave behind backdoors in one of these paths and still pass the integrity check.  
  
Eclypsium本月也曾强调过目录排除，指出该工具跳过了十几个目录的扫描，因此允许攻击者在其中一个路径中留下后门并仍然通过完整性检查。  
  
  
"The safest course of action for network defenders is to assume a sophisticated threat actor may deploy rootkit level persistence on a device that has been reset and lay dormant for an arbitrary amount of time," agencies from Australia, Canada, New Zealand, the U.K., and the U.S. said.  
  
澳大利亚、加拿大、新西兰、英国和美国的机构表示，“网络防御者采取的最安全措施是假设一名复杂的威胁行为者可能在设备上部署根包级持久性，并在任意时间内保持休眠状态”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfPp3dAJ2kUugdJZicy83I7QIdYbZkrsO4AOrsSPmY4542lZ9P5aaFIkzJFW3SfKTLeQqgYhyHR5NPw/640?wx_fmt=png "")  
  
They also urged organizations to "consider the significant risk of adversary access to, and persistence on, Ivanti Connect Secure and Ivanti Policy Secure gateways when determining whether to continue operating these devices in an enterprise environment."  
  
他们还敦促组织在确定是否继续在企业环境中运行这些设备时“考虑对Ivanti Connect Secure和Ivanti Policy Secure网关的对手访问和持久性的重大风险”。  
  
  
Ivanti, in response to the advisory, said it's not aware of any instances of successful threat actor persistence following the implementation of security updates and factory resets. It's also releasing a new version of ICT that it said "provides additional visibility into a customer's appliance and all files that are present on the system."  
  
作为对咨询的回应，Ivanti表示，它不知晓在实施安全更新和出厂复位后成功的威胁行为者持久性的任何实例。该公司还发布了一个新版本的ICT，据称“提供了对客户设备和系统上存在的所有文件的额外可见性。”  
  
