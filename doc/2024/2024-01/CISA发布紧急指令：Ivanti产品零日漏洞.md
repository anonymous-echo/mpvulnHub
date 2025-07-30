#  CISA发布紧急指令：Ivanti产品零日漏洞   
THN  知机安全   2024-01-21 13:26  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfPDfBcOlXOr5ibIuEj0TxC3k2Bj2s97wOZZD5A74IJcxZqFbmshrpDUfRjqSiboVzYJeKJUVwWWoE9w/640?wx_fmt=webp&from=appmsg "")  
  
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) on Friday issued an emergency directive  
 urging Federal Civilian Executive Branch (FCEB) agencies to implement mitigations against two actively exploited zero-day flaws in Ivanti Connect Secure (ICS) and Ivanti Policy Secure (IPS) products.  
  
美国网络安全和基础设施安全局（CISA）于周五发布了一份紧急指令，敦促联邦行政机构（FCEB）采取措施，针对Ivanti Connect Secure（ICS）和Ivanti Policy Secure（IPS）产品中的两个正在被积极利用的零日漏洞实施缓解措施。  
  
The development came after the vulnerabilities – an authentication bypass (CVE-2023-46805) and a code injection bug (CVE-2024-21887) – came under widespread exploitation of vulnerabilities by multiple threat actors. The flaws allow a malicious actor to craft malicious requests and execute arbitrary commands on the system.  
  
此举发生在多个威胁行为者广泛利用Ivanti Connect Secure（ICS）和Ivanti Policy Secure（IPS）产品的两个零日漏洞——身份验证绕过（CVE-2023-46805）和代码注入漏洞（CVE-2024-21887）之后。这些漏洞允许恶意行为者制作恶意请求并在系统上执行任意命令。  
  
The U.S. company acknowledged in an advisory that it has witnessed a "sharp increase in threat actor activity" starting on January 11, 2024, after the shortcomings were publicly disclosed.  
  
美国公司在一份咨询中承认，自2024年1月11日漏洞公开披露后，它已经注意到"威胁行为活动急剧增加"。  
  
"Successful exploitation of the vulnerabilities in these affected products allows a malicious threat actor to move laterally, perform data exfiltration, and establish persistent system access, resulting in full compromise of target information systems," the agency said.  
  
"成功利用这些受影响产品的漏洞允许恶意威胁行为者横向移动，执行数据外泄，并建立持久的系统访问，导致目标信息系统完全被 compromise，" 该机构表示。  
  
Ivanti, which is expected to release an update to address the flaws next week, has made available a temporary workaround through an XML file that can be imported into affected products to make necessary configuration changes.  
  
预计Ivanti将在下周发布更新来解决这些漏洞，并提供一个通过XML文件进行临时解决方案，可以导入到受影响的产品中进行必要的配置更改。  
  
CISA is urging organizations running ICS to apply the mitigation and run an External Integrity Checker Tool to identify signs of compromise, and if found, disconnect them from the networks and reset the device, followed by importing the XML file.  
  
CISA敦促运行ICS的组织应用缓解措施并运行外部完整性检查工具来识别 compromise 迹象，如果发现，断开它们与网络的连接并重置设备，然后导入XML文件。  
  
In addition, FCEB entities are urged to revoke and reissue any stored certificates, reset the admin enable password, store API keys, and reset the passwords of any local user defined on the gateway.  
  
此外，FCEB实体被敦促吊销并重新签发任何存储的证书，重置管理员启用密码，存储API密钥，并重置网关上定义的任何本地用户的密码。  
  
Cybersecurity firms Volexity and Mandiant have observed attacks weaponizing the twin flaws to deploy web shells and passive backdoors for persistent access to compromised appliances. As many as 2,100 devices worldwide are estimated to have been compromised to date.  
  
网络安全公司Volexity和Mandiant已观察到攻击者正在利用这两个缺陷部署Web Shell和被动后门，以持久访问受 攻击 的设备。全球范围内估计已有2,100台设备受到 攻击。  
  
Threat intelligence firm GreyNoise said it has also observed the vulnerabilities being abused to drop persistent backdoors and XMRig cryptocurrency miners, indicating opportunistic exploitation by bad actors for financial gain.  
  
威胁情报公司GreyNoise表示，它还观察到攻击者滥用这些漏洞来部署持久后门和XMRig加密货币挖矿机，表明恶意行为者出于经济利益的目的进行机会主义性的滥用。  
  
