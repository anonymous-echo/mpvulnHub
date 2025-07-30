#  微软Copilot Studio存在严重的信息泄露漏洞   
鹏鹏同学  黑猫安全   2024-08-22 11:27  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce8mUnuZHLyF46ENb6a1BCZ7eAqXEFu8BbJs2X19hnWWbmdCUzSZ4TbOMKqJz2sHX9Q33znefZVOVw/640?wx_fmt=png&from=appmsg "")  
  
微软Copilot Studio存在严重的安全漏洞，CVE-2024-38206编号，CVSS评分8.5分。攻击者可以利用漏洞访问敏感信息。漏洞是一种信息泄露漏洞，源于服务器端请求 forgery（SSRF）攻击。微软发布的安全通报中写道：“已认证的攻击者可以绕过Microsoft Copilot Studio的服务器端请求 forgery保护，泄露网络上的敏感信息。”  
  
微软确认漏洞已被完全修复，没有用户需要采取任何行动。漏洞由Tenable的安全研究员Evan Grant报告。报告中写道：“我们检查了Copilot Studio中的服务器端请求 forgery漏洞，该漏洞利用Copilot Studio的能力来执行外部网络请求。结合SSRF保护绕过，我们使用该漏洞访问Microsoft Copilot Studio的内部基础设施，包括实例元数据服务（IMDS）和内部Cosmos DB实例。”  
  
T  
enable研究人员解释，漏洞允许攻击者利用Copilot Studio执行HTTP请求，通过操纵HTTP头和使用重定向技术绕过保护，访问敏感云资源，包括实例元数据服务（IMDS）。  
攻击者可以利用该漏洞获取实例元数据和管理标识访问令牌，潜在地允许未经授权的访问其他内部Azure资源。  
研究人员还解释，他们使用访问令牌探索Azure订阅，发现了一个Cosmos DB资源。  
虽然该数据库被限制于Microsoft内部基础设施，但Copilot Studio的能力执行HTTP请求使其可以访问。  
研究人员成功获取了内部Cosmos DB实例的读写访问权限，生成了有效的授权令牌，并使用合适的头部。  
  
报告中写道：  
“我们从多个租户测试了该漏洞，并确认该基础设施用于Copilot Studio服务在租户之间共享。  
对该基础设施的任何影响都可能影响多个客户。  
虽然我们不知道该基础设施的影响可能有多大，但很 clear，因为它在租户之间共享，风险加剧。  
”“我们还确定，我们可以无限制地访问内部主机，位于本地子网（10.0.x.0/24）中的我们的实例所属子网。  
”  
  
  
