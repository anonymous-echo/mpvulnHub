#  【漏洞通告】Apache Kafka多个高危漏洞安全风险通告  
 嘉诚安全   2025-06-11 08:34  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
Apache Kafka多个高危漏洞，漏洞编号为：  
CVE-2025-27817、CVE-2025-27818、CVE-2025-27819  
。  
  
  
Apache Kafka是一款开源的分布式事件流平台，广泛用于高性能数据管道、流式分析和数据集成。它支持高吞吐量的消息传递，具备可扩展性、持久化存储和高可用性等特点，能够处理海量数据并支持多种编程语言的客户端库。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
。  
  
CVE-2025-27817攻击者可以利用该漏洞，读取服务器上的敏感文件（如配置文件、环境变量等），或者发起SSRF攻击，访问内部网络或其他受限资源，从而获取敏感信息或进一步扩大攻击范围。  
  
CVE-2025-27818攻击者可以利用该漏洞通过精心构造的LDAP响应，触发Java反序列化漏洞，从而在Kafka Connect服务器上执行任意代码，获取服务器的控制权或进一步攻击其他系统。  
  
CVE-2025-27819攻击者可以利用该漏洞，通过精心构造的JNDI配置，连接到攻击者控制的LDAP或RMI服务器，并反序列化恶意响应，从而在Kafka服务器上执行任意代码或导致服务不可用  
。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
CVE-2025-27817：  
  
3.1.0 <= Apache Kafka <= 3.9.0  
  
CVE-2025-27818：  
  
2.3.0 <= Apache Kafka <= 3.9.0  
  
CVE-2025-27819：  
  
2.0.0 <= Apache Kafka <= 3.3.2  
  
**处置建议**  
  
  
  
  
  
  
  
  
官方修复方案：  
  
建议用户尽快升级到以下或更高的安全版本：  
  
Apache Kafka 3.9.1   
  
Apache Kafka 4.0.0   
  
官方补丁下载链接：  
  
https://kafka.apache.org/downloads  
  
临时缓解措施：  
  
对于使用受影响版本的用户，建议通过系统属性-  
  
Dorg.apache.kafka.disallowed.login.modules禁用  
  
LdapLoginModule，JndiLoginModule 和其他危险的登录模块。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
