#  漏洞预警 | Apache Kafka任意文件读取和远程代码执行漏洞  
浅安  浅安安全   2025-06-12 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-27817  
  
- # CVE-2025-27818  
  
- # CVE-2025-27819  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Kafka是一个开源分布式事件流平台，通常用于高性能数据管道、流分析、数据集成和和关键任务应用，ZooKeeper通常用于管理Kafka集群的元数据，而KRaft模式则通过Raft协议直接在Kafka集群内部处理这些元数据。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWHcjWpJoIKtCyjMJqic5AxepWNDabZ1Qq0SXosKNCJQfAKhHAnR81ic3FsTmMuS1UachEZDCIYQ8FQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-27817**  
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
  
  
**简述：**  
Apache Kafka Client中存在任意文件读取与SSRF漏洞，攻击者可通过配置sasl.oauthbearer.token.endpoint.url和sasl.oauthbearer.jwks.endpoint.url参数，读取服务器磁盘文件、环境变量，或向任意目标地址发起请求。  
  
**CVE-2025-27818**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
  
  
**简述：**  
Apache Kafka存在LDAP远程代码执行漏洞，攻击者可通过Kafka Connect配置中的sasl.jaas.config参数，将Kafka客户端指向恶意LDAP服务器，诱导服务器反序列化不可信数据，从而实现任意代码执行。  
  
**CVE-2025-27819**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
  
  
**简述：**  
Apache Kafka Broker存在JNDI远程代码执行漏洞，攻击者如具备AlterConfigs权限，可通过修改SASL JAAS配置启用JndiLoginModule，诱使Broker连接至恶意JNDI服务，触发Java反序列化链，最终导致任意代码执行或拒绝服务攻击。  
  
**0x04 影响版本**  
  
CVE-2025-27817  
- 3.1.0 <= Apache Kafka <= 3.9.0  
  
CVE-2025-27818  
- 2.3.0 <= Apache Kafka <= 3.9.0  
  
CVE-2025-27819  
- 2.0.0 <= Apache Kafka <= 3.3.2  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://kafka.apache.org/  
  
  
  
