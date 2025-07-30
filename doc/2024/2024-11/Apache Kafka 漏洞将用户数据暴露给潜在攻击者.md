#  Apache Kafka 漏洞将用户数据暴露给潜在攻击者   
 独眼情报   2024-11-19 03:35  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTYCWic3W1Qtc8OVeHiaDdv8Hz6f5VyvmYlODn0yYstJicBrDkibRFTVENkRBib97eqm4LdIZJbEXfUHYA/640?wx_fmt=png&from=appmsg "")  
  
流行的开源事件流平台 Apache Kafka 中最近发现了一个漏洞，攻击者可以利用该漏洞未经授权访问敏感信息。该漏洞的编号为 CVE-2024-31141，影响了 Apache Kafka 客户端的多个版本，可能会影响依赖该平台进行关键数据操作的数千家公司。  
  
该漏洞源于 Apache Kafka 客户端处理配置数据的方式。根据官方安全公告，“ Apache Kafka 客户端接受配置数据以自定义行为，并包含 ConfigProvider 插件以操纵这些配置。”这种机制虽然旨在提高灵活性，但却无意中为攻击者打开了一扇大门。  
  
该通报进一步解释说：“ Apache Kafka 还提供了 FileConfigProvider、DirectoryConfigProvider 和 EnvVarConfigProvider 实现，其中包括从磁盘或环境变量读取的能力。在 Apache Kafka 客户端配置可以由不受信任的一方指定的应用程序中，攻击者可能会使用这些 ConfigProvider 读取磁盘和环境变量的任意内容。”  
  
本质上，这意味着在某些配置中，恶意行为者可以利用此漏洞访问敏感文件和环境变量。这在 SaaS 产品等环境中尤其令人担忧，该咨询指出，“此漏洞可能会在 Apache Kafka Connect 中用于从 REST API 访问升级到文件系统 / 环境访问，这可能是不受欢迎的。”  
  
Apache Kafka 项目已敦促用户立即采取行动以降低风险。他们建议将 kafka-clients 升级到3.8.0 或更高版本，并设置 JVM 系统属性“ org.apache.kafka.automatic.config.providers=none ”。  
  
但是，该公告还警告称，不应为 Kafka Broker、Kafka MirrorMaker 2.0、Kafka Streams 和 Kafka 命令行工具的用户设置此系统属性。此外，建议使用特定 ConfigProvider 实现的 Kafka Connect 用户实施“allowlist.pattern”和“llowed.paths”来限制访问。  
  
  
