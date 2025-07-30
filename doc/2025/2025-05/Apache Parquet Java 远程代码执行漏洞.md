#  Apache Parquet Java 远程代码执行漏洞   
 网安百色   2025-05-05 11:26  
  
在 Apache Parquet Java 中发现一个高严重性漏洞 （CVE-2025-46762），该漏洞使使用 parquet-avro 模块的系统面临远程代码执行 （RCE） 攻击。  
  
Apache Parquet 贡献者 Gang Wu 于 2025 年 5 月 2 日披露了该漏洞，该漏洞影响了 1.15.1 及以下版本。  
  
漏洞的技术细分  
  
该漏洞源于 parquet-avro 模块中不安全的架构解析。攻击者可以在 Parquet 文件元数据中嵌入恶意代码，当易受攻击的系统读取文件的 Avro 架构时，该元数据会自动执行。  
  
虽然 Apache Parquet 1.15.1 通过限制不受信任的包引入了部分缓解措施，但其默认的“受信任的包”配置仍然允许从预先批准的 Java 包（例如 java.util）执行代码。  
  
需要使用 “specific” 或 “reflect” 数据模型（而不是更安全的 “generic” 模型）。  
  
易受攻击的系统必须处理攻击者控制的 Parquet 文件。  
  
受影响的系统  
  
所有 Apache Parquet Java 版本≤ 1.15.1。  
  
利用 parquet-avro 在 Apache Spark、Hadoop 或 Flink 等大数据框架中进行反序列化的应用程序。  
  
缓解策略  
  
Apache Software Group 建议立即采取行动：  
  
升级到 Parquet Java 1.15.2，它通过收紧软件包信任边界完全解决了该问题。  
  
对于卡在 1.15.1 上的系统，请设置 JVM 系统属性：  
  
-Dorg.apache.parquet.avro.SERIALIZABLE_PACKAGES=（空字符串）。  
  
组织还应审核数据管道，以确保尽可能使用 “通用” Avro 模型，因为它不受此漏洞的影响。  
  
安全专家警告说，未打补丁的系统面临供应链攻击的风险，其中损坏的 Parquet 文件会触发后端漏洞。  
  
“这是一个教科书式的例子，说明序列化漏洞如何绕过边界防御，”网络安全公司 DataShield 的首席技术官 Maria Chen 说。“攻击者可以将常见数据格式作为武器来渗透分析平台。”  
  
Apache 团队发布了更新的文档，强调了 Avro 架构处理的安全配置实践。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
