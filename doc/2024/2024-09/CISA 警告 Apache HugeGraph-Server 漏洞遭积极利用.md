#  CISA 警告 Apache HugeGraph-Server 漏洞遭积极利用   
Rhinoer  犀牛安全   2024-09-26 06:20  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkxw9H6xwors31sSIO6CKaRItHibJ9SLGJdkZPkYeNhYcpIUf1iclib2hmTsMssBasHekicQVhOT8szzA/640?wx_fmt=png&from=appmsg "")  
  
美国网络安全和基础设施局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加了五个漏洞，其中包括影响 Apache HugeGraph-Server 的远程代码执行 (RCE) 漏洞。  
  
该漏洞的编号为CVE-2024-27348，级别为严重（CVSS v3.1 评分：9.8），是一个不当的访问控制漏洞，影响 HugeGraph-Server 1.0.0 及以上版本（但不包括 1.3.0）。  
  
Apache于 2024 年 4 月 22 日发布 1.3.0 版本修复了该漏洞。除了升级到最新版本外，还建议用户使用 Java 11 并启用 Auth 系统。  
  
此外，还提出了启用“白名单IP/端口”功能以提高RESTful-API执行的安全性，该功能涉及潜在的攻击链。  
  
现在，CISA 警告称，已经发现有人在野外积极利用CVE-2024-27348 ，并要求联邦机构和其他关键基础设施组织必须在 2024 年 10 月 9 日之前采取缓解措施或停止使用该产品。  
  
Apache HugeGraph-Server 是Apache HugeGraph项目的核心组件，这是一个开源图形数据库，旨在以高性能和可扩展性处理大规模图形数据，支持深度关系开发、数据聚类和路径搜索所需的复杂操作。  
  
该产品主要被电信供应商用于欺诈检测和网络分析、金融服务用于风险控制和交易模式分析、社交网络用于连接分析和自动推荐系统。  
  
随着积极开发的进行和产品在高价值企业环境中的使用，尽快应用可用的安全更新和缓解措施势在必行。  
  
此次 KEV 中新增的另外四个缺陷为：  
- CVE-2020-0618：Microsoft SQL Server Reporting Services 远程代码执行漏洞  
  
- CVE-2019-1069：Microsoft Windows 任务计划程序权限提升漏洞  
  
- CVE-2022-21445：Oracle JDeveloper 远程代码执行漏洞  
  
- CVE-2020-14644：Oracle WebLogic Server 远程代码执行漏洞  
  
这些旧漏洞的纳入并不表示最近存在利用，而是通过记录已确认在过去某个时间点的攻击中被利用的安全漏洞，丰富了 KEV 目录。  
  
  
信息来源：BleepingComputer  
  
