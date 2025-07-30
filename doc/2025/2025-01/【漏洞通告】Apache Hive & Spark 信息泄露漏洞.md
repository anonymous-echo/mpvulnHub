#  【漏洞通告】Apache Hive & Spark 信息泄露漏洞   
 安迈信科应急响应中心   2025-01-02 06:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况      在 Apache Hive 和 Apache Spark 这两个广泛用于大规模数据处理和分析的系统中发现了一个新披露漏洞CVE-2024-23945，该漏洞影响 CookieSigner 机制，在消息验证失败时会暴露有效的 cookie 签名，从而绕过认证机制，导致未授权访问和敏感信息泄露。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称Apache Hive & Spark 信息泄露漏洞漏洞编号CVE编号CVE-2024-23945‍漏洞评估披露时间2024-12-26漏洞类型信息泄露危害评级高危公开程度PoC未公开威胁类型远程利用情报在野利用是影响产品产品名称 Apache Hive受影响版本1.2.0 ≤ Apache Hive < 4.0.0,2.0.0 ≤ Apache Spark < 3.0.0,3.0.0 ≤ Apache Spark < 3.3.4,3.4.0 ≤ Apache Spark < 3.4.2,Apache Spark 3.5.0影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查应用系统Apache Hive应用版本。若存在应用使用，极大可能会受到影响。04 修复方案官方已发布最新版本修复该漏洞，建议受影响用户将Apache Hive 和 Apache Spark更新到安全版本以上。Apache Hive >= 4.0.0Apache Spark >= 3.0.0Apache Spark 3.0.0 >= 3.3.4Apache Spark 3.4.0 >= 3.4.2Apache Spark 3.5.0 >= 3.5.1下载链接：https://github.com/apache/spark/tagshttps://hive.apache.org/general/downloads/05 时间线      2024.12.23 厂商发布安全补丁      2025.01.02 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
