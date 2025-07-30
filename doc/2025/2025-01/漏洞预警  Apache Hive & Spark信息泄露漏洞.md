#  漏洞预警 | Apache Hive & Spark信息泄露漏洞   
浅安  浅安安全   2025-01-01 00:01  
  
**0x00 漏洞编号**  
- # CVE-2024-23945  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Hive和Apache Spark是两个广泛用于大数据生态系统的开源框架，主要用于处理和分析大规模数据集。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVSezp9oVjJCRe69VSP3FVmWv9iaQbc93cLqbNR9faeshpXlDC4Hy0641G3M3fXyPXrfeUtvnOm6nQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-23945**  
  
**漏洞类型：**  
信息泄露  
  
**影响：**  
未授权访问  
  
**简述：**  
Apache Hive和Apache Spark的CookieSigner逻辑存在安全漏洞，当签名验证失败时，系统错误地将正确的签名值暴露给用户，导致攻击者可以通过构造错误的Cookie请求触发签名验证失败并获取有效签名，成功利用该漏洞可能允许攻击者伪造合法的Cookie，从而绕过认证机制，导致未授权访问，并可能进一步引发会话劫持、权限提升等攻击。  
  
**0x04 影响版本**  
- 1.2.0 <= Apache Hive < 4.0.0  
  
- 2.0.0 <= Apache Spark < 3.0.0  
  
- 3.0.0 <= Apache Spark < 3.3.4  
  
- 3.4.0 <= Apache Spark < 3.4.2  
  
- Apache Spark 3.5.0  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.apache.org/  
  
  
  
