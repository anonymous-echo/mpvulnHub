#  漏洞预警 | 家装ERP管理系统SQL注入漏洞   
浅安  浅安安全   2025-01-20 00:01  
  
**0x00 漏洞编号**  
- 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
家装ERP管理系统是一种专为家装行业设计的企业资源计划管理软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVzMC5PhTRfg5YJicJicoQSeX8J47yfBsJJ5gFHoaWibjxcEGaqOjoDarEqL022cPhnpiahDV7vDsx5kQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露  
  
**简述：**  
家装ERP管理系统的/WEB_SERVICE/Public.asmx/GetDs接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 家装ERP管理系统  
  
**0x05 POC状态**  
- 已公开  
  
**0x06 修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本**  
**：**  
  
http://www.znfit.com/  
  
  
  
