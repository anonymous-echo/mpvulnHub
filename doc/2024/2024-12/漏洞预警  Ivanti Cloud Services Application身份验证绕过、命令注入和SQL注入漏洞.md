#  漏洞预警 | Ivanti Cloud Services Application身份验证绕过、命令注入和SQL注入漏洞   
浅安  浅安安全   2024-12-19 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-11639  
  
- # CVE-2024-11772  
  
- # CVE-2024-11773  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Ivanti Cloud Services Appliance是一个面向企业的解决方案，专注于为远程设备管理提供安全通信渠道，它通过与Ivanti的其他产品的集成，帮助企业实现更高效的IT操作和增强的安全性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVCNHFLfHUWEkjmS3Eg21R1I6cf8JMqSzdkzMnDJ7Aia6L8CRiaSPkm3bMnnVA2EaIiciadAibQic8O56icw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-11639**  
  
**漏洞类型：**  
身份验证绕过  
  
**影响：**  
越权访问  
  
**简述：**  
Ivanti CSA在管理Web控制台中存在身份验证绕过漏洞，未经身份验证的远程攻击者可利用该漏洞获取管理访问权限，从而可能导致敏感信息泄露、篡改配置/设置或执行其他恶意操作。  
  
**CVE-2024-11772**  
  
**漏洞类型：**  
命令注入  
  
**影响：**  
执行任意命令  
  
**简述：**  
Ivanti CSA在管理Web控制台中存在命令注入漏洞，经过身份验证且拥有管理员权限的远程攻击者可利用该漏洞实现远程代码执行。  
### CVE-2024-11773  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
Ivanti CSA在管理Web控制台中存在SQL注入漏洞，经过身份验证且拥有管理员权限的远程攻击者可利用该漏洞运行任意SQL语句，从而可能导致获取敏感信息、篡改或删除数据库、提升权限等。  
  
**0x04 影响版本**  
- Ivanti Cloud Services Application (CSA) <= 5.0.2  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.ivanti.com.cn/  
  
  
  
