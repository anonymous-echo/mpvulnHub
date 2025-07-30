#  漏洞预警 | Adobe ColdFusion反序列化漏洞   
浅安  浅安安全   2025-01-03 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-53961  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Adobe ColdFusion是一个快速应用程序开发平台，其运行的CFML针对Web应用的一种脚本语言。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXAqMr1ficNFgzXiab1XQRowvUN93t6IOq9wiaOqUgiadPVU5xicErvibAZTmQUoGUG4EdiblhuHntfuV6Kw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-53961**  
  
**漏洞类型：**  
路径遍历  
  
**影响：**  
敏感信息泄露  
  
  
**简述：**  
Adobe ColdFusion存在路径遍历漏洞，该漏洞可能导致未经身份验证的远程攻击者绕过应用程序的访问限制，从而读取受限目录之外的文件或目录，成功利用该漏洞可能导致敏感信息泄露或系统数据被操纵。  
  
**0x04 影响版本**  
- Adobe ColdFusion 2023 <= Update 11  
  
- Adobe ColdFusion 2021 <= Update 17  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.adobe.com/cn/products/coldfusion-family.html  
  
  
  
