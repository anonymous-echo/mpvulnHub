#  漏洞预警 | 平升电子水库安全监管平台SQL注入漏洞   
浅安  浅安安全   2025-02-14 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
平升电子水库安全监管平台通过实时监测、数据分析、预警系统和远程控制等功能，为水库管理部门提供了一种全面、高效的数字化解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SViaXBcPmqLJsna89wudwQ1UOVkLh0n9O9bMVeOsP9d477CX6Otf4y1lCY1OGM2Fnt0Gskofc41l1A/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
平升电子水库安全监管平台的/WebServices/DataBaseService.asmx/GetRecordsByTableNameAndColumns接口处存在SQL注入漏洞，经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 平升电子水库安全监管平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.data86.com/  
  
  
  
