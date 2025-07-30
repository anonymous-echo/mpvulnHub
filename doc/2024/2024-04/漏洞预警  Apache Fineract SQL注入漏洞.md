#  漏洞预警 | Apache Fineract SQL注入漏洞   
浅安  浅安安全   2024-04-04 09:01  
  
**0x00 漏洞编号**  
- # CVE-2024-23539  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Fineract是一个开源的金融服务平台,旨在为全球范围内的金融机构提供可靠和可扩展的解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXGQIIlHG6aTeP4zxVCPMbbK7eKrgUWHFVXniaF17lESPG4lFSd0HGLByJVLeINjeyCAMiaLsxmLGcQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-23539**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
在Apache Fineract 1.8.4及之前版本存在sql注入漏洞，由于系统未对参数sqlSearch做过滤操作，导致经过授权的用户通过sqlserver参数的恶意构造可获取数据库敏感信息，导致信息泄露。  
###   
  
**0x04 影响版本**  
- Apache Fineract < 1.9.0  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://github.com/apache/fineract/  
  
  
  
