#  漏洞预警 | PAN-OS Web管理界面身份认证绕过漏洞   
浅安  浅安安全   2024-12-02 00:00  
  
**0x00 漏洞编号**  
- CVE-2024-0012  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
PAN-OS是运行Palo Alto Networks下一代防火墙的软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVWUkxxltiaJdA3BTAAzJwUKC9GCSQ2ZjAicD6UDCRZaL8VSWqokSlA1wjrPXxauJfOwzxToSibgRSSw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-0012**  
  
**漏洞类型：**  
身份认证绕过  
  
**影响：**  
越权访问  
  
**简述：**  
PAN-OS设备管理Web界面的/php/ztp_gate.php接口存在身份认证绕过漏洞，未经身份验证的远程攻击者可以通过网络访问管理Web界面，从而进行后续活动，包括修改设备配置、访问其他管理功能。  
  
**0x04 影响版本**  
- PAN-OS 10.2 < 10.2.12-h2  
  
- PAN-OS 11.0 < 11.0.6-h1  
  
- PAN-OS 11.1 < 11.1.5-h1  
  
- PAN-OS 11.2 < 11.2.4-h1  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.paloaltonetworks.cn/  
  
  
  
