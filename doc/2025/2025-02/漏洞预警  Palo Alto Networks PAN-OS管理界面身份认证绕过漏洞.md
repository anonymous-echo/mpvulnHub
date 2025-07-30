#  漏洞预警 | Palo Alto Networks PAN-OS管理界面身份认证绕过漏洞   
浅安  浅安安全   2025-02-15 00:00  
  
**0x00 漏洞编号**  
- CVE-2025-0108  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Palo Alto Networks PAN-OS 是一款由Palo Alto Networks开发的下一代防火墙操作系统，提供全面的网络安全功能，包括深度包检测、入侵防御、应用控制、URL过滤、恶意软件防护等。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVWUkxxltiaJdA3BTAAzJwUKC9GCSQ2ZjAicD6UDCRZaL8VSWqokSlA1wjrPXxauJfOwzxToSibgRSSw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-0108**  
  
**漏洞类型：**  
身份认证绕过  
  
**影响：**  
越权访问  
  
**简述：**  
Palo Alto Networks PAN-OS管理界面存在认证绕过漏洞，未经身份验证的攻击者可通过网络访问管理界面，进而绕过身份验证机制。  
  
**0x04 影响版本**  
- PAN OS 11.2 < 11.2.4-h4  
  
- PAN OS 11.1 < 11.1.6-h1  
  
- PAN OS 10.2 < 10.2.13-h3  
  
- PAN OS 10.1 < 10.1.14-h9  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.paloaltonetworks.cn/  
  
  
  
