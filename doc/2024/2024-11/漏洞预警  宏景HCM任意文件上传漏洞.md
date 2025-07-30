#  漏洞预警 | 宏景HCM任意文件上传漏洞   
浅安  浅安安全   2024-11-18 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
宏景人力资源管理软件是一款人力资源管理与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7stTqD182SXhZfJGiaXfdjmnmnU9CcG6XajFjVjAA4Jno8LwWB1ia5Py19wpjxzZ7EOR0eoXNIfiaiceHt9Siby29Sg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
任意文件上传  
  
**影响：**  
上传恶意脚本****  
  
**简述：**  
宏景HCM的/sys/cms/uploadLogo.do接口存在任意文件上传漏洞，未经身份验证的攻击者可以通过该漏洞上传恶意脚本文件到服务器，从而控制目标服务器。  
###   
  
**0x04 影响版本**  
- 宏景HCM  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.hjehr.com/  
  
  
  
