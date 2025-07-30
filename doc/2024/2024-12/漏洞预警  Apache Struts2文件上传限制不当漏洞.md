#  漏洞预警 | Apache Struts2文件上传限制不当漏洞   
浅安  浅安安全   2024-12-20 00:02  
  
**0x00 漏洞编号**  
- # CVE-2024-53677  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Struts2是一个免费、开源的MVC框架，用于创建Java Web应用程序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVDY1k1EV3mQPDLmTdI33eb3QzvmIVC7HcvvMgtdtYQj6TomcOd5MjaKeicrJy7GZibiaPmACibOZvxdg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-53677**  
  
**漏洞类型：**  
文件上传限制不当****  
  
**影响：**  
上传恶意文件  
  
**简述：**  
Apache Struts2存在文件上传限制不当漏洞，由于其文件上传中存在逻辑缺陷，未经授权的攻击者可以操纵文件上传参数来启用路径遍历，上传可用于执行远程代码的恶意文件。  
  
**0x04 影响版本**  
- 2.0.0 <= Struts <= 2.3.37(EOL)  
  
- 2.5.0 <= Struts <= 2.5.33  
  
- 6.0.0 <= Struts <= 6.3.0.2  
  
**0x05 POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://struts.apache.org/  
  
  
  
