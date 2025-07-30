#  漏洞预警 | JEEWMS任意文件读取漏洞   
浅安  浅安安全   2025-05-29 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
JEEWMS基于JAVA的仓库管理系统，包含PDA端和WEB端，功能涵盖WMS、OMS、BMS、TMS。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SV5c5fjMPRA8L7bFrkibpMUW5zfvTx0EzgSfXq1p3JdQsULDGic38X1VvEEenMmdEscsTfP1p4HXujA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
**简述：**  
JEEWMS的  
/systemController/showOrDownByurl.do/../../cgformTemplateController.do?showPic=11和/wmsApiController.do/../cgformTemplateController.do?showPic=11接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取服务器敏感信息。  
  
**0x04 影响版本**  
- JEEWMS  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.huayi-tec.com/  
  
  
  
