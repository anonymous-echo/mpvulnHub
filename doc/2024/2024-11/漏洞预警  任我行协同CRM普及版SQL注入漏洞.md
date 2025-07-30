#  漏洞预警 | 任我行协同CRM普及版SQL注入漏洞   
浅安  浅安安全   2024-11-29 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
任我行协同CRM普及版是由成都市任我行信息技术有限公司开发的一款客户关系管理软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVjdb8W7T5YIrddGeQMLUBTCITc7yqk7uWHwE3mjHRib4icEDBqxTK6z5RiakIkyfEpK4G50puGmyAyQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露****  
  
**简述：**  
任我行协同CRM普及版的/crm/api/OpenApi/CommonDict/Edit接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 任我行协同CRM普及版  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.wecrm.com/  
  
  
  
