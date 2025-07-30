#  漏洞预警 | 飞企互联FE业务协作平台任意文件读取漏洞   
浅安  浅安安全   2025-05-20 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
数夫CRM客户关系管理系统是专为家居、家具等制造业深度定制的全流程客户管理平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVaVytqmJZ0nCkILbcyKBMSpyGgjicAIgeUibFkMJtH7IicocgF7rhu6dSAX9CXYtiazYotJWxbEpCpDA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
文件读取  
  
  
**影响：**  
获取敏感信息****  
  
**简述：**  
数夫CRM客户关系管理系统的/Web/common/Handler/file_download.ashx存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取服务器大量敏感信息。  
  
**0x04 影响版本**  
- 数夫CRM客户关系管理系统  
  
**0x05****POC****状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.soonfor.com/  
  
  
  
