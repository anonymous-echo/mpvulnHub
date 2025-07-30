#  漏洞预警 | 万户ezOFFICE SQL注入漏洞   
浅安  浅安安全   2025-05-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
万户ezOFFICE协同管理平台是一个综合信息基础应用平台分为企业版和政务版。解决方案由五大应用、两个支撑平台组成，分别为知识管理、工作流程、沟通交流、辅助办公、集成解决方案及应用支撑平台、基础支撑平台。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVeemR7wLPNZGZtdPjw4eLqOVVq8ryDyFuM9m1TXH2Sy7dMzlFrVt1Yf6Fz75gLLqAwmxy3IrxzVg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
万户ezOFFICE的  
  
/defaultroot/modules/govoffice/gov_documentmanager/govdocumentmanager_judge_receivenum.jsp;.js  
  
接口存在SQL注入漏洞，恶意攻击者可利用此漏洞获取数据库信息，获取服务器敏感信息。  
  
**0x04 影响版本**  
- 万户ezOFFICE 11.5.0.12_SP_20161110  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.whir.net/  
  
  
  
