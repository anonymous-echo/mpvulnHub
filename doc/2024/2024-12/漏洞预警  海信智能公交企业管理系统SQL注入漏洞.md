#  漏洞预警 | 海信智能公交企业管理系统SQL注入漏洞   
浅安  浅安安全   2024-12-06 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
海信智能公交企业管理系统是一款专为公交企业打造的智能化管理平台，旨在提升公交运营效率和服务质量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVL22sXWZReVaj95PAsCUQ0KpOnGTmNMOwm38ECxVwdftIeHVBXiacl3MOvyMZicnVibibKSLLxwM2KibA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露****  
  
**简述：**  
海信智能公交企业管理系统的/YZSoft/Forms/XForm/BM/MaintainComManagement/AdjustWorkHours.aspx接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 海信智能公交企业管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.hisense-transtech.com.cn/  
  
  
  
