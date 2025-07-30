#  漏洞预警 | 维达外贸客户关系管理系统SQL注入漏洞   
浅安  浅安安全   2025-04-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
维达外贸客户关系管理系统是一款由维达外贸软件公司研发，专注于外贸企业客户关系管理，集客户信息管理、销售流程跟踪、市场分析等功能于一体，帮助外贸企业提升客户关系管理效率、优化业务流程、实现业绩增长的管理软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVxJ5jObaWToJibbGsfXSBDgib9cWH88KfKOdy5v0micfOk5PfgUxcjWJDuootwMfysEeGYMWuWlsdVg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
维达外贸客户关系管理系统的/wap/common/sendmailview.jsp接口存在SQL注入漏洞，未经身份验证得攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 维达外贸客户关系管理系统  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.weidasoft.com/  
  
  
  
