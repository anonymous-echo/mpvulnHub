#  漏洞预警 | 杜特网上订单管理系统SQL注入漏洞   
浅安  浅安安全   2024-12-26 00:04  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
杜特网上订单管理系统是一款专为门窗行业设计的高效订单管理工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVLNvdLkO9wEiaL55HVyibFlmiaup2rnpJ7qV5ruibtw9O0w1RJE2xMaj04f188LT9FKZCDibZ5qod7sCg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
杜特网上订单管理系统的/ajax/getUserImage.ashx接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 杜特网上订单管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.fstutor.com/  
  
  
  
