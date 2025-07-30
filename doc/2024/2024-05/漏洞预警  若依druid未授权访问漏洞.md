#  漏洞预警 | 若依druid未授权访问漏洞   
浅安  浅安安全   2024-05-01 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
若依框架是一款基于Spring Boot、Spring Cloud、OAuth2与JWT鉴权等核心技术的快速开发平台。它支持多种安全框架和持久化框架，并采用前后端分离的模式进行开发，具备高度的灵活性和可扩展性。若依框架提供了丰富的功能模块，如用户管理、角色管理、菜单管理、定时任务等，适用于企业级应用的快速搭建。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWr1DyGUwYJ0277PmtzdjqEVofWaPK6QuUpfp1ZhbibE7aMovybQ2qp5nanvYQy6ticJuicYC9EQq1EQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
未授权访问  
  
**影响：**  
获取敏感信息  
  
**简述：**  
若依框架存在未授权访问漏洞，攻击者可以通过该漏洞获取大量敏感信息。  
###   
  
**0x04 影响版本**  
- 若依管理系统  
  
**0x05****POC**  
  
https://github.com/MY0723/goby-poc/blob/4350273252bbf6b5842f8e709a97fb747329b67a/RuoYi_Druid_Unauthorized_access.json  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://gitee.com/y_project/RuoYi-Vue  
  
  
  
