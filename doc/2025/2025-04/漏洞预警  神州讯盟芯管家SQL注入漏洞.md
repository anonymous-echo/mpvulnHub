#  漏洞预警 | 神州讯盟芯管家SQL注入漏洞   
浅安  浅安安全   2025-04-21 00:00  
  
**0x00 漏洞编号**  
- 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
神州讯盟芯管家是深圳神州讯盟软件有限公司专门针对电子元器件行业特点和业务流程研发的管理软件，具有智能分配、大数据匹配报价等功能，有多种版本以满足不同企业需求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWGh7pRWFjYibK2XqwsE4Jcz6XCMY8lAeZVztoybJvAiaJV6HzTAuJicbL2aolP3QtDqqZ8HtQSAzVMg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露  
  
**简述：**  
神州讯盟芯管家的/login_confirm.jsp接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 神州讯盟芯管家  
  
**0x05 POC状态**  
- 已公开  
  
**0x06 修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本**  
**：**  
  
http://sunmochina.com/  
  
  
  
