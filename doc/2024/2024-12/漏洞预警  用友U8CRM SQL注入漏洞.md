#  漏洞预警 | 用友U8CRM SQL注入漏洞   
浅安  浅安安全   2024-12-18 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友U8CRM是一款功能全面、灵活定制的客户关系管理软件，能够帮助企业建立健全、改善与客户之间的关系，提高客户满意度和获利能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVu3P6aBo1Yk94n6hrnfSbsrCicicVAEYDxVaLIbE9eqnNdW0VVAC3mvYcpXITbq5ZgnfW7A86j7t7g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
用友U8CRM客户关系管理系统的/config/rellistname.php接口存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xp_cmdshell写入后门文件，执行任意代码，从而获取到服务器权限。  
  
**0x04 影响版本**  
- 用友U8-CRM  
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.itusing.com/  
  
  
  
