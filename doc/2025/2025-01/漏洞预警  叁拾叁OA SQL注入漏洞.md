#  漏洞预警 | 叁拾叁OA SQL注入漏洞   
浅安  浅安安全   2025-01-22 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
叁拾叁OA是一款面向企业的办公自动化软件，主要目的是通过信息化手段提升企业的办公效率，帮助组织实现办公流程的自动化、信息的集成和共享，从而提升管理水平和工作效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVEYE88gHDMwXbdwCrcVj1qOuic50607wj5khiaicjoLiacrecqmo4NF21ohgaFs3vjmyWVHHWMhkpklw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
叁拾叁OA的/login接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 叁拾叁OA  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://33iot.com/  
  
  
  
