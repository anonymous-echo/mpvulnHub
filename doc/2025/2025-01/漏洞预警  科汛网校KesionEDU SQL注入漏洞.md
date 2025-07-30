#  漏洞预警 | 科汛网校KesionEDU SQL注入漏洞   
浅安  浅安安全   2025-01-07 00:01  
  
**0x00 漏洞编号**  
- 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
科汛网校KesionEDU是KESION科汛开发的在线教育建站系统，支持在线直播教学、课程点播、录播授课等多种教学方式，满足不同场景下的教学需求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXmJaNdJcVPOibCzCLogHKfIjU9Chtk9b87XJ6pkkeRBQ1lyhbO8w022h7iaZX1PB9bJ6e9OPibRpuvQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露  
  
**简述：**  
科汛网校KesionEDU的/webapi/APP/CheckOrder接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 科汛网校KesionEDU  
  
**0x05 POC状态**  
- 已公开  
  
**0x06 修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本**  
**：**  
  
https://www.kesion.com/  
  
  
  
