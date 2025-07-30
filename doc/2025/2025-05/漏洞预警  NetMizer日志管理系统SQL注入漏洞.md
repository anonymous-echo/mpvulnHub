#  漏洞预警 | NetMizer日志管理系统SQL注入漏洞   
浅安  浅安安全   2025-05-21 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
NetMizer日志管理系统是一款可以记录流经设备的所有会话日志并将其传送到外部的管理中心上的系统。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUgFcdTclLpaibaNFbexjyNfok47S50jQeiaXgwQhyHdFNLgRrI4w7iau9icVfth12be0ze1PjDzgXJlQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
NetMizer日志管理系统的  
/data/echart/terminals.php接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- NetMizer日志管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.lingzhou.com.cn/  
  
  
  
