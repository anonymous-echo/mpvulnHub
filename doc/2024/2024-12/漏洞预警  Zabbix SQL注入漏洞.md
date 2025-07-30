#  漏洞预警 | Zabbix SQL注入漏洞   
浅安  浅安安全   2024-12-07 00:30  
  
**0x00 漏洞编号**  
- # CVE-2024-42327  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Zabbix是开源的网络监控工具，用于监控网络服务、服务器和网络设备的性能和可用性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXVWpknFJg9UMKCu4qeRd8jFfGPNGWVl6g9BYM723d9M5iajrQibuqfLYhib4TDqZ7HzOLhT1F5OBQzQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-42327**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
Zabbix前端的CUser类中的addRelatedObjects函数未对输入数据进行充分验证和转义，导致具有API访问权限的恶意用户可以通过user.get API传递特制输入触发SQL注入攻击，进而利用该漏洞实现权限提升或访问敏感数据。  
  
**0x04 影响版本**  
- 6.0.0 <= Zabbix <= 6.0.31  
  
- 6.4.0 <= Zabbix <= 6.4.16  
  
- Zabbix 7.0.0  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.zabbix.com/  
  
  
  
