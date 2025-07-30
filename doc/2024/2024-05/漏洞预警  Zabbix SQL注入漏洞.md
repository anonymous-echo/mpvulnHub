#  漏洞预警 | Zabbix SQL注入漏洞   
浅安  浅安安全   2024-05-25 08:00  
  
**0x00 漏洞编号**  
- # CVE-2024-22120  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Zabbix是开源的网络监控工具，用于监控网络服务、服务器和网络设备的性能和可用性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVAS3cgxzDKew2rV0NjbAZGDsoCaP1TJicVXDiajtWTTWR7lYXrw6vmicnNZ8gOgQApibVtOdLlZYdqGA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-22120**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
Zabbix存在SQL注入漏洞，由于audit.c中的zbx_auditlog_global_script函数中未对用户可控的clientip进行过滤，从而使得具有登录权限的攻击者可通过Host->SCRIPTS执行包含payload的脚本，脚本执行后将日志添加至Audit Log时进行时间盲注，窃取数据库敏感敏感信息进而提权至管理员，或在目标服务器上远程执行任意代码。  
###   
  
**0x04 影响版本**  
- zabbix < 6.0.28rc1  
  
- 6.4.0 <= zabbix < 6.4.13rc1  
  
- 7.0.0alpha1 <= zabbix < 7.0.0beta2  
  
**0x05****POC**  
  
https://github.com/W01fh4cker/CVE-2024-22120-RCE  
  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.zabbix.com/cn  
  
  
  
