#  漏洞预警 | Fortinet FortiClientEMS SQL注入漏洞   
浅安  浅安安全   2024-03-16 08:00  
  
**0x00 漏洞编号**  
- # CVE-2023-48788  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Fortinet FortiClientEMS是一款用于管理和保护Fortinet FortiClient客户端安全性的集中式管理平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWJkBhlicYtEdFMCXic0K33FvSAPVxUU0t7BticA8mrCwTscfDryuXyG4NEW7GND00OWXCMvGrVeyp2g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2023-48788**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
执行任意命令  
  
**简述：**  
Fortinet FortiClientEMS平台存在一个SQL注入漏洞，未经认证的远程攻击者可通过创建恶意日志条目，并向服务器发出精心制作的请求，成功的利用此漏洞可在管理员工作站上执行任意命令。  
###   
  
**0x04 影响版本**  
- 7.2.0 <= FortiClientEMS <= 7.2.2  
  
- 7.0.1 <= FortiClientEMS <= 7.0.10  
  
**0x05****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.fortiguard.com/  
  
  
  
