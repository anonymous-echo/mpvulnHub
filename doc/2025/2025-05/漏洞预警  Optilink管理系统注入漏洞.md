#  漏洞预警 | Optilink管理系统注入漏洞   
浅安  浅安安全   2025-05-21 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Optilink管理系统是一款基于现代通信技术，用于对不同领域的设备、生产流程或环境进行实时监控、数据可视化以及远程控制，以实现优化管理和提高效率等功能的软件系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVoiczLZwszDtBdU2kW2BKlKZkzoykJe6sOpueYicECDaLRAsQEBKQf8CqOFragKkeckSpf1AwhLuyw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
命令注入  
  
**影响：**  
执行任意代码  
  
**简述：**  
Optilink管理系统的/cgi/fsystem/gene.php接口存在命令注入漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- Optilink管理系统101-V1.2.0-en-200723  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.optilinknetwork.com/  
  
  
  
