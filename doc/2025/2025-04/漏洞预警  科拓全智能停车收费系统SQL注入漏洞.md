#  漏洞预警 | 科拓全智能停车收费系统SQL注入漏洞   
浅安  浅安安全   2025-04-18 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
科拓全智能停车收费系统是一套先进的停车场管理系统，它集成了计算机、网络设备、车道管理设备等多种技术，旨在实现对停车场车辆出入、场内车流引导、以及停车费收取的智能化管理。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXD5tKdUfHzxwJVjGKeMYpIZWNwBLtyTD84d9dCnWuTgl14SBqEWgKEaFCUZdxmJ0p2LE7Fp0uBcw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露****  
  
**简述：**  
科拓全智能停车收费系统的  
/Webservice.asmx/GetAdSubByID接口存在SQL注入漏洞，未经过身份认证的远程攻击者可利用此漏洞执行任意SQL指令，从而窃取数据库敏感信息。  
  
**0x04 影响版本**  
- 科拓全智能停车收费系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.keytop.com.cn/  
  
  
  
