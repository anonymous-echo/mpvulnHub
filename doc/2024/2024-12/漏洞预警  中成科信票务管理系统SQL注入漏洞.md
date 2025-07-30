#  漏洞预警 | 中成科信票务管理系统SQL注入漏洞   
浅安  浅安安全   2024-12-16 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
中成科信票务管理系统是专注于演出剧院、体育场馆、旅游景区、游乐园、场地活动的票务管理系统,并为特殊客户量身定制票务应用解决方案，可根据用户的要求采用不同的技术载体实现门票的防伪。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXtAPtWzrWO4iaJicvAtMDHxcnvwMpR6zIO08N92PpQ2SzeDc9bgVYfU759m2SJMtnbxvQorzCt5kww/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL漏洞  
  
**影响：**  
获取敏感信息  
  
**简述：**  
中成科信票务管理系统的/SystemManager/TicketSystem/ReturnTicketPlance.ashx接口存在SQL注入漏洞复现，未经身份验证的恶意攻击者利用SQL注入漏洞获取数据库中的信息。  
  
**0x04 影响版本**  
- 中成科信票务管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.zckx.net/  
  
  
  
