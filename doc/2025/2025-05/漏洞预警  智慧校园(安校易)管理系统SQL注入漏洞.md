#  漏洞预警 | 智慧校园(安校易)管理系统SQL注入漏洞   
浅安  浅安安全   2025-05-28 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
“安校易"是银达云创公司基于多年教育市场信息化建设经验沉淀，经过充分的客户需求调研，并依据国家"十三五"教育信息化建设规范而推出的综合互联网+教育信息化解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU4fzyXow7sKwcNrgrta4pab6CiaRedyu2TB39FNwl2jOsr3KUjfI9M88PxXIQ6djppiaRHyWiahgOyA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
智慧校园(安校易)管理系统的/Module/CJGL/Controller/PPlugList.ashx接口处存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 智慧校园(安校易)  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.winstaryc.com/  
  
  
  
