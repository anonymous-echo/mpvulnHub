#  漏洞预警 | 用友U8Cloud SQL注入漏洞   
浅安  浅安安全   2024-04-04 09:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友U8 cloud是一款集成的企业资源计划解决方案，旨在帮助不断发展的企业同步前后端业务功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jsiaZ70u94EB6R9eOgsPln1PWpP3MSljJmZEwZYep2iakwjxN7DsbXlfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL漏洞  
  
**影响：**  
获取敏感信息  
  
**简述：**  
用友U8Cloud MeasureQueryByToolAction接口存在sql注入漏洞，未授权的攻击者可通过此漏洞获取数据库敏感信息，从而盗取服务器数据，造成服务器信息泄露。  
###   
  
**0x04 影响版本**  
- U8Cloud 1.0  
  
- 2.0 <= U8Cloud <= 2.7  
  
- 3.0 <= U8cloud <= 3.6.sp  
  
- U8cloud 5.0  
  
- U8cloud 5.0sp  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
