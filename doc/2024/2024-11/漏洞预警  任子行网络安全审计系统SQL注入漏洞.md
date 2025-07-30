#  漏洞预警 | 任子行网络安全审计系统SQL注入漏洞   
浅安  浅安安全   2024-11-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
任子行网络安全审计系统是一款提供全方位网络流量监控与分析的安全解决方案，适用于政府、企业和公共机构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVWUkxxltiaJdA3BTAAzJwUKNZBLqMzC7HYo6A21NdsM6qraN8AIwTjox9Dw0Vf1TDIeb1wsWys1Vw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
任子行网络安全审计系统的/webui接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 任子行网络安全审计系统  
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.surfilter.com/  
  
  
  
