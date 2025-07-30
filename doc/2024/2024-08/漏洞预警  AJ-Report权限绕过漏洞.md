#  漏洞预警 | AJ-Report权限绕过漏洞   
浅安  浅安安全   2024-08-24 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
AJ-Report是全开源的一个BI平台，酷炫大屏展示，能随时随地掌控业务动态，让每个决策都有数据支撑。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWibIrxzAyC8yLPm7CbDAKHMudJpq1ZbgT9HCiamTxNOHETsHB8FFIvlMFZG4hrkEMAXwAEibYKIjhaA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
权限绕过  
  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
AJ-Report的filter接口权限可绕过，攻击者可通过包含swagger-ui或swagger-resources绕过权限限制，从而获取敏感信息。  
###   
  
**0x04 影响版本**  
- AJ-Report <= 1.4.1  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://github.com/anji-plus/report  
  
  
  
