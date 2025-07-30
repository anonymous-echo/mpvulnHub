#  漏洞预警 | Trimble Cityworks反序列化漏洞   
浅安  浅安安全   2025-02-13 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-0994  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Trimble Cityworks是一款基于地理信息系统的资产管理平台，专为公共设施管理、城市规划和基础设施维护设计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUwXyfYXUesLFq9ZFTycId6rlPclpbErhgwUQNlJNLIAUb6NELgeP8TGcSkbtMN4YiaIVlZicpLpCnw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-0994**  
  
**漏洞类型：**  
反序列化  
  
**影响：**  
执行任意命令  
  
**简述：**  
Cityworks存在反序列化漏洞，经过身份验证的攻击者可通过该漏洞在客户的Microsoft Internet Information Services服务器上执行远程代码，导致系统被控制并危及数据安全。  
  
**0x04 影响版本**  
- Cityworks < 15.8.9  
  
- Cityworks with Office Companion < 23.10  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://learn.assetlifecycle.trimble.com/  
  
  
  
