#  漏洞预警 | ZZCMS SQL 注入漏洞   
浅安  浅安安全   2025-02-11 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
ZZCMS是一款适用于招商代理型的行业网站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SW5vXyMEFmaicVZQj8sb1r3ISjDdiawECiap4XWglYYAg1PLxkLz5k9pCBUCaC8pAJkNo7qnARND0qIA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
ZZCMS的/index.php接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- ZZCMS  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.zzcms.net/  
  
  
  
