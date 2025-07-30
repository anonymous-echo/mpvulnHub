#  漏洞预警 | 易思智能物流无人值守系统 SQL注入漏洞   
浅安  浅安安全   2025-01-01 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
易思智能物流无人值守系统是一种基于人工智能、物联网和自动化技术的无人值守物流解决方案，旨在提高物流运营效率，降低人工成本，增强物流过程的智能化与安全性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWfbQHqUezfh8d1kJYCd3lM6CAJGwL4icS7R9Y3huSCMwFUKoDEVqgWkKnM3GG7ibJKMuoU27fOFL6g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
易思智能物流无人值守系统的/api/SingleLogin/login接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞执行任意SQL语句，从而获取数据库敏感信息。  
  
**0x04 影响版本**  
- 易思智能物流无人值守系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.eosine.com.cn/  
  
  
  
