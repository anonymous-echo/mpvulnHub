> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493700&idx=3&sn=56851215cf8e0bbdc548118a45078332

#  漏洞预警 | ZKTime熵基智能考勤管理系统SQL注入漏洞  
浅安  浅安安全   2025-07-14 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
ZKTime熵基智能考勤管理系统是一款集生物识别技术与AI算法于一体的企业级考勤解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXibicaYVFNppHJFsXuaib4e9IQBPfJ6NGo7gLvtgPfssgCcib3OQ3XM5vaywaJWueCFtOyDf8FRbSnxA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
ZKTime熵基智能考勤管理系统的/iclock/ic1ock接口存在SQL注入漏洞，  
未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- ZKTime熵基智能考勤管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://zktecosz.com/  
  
  
  
