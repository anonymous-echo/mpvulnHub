> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493665&idx=1&sn=48ab394f77cef01caa709b6988d5a145

#  漏洞预警 | PHPStudy后门漏洞  
浅安  浅安安全   2025-07-09 00:00  
  
**0x00 漏洞编号**  
- CVE-2025-34061  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
phpStudy是一款老牌知名的PHP开发集成环境工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWaLw2vQgZuyUrIFYzJaw7W3mFPXGMWg7sj6R50D7juN0tGSgqj6JE0lxnBDVHmQ2r9JlhcfTHjtQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2025-34061漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息****  
  
**简述：**  
PHPStudy存在后门漏洞，当监听到请求头包含Accept-Charset（内含有base64编码的PHP载荷），会以Web服务器的用户权限执行，未经身份验证的远程攻击者在受影响的系统中执行任意的PHP代码。  
  
**0x04 影响版本**  
- 2016 <= PHPStudy <= 2018  
  
**0x05****POC状态**  
- 已公开  
  
**0x06 修复建议**  
  
**目前官方暂未布漏洞修复版本，建议用户关注官网****：**  
  
https://www.xp.cn/  
  
  
  
