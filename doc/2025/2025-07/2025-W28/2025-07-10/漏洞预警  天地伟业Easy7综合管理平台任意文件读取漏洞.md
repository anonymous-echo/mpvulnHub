> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493676&idx=1&sn=ad0a272ee956a13f9d98df5aabdbdaf3

#  漏洞预警 | 天地伟业Easy7综合管理平台任意文件读取漏洞  
浅安  浅安安全   2025-07-10 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
天地伟业Easy7综合管理平台采用分布式架构，融合模数混合切换显示、用户权限控制、数据存储点播等功能，具备智能检索、视频诊断等特色应用，能为各行业提供高效可靠的安防综合管理方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWaLw2vQgZuyUrIFYzJaw7Wq8JT3p6gtDdlQkjnCfQTfZgUJ0NFdz1icCuk7DcAviaMZGvrmxkTGVhQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
  
  
  
**简述：**  
天地伟业Easy7综合管理平台的/Easy7/rest/file/downloadResource接口存在任意文件读取漏洞  
，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- 天地伟业Easy7综合管理平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.tiandy.com/  
  
  
  
