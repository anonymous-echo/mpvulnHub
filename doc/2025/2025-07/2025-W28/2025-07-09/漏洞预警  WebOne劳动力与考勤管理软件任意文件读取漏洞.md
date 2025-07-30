> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493665&idx=3&sn=1221ce55fb0740963a6b753ce6508465

#  漏洞预警 | WebOne劳动力与考勤管理软件任意文件读取漏洞  
浅安  浅安安全   2025-07-09 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
WebOne劳动力与考勤管理软件以B/S架构为依托，集考勤、门禁、巡更等功能于一体，可处理复杂考勤规则，支持多种识别方式与数据传输，能实现智能排班、实时监控与报表自动生成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWaLw2vQgZuyUrIFYzJaw7WIZWXb2M5qOctPichtZ2DGSFT1qtTjYMsxlcbGhWorArJFGsguL7TSTA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
  
  
  
**简述：**  
WebOne劳动力与考勤管理软件的/webForms/Download/DownloadFile.aspx接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- WebOne劳动力与考勤管理软件  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.coho.net.cn/  
  
  
  
