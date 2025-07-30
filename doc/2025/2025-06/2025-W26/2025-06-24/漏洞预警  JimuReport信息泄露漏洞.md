> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493483&idx=2&sn=7928bf75a665a3f3f2320e3eae44f879

#  漏洞预警 | JimuReport信息泄露漏洞  
浅安  浅安安全   2025-06-24 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
JimuReport是一款免费的数据可视化报表，含报表和大屏设计，像搭建积木一样在线设计报表！功能涵盖，数据报表、打印设计、图表报表、大屏设计等！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWNfZia7pszlicT0cUDMGfUNf32rdkibzMIHZ4Ac5yVANVJTMybYKb3AmbDhSYw7iaVfjzYnTQZSw4uIw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
信息泄露  
  
**影响：**  
获取敏感信息  
  
**简述：**  
JimuReport的  
/jmreport/getDataSourceByPage接口存在信息泄露漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库账号密码等大量敏感信息。  
  
**0x04 影响版本**  
- JimuReport   
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://jimureport.com/  
  
  
  
