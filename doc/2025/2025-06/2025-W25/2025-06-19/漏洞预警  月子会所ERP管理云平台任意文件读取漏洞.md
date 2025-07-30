> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493446&idx=3&sn=36633d2511379f57d133547778a390f8

#  漏洞预警 | 月子会所ERP管理云平台任意文件读取漏洞  
浅安  浅安安全   2025-06-19 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
月子会ERP管理云平台是由武汉金同方科技有限公司研发团队结合行业月子中心相关企业需求开发的一套综合性管理软件。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVe25Zwwd7Q7fqnAExJYXqUzwV6uCqTCtm59D1zDYxPqovqZzgMWnOBS7mdoSnhLKJhU0sDeK6WZw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
  
  
  
**简述：**  
月  
子会所ERP管理云平台的/Page/upload/UploadHandler.ashx接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- 月子会ERP管理云平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.mamabaohe.net/  
  
  
  
