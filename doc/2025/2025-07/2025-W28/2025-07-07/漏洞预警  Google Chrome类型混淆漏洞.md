> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493630&idx=2&sn=21b63bf4d6e6aa5fc10ea8af3379a031

#  漏洞预警 | Google Chrome类型混淆漏洞  
浅安  浅安安全   2025-07-07 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-6554  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Google Chrome是由Google开发的免费网页浏览器。Chrome代码是基于其他开放源代码软件所编写，包括Apple WebKit和Mozilla Firefox。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7stTqD182SXxjX8p8WklXuc23v1DKPW7yY83Sic75o0z0rlPgZHmmCPxBNvutPR92HthYPDsg7ia0ODDgsgQYjBQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-6554**  
  
**漏洞类型：**  
类型混淆  
  
**影响：**  
拒绝服务  
  
**简述：**  
Google Chrome存在类型混淆漏洞，  
由于V8引擎在执行JavaScript代码时，对某些数据类型的边界检查和类型转换处理不当，导致浏览器无法正确区分不同类型的内存数据。远程攻击者可通过诱导用户打开恶意链接来利用此漏洞，从而获取敏感信息或代码执行。  
  
**0x04 影响版本**  
- Google Chrome(Windows) < 138.0.7204.96/.97  
  
- Google Chrome(Mac) < 138.0.7204.92/.93  
  
- Google Chrome(Linux) < 138.0.7204.92  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
chrome://settings/help  
  
  
  
