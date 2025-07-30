> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493676&idx=3&sn=6262141acaaa57e44ec39aa1bebdbaf0

#  漏洞预警 | 明源地产ERP身份认证绕过漏洞  
浅安  浅安安全   2025-07-10 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
明源地产ERP是一款专为房地产行业设计的企业资源计划管理系统，致力于为房地产开发企业提供全面的管理解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWQK5AoL9cDCdtkAibcBYVMwfsHWN5QSk6PH1B7RodiaAU8ztHAj2tsSH9bkArJ1WfxLQhS8uECvslQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
身份认证绕过  
  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
明源地产ERP系统的/PubPlatform/Nav/Login/SSO/Login.aspx接口存在身份认证绕过漏洞，未授权的攻击者可以通过该漏洞绕过身份验证，从而获取后台管理员权限。  
  
**0x04 影响版本**  
- 明源地产ERP  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.mingyuanyun.com/  
  
  
  
