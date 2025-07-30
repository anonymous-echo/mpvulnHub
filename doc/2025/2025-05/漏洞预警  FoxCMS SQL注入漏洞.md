#  漏洞预警 | FoxCMS SQL注入漏洞   
浅安  浅安安全   2025-05-28 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-5155  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
FoxCMS是一款采用PHP+MySQL架构、可免费商用且开源的内容管理系统，内置多种企业常用内容模型，具备丰富模板标签、强大SEO和伪静态优化机制，还支持多语言等功能，能助力中小企业高效进行网站内容管理与数字化转型。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SW9tr2La24Zpwljl38LqYvR6jspFjwCXSWQdP0UeGQ4JSkv3457b6vew5D4ofTM7g8d0mrtdPiamPw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
CVE-2025-5155  
  
漏洞类型：  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
FoxCMS的  
/index.php/admin/Article/batchCope.html接口存在SQL注入漏洞，攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- FoxCMS V1.2.5  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.foxcms.cn/  
  
  
  
