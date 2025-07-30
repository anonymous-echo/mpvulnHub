> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493794&idx=1&sn=23458646401be62b9d63135180ab883d

#  漏洞预警 | LaRecipe服务器端模板注入漏洞  
浅安  浅安安全   2025-07-22 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-53833  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
LaRecipe是一款允许用户在Laravel应用中使用Markdown创建文档的应用程序。  
  
![LaRecipe Screenshot](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUs1EVWC1KUYrGG7njBzt5NibQ7cES2CAEJe9fYiarVtvftzCWI0YnPdiaLliaElAziaicX7IW03Ycoicp2w/640?wx_fmt=png&from=appmsg "")  
  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-53833**  
  
**漏洞类型：**  
模板注入  
  
**影响：**  
执行任意代码  
  
**简述：**  
LaRecipe存在服务端模板注入漏洞  
，攻击者可构造恶意请求利用模版注入漏洞执行任意代码，控制服务器。  
  
**0x04 影响版本**  
- LaRecipe < 2.8.1  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://github.com/saleem-hadad/larecipe  
  
  
  
