#  漏洞预警 | Apache Superset跨站脚本攻击漏洞   
浅安  浅安安全   2023-12-02 08:00  
  
**0x00 漏洞编号**  
- # CVE-2023-43701  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
Apache Superset是一个现代的、企业级的数据可视化和数据探索的网络应用程序。它可以连接多种数据源，提供各种图表选项，让不同技能水平的用户都能轻松地分析和呈现数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVHepuGnzla1Sd7leHIFuBEpagH9bLsksy2uiauialdWIFe6RA0W53DtUkLQVKgSt7aRLBE4XiaKoOibA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2023-43701**  
  
**漏洞类型：**  
跨站脚本  
  
**影响：**  
获取敏感数据  
  
**简述：**  
Apache Superset在2.1.2之前版本中存在跨站脚本攻击漏洞，经过身份认证的攻击者可以通过不完善的有效载荷认证和REST API响应类型将恶意代码存入Chart的元数据中，当有用户访问特定的API端点时，恶意代码将被执行。  
###   
  
**0x04 影响版本**  
- Apache Superset < 2.1.2  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://superset.apache.org/  
  
  
  
