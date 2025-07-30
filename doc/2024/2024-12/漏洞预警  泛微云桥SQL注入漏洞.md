#  漏洞预警 | 泛微云桥SQL注入漏洞   
浅安  浅安安全   2024-12-25 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
泛微云桥e-Bridge提供了一套全面的办公自动化工具，包括文档管理、流程管理、协同办公、知识管理、移动办公等功能。它的核心理念是将企业内部的各种业务流程数字化，并通过云端技术实现跨部门、跨地域的协同办公和信息共享。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVeemR7wLPNZGZtdPjw4eLqbibYeFFeLRvSY5ErBfEvY5hlQ20uf6qlUYD2Gib5h44qmibI9icpk9B93w/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
泛微云桥E-Bridge的/taste/addTasteJsonp接口存在SQL注入漏洞，经过身份认证的攻击者可以通过addTaste接口进行SQL注入，从而获取数据库中的敏感信息。  
  
**0x04 影响版本**  
- 泛微云桥E-Bridge  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.weaver.com.cn/  
  
  
  
