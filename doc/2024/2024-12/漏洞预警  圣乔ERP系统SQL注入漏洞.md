#  漏洞预警 | 圣乔ERP系统SQL注入漏洞   
浅安  浅安安全   2024-12-18 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
圣乔ERP系统是杭州圣乔科技有限公司开发的一款企业级管理软件，旨在为企业提供一套全面、集成化的管理解决方案，帮助企业实现资源的优化配置和高效利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUlxtwpd4P0rFf3icGicd7SNwu2apyxNc1vbICDA5ZZd5ZeaQzmdNmqwROugCWOhErIjb4SaGgia5orQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
圣乔ERP系统的/erp/dwr/call/plaincall/DwrUtil.getSupplyQueryKeyword.dwr和/erp/dwr/call/plaincall/SingleRowQueryConvertor.queryForString.dwr接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 圣乔ERP系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.hzsage.com/  
  
  
  
