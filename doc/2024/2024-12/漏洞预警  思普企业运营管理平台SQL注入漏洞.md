#  漏洞预警 | 思普企业运营管理平台SQL注入漏洞   
浅安  浅安安全   2024-12-09 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
思普企业运营管理平台是一款专为企业提供全方位运营管理解决方案的软件平台，旨在帮助企业实现运营流程的可视化、自动化和协同化管理，提升运营效率和管理水平。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXmqBsiblH0BvyZ49iclLyYb2UsDGAH0ozhuCZibGt4lSJRaticYqC8aGo3uumSpL5o3GT9t1sbfIYj0Q/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
思普企业运营管理平台的/IdsCenter/idsCheck接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 思普企业运营管理平台  
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.xspinfo.com/  
  
  
  
