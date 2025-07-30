#  漏洞预警 | 方正全媒体采编系统SQL注入漏洞   
浅安  浅安安全   2024-12-31 00:03  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
方正全媒体新闻采编系统是一个面向媒体深度融合的技术平台，它以大数据和AI技术为支撑，集成了指挥中心、采集中心、编辑中心、发布中心、绩效考核中心、资料中心等多个功能，全面承载“策采编审发存传评”的融媒体业务流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWA27o97G4gEuv1V27DowOJZWSWyUMZtHF2uiaHgQtfnqNwrBIdPB6iaUpmdd11qM130TUHibj6JGB4Q/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
方正全媒体新闻采编系统screen.do和/newsedit/report/reportCenter.do接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 方正全媒体新闻采编系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.founder.com.cn/  
  
  
  
