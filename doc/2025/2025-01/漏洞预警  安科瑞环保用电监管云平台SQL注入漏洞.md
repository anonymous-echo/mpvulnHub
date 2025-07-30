#  漏洞预警 | 安科瑞环保用电监管云平台SQL注入漏洞   
浅安  浅安安全   2025-01-06 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
安科瑞环保用电监管云平台集成了物联网技术、云计算和大数据分析，通过对企业和工业园区的用电情况实时采集、监测和分析，为环保合规、能耗管理和智能用电提供技术支持。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXfjAibRSNGWpmwPlJwZg4r86BWFLibIDgYHEbtC1SplJcM9kkr0W5on22b1ZmeAa2NahNABWCUYGuw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
安科瑞环保用电监管云平台的/MainMonitor/GetEnterpriseInfoY接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 安科瑞环保用电监管云平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.acreldny.cn/  
  
  
  
