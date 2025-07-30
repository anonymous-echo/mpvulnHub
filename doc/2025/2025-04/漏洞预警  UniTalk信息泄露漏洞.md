#  漏洞预警 | UniTalk信息泄露漏洞   
浅安  浅安安全   2025-04-23 00:03  
  
**0x00 漏洞编号**  
- # CVE-2024-39676  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
Apache Pinot是由Apache软件基金会开源的分布式、实时OLAP数据库，它专为高性能数据查询和分析设计，具备实时数据摄入、低延迟查询响应以及水平扩展能力，广泛应用于广告分析、金融数据监测、物联网数据分析等领域。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXBWzKcPxKTbCAudbicoRhD4KiaEnDHk6rFMibjMA7vjmfwzqxojLCrvYTXpeiblD9GFxeZzareX9XR7g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
CVE-2024-39676  
  
漏洞类型：  
信息泄露  
  
**影响：**  
获取敏感信息****  
  
**简述：**  
Apache Pinot的/appConfigs接口存在信息泄露漏洞，未经身份验证的攻击者可以通过该漏洞获取服务器敏感信息。  
  
**0x04 影响版本**  
- 0.1 <= Apache Pinot < 1.0.0  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://pinot.apache.org/  
  
  
  
