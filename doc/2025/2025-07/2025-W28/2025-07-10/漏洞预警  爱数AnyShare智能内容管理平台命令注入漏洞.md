> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493676&idx=2&sn=d36ca7a2cbbe4c946eed6fc5114a281e

#  漏洞预警 | 爱数AnyShare智能内容管理平台命令注入漏洞  
浅安  浅安安全   2025-07-10 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
AnyShare Family 7是一款全新的企业内容管理平台，利用AI和云计算技术作为其系统架构和核心技术能力，是为每一个组织专程打造的智能内容云。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWaLw2vQgZuyUrIFYzJaw7WnYw6cIUshgBicwwdibHicN5QUDzzsdm8kHkibuM8g776GiagicS8vuADlsRw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
命令注入  
  
**影响：**  
执行任意命令  
  
**简述：**  
爱数Anyshare智能内容管理平台的/api/ServiceAgent/start_service存在命令执行漏洞  
，未经身份验证的攻击者可通过该漏洞执行任意命令。  
  
**0x04 影响版本**  
- 爱数Anyshare智能内容管理平台  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
h  
ttps://www.yun88.com/  
  
  
  
