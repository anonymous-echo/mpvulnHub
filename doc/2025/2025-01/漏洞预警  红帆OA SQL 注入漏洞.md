#  漏洞预警 | 红帆OA SQL 注入漏洞   
浅安  浅安安全   2025-01-25 00:03  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
红帆OA是红帆科技基于微软.NET最新技术开发的信息管理平台，红帆oa系统为医院提供oA功能，完成信息发布、流程审批、公文管理、日程管理、工作安排、文件传递、在线沟通等行政办公业务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWjP6kdhjibnhNYQQ7ibGoNqaibE27cvOiabfDKbtmpJMn9tib23D0YRNaxib3FH0IujjkANlGrMMroAvCg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
红帆iOffice的/api/portal-public-link/anon/list和/iOffice/prg/set/wss/wssRtFile.aspx接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 红帆OA  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.ioffice.cn/  
  
  
  
