#  漏洞预警 | 昂捷CRM SQL注入漏洞   
浅安  浅安安全   2025-04-29 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
昂捷CRM是深圳市昂捷信息技术股份有限公司提供的一款专注于零售行业客户关系管理的系统。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUkgWHnZO6mDZiaWyGJ899SSF1vXSJCXicyOeaKTfSO1RJ2XtbyYVqomlwmjafR40LMVo3pWPYKjJiaw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
昂捷  
CRM  
的/EnjoyRMIS_WS/WS/ReportTool/cwsqry.asmx中GetDictionary和GetAllQryColumn接口存在SQL注入漏洞，未经身份验证的攻击者可以利用该漏洞泄露系统敏感信息。  
  
**0x04 影响版本**  
- 昂捷  
CRM  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方暂无发布漏洞修复版本，建议用户关注官网动态****：**  
  
https://www.enjoyit.com.cn/  
  
  
  
