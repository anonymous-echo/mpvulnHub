#  漏洞预警 | 银达汇智智慧综合管理平台SQL注入漏洞   
浅安  浅安安全   2025-06-02 23:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
银达汇智智慧综合管理平台是福建银达汇智信息科技股份有限公司推出的，融合先进信息技术，面向多行业打造的综合性管理系统，能整合门禁、考勤、消费、停车场等多场景应用，以 “一卡、一库、一网”实现集中管控与数据交互，提供便捷高效的智能化管理服务，助力校园、园区、企业等提升整体管理效能。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUSrTXFyed2bcrnEXGGkNj0WdzG2v2iacEdc3ff7wZ5aP0XibaeW6hfp67OaIclhs4uokpM42QNLy0Q/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
  
漏洞类型：  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
银达汇智智慧综合管理平台的/Module/CJGL/Controller/PPlugList.ashx接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 银达汇智智慧综合管理平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://windor.corp.dav01.com/  
  
  
  
