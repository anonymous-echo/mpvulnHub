#  漏洞预警 | 傲发办公通信专家系统SQL注入漏洞   
浅安  浅安安全   2025-06-05 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
傲发办公通信专家系统是由深圳市傲发科技有限公司推出的，集协同办公、通信管理、客户管理等多种功能于一体，为中小企业提供一站式融合通信服务，助力企业提升办公效率、降低通信成本的综合办公通信解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXNvm3yLTj4UnWBo60icuoJnJnVDMFuuKicAR3rPAibIh5pbvMpcXKPcvYVxC9C5ssb0zmJFAY19ZP9A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息****  
  
**简述：**  
傲发办公通信专家系统的/handle/Checkingin.ashx接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 傲发办公通信专家系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.aofax11.com/  
  
  
  
