#  漏洞预警 | 圣乔ERP系统任意文件读取漏洞   
浅安  浅安安全   2025-01-13 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
互慧急诊综合管理平台是用于管理门诊急诊病人的系统，主要包括门诊急诊业务和急诊物资管理两部分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWPk90dXoicehNCiaV83NFlBiardfTOGAztaPCQWwdmemTo5Zb8hz1RXbNFQEUxCwFDhrjwVxIN4QZIw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
互慧急诊综合管理平台的/dcwriter/thirdpart/ServicePage.aspx接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- 急诊综合管理平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.schhsw.com/  
  
  
  
