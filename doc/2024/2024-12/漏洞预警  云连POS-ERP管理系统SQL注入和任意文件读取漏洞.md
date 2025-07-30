#  漏洞预警 | 云连POS-ERP管理系统SQL注入和任意文件读取漏洞   
浅安  浅安安全   2024-12-26 00:04  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
云连POS-ERP管理系统是一款面向零售行业的综合管理解决方案，集销售管理、库存管理、财务核算和门店运营于一体，旨在帮助企业实现高效运营与精准决策。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU8iaTUOG2Yp65MtC7pXugJBicnDVMDTqjgZicXA58CkbX0weYyicIrrnceybZDZfzicKujewrGF1jYcIw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
云连POS-ERP管理系统的ZksrService接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
漏洞类型：  
任意文件读取  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
云连POS-ERP管理系统的/admin/file!download.action接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- 云连POS-ERP管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.zksr.cn/  
  
  
  
