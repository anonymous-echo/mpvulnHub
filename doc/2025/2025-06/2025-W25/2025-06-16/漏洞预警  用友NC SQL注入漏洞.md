> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493396&idx=3&sn=e6333cfc3d94d4f6d2e1c601a6b79df2

#  漏洞预警 | 用友NC SQL注入漏洞  
浅安  浅安安全   2025-06-16 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友NC是一款企业级ERP软件。作为一种信息化管理工具，用友NC提供了一系列业务管理模块，包括财务会计、采购管理、销售管理、物料管理、生产计划和人力资源管理等，帮助企业实现数字化转型和高效管理。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWqko9FpUNxKIEDk0mJhFKw1HJbpgNfiaEUdblU1ERoa1gR7GTHagEoXDiapJZibfNNK7wRic67UibUyuA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
用友NC的  
/ebvp/register/qrySubPurchaseOrgByParentPk  
接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 用友NC  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
