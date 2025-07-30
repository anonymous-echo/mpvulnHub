#  漏洞预警 | SRM智联云采系统SQL注入漏洞   
浅安  浅安安全   2024-12-02 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
智互联科技有限公司的SRM智联云采系统是一款专业的数字采购平台，旨在助力企业实现采购数字化转型，提升供应链管理的效率和协同能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVNefZOic7NAGVkmrmX7icIxZMj3oaKdUZXibQrqb7rg1TO16M3B6tm6smLCyVVmuia3GpIrQLptYiaC9Q/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
SRM智联云采系统的/adpweb/api/srm/delivery/quickReceiptDetail、/adpweb/static/..;/a/sys/sysMessage/statusList、/adpweb/api/srm/delivery/receiptDetail和/adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- SRM智联云采系统 2.0  
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.zhilink.com/  
  
  
  
