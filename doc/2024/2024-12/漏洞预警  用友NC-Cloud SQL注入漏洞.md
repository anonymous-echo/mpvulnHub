#  漏洞预警 | 用友NC-Cloud SQL注入漏洞   
浅安  浅安安全   2024-12-30 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友NC Cloud是新一代云ERP产品，为成长型、大型、巨型集团企业提供混合云解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWqko9FpUNxKIEDk0mJhFKw1HJbpgNfiaEUdblU1ERoa1gR7GTHagEoXDiapJZibfNNK7wRic67UibUyuA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
用友NC-Cloud的/ncchr/attendstaff/getStaffInfo接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp cmdshel可以执行任意命令，从而控制服务器。  
  
**0x04 影响版本**  
- 用友NC-Cloud  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
