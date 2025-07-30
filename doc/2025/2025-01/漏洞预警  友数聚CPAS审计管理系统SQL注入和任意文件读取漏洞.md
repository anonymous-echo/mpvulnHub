#  漏洞预警 | 友数聚CPAS审计管理系统SQL注入和任意文件读取漏洞   
浅安  浅安安全   2025-01-06 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
友数聚CPAS审计管理系统是友数聚科技有限公司开发的一款审计软件产品，它是CPAS审计信息系统的一个重要组成部分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXfjAibRSNGWpmwPlJwZg4r8rJyia4QRKmJWSoC8Jay9jTuR5Z2yjyY3rJIuibORsw39qMhiajRhdCnUg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
友数聚CPAS审计管理系统的/cpasm4/cpasList/getCurserIfAllowLogin接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
漏洞类型：  
任意文件读取  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
友数聚CPAS审计管理系统的/cpasm4/plugInManController/downPlugs接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- 友数聚CPAS审计管理系统V4  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://youdatasum.com/  
  
  
  
