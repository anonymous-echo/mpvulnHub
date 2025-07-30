#  漏洞预警 | Elber身份认证绕过漏洞   
浅安  浅安安全   2025-06-06 00:01  
  
**0x00 漏洞编号**  
- CVE-2025-0674  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Elber是一家从事广播行业模拟/数字微波链路的公司。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU3iaq7UqVQqlTrx6jSSnbGzVZRbfXaISeuq6DvtAwdg2c5OkCzpaBia5RabCxJXjYbnjuSOxiclCAkQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-0674**  
  
**漏洞类型：**  
身份认证绕过  
  
**影响：**  
越权访问  
  
**简述：**  
Elber多个产品的/modules/pwd.html和/json_data/set_pwd存在身份验证绕过漏洞，未经身份验证的攻击者可以通过该漏洞获取管理访问权限，从而损害设备的系统安全性。  
  
**0x04 影响版本**  
- Elber  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.elber.it/  
  
  
  
