#  漏洞预警 | BeyondTrust RS & PRA命令注入漏洞   
浅安  浅安安全   2024-12-27 00:03  
  
**0x00 漏洞编号**  
- # CVE-2024-12356  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
BeyondTrust特权远程访问和远程支持产品是由BeyondTrust公司提供的一套安全解决方案，主要用于管理和保护IT系统中的远程访问权限和特权账户。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU8iaTUOG2Yp65MtC7pXugJBOq2icrS5B7R5JnshOq97Sdo5j7OD9raOSlibg4Jn71Yj9njLLxc3IuaA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-12356**  
  
**漏洞类型：**  
命令注入  
  
**影响：**  
执行任意命令  
  
**简述：**  
BeyondTrust PRA和RS中存在命令注入漏洞，由于对恶意客户端请求缺乏充分的输入验证，攻击者可通过向目标设备发送特制请求注入恶意命令，成功利用该漏洞可能导致在受害站点用户的上下文中执行任意命令，从而可能导致权限提升、敏感信息泄露或系统控制等。  
  
**0x04 影响版本**  
- BeyondTrust Privileged Remote Access (PRA) <= 24.3.1  
  
- BeyondTrust Remote Support (RS) <= 24.3.1  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.beyondtrust.com/  
  
  
  
