#  漏洞预警 | vBulletin远程代码执行漏洞  
浅安  浅安安全   2025-06-08 23:50  
  
**0x00 漏洞编号**  
- # CVE-2025-48827  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
vBulletin是一款功能强大的开源论坛软件，提供了灵活的权限管理系统，让管理员可以精细控制不同用户组和用户的访问权限和功能使用，适用于各种规模的在线社区。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU3iaq7UqVQqlTrx6jSSnbGzE6h4MOJG6MFtrOz6aaJYrO2IG7LricyArIib4bh9K82R4qO1YkJYe2dQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
CVE-2025-48827****  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：vBulletin存在远程代码执行漏洞，攻击者可以利用这个漏洞调用受保护的API控制器执行未授权的操作，从而执行任意代码。**  
  
**0x04 影响版本**  
- 5.0.0 <= vBulletin < 5.7.6  
  
- 6.0.0 <= vBulletin < 6.0.4  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.vbulletin.com/  
  
  
  
