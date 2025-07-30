#  漏洞预警 | Ivanti Connect Secure栈溢出漏洞   
浅安  浅安安全   2025-01-18 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-0282  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Ivanti Connect Secure是一款远程访问和零信任安全解决方案，它提供了SSL VPN功能，使远程和移动用户能够安全地访问企业资源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVjR0a11MK0DTHc9DqsMz38YVicDmjsBO1OeiboEwlqfUMXj47ibSgRTQFicC5vdckgWDu5DBFibJn8uwQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**CVE-2025-0282**  
  
**漏洞类型：**  
栈溢出  
  
**影响：**  
执行任意代码  
  
**简述：**  
Ivanti Connect Secure存在栈缓冲区溢出漏洞，攻击者可能利用该漏洞实现未授权远程代码执行。  
  
**0x04 影响版本**  
- 22.7R2 <= Ivanti Connect Secure <= 22.7R2.4  
  
- 22.7R1 <= Ivanti Policy Secure <= 22.7R1.2  
  
- 22.7R2 <= Ivanti Neurons for ZTA gateways <= 22.7R2.3  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://forums.ivanti.com/  
  
  
  
