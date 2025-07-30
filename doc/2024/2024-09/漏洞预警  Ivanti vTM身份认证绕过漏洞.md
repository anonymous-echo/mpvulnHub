#  漏洞预警 | Ivanti vTM身份认证绕过漏洞   
浅安  浅安安全   2024-09-01 08:00  
  
**0x00 漏洞编号**  
- # CVE-2024-7593  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Ivanti vTM通过提供强大的流量管理和优化功能，帮助企业确保应用程序的高可用性和性能。它支持多种协议和负载均衡算法，能够灵活应对各种复杂的网络环境和业务需求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVjR0a11MK0DTHc9DqsMz38YVicDmjsBO1OeiboEwlqfUMXj47ibSgRTQFicC5vdckgWDu5DBFibJn8uwQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-7593**  
  
**漏洞类型：**  
身份认证绕过  
  
**影响：**  
越权操作  
  
**简述：**  
Ivanti vTM的/apps/zxtm/wizard.fcgi接口存在身份认证绕过漏洞，由于身份验证算法的实施不正确，导致未经身份验证的远程攻击者可以通过该漏洞绕过管理面板的身份验证。  
###   
  
**0x04 影响版本**  
- Ivanti vTM  22.2  
  
- Ivanti vTM  22.3  
  
- Ivanti vTM  22.3R2  
  
- Ivanti vTM  22.5R1  
  
- Ivanti vTM  22.6R1  
  
- Ivanti vTM  22.7R1  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://forums.ivanti.com/  
  
  
  
