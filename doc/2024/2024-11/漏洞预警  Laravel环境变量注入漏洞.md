#  漏洞预警 | Laravel环境变量注入漏洞   
浅安  浅安安全   2024-11-19 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-52301  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Laravel是Laravel社区的一个Web 应用程序框架。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXVjSO8zzszuc8UiaVo19la91yBNVOlwm8WtQtlBTjs96mk231G09Fcict37BKqZGDgkTgm7e0IsNZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-52301**  
  
**漏洞类型：**  
环境变量注  
入  
  
**影响：**  
获取  
敏感信息  
  
  
  
**简述：**  
Laravel存在环境变量注入漏洞，由于框架在非CLI模式下处理请求时未正确隔离PHP的argv参数，当register_argc_argv PHP指令被设置为on时，攻击者可以通过向任意URL发送附带特制查询字符串的请求，来更改框架在请求处理时使用的环境配置，成功利用该漏洞可能导致敏感信息泄露、权限提升、应用崩溃或配置被篡改等。  
###   
  
**0x04 影响版本**  
- Laravel < 6.20.45  
  
- 7.0.0 <= Laravel < 7.30.7  
  
- 8.0.0 <= Laravel < 8.83.28  
  
- 9.0.0 <= Laravel < 9.52.17  
  
- 10.0.0 <= Laravel < 10.48.23  
  
- 11.0.0 <= Laravel < 11.31.0  
  
**0x05****POC状态**  
- 未公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://laravel.com/  
  
  
  
