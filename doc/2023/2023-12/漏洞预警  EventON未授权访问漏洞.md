#  漏洞预警 | EventON未授权访问漏洞   
浅安  浅安安全   2023-12-02 08:00  
  
**0x00 漏洞编号**  
- # CVE-2023-2796  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
EventON是一个活动日历插件，以最小的整洁设计呈现活动。它包含200多个有用的功能，例如高度可定制的重复事件、多个事件图像、无限的事件创建、各种日历布局设计、事件地点和组织者，以及多数据类型和语言对应事件等高级功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUKbciaZu6IE6qjtmf2utfnTlXSEVCq8PaVsUVyDdYnp5C6c0XVo5wQ2oAcqrKTzmQdeswg1Wx42Dg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2023-2796**  
  
**漏洞类型：**  
未授权访问  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
WordPress插件EventON在2.1.2版本之前存在未授权访问漏洞，其eventon_ics_download ajax操作中缺乏身份验证和授权，允许未经身份验证的访问者通过猜测其数字id来访问私有和受密码保护的敏感数据。  
###   
  
**0x04 影响版本**  
- EventON < 2.1.2  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.myeventon.com/  
  
  
  
