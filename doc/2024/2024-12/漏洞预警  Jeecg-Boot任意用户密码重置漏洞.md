#  漏洞预警 | Jeecg-Boot任意用户密码重置漏洞   
浅安  浅安安全   2024-12-25 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Jeecg-Boot是一款开源的低代码开发平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVx0FEgaIcicuklqRYzOCgXSZic9kKZfdhL3nGNP382GXibRJk0YOrV0bNGYCbCYZRicAFZtNUVOfSWXw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
任意用户密码重置  
  
**影响：**  
接管服务  
  
**简述：**  
Jeecg-Boot的/jeecg-boot/sys/user/passwordChange接口存在任意用户密码重置漏洞，未经身份验证的攻击者可以通过该漏洞重置任意用户密码，从而登录后台，获取管理员权限。  
  
**0x04 影响版本**  
- jeecg-boot  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.jeecg.com/  
  
  
  
