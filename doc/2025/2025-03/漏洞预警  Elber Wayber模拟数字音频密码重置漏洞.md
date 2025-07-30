#  漏洞预警 | Elber Wayber模拟数字音频密码重置漏洞   
浅安  浅安安全   2025-03-01 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Elber wayber是一家专注于音频技术解决方案的公司，提供高质量的模拟和数字音频Q设备，广泛应用于专业录音、广播、现场演出和多媒体制作等领域。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXpKCXcY7jiciaYnBrycvfm1pb02Fn1CSFGsWmTnrzgjMwebQC5d5icuMZ9iav5ZMWXzTTMpFH0zwYYfw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
密码重置  
  
**影响：**  
接管服务  
  
**简述：**  
Elber wavber模拟/数字音频系统的/json_data/set_pwd接口存在密码重置漏洞，未经身份验证的攻击者可以通过该漏洞重置用户密码，从而登录后台，获取管理员权限。  
  
**0x04 影响版本**  
- Elber wavber模拟/数字音频系统  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.elber.it/  
  
  
  
