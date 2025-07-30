#  漏洞预警 | TamronOS IPTV系统任意用户创建漏洞   
浅安  浅安安全   2024-11-29 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
TamronOS IPTV系统是一款基于Linux内核开发的直播和点播一体化解决方案，广泛应用于宽带运营商、酒店、学校等场景。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVjdb8W7T5YIrddGeQMLUBTmyZw3RKn44SaBexYgfbvFwXiaE8c0HqdRUANBCl3taNmGAuqFyBj1MA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
任意用户创建  
  
**影响：**  
获取服务权限  
  
**简述：**  
TamronOS IPTV系统的/api/manager/submit接口存在任意用户创建漏洞，未经身份验证的攻击者可以通过该漏洞创建用户，从而登录后台。  
  
**0x04 影响版本**  
- TamronOS IPTV系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.tamronos.com/  
  
  
  
