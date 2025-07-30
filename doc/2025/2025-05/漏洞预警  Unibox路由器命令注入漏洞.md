#  漏洞预警 | Unibox路由器命令注入漏洞   
浅安  浅安安全   2025-05-09 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Unibox路由器是一款由Wifisoft公司推出的，专为小型场所如咖啡馆、餐厅、小型酒店、培训机构、小办公室和公共Wi-Fi热点等设计的智能接入控制器，它集成了全面的计费和带宽管理功能，可帮助网络管理员集中管理有线和无线网络，具备多种特性和功能，能有效避免未经授权的访问并跟踪网络上的实时活动。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWc1fThDhTG13bAQibnj0lmZapO4XLpKAIAj5Ltz5GB3IPsIsLf0BfFWe0PaOib5JghzktV7pU325xA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
命令注入  
  
**影响：**  
执行任意代码  
  
**简述：**  
Unibox路由器的  
/network/checkstatus_ping.php和/authentication/test_userlogin.php接口存在命令注入漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- Unibox路由器  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.wifi-soft.com/  
  
  
  
