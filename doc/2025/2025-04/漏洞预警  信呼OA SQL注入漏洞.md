#  漏洞预警 | 信呼OA SQL注入漏洞   
浅安  浅安安全   2025-04-25 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
信呼OA是一款免费开源的办公OA系统，包括APP，pc上客户端，REIM即时通信，服务端等。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7stTqD182SUzVZkQLwNEC60ckJDVg1SlT9cW0DUsHBib55r3mvcNHOGLXYe1LVxyFnovHoC2X48rklsIohu2siaw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
信呼OA的/xhoa/api.php?a=getmfilv&m=upload|api&d=task接口存在SQL注入漏洞，未经身份验证得攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 信呼OA   
 >= V2.6.5  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.rockoa.com/  
  
  
  
