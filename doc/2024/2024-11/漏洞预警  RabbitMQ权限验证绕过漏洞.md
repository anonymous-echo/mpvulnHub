#  漏洞预警 | RabbitMQ权限验证绕过漏洞   
浅安  浅安安全   2024-11-18 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-51988  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
RabbitMQ是一个开源的消息代理和队列管理工具，用于分布式系统中的消息传递。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWxLsDR4P3KiaMEGR1hbiabWAoLWopvdAMgRTvaLvrKz7f8gnrAgUM3YbeHdwJmhvric3h4sQea4NApQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-51988**  
  
**漏洞类型：**  
权限验证绕过  
  
**影响：**  
越权操作  
  
**简述：**  
RabbitMQ的HTTP API在执行队列删除操作时，由于未充分验证用户的configure权限，拥有HTTP API访问凭据但不具有队列删除权限的攻击者可绕过权限限制，通过DELETE /api/queues/{vhost}/{name}请求删除其不具备删除权限的队列。  
  
**0x04 影响版本**  
- 3.12.7 <= RabbitMQ < 3.12.11  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.rabbitmq.com/  
  
  
  
