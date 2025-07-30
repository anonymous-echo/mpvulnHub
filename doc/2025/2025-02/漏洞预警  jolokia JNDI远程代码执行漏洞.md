#  漏洞预警 | jolokia JNDI远程代码执行漏洞   
浅安  浅安安全   2025-02-22 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Jolokia是一个用于通过HTTP访问JMX MBean的桥梁工具，它提供了简单易用的RESTful接口，使得开发者可以通过HTTP请求直接与JMX MBean交互。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVmgxocvbZpHSwERgOr35s3kz6os769nO8RCIhm1DIzucziaagJj8CicL0wtvRbLsSpiaeeIXPWFK3ag/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：JNDI**  
远程  
命令  
执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
Jolokia存在JNDI远程代码执行漏洞，未经身份验证的攻击者可以通过该漏洞远程执行代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- Jolokia  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://jolokia.org/  
  
  
  
