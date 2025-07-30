#  漏洞预警 | Apache Ignite远程代码执行漏洞   
浅安  浅安安全   2025-02-21 00:02  
  
**0x00 漏洞编号**  
- # CVE-2024-52577  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Ignite是一个高性能、分布式数据库和计算平台，专为大规模数据处理和实时分析设计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SViaW9b9I3m7ibLoBGVnWD37XK5VeeX7eAeYWXOH0krLxXKINqia3zwXu1ljDgFsjqMiatPbiaAlJPJdvw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-52577**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
Apache Ignite存在远程代码执行漏洞，攻击者可通过发送恶意消息至易受攻击的Ignite服务器，从而绕过类序列化过滤机制并执行任意代码。  
  
**0x04 影响版本**  
- 2.6.0 <= Apache Ignite < 2.17.0  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://ignite.apache.org/  
  
  
  
