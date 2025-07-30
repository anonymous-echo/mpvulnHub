#  漏洞预警 | CraftCMS模板注入漏洞   
浅安  浅安安全   2025-01-18 00:01  
  
**0x00 漏洞编号**  
- # CVE-2024-56145  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
CraftCMS是一个灵活的、易于使用的内容管理系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU8Hf5YibCK8obmSCq5lcwuicW45vQDp2TGuPUldZibXaj87iaPNkrGu3D3R2ib7oc5lK6rPab4859G6gQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-56145**  
  
**漏洞类型：**  
模板注入  
  
**影响：**  
执行任意代码  
  
**简述：**  
CraftCMS存在模板注入漏洞，若开启了PHP配置中的register_argc_argv，攻击者可构造恶意请求利用模版注入漏洞执行任意代码，控制服务器。  
  
**0x04 影响版本**  
- 5.0.0-RC1 <= CraftCMS < 5.5.2  
  
- 4.0.0-RC1 <= CraftCMS < 4.13.2  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://craftcms.com/  
  
  
  
