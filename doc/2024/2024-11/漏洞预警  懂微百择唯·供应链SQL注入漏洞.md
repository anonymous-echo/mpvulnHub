#  漏洞预警 | 懂微百择唯·供应链SQL注入漏洞   
浅安  浅安安全   2024-11-28 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
懂微科技是一家专注于办公服务行业电商解决方案的提供商，致力于为办公服务行业赋能、提升效率和核心竞争力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVjdb8W7T5YIrddGeQMLUBTlL49QfAEw54JUb0x6Bw7xYhKSibzxCODqv68rIGNx3qib7XAWnicicpqzg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露****  
  
**简述：**  
懂微百择唯·供应链的/Goods/RankingGoodsList2接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用SQL注入漏洞获取数据库中的信息之外，甚至在高权限的情况下可以向服务器中写入木马，进一步获取服务器系统权限。  
  
**0x04 影响版本**  
- 懂微百择唯·供应链  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.donvv.com/  
  
  
  
