#  漏洞预警 | Redis拒绝服务漏洞   
浅安  浅安安全   2025-04-26 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-21605  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Redis是一个持久存在于磁盘上的内存数据库。数据模型是键值对，但支持许多不同类型的值：字符串、列表、集合、有序集合、哈希、流、HyperLogLogs、位图。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7stTqD182SUbPlJfxfPGK7UNcIKiciaP0gmGWW9wXH3LWenX7lFtMPy2Lqb6WtIXHYv7Hecd5dkgm3m1OVRwBPsg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-21605**  
  
**漏洞类型：**  
拒绝服务  
  
**影响：**  
资源耗尽  
  
**简述：**  
Redis存在拒绝服务攻击漏洞，未认证的客户端可以导致输出缓冲区无限增长，直到服务器内存耗尽或进程被终止。  
  
**0x04 影响版本**  
- 2.6 <= Redis < 7.4.3  
  
**0x05 POC状态**  
- **未公开**  
  
**0x06 修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://redis.io/  
  
  
  
