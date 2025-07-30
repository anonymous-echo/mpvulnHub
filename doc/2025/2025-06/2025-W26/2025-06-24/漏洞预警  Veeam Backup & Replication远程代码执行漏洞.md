> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493483&idx=1&sn=9c590617818f23d89234775a6c23dac4

#  漏洞预警 | Veeam Backup & Replication远程代码执行漏洞  
浅安  浅安安全   2025-06-24 00:01  
  
# 0x00 漏洞编号  
- # CVE-2025-23121  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Veeam Backup & Replication是一款功能强大的数据备份与恢复软件，它不仅可以保护虚拟化环境，还提供了跨平台的备份支持，为企业提供强大的数据保护功能，包括快速备份、即时恢复、灾难恢复和复制等功能，旨在确保数据的高可用性和业务的持续性。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWdS9YicuaOwLnxqSibmTDDfMKDOQb0XaTa47KNJRrdd3bQJ80c9vmRqFjTe4XC7gGGKVWPKKXoqbiag/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-23121**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
V  
eeam Backup & Replication存在远程代码执行漏洞，该漏洞允许经过身份验证的域用户在Veeam Backup & Replication备份服务器上执行任意代码。  
  
**0x04 影响版本**  
- Veeam Backup & Replication <= 12.3.1.1139  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户关注官方动态****：**  
  
https://www.veeam.com/  
  
  
  
