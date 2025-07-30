#  【漏洞通告】NAKIVO Backup & Replication任意文件读取漏洞安全风险通告   
 嘉诚安全   2025-02-27 05:42  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到NAKIVO Backup & Replication任意文件读取漏洞，漏洞编号为：  
CVE-2024-48248。  
  
  
NAKIVO Backup & Replication 是一款专注于虚拟化、云端及混合环境的备份与灾难恢复的解决方案。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞。PoC/EXP  
**已公开。**  
攻击者可利用STPreLoadManagement 类中的 getImageByPath方法，绕过路径验证并读取目标服务器上的任意文件（包括敏感配置文件、数据库、备份日志等）。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
NAKIVO Backup & Replication < v11.0.0.88174  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前官方已发布安全更新，建议用户尽快升级至最新版本：https://www.nakivo.com/resources/download/trial-download/download/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
