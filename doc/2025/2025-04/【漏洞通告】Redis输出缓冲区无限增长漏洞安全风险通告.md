#  【漏洞通告】Redis输出缓冲区无限增长漏洞安全风险通告   
 嘉诚安全   2025-04-25 06:28  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
Redis输出缓冲区无限增长漏洞，漏洞编号为：  
CVE-2025-21605  
。  
  
  
Redis是一个开源的内存数据结构存储系统，广泛应用于缓存、消息队列、实时分析等场景。它支持多种数据结构，如字符串、哈希、列表、集合、有序集合等，并提供丰富的操作命令。Redis具有高性能、灵活性和持久化能力，数据可以保存在内存中，定期或根据需求同步到磁盘。它支持主从复制、分区和高可用性配置，常用于提高系统响应速度和可扩展性。由于其高效的读取和写入性能，Redis成为现代分布式系统中不可或缺的组件之一。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞。  
在7.4.3 > Redis >= 2.6版本中，未认证的客户端可以导致输出缓冲区无限增长，直到服务器内存耗尽或进程被终止。默认配置下，Redis不限制普通客户端的输出缓冲区，允许其无限增长，导致服务崩溃或内存不可用。即使启用了密码认证，但未提供密码，客户端仍可通过"NOAUTH"响应导致缓冲区增长，最终耗尽系统内存。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
7.4.3 > Redis >= 2.6  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
官方已发布安全更新，建议受影响用户尽快升级至Redis 7.4.3版本。  
  
下载链接：  
  
https://github.com/redis/redis/releases/  
  
2.参考链接  
  
https://github.com/redis/redis/releases/tag/7.4.3  
  
https://github.com/redis/redis/security/advisories/GHSA-r67f-p999-2gff  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
