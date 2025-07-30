#  【漏洞通告】pgAdmin信息泄露漏洞安全风险通告   
 嘉诚安全   2024-09-26 10:47  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到pgAdmin中修复了一个信息泄露漏洞，漏洞编号为：CVE-2024-9014。  
  
  
pgAdmin是PostgreSQL的官方图形界面管理工具，以便于管理和维护PostgreSQL数据库。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞。受影响版本的OAuth2身份验证实现中存在漏洞，可能导致OAuth2的客户端ID和密钥在web浏览器中被暴露或泄露，攻击者可利用该漏洞获取敏感信息并未授权访问用户数据。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
pgAdmin 4 <= v8.11  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到pgAdmin 4 v8.12或更高版本。  
  
下载链接：  
  
https://www.pgadmin.org/download/  
  
参考链接：  
  
https://www.pgadmin.org/docs/pgadmin4/8.12/release_notes_8_12.html  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-9014  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
