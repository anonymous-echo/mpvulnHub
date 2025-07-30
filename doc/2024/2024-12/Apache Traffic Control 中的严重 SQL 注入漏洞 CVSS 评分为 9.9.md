#  Apache Traffic Control 中的严重 SQL 注入漏洞 CVSS 评分为 9.9   
会杀毒的单反狗  军哥网络安全读报   2024-12-26 01:00  
  
**导****读**  
  
  
  
Apache 软件基金会 (ASF) 已发布安全更新来修复流量控制中的一个严重安全漏洞，如果成功利用该漏洞，攻击者可以在数据库中执行任意结构化查询语言 (SQL) 命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGCH2rbe0sOnb9of1nV0CgcvzELVut8gG1x480oZicA3ibb4Mu9xnuCRXTUUxdm66HCFejjGGnYmY6g/640?wx_fmt=png&from=appmsg "")  
  
  
该 SQL 注入漏洞的编号为CVE-2024-45387，在 CVSS 评分系统中的评分为 9.9 分（满分 10.0 分）。  
  
  
项目维护人员在一份公告中表示：“Apache Traffic Control <= 8.0.1、>= 8.0.0 中的 Traffic Ops 中存在一个 SQL 注入漏洞，允许具有‘管理员’、‘联合’、‘操作’、‘门户’或‘指导’角色的特权用户通过发送特制的 PUT 请求对数据库执行任意 SQL 。 ”  
  
  
Apache Traffic Control是内容分发网络 (CDN) 的开源实现。它于 2018 年 6 月被AS宣布为顶级项目 (TLP)。  
  
  
腾讯云鼎安全实验室研究员罗远发现并报告了该漏洞。该漏洞已在 Apache Traffic Control 8.0.2 版本中得到修复。  
  
  
此次开发正值 ASF解决了Apache HugeGraph-Server (CVE-2024-43441) 1.0 至 1.3 版本中的身份验证绕过漏洞。1.5.0 版本中已发布了针对该缺陷的修复程序。  
  
  
它还发布了针对 Apache Tomcat（CVE-2024-56337）中一个重要漏洞的补丁，该漏洞可能在某些条件下导致远程代码执行（RCE）。  
  
  
建议用户将其实例更新到软件的最新版本，以防范潜在威胁。  
  
  
官方安全公告：  
https://lists.apache.org/thread/t38nk5n7t8w3pb66z7z4pqfzt4443trr  
  
  
新闻链接：  
  
https://thehackernews.com/2024/12/critical-sql-injection-vulnerability-in.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
