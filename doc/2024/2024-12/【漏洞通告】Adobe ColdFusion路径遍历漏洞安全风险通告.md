#  【漏洞通告】Adobe ColdFusion路径遍历漏洞安全风险通告   
 嘉诚安全   2024-12-25 01:35  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Adobe官方发布安全公告，修复了一个Adobe ColdFusion路径遍历漏洞，漏洞编号为：  
CVE-2024-53961。  
  
  
Adobe ColdFusion是美国奥多比（Adobe）公司的一套快速应用程序开发平台。该平台包括集成开发环境和脚本语言，将可扩展、改变游戏规则且可靠的产品的愿景变为现实。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，且  
**PoC/EXP已公开**  
。该漏洞可能导致未经身份验证的远程攻击者绕过应用程序的访问限制，从而读取受限目录之外的文件或目录，成功利用该漏洞可能导致敏感信息泄露或系统数据被操纵。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Adobe ColdFusion 2023 <= Update 11  
  
Adobe ColdFusion 2021 <= Update 17  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
Adobe ColdFusion 2023 >= Update 12  
  
Adobe ColdFusion 2021 >= Update 18  
  
  
官方补丁下载地址：  
  
ColdFusion 2023：  
  
https://helpx.adobe.com/coldfusion/kb/coldfusion-2023-update-12.html  
  
ColdFusion 2021：  
  
https://helpx.adobe.com/coldfusion/kb/coldfusion-2021-update-18.html  
  
  
参考链接：  
  
https://www.adobe.com/products/coldfusion-family.html  
  
https://helpx.adobe.com/security/products/coldfusion/apsb24-107.html  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-53961  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
