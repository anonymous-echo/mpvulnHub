#  【漏洞通告】ProjectSend身份验证绕过漏洞安全风险通告   
 嘉诚安全   2024-11-29 07:50  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到ProjectSend修复了一个身份验证绕过漏洞，漏洞编号为：  
CVE-2024-11680。  
  
  
ProjectSend是一个开源文件共享Web应用程序，旨在促进服务器管理员和客户端之间的安全、私密文件传输。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，已发现被  
**在野利用**  
，且  
**PoC/EXP已公开**  
。未经身份验证的远程攻击者可通过向options.php发送恶意构造的HTTP POST请求来利用该漏洞，成功利用可能导致更改站点配置（比如修改站点标题、启用用户注册等）、上传恶意文件（WebShell）或注入恶意JavaScript。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
ProjectSend < r1720  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
ProjectSend >= r1720  
  
下载链接：  
  
https://github.com/projectsend/projectsend/commit/193367d937b1a59ed5b68dd4e60bd53317473744  
  
https://github.com/projectsend/projectsend/releases/tag/r1720  
  
参考链接：  
  
https://github.com/projectsend/projectsend  
  
https://thehackernews.com/2024/11/critical-flaw-in-projectsend-under.html  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
