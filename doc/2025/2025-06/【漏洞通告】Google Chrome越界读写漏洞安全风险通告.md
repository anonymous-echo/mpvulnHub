#  【漏洞通告】Google Chrome越界读写漏洞安全风险通告   
 嘉诚安全   2025-06-03 07:26  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
Google Chrome越界读写漏洞，漏洞编号为：  
CVE-2025-5419  
。  
  
  
Chrome是一款由Google公司开发的免费的、快速的互联网浏览器软件，目标是为使用者提供稳定、安全、高效的网络浏览体验。Google Chrome基于更强大的JavaScript V8引擎，提升浏览器的处理速度。支持多标签浏览，每个标签页面都在独立的“沙箱”内运行。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
已发现被  
**在野利用**  
。  
该漏洞源于V8引擎中的越界读写问题，攻击者通过恶意网页触发漏洞，可绕过沙箱防护实现远程代码执行，完全控制用户设备。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Windows/Mac：  
  
Google Chrome < 137.0.7151.68/.69  
  
Linux：  
  
Google Chrome < 137.0.7151.68  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前官方已发布安全更新，建议用户尽快升级至最新版本：  
  
Windows/Mac：  
  
Google Chrome >= 137.0.7151.68/.69  
  
Linux：  
  
Google Chrome >= 137.0.7151.68  
  
官方补丁下载地址：  
  
https://www.google.cn/chrome/  
  
参考链接：  
  
https://chromereleases.googleblog.com/2025/06/stable-channel-update-for-desktop.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
