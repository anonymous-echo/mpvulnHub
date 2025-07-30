#  三星MagicINFO漏洞在PoC发布几天后被利用   
会杀毒的单反狗  军哥网络安全读报   2025-05-07 01:03  
  
**导****读**  
  
  
  
漏洞PoC 发布几天后，威胁组织就开始利用三星 MagicINFO 中的漏洞。  
  
  
三星 MagicINFO 9 服务器是一种流行的内容管理系统，广泛部署用于管理和控制零售、交通和企业环境中的数字标牌显示器。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGvuTuhPS1I4JAiaDwjU3zHRay8icLGEcRX4EUjULsicBibC6YuuMkubAU2W5zbdQMJaPLj8uecoiaZ88w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
漏洞 (CVE-2024-7399) 源于服务器文件上传功能中输入验证不足。具体而言，该漏洞是由于文件名输入的过滤不充分以及缺乏对文件扩展名或用户身份验证的检查而导致的。  
  
  
Arctic Wolf研究人员观察到，在概念验证 (PoC) 漏洞代码公开发布几天后，威胁组织就开始利用三星 MagicINFO 内容管理系统 (CMS) 中的高严重性漏洞，该漏洞编号为CVE-2024-7399（CVSS 评分：8.8）。  
  
  
该漏洞是三星MagicINFO 9 Server 21.1050之前版本中存在的一个路径名限制到受限目录的漏洞，攻击者可以利用该漏洞以系统权限写入任意文件。  
  
  
Arctic Wolf发布的报告指出：“截至2025年5月初，  
Arctic Wolf已观察到三星MagicINFO 9服务器（用于管理和远程控制数字标牌显示器的内容管理系统 (CMS)）中存在CVE-2024-7399漏洞的广泛利用。该漏洞允许未经身份验证的用户写入任意文件，并且当该漏洞被用于编写特制的JavaServer Pages (JSP) 文件时，最终可能导致远程代码执行。”  
  
  
CVE-2024-7399 是三星 MagicINFO 9 Server 输入验证中的一个缺陷，它允许未经身份验证的攻击者上传 JSP 文件并以系统级访问权限执行代码。  
  
  
三星于2024年8月首次披露该漏洞，当时尚无任何迹象表明该漏洞已被利用。  
  
  
2025年4月30日概念验证（PoC）代码公开几天后，威胁组织开始利用该漏洞。鉴于该漏洞易于利用且PoC已公开发布，专家认为此类攻击可能会持续下去。  
  
  
三星于 2024 年 8 月发布 MagicINFO 9 Server 版本 21.1050解决了该漏洞。  
  
  
由于漏洞的严重性以及功能性 PoC 的公开可用性，使用三星 MagicINFO 9 Server 的组织面临着巨大的风险。  
  
  
漏洞公告：  
  
https://arcticwolf.com/resources/blog/cve-2024-7399/  
  
  
新闻链接：  
  
https://securityaffairs.com/177529/hacking/samsung-magicinfo-vulnerability-exploited-after-poc-publication.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
