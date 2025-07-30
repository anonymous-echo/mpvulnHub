#  攻击者正在利用 Four-Faith 工业路由器中的命令注入漏洞来部署反向 shell   
会杀毒的单反狗  军哥网络安全读报   2024-12-31 01:00  
  
**导****读**  
  
  
  
漏洞情报公司 VulnCheck 警告称，已观察到威胁组织利用 Four-Faith 工业路由器中的漏洞来部署反向 shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGEms39BqqVc5veRN6l3F8V7c08HzoIZPwOt4lpuc3sbbkSXc3VIZDE9fagmUg4EIZfTMibtzia1ia0g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞编号为 CVE-2024-12856（CVSS 评分为 7.2），是一个操作系统命令注入问题，可以远程利用但需要身份验证。  
  
  
受影响的设备包括运行固件版本 2.0 的 Four-Faith 路由器型号 F3x24 和 F3x36，还发现其中包含可用于获取未经身份验证的远程命令注入的默认凭据。  
  
  
NIST 公告指出： “至少固件版本 2.0 允许经过身份验证的远程攻击者通过 apply.cgi 修改系统时间，通过 HTTP 执行任意操作系统命令。”  
  
  
此固件版本具有默认凭据，如果不进行更改，将有效地将此漏洞转变为未经身份验证的远程操作系统命令执行问题。  
  
  
据VulnCheck称，攻击者被发现使用 HTTP 上的 POST 请求修改系统时间参数。约 15,000 款面向互联网的路由器型号可能受到此安全缺陷的影响。  
  
  
2024 年 11 月，其他人观察到了利用 CVE-2024-12856 的首次攻击，VulnCheck 表示，尽管有效载荷已被修改，但识别出的用户代理与它所见过的类似。这些攻击至少来自两个不同的 IP 地址。  
  
  
VulnCheck 还指出，这些攻击可能看起来像是针对 CVE-2019-12168（另一个涉及 apply.cgi 端点的漏洞）的利用尝试，但具有不同的底层组件。  
  
  
VulnCheck 表示，它于 12 月 20 日向 Four-Faith 通报了该漏洞的野外利用情况，但目前尚不清楚何时会推出补丁。  
  
  
新闻链接：  
  
https://www.securityweek.com/four-faith-industrial-router-vulnerability-exploited-in-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
