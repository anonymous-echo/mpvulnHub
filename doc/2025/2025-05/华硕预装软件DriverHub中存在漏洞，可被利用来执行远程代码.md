#  华硕预装软件DriverHub中存在漏洞，可被利用来执行远程代码   
会杀毒的单反狗  军哥网络安全读报   2025-05-13 01:00  
  
**导****读**  
  
  
  
新西兰安全研究员“MrBruh”表示，华硕主板预装的驱动程序软件 DriverHub 中存在两个漏洞，可被远程利用执行任意代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaELH3YEg8S4VL14rFVP9yiavALYEWKzDPdeCOWYNiccQA8TdicAWFxE4YdIHZN4HnKg5y3Mw2AFvpQvA/640?wx_fmt=webp&from=appmsg "")  
  
  
这两个漏洞编号为CVE-2025-3462（CVSS 评分为 8.4）和CVE-2025-3463（CVSS 评分为 9.4），可以通过精心设计的 HTTP 请求利用这些漏洞 与 DriverHub 进行交互。  
  
  
这两个漏洞均源于验证不足，导致 DriverHub 功能被滥用。华硕表示，这些漏洞不会影响笔记本电脑和台式机。  
  
  
DriverHub 是一款无图形用户界面 (GUI) 的驱动程序更新程序，它会在后台运行一个进程，通过本地主机 53000 端口上的 RPC 与 driverhub.asus.com 进行通信。  
  
  
研究员 MrBruh 发现，虽然它只接受源头设置为“driverhub.asus.com”的请求，但通配符匹配机制存在缺陷，允许来自“driverhub.asus.com.mrbruh.com”等域名的请求。攻击者可以利用此漏洞安装恶意软件。  
  
  
DriverHub 在后台运行，与 driverhub.asus.com 通信，通知用户需要安装或更新的驱动程序。它依赖于远程过程调用 (RPC) 协议，并托管一个本地服务，网站可以通过 API 请求连接到该服务。  
  
  
根据 MrBruh 的说法，虽然 DriverHub 只接受来自 driverhub.asus.com 的 RPC 请求，但将来源切换为“driverhub.asus.com.*”将允许未经授权的用户向其发送请求。  
  
  
此外，驱动程序的UpdateApp端点将接受精心设计的 URL 参数（如果它们包含“.asus.com”），保存具有指定名称的文件，下载具有任何扩展名的任何文件，自动以管理员权限执行签名的文件，并且不会删除未通过签名检查的文件。  
  
  
通过查看 ZIP 存档中分发的独立 Wi-Fi 驱动程序，MrBruh 发现可以利用静默安装功能来针对 UpdateApp 端点执行任何文件。  
  
  
研究人员演示了如何利用这些漏洞通过让目标用户访问托管在 driverhub.asus.com.* 子域上的恶意网页来一键执行远程代码。  
  
  
MrBruh 于 4 月 8 日报告了这些漏洞，华硕于 5 月 9 日推出了修复程序。这位研究人员表示，他没有看到任何注册了 driverhub.asus.com.* 的域名，“这意味着在他的报告之前，这个漏洞不太可能被主动利用”。  
  
  
MrBruh 询问华硕是否提供漏洞赏金。该公司表示，他们不提供漏洞赏金，但会将研究人员的名字添加到他们的“名人堂”。  
  
  
漏洞详情：  
  
https://mrbruh.com/asusdriverhub/  
  
  
新闻链接：  
  
https://www.securityweek.com/asus-driverhub-vulnerabilities-expose-users-to-remote-code-execution-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
