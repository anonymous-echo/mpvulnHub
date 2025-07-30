#  Exim 存在严重漏洞，可绕过 150 万个邮件服务器的安全过滤器   
flyme  独眼情报   2024-07-13 13:14  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnT8N5goX0doUm2iblaPWbgkQLqKfrqWQkpQCkuWyAOk25FTzHibjk9ibxmz86qCL8lEw4BnsdnQqoClA/640?wx_fmt=jpeg&from=appmsg "")  
  
Censys 警告称，超过 150 万个 Exim 邮件传输代理 (MTA) 实例未修补一个严重漏洞，该漏洞可让威胁行为者绕过安全过滤器。  
  
该安全漏洞被编号为  
CVE-2024-39929 ，并于  
  
周三  
由 Exim 开发人员进行了修补，  
影响 Exim 4.97.1 及以下版本。  
  
该漏洞是由于对多行 RFC2231 头文件名的错误解析造成的，这使得远程攻击者可以绕过$mime_filename  
扩展名阻止保护机制，将恶意的可执行附件传送到最终用户的邮箱中。  
  
Censys 警告称：“如果用户下载或运行其中一个恶意文件，系统可能会受到威胁”，并补充道，“目前已经有了 PoC，但尚未发现任何主动攻击。”  
  
  
该公司补充道  
：“截至 2024 年 7 月 10 日，Censys 观察到 1,567,109 台公开暴露的 Exim 服务器运行着潜在易受攻击的版本（4.97.1 或更早版本），主要集中在美国、俄罗斯和加拿大。  
”  
  
虽然电子邮件收件人仍需启动恶意附件才会受到影响，但该漏洞可让威胁者绕过基于文件扩展名的安全检查。这样一来，他们便可将通常被阻止的危险文件（如可执行文件）发送到目标邮箱。  
  
建议无法立即升级 Exim 的管理员限制从互联网对其服务器的远程访问，以阻止传入的攻击尝试。  
## 数百万台服务器暴露在网上  
  
MTA 服务器（例如 Exim）经常成为攻击目标，因为它们几乎总是可以通过互联网访问，这使得它们很容易找到进入目标网络的潜在入口点。  
  
根据本月初的  
邮件服务器调查，  
 Exim 也是默认的 Debian Linux MTA，并且是世界上最受欢迎的 MTA 软件。  
  
调查显示，在调查期间可通过互联网访问的 409,255 台邮件服务器中，超过 59% 运行着 Exim，也就是超过 241,000 个 Exim 实例。  
  
此外，根据  
Shodan 搜索  
，目前有超过 330 万台 Exim 服务器暴露在网上，其中大部分位于美国，其次是俄罗斯和荷兰。Censys 发现网上有 6,540,044 台面向公众的邮件服务器，其中 4,830,719 台（约占 74%）运行着 Exim。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnT8N5goX0doUm2iblaPWbgkQAMmVxyO9MBcj58EVX3ia0mkdqJW8Nvqz5O6wLT6248seThoqNr1WRAQ/640?wx_fmt=jpeg&from=appmsg "")  
  
可在线访问 Exim 服务器（Shodan）  
  
  
美国国家安全局 (NSA)  
于 2020 年 5 月透露  
，臭名昭著的俄罗斯军事黑客组织 Sandworm 至少自 2019 年 8 月以来一直在利用关键的 CVE-2019-10149 Exim 漏洞（被称为“WIZard 的回归”）。  
  
最近，在 10 月份，Exim 开发人员  
修补了通过趋势科技零日计划 (ZDI) 披露的三个零日漏洞  
，其中一个 (CVE-2023-42115)  
使数百万  
台暴露在互联网上的 Exim 服务器面临预授权 RCE 攻击。  
  
原文见：  
  
https://www.bleepingcomputer.com/news/security/critical-exim-bug-bypasses-security-filters-on-15-million-mail-servers/  
  
