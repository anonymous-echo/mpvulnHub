#  Adobe 发布带有 PoC 漏洞代码的严重 ColdFusion 错误提醒   
胡金鱼  嘶吼专业版   2025-01-15 06:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Adobe 发布了安全更新，以利用概念验证 (PoC) 漏洞利用代码来解决关键的 ColdFusion 漏洞。该漏洞（编号为 CVE-2024-53961）是由影响 Adobe ColdFusion 2023 和 2021 版本的路径遍历漏洞引起的，攻击者可以读取易受攻击的服务器上的任意文件。  
  
Adobe 表示：“Adobe 意识到 CVE-2024-53961 具有已知的概念验证，可能会导致任意文件系统读取”，同时还提醒客户，它为该漏洞分配了“优先级 1”严重性评级，因为对于给定的产品版本和平台，它“被野地利用的风险更高”。  
  
该公司建议管理员尽快安装当前的紧急安全补丁（ColdFusion 2021 Update 18 和 ColdFusion 2023 Update 12），并应用 ColdFusion 2023 和 ColdFusion 2021 锁定指南中概述的安全配置设置。  
  
虽然 Adobe 尚未透露此漏洞是否已被广泛利用，但它建议客户应当查看其更新的串行过滤器文档，以获取有关阻止不安全的 Wddx 反序列化攻击的更多信息。  
  
正如 CISA 在 2024 年 5 月份那样，敦促软件公司在发布产品之前清除路径遍历安全漏洞，攻击者可以利用此类漏洞访问敏感数据，包括可用于暴力破解现有帐户并破坏目标系统的凭据。  
  
至少从 2007 年起，像目录遍历这样的漏洞就被人们多加关注。尽管有这一发现，目录遍历漏洞（例如 CWE-22 和 CWE-23）仍然是常见的漏洞类别。  
  
此前，CISA 还命令联邦机构在 8 月 10 日之前确保其 Adobe ColdFusion 服务器的安全，防止攻击中利用的两个关键安全漏洞（CVE-2023-29298 和 CVE-2023-38205），其中一个是零攻击漏洞。  
  
如今，美国网络安全机构还透露，自 2023 年 6 月以来，黑客一直在使用另一个关键的 ColdFusion 漏洞 (CVE-2023-26360) 来破坏过时的政府服务器，同样的漏洞已在“非常有限的攻击”中被积极利用。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/adobe-warns-of-critical-coldfusion-bug-with-poc-exploit-code/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29Sgp8iaMCnhMqNv8BTEu3YEByZv6dvZn9uYntTnnByzSh05ticBicnHNj4s7FWN4rtdfQJ7qcrK0fRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29Sgp8iaMCnhMqNv8BTEu3YEgdyCQWibVr37Sab1hE5Z1ibjsOBNErRwpy4fJJTlPPN9xT4DCHJIy58Q/640?wx_fmt=png&from=appmsg "")  
  
  
