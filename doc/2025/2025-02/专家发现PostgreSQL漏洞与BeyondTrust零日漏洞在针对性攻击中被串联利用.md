#  专家发现PostgreSQL漏洞与BeyondTrust零日漏洞在针对性攻击中被串联利用   
鹏鹏同学  黑猫安全   2025-02-16 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicW7k9uGemdD0ZdKticF5gjYfBCICITfCec5KyWdNNuopbO8tq90NdUbcsMbmHUxwoupxLtQCA5UGg/640?wx_fmt=png&from=appmsg "")  
  
Rapid7的研究人员发现PostgreSQL的psql工具中存在一个高危SQL注入漏洞，追踪为CVE-2025-1094。专家在调查CVE-2024-12356漏洞的远程代码执行利用时发现了该漏洞。BeyondTrust于2024年12月修复了CVE-2024-12356，阻止了这两个漏洞的利用，但CVE-2025-1094在Rapid7向PostgreSQL报告之前一直是一个零日漏洞。  
  
对BeyondTrust遭受的网络攻击的调查导致了零日漏洞CVE-2024-12356和CVE-2024-12686的发现。威胁行为者利用这些漏洞接管了Remote Support SaaS实例，包括美国财政部的实例。  
  
“Rapid7发现，在我们测试的每种场景中，成功利用CVE-2024-12356都必须结合利用CVE-2025-1094才能实现远程代码执行。”Rapid7发布的公告中写道。“虽然BeyondTrust在2024年12月修复了CVE-2024-12356，并且该补丁成功阻止了CVE-2024-12356和CVE-2025-1094的利用，但该补丁并未解决CVE-2025-1094的根本原因，直到Rapid7发现并向PostgreSQL报告之前，它仍然是一个零日漏洞。”  
  
漏洞CVE-2025-1094（CVSS评分：8.1）是PostgreSQL中的一个SQL注入问题，由libpq函数（PQescapeLiteral()、PQescapeIdentifier()、PQescapeString()和PQescapeStringConn()）中引用语法的不当处理引起。当应用程序不当使用函数输出来为psql（PostgreSQL的交互式终端）构建查询时，就会出现此漏洞。  
  
该漏洞影响PostgreSQL 17.3、16.7、15.11、14.16和13.19之前的版本，可能允许攻击者在易受攻击的实现中注入恶意SQL命令。  
  
CVE-2025-1094利用了PostgreSQL处理无效UTF-8字符的方式，允许在psql中进行SQL注入。攻击者可以通过使用psql元命令（特别是感叹号（!）命令）执行任意代码，该命令运行操作系统shell命令，可能导致完全控制系统。  
  
“由于PostgreSQL字符串转义例程处理无效UTF-8字符的方式，以及psql处理无效UTF-8字符中的无效字节序列的方式，攻击者可以利用CVE-2025-1094生成SQL注入。”报告中继续写道。“能够通过CVE-2025-1094生成SQL注入的攻击者，可以通过利用交互式工具运行元命令的能力实现任意代码执行（ACE）。元命令通过提供交互式工具可以执行的各种附加操作来扩展其功能。由感叹号符号标识的元命令允许执行操作系统shell命令。攻击者可以利用CVE-2025-1094执行此元命令，从而控制执行的操作系统shell命令。”  
  
PostgreSQL通过发布以下版本修复了该漏洞：  
  
 PostgreSQL 17.3    
  
 PostgreSQL 16.7    
  
 PostgreSQL 15.11    
  
 PostgreSQL 14.16    
  
 PostgreSQL 13.19    
  
该漏洞由Rapid7的首席安全研究员Stephen Fewer发现。  
  
  
