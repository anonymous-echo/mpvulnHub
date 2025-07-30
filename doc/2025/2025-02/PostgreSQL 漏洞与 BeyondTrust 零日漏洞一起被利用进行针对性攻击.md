#  PostgreSQL 漏洞与 BeyondTrust 零日漏洞一起被利用进行针对性攻击   
Rhinoer  犀牛安全   2025-02-14 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdsiaGvBnrWQNkm8APr73BRkpRmLebXHLJYVia4eMaLqxXMeeIUNyCNftQ/640?wx_fmt=png&from=appmsg "")  
  
根据 Rapid7 的调查结果，2024 年 12 月利用 BeyondTrust 特权远程访问 (PRA) 和远程支持 (RS) 产品中零日漏洞的攻击者可能也利用了 PostgreSQL 中以前未知的 SQL 注入漏洞。  
  
该漏洞编号为**CVE-2025-1094**  
（CVSS 评分：8.1），影响 PostgreSQL 交互式工具 psql。  
  
安全研究员 Stephen Fewer表示  
：“能够通过 CVE-2025-1094 生成 SQL 注入的攻击者可以利用交互式工具运行元命令的能力来实现任意代码执行 (ACE)。”  
  
该网络安全公司进一步指出，它是在对  
CVE-2024-12356  
进行调查时发现这一问题的，CVE-2024-12356 是 BeyondTrust 软件中最近修补的一个安全漏洞，允许未经身份验证的远程代码执行。  
  
具体来说，研究发现“成功利用 CVE-2024-12356 必须包括利用 CVE-2025-1094 才能实现远程代码执行。”  
  
在协调披露中，PostgreSQL 的维护人员  
发布了  
更新来解决以下版本中的问题 -  
- PostgreSQL 17（已在 17.3 中修复）  
  
- PostgreSQL 16（已在 16.7 中修复）  
  
- PostgreSQL 15（已在 15.11 中修复）  
  
- PostgreSQL 14（已在 14.16 中修复）  
  
- PostgreSQL 13（已在 13.19 中修复）  
  
该漏洞源于 PostgreSQL 处理无效 UTF-8 字符的方式，从而为攻击者利用  
快捷命令“\!”  
进行 SQL 注入打开了大门，从而实现了 shell 命令执行。  
  
攻击者可以利用 CVE-2025-1094 执行此元命令，从而控制所执行的操作系统 shell 命令，”Fewer 说道。“或者，能够通过 CVE-2025-1094 生成 SQL 注入的攻击者可以执行任意受攻击者控制的 SQL 语句。”  
  
目前，美国网络安全和基础设施安全局 (CISA)将影响 SimpleHelp 远程支持软件的安全漏洞 (   
CVE-2024-57727 ，CVSS 评分：7.5)  
添加  
到已知利用漏洞 (   
KEV  
 ) 目录中，要求联邦机构在 2025 年 3 月 6 日之前应用修复程序。  
  
  
信息来源：The hacker News  
  
