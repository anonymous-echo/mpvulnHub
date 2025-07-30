#  VMware vCenter 和 Kemp LoadMaster 漏洞正受到积极利用   
会杀毒的单反狗  军哥网络安全读报   2024-11-20 01:00  
  
**导****读**  
  
  
  
据了解，影响
Progress Kemp LoadMaster 和 VMware vCenter Server 的安全漏洞现已得到修补，并正在遭到广泛利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGSicEKW0wkjBiadwDknWozm7X7eMEf3e2Ocy4xGdcA18DwG6zcaKtIib5iaDIkgViceW7okXf7icwbxdbA/640?wx_fmt=jpeg&from=appmsg "")  
  
美国网络安全和基础设施安全局 (CISA) 周一将Progress Kemp LoadMaster
中最高严重性安全漏洞（CVE-2024-1212   
,  
CVSS
评分：10.0）添加到其已知被利用漏洞 ( KEV ) 目录中。Progress Software 早在2024 年 2 月就解决了这个问题。  
  
  
该机构表示：“Progress
Kemp LoadMaster 包含一个操作系统命令注入漏洞，允许未经身份验证的远程攻击者通过 LoadMaster
管理界面访问系统，从而执行任意系统命令。”  
  
  
发现并报告该漏洞的Rhino
安全实验室表示，如果攻击者可以访问管理员 Web 用户界面，则成功利用该漏洞可以在 LoadMaster 上执行命令，从而授予他们对负载均衡器的完全访问权限。  
  
  
CISA 添加
CVE-2024-1212 之际，博通也发出警告称，攻击者目前正在利用 VMware vCenter Server
中的两个安全漏洞，这两个漏洞在今年早些时候在中国举行的 Matrix Cup 网络安全竞赛中得到了展示。  
  
  
这两个漏洞分别为
CVE-2024-38812（CVSS 评分：9.8）和 CVE-2024-38813（CVSS 评分：7.5），最初于 2024 年 9
月得到解决，但该公司上个月第二次对前者进行了修复，并表示之前的补丁“并未完全解决”问题。  
  
- CVE-2024-38812DCERPC 协议实现中存在堆溢出漏洞，可能允许具有网络访问权限的恶意行为者获取远程代码执行权限  
  
- CVE-2024-38813一个权限提升漏洞，可能允许具有网络访问权限的恶意行为者将权限提升至 root  
  
虽然目前还没有关于在现实世界的攻击中观察到的利用这些漏洞的详细信息，但
CISA 建议联邦民事行政部门 (FCEB) 机构在 2024 年 12 月 9 日之前修复 CVE-2024-1212，以确保其网络的安全。  
  
  
几天前，Sophos披露，网络犯罪分子正在积极利用
Veeam Backup & Replication 中的一个严重漏洞（CVE-2024-40711，CVSS
评分：9.8）来部署一种之前未记录的勒索软件 Frag。  
  
  
**新闻链接：**  
  
https://thehackernews.com/2024/11/cisa-alert-active-exploitation-of.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
