#  新的Windows 0day漏洞：攻击者几乎无需用户交互即可窃取 NTLM 凭据   
会杀毒的单反狗  军哥网络安全读报   2024-12-07 01:01  
  
**导****读**  
  
  
  
0patch 的研究人员警告说，从  
Windows  
7 到最新的  
Windows  
11  
2  
4H2 、  
Windows  
Server 2022 的所有 Windows Workstation 和 Server 版本都受到该  
0day  
漏洞影响。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFwCs0hTGpria4ofdqRDLfdOyzGaG6lbaGmKiaksbEiauZyjDib83aKZqnMUFMI95mXhdvjkFFrWYDHpA/640?wx_fmt=png&from=appmsg "")  
  
攻击者可以通过制作恶意文件并诱骗用户打开包含该文件的文件夹来利用此漏洞。  
  
  
0patch 研究员 Mitja Kolsek 表示：“该漏洞允许攻击者通过让用户在 Windows 资源管理器中查看恶意文件来获取用户的 NTLM 凭据。例如，打开包含此类文件的共享文件夹或 USB 磁盘，或者查看先前从攻击者的网页自动下载此类文件的下载文件夹。”  
  
  
NTLM（新技术 LAN 管理器）是 Microsoft 的内置身份验证系统，已被 Kerberos 等更现代的解决方案所取代。  
  
  
NTLM 仍在使用，以兼容旧系统和应用程序。这套安全协议在用户访问网络资源（如共享文件或打印机）时提供身份验证、完整性和机密性。然而，攻击者可能会利用这些凭据未经授权访问公司网络和敏感数据。  
  
  
0patch 是安全公司 ACROS Security 提供的一项服务，在微软停止支持旧版操作系统后，它会继续为 Windows 提供安全更新。  
  
  
该公司向微软报告了该问题，并发布了一个免费的非官方微补丁，微软尚未提供官方修复补丁。  
  
  
研究人员表示：“我们将保留此漏洞的详细信息，直到微软发布修复程序，以最大限度地降低恶意利用的风险。”  
  
  
这是继影响 Server 2012 的 Windows 主题欺骗漏洞和 Mark of the Web 漏洞之后，0patch 近期发现并报告给微软的第三个  
0day  
漏洞。  
  
  
据该公司称，所有三个漏洞均尚未得到官方修复，此外还有研究员 Florian 发现的另一个“EventLogCrasher”漏洞，该漏洞可使攻击者禁用所有域计算机上的所有 Windows 事件日志记录。  
  
  
0patch 警告“出于任何原因”使用 NTLM 的组织，他们可能会受到微软决定不修补的另外三个漏洞的影响。  
  
  
该公司表示：“此类漏洞经常被发现，而且攻击者对它们了如指掌。”  
  
  
0patch 声称为旧版 Windows 和仍在接收 Windows 更新的版本提供补丁。该公司计划在 2025 年 10 月 Windows 10 寿终正寝时“安全采用”它。  
  
  
0patch  
官方博客：  
  
https://blog.0patch.com/2024/12/url-file-ntlm-hash-disclosure.html  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/new-windows-zero-day-exposes-ntlm-credentials-gets-unofficial-patch/  
  
https://cybernews.com/security/windows-zero-day-attackers-can-steal-ntlm-credentials/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
