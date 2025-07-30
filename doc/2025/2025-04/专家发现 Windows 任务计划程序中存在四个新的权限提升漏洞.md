#  专家发现 Windows 任务计划程序中存在四个新的权限提升漏洞   
会杀毒的单反狗  军哥网络安全读报   2025-04-17 01:00  
  
**导****读**  
  
  
  
网络安全研究人员详细介绍了 Windows任务调度服务核心组件中的四个不同漏洞，本地攻击者可以利用这些漏洞实现权限提升并擦除日志以掩盖恶意活动的证据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEsI3ZzhibylufXuib7LpJUyZ0EXBBy6wryJIm61Ksib09CS1JPZTcNvKoYQOXymf5dic6uDPsb9yZFhw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞出在名为“ schtasks.exe ”的二进制文件中，该程序允许管理员在本地或远程计算机上创建、删除、查询、更改、运行和结束计划任务。  
  
  
Cymulate 安全研究员 Ruben Enkaoua 在一份报告中表示：“在 Microsoft Windows 中发现了一个 [用户帐户控制] 绕过漏洞，攻击者可以利用该漏洞绕过用户帐户控制提示，从而在未经用户批准的情况下执行高权限 (SYSTEM) 命令。”  
  
  
通过利用此漏洞，攻击者可以提升其权限并以管理员权限运行恶意负载，从而导致未经授权的访问、数据盗窃或进一步的系统入侵。  
  
  
该网络安全公司表示，问题发生在攻击者使用批量登录（即密码）而不是交互式令牌创建计划任务时，导致任务计划程序服务授予正在运行的进程最大允许权限。  
  
  
这种攻击要想奏效，需要攻击者通过其他方式获取密码，例如在针对 SMB 服务器进行身份验证后破解 NTLMv2 哈希或利用CVE-2023-21726等漏洞。  
  
  
该问题的最终结果是，低权限用户可以利用 schtasks.exe 二进制文件并使用已知密码模拟管理员、备份操作员和性能日志用户等组的成员，以获得允许的最大权限。  
  
  
使用批量登录身份验证方法和 XML 文件注册计划任务还可以为两种防御规避技术铺平道路，这些技术可以覆盖任务事件日志，有效地擦除先前活动的审计跟踪以及溢出安全日志。  
  
  
具体来说，这涉及向一个作者注册一个任务，该作者的名称中字母 A 重复了 3500 次，在 XML 文件中，这会导致整个 XML 任务日志描述被覆盖。此行为可以进一步扩展，覆盖整个“C:\Windows\System32\winevt\logs\ Security.evtx ”数据库。  
  
  
Enkaoua 表示：“任务计划程序是一个非常有趣的组件。任何愿意创建任务的人都可以访问它，由 SYSTEM 运行的服务启动，并在权限、进程完整性和用户模拟之间进行权衡。”  
  
  
“报告的第一个漏洞不仅仅是UAC绕过。它的作用远不止于此：它本质上是一种通过CLI使用密码模拟任何用户，并使用/ru和/rp标志获取任务执行会话中授予的最大权限的方法。”  
  
  
漏洞报告：  
  
https://cymulate.com/blog/task-scheduler-new-vulnerabilities-for-schtasks-exe/  
  
  
新闻链接：  
  
https://thehackernews.com/2025/04/experts-uncover-four-new-privilege.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
