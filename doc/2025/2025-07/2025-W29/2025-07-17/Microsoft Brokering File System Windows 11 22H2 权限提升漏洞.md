> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531794&idx=1&sn=8981d6a46b6b158edab4ffeb30db9bc4

#  Microsoft Brokering File System Windows 11 22H2 权限提升漏洞  
 Ots安全   2025-07-17 06:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在2025年7月16日，安全研究人员通过Exploit Database（@ExploitDB）披露了一项新的安全漏洞，编号为CVE-2025-49677。这一漏洞影响Microsoft Brokering File System（Brokering 文件系统），特别是在Windows 11 22H2版本中，允许本地经过身份验证的攻击者通过权限提升（Privilege Escalation）获取SYSTEM级别的权限。这一发现引起了广泛关注，因为它可能为恶意行为者提供了一个在已妥协的系统中进一步扩展控制的途径。  
  
漏洞描述  
  
CVE-2025-49677 是一种由于Microsoft Brokering File System中存在竞争条件（Race Condition）而引发的权限提升漏洞。该文件系统是一个内核模式驱动程序，负责处理Windows操作系统的文件操作和进程间通信。  
  
漏洞的具体成因是内存分配和释放过程中存在双重释放（Double Free）问题（CWE-415），这使得攻击者能够在特定条件下利用该漏洞执行任意代码，并将权限提升至SYSTEM级别。根据相关研究（例如ZeroPath Blog），该漏洞允许经过身份验证的本地攻击者在已有初始访问权限的情况下，进一步提升权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadAbDQibLNibQ3hnDtciayfrzPnBDyeYLTb6JHgjIiaEO6PBbiaF7ZKmbAsLEakcEMfQAKgRdM82YicKwbg/640?wx_fmt=png&from=appmsg "")  
  
这类漏洞在安全领域被称为垂直权限提升（Vertical Privilege Escalation），其危害性在于攻击者可以从普通用户权限跃升至系统最高权限，控制整个操作系统。  
  
受影响的系统  
- Windows 11 22H2  
  
- Windows 10 (版本1607至22H2)  
  
- Windows Server 2022 及 2025 版本  
  
需要注意的是，漏洞的利用需要攻击者具备本地访问权限和有效的身份验证凭据，因此它更可能在内部威胁或已成功入侵的场景中被利用。  
  
漏洞成因  
  
根据nu11secur1ty提供的概念验证（Proof of Concept, PoC）代码，该漏洞源于Brokering File System在处理内存对象时未能正确管理资源释放。当系统在高并发场景下处理多个请求时，同一内存地址可能被多次释放，导致内存损坏或可预测的内存重用。这种情况为攻击者提供了可利用的窗口，通过精心构造的输入触发漏洞。PoC利用了Windows计划任务（Scheduled Tasks）和批处理脚本，运行一个以SYSTEM权限执行的交互式shell。攻击者只需以管理员权限运行Python脚本，即可创建计划任务并执行任意命令，输出结果返回至控制台。  
  
利用流程  
- 准备阶段: 攻击者需要在目标系统上获得管理员权限（例如通过其他漏洞或社会工程手段）。  
  
- 漏洞触发: 运行PoC脚本，创建以SYSTEM用户身份运行的计划任务。  
  
- 命令执行: 在交互式提示符（SYSTEM>）中输入Windows命令（如whoami、dir或net user），获取SYSTEM级别的输出。  
  
- 清理: 输入exit以删除临时文件和计划任务。  
  
检测与验证  
  
要检测系统是否受影响，用户可以通过以下步骤验证：  
- 检查操作系统版本（运行winver命令，确认是否为Windows 11 22H2）。  
  
- 查看已安装的安全更新，确认是否包含针对CVE-2025-49677的补丁。  
  
结论  
  
CVE-2025-49677是Microsoft Brokering File System中的一个严重权限提升漏洞，其影响范围涵盖Windows 11 22H2及其他相关版本。尽管利用该漏洞需要本地访问权限，但其能够实现SYSTEM级别的控制使其成为高危威胁。安全研究人员nu11secur1ty提供的PoC进一步证实了漏洞的可利用性。用户应立即应用Microsoft的官方补丁，并采取额外的安全措施以降低风险。随着操作系统复杂性的增加，内核驱动程序漏洞的发现和利用将成为常态。本次事件提醒我们，持续的漏洞管理、及时的补丁应用以及全面的安全策略是保护系统免受攻击的关键。  
  
POC：  
  
https://github.com/nu11secur1ty/CVE-mitre/tree/main/2025/CVE-2025-496  
  
为了您的真实环境安全风险，请在虚拟测试环境进行复现  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
