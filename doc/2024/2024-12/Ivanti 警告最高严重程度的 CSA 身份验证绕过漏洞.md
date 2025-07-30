#  Ivanti 警告最高严重程度的 CSA 身份验证绕过漏洞   
会杀毒的单反狗  军哥网络安全读报   2024-12-11 01:00  
  
**导****读**  
  
  
  
Ivanti 向客户发出警告，称其云服务设备 (CSA) 解决方案中存在一个新的最高严重性身份验证绕过漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGnMKnGu807Ulib4zCAPZMSWFR32z85bGjvYvV2TPiaM78zK9lZjV70n5FcB0QWbD9BNQrFUh1t6Zdw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该安全漏洞编号为 CVE-2024-11639，由 CrowdStrike 高级研究团队报告。  
  
  
漏洞可使远程攻击者通过使用备用路径或通道绕过身份验证，在运行 Ivanti CSA 5.0.2 或更早版本的易受攻击的设备上获得管理权限，而无需进行身份验证或用户交互。  
  
  
Ivanti 建议管理员使用支持文档中提供的详细信息将易受攻击的设备升级到 CSA 5.0.3 。  
  
  
该公司周二表示： “在公开披露之前，我们不知道有任何客户被这些漏洞利用。这些漏洞是通过我们的负责任披露计划披露的。目前，尚无任何已知的公开利用这些漏洞的案例，这些漏洞可用于提供一份入侵指标列表。”  
  
  
今天，Ivanti 还修补了桌面和服务器管理 (DSM)、Connect Secure 和 Policy Secure、Sentry和Patch SDK产品中的其他中、高和严重漏洞。该公司在安全公告指出，没有证据表明这些漏洞已被利用。  
  
  
CVE-2024-11639 是近几个月来修补的第六个 CSA 安全漏洞，之前修补的五个漏洞分别是：  
  
9 月：CVE-2024-8190（远程代码执行）  
  
9 月：CVE-2024-8963（管理员身份验证绕过）  
  
10 月：CVE-2024-9379、CVE-2024-9380、CVE-2024-9381（SQL 注入、OS 命令注入、路径遍历）  
  
  
今年 9 月，该公司还警告客户，CVE-2024-8190 和 CVE-2024-8963 漏洞已成为攻击目标。  
  
  
此外，它还警告管理员，10 月份修复的三个安全漏洞与 CVE-2024-8963 CSA 管理员绕过相结合，可以通过 SQL 注入运行 SQL 语句、绕过安全限制并通过命令注入执行任意代码。  
  
  
Ivanti表示，其已升级测试和内部扫描能力，并正在改进其负责任的披露流程，以更快地修补安全漏洞，而这一系列漏洞却被积极利用。  
  
  
今年早些时候，在针对 Ivanti VPN 设备以及ICS、IPS 和 ZTA 网关的大规模攻击活动中，其他几个漏洞也被用作0day漏洞，本次攻击行动危害十分广泛，大量企业机密信息泄露。  
  
  
Ivanti 为超过 40,000 家使用其产品来管理其系统和 IT 资产的公司提供服务。  
  
  
参考  
Ivanti  
官方漏洞公告：  
  
https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Cloud-Services-Application-CSA-CVE-2024-11639-CVE-2024-11772-CVE-2024-11773  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/ivanti-warns-of-maximum-severity-csa-auth-bypass-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
