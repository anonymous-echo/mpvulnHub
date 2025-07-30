> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795670&idx=2&sn=5a43c62fd78188c6e942755268c937ef

#  微软修复 Windows 和服务器中可蠕虫的远程代码执行漏洞  
会杀毒的单反狗  军哥网络安全读报   2025-07-10 01:01  
  
**导****读**  
  
  
  
微软发布了  
7  
月份关键安全更新，其中包括一个严重级别的远程代码执行漏洞，该漏洞可能允许攻击者在没有用户交互的情况下跨网络执行恶意代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFJgxeo5hvrUX9OYPBYtpupDjHq4AdFbhIrXAEcclNCK66QH4zsUnOxLF2MnaKTth1Jp0ia19gbLYw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞编号为CVE-2025-47981，影响运行 Windows 10 版本 1607 及更高版本的 Windows 计算机，可能使数百万个系统面临网络攻击。  
  
### 严重安全漏洞详情  
###   
  
SPNEGO 扩展协商 (NEGOEX) 安全机制远程代码执行漏洞对企业和消费者 Windows 环境构成重大威胁。  
  
  
这种基于堆的缓冲区溢出漏洞允许未经授权的攻击者通过网络连接远程执行任意代码，这对于网络环境来说尤其危险。  
  
  
安全研究人员已将此漏洞归类为可蠕虫漏洞，这意味着恶意代码可能会在无人干预的情况下从一个受感染的系统传播到另一个受感染的系统。  
  
  
该漏洞的 CVSS 评分为 9.8（满分 10 分），表明其在机密性、完整性和可用性指标方面具有最高严重性。  
  
  
该漏洞源于 Windows 身份验证机制中对 SPNEGO 扩展协商协议的不当处理。  
  
  
攻击者可以通过无需用户交互或提升权限的网络攻击来利用此漏洞，这对于具有互联系统的组织来说极其危险。  
  
  
微软的可利用性评估表明，利用的可能性“更大”， 尽管目前尚未记录任何公开的利用或主动攻击。  
  
  
该漏洞影响默认启用组策略对象“网络安全：允许 PKU2U 身份验证请求到此计算机使用在线身份”的系统。  
  
  
微软于 2025 年 7 月 8 日发布了官方修复程序。微软将此漏洞归类为通用弱点枚举类别 CWE-122，表明该漏洞具有基于堆的缓冲区溢出特性。  
  
  
系统管理员应优先在所有受影响的 Windows 系统上立即部署这些安全更新。  
  
  
该漏洞的严重性及其易受蠕虫攻击的特性使得快速修补对于维护网络安全至关重要。  
  
  
微软漏洞公告：  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-47981  
  
  
新闻链接：  
  
https://gbhackers.com/microsoft-fixes-wormable-remote-code-execution-flaw/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
