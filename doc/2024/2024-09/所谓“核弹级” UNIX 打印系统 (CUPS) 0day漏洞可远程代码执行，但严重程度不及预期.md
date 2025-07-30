#  所谓“核弹级” UNIX 打印系统 (CUPS) 0day漏洞可远程代码执行，但严重程度不及预期   
会杀毒的单反狗  军哥网络安全读报   2024-09-28 09:00  
  
**导****读**  
  
  
  
一名研究人员披露了一个未修补的  
Linux  
漏洞的细节，该漏洞原本预计会对许多
Linux 系统构成严重威胁，但实际威胁并没有预期的那么严重。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaE2SEIm5HLy9SXGXJMnXxadhrXcwvKcBu0LMxxTjjsWHKtKMqAsfBibV1kwqke5JwFAot4OcB2ciaMg/640?wx_fmt=jpeg&from=appmsg "")  
  
9 月 23
日，研究员 Simone Margaritelli透露，他将在不到两周的时间内披露影响所有 GNU/Linux 系统未经身份验证的远程代码执行 (RCE)
漏洞的详细信息。他指出，该漏洞的 CVSS 评分为 9.9，  
这让许多网络安全行业人士相信，这将是一个高度关键、影响深远的问题。  
  
  
Margaritelli  
   
当时表示，他对整个负责任的披露过程感到不满，并指出该漏洞尚未开发出可行的修复程序，也没有分配
CVE 标识符。  
  
  
不久之后，有关该漏洞的信息在
GitHub 上泄露，并开始在网络犯罪论坛上流传。因此，研究人员于周四披露了技术细节并发布了概念验证 (PoC) 漏洞利用程序。  
  
  
事实证明，Margaritelli
发现了几个与 OpenPrinting 的通用 UNIX 打印系统 (CUPS) 相关的漏洞，CUPS 是一种流行的互联网打印协议 (IPP)
开源打印系统，主要为 Linux 和类 UNIX 操作系统设计。  
  
  
现已披露了四个
CUPS 漏洞，并已分配标识符 CVE-2024-47076、CVE-2024-47175、CVE-2024-47176 和
CVE-2024-47177。它们被描述为 IPP 属性清理、命令执行和数据包信任问题。  
  
  
远程未经身份验证的攻击者可以通过悄悄地用恶意
URL 替换 IPP URL 来实现任意代码执行。成功的攻击会导致在从目标设备启动打印作业时执行攻击者准备的命令。  
  
  
Red Hat
表示：“通过将这组漏洞链接在一起，攻击者可能会实现远程代码执行，从而导致敏感数据被盗和/或关键生产系统受损。”  
  
  
无论是从互联网还是从本地网络，都可能存在漏洞。互联网上至少有
75,000 个 CUPS 守护进程暴露，其中许多位于韩国和美国。  
  
  
虽然该漏洞似乎非常严重，并且可能被大规模利用，但仍存在一些重要的缓解因素。  
  
  
首先，根据修订后的
CVSS 评分，CUPS 漏洞实际上似乎具有“高”严重性评级，而不是“严重”评级，研究人员对此并未提出异议。  
  
  
例如，Red Hat
指出受影响的软件包在默认配置下不易受攻击。此外，要利用这些漏洞，需要手动启用受影响的 CUPS
服务之一，攻击者需要访问易受攻击的服务器并配置恶意打印机，受害者需要启动打印作业。  
  
  
托管扩展检测和响应公司
Ontinue 已分析了这些漏洞，并确定“实际适用性较低”。  
  
  
“此漏洞的利用方式已被公开披露，并且可以轻松用于在受感染的系统上安装恶意软件，例如远程访问工具
(RAT)。根据我们的评估，对于经常打印的 Linux
系统而言，这个问题十分紧急，而在其他系统中，这个问题在现实世界中的利用可能性极小。”该公司解释道：“攻击者仍必须通过端口 631
访问系统，并在主机打印时通过 LAN 访问主机。”  
  
  
此外，自动红队和攻击面管理解决方案提供商
WatchTowr 的首席执行官本杰明·哈里斯 (Benjamin Harris) 告诉SecurityWeek，这些漏洞可能只会影响部分系统。  
  
  
Harris
说：“虽然这些漏洞在技术影响方面非常严重，但运行 CUPS 的台式机/工作站以与典  
  
型的 Linux
服务器版本相同的方式或数量暴露在互联网中的可能性要小得多，因此这些漏洞不太可能成为 MS08-067、ExternalBlue 和
HeartBleed（这些漏洞已被拿来与之比较）那样的影响力。”  
  
  
补丁尚未发布，Margaritelli
声称 CUPS
开发人员已经承认这些漏洞并不容易修复。  
  
  
有一些简单的缓解措施，特别是对于不需要打印的环境——用户可以运行两个命令来停止易受攻击的服务并防止它在系统重新启动时重新启动。阻止所有到
UDP 端口 631 的流量和 DNS-SD 流量也可以缓解攻击。  
  
  
**链接：**  
  
https://www.securityweek.com/highly-anticipated-linux-flaw-allows-remote-code-execution-but-less-serious-than-expected/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
