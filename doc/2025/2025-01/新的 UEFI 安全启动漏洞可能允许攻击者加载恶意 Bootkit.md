#  新的 UEFI 安全启动漏洞可能允许攻击者加载恶意 Bootkit   
会杀毒的单反狗  军哥网络安全读报   2025-01-17 01:02  
  
**导****读**  
  
  
  
根据ESET 的一份报告，新的 UEFI 安全启动漏洞  
CVE-2024-7344（CVSS 分数：6.7），位于由微软“Microsoft Corporation UEFI CA 2011”第三方 UEFI 证书签名的 UEFI 应用程序中。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaE4P1uBRdRPv4h2v1EhNESicGVWa9f5AxjuRZgMBZ3c1VtqXbbeVGaw6rv5clsUwpHEfpOhibesbU2w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
成功利用该漏洞可导致系统启动期间执行不受信任的代码，从而使攻击者能够在启用安全启动的机器上部署恶意 UEFI 启动套件，而不管所安装的操作系统是什么。  
  
  
安全启动（Secure Boot）是一种固件安全标准，可确保设备仅使用原始设备制造商 (OEM) 信任的软件进行启动，从而防止计算机启动时加载恶意软件。该功能利用数字签名来验证加载代码的真实性、来源和完整性。  
  
  
受影响的 UEFI 应用程序是 Howyar Technologies Inc.、Greenware Technologies、Radix Technologies Ltd.、SANFONG Inc.、Wasay Software Technology Inc.、Computer Education System Inc. 和 Signal Computer GmbH 开发的几款实时系统恢复软件套件的一部分：  
- Howyar SysReturn 10.2.023_20240919 之前的版本  
- Greenware GreenGuard 10.2.023-20240927 之前的版本  
- Radix SmartRecovery  11.2.023-20240927 之前的版本  
- Sanfong EZ-back  
 system   
10.3.024-20241127之前版本  
- WASAY eRecoveryRX  8.4.022-20241127 之前的版本  
- CES NeoImpact 10.1.024-20241127 之前版本  
- SignalComputer HDD King 10.3.021-20241127 之前版本  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaE4P1uBRdRPv4h2v1EhNESiceGjQ6cPjPLPEwqMEzvlpicGTfmnEEfmV86iaXabMk9qVwB0u93NUcvTQ/640?wx_fmt=png&from=appmsg "")  
  
  
ESET 研究员 Martin Smolár 表示： “该漏洞是由于使用自定义 PE 加载程序而不是使用标准且安全的 UEFI 函数LoadImage和StartImage而导致。无论 UEFI 安全启动状态如何，该应用程序都允许在系统启动期间从名为 cloak.dat 的特制文件加载任何 UEFI 二进制文件（甚至是未签名的二进制文件）。”  
  
  
因此，利用 CVE-2024-7344 的攻击者可以绕过 UEFI 安全启动保护，并在操作系统加载之前在 UEFI 上下文中的启动过程中执行未签名的代码，从而授予他们对主机的隐蔽、持久的访问权限。  
  
  
CERT 协调中心 (CERT/CC)表示：“在此早期启动阶段执行的代码可以保留在系统中，可能会加载恶意内核扩展，这些扩展在重新启动和操作系统重新安装后仍会存在。此外，它可能会逃避基于操作系统和端点检测和响应 (EDR) 安全措施的检测。”  
  
  
恶意攻击者可以通过将自己的易受攻击的“reloader.efi”二进制文件副本带到任何已注册 Microsoft 第三方 UEFI 证书的 UEFI 系统，进一步扩大利用范围。但是，需要提升权限才能将易受攻击的恶意文件部署到 EFI 系统分区：Windows 上的本地管理员和 Linux 上的 root。  
  
  
ESET  
表示，它于 2024 年 6 月负责任地向 CERT/CC 披露了调查结果，随后 Howyar Technologies 及其合作伙伴在相关产品中解决了该问题。2025 年 1 月 14 日，微软在  
1  
月安全更新中撤销了旧的易受攻击的二进制文件。  
  
  
除了应用 UEFI 撤销之外，管理对位于 EFI 系统分区上的文件的访问、安全启动定制以及使用可信平台模块 ( TPM ) 进行远程证明是防止利用未知的易受攻击的签名 UEFI 引导加载程序和部署 UEFI 引导套件的其他一些方法。  
  
  
Smolár 表示：“近年来发现的 UEFI 漏洞数量，以及在合理时间范围内修补这些漏洞或撤销易受攻击的二进制文件的失败表明，即使是像 UEFI 安全启动这样重要的功能也不应被视为坚不可摧的屏障。”  
  
  
“关于这个漏洞，我们最担心的不是修复和撤销二进制文件所花的时间，与类似情况相比，这个时间已经很不错了，但事实是，这并不是第一次发现这种明显不安全的签名 UEFI 二进制文件。这引发了这样的疑问：第三方 UEFI 软件供应商使用这种不安全技术有多普遍，以及可能还有多少其他类似的晦涩难懂但签名的引导加载程序。”  
  
  
技术报告：  
  
https://www.welivesecurity.com/en/eset-research/under-cloak-uefi-secure-boot-introducing-cve-2024-7344/  
  
  
新闻链接：  
  
https://thehackernews.com/2025/01/new-uefi-secure-boot-vulnerability.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
