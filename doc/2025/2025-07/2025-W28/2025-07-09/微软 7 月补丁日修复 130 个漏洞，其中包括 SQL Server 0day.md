> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795661&idx=3&sn=2488e7df2447ab0208b59164f15dd06a

#  微软 7 月补丁日修复 130 个漏洞，其中包括 SQL Server 0day  
会杀毒的单反狗  军哥网络安全读报   2025-07-09 01:02  
  
**导****读**  
  
  
  
微软  
7  
月补丁日修复其产品中的 130 个漏洞，包括之前披露的 SQL Server 漏洞。  
  
  
微软本月解决的 130 个漏洞中，有 53 个可能导致权限提升，41 个可能导致 RCE，18 个可能导致信息泄露，8 个可能导致安全绕过，6 个可能导致拒绝服务，4 个可能导致欺骗。  
  
  
须重点关注的漏洞包括：  
  
  
CVE-2025-49735  
  
  
Windows KDC 代理服务 (KPSSVC) 中的一个 RCE 漏洞，CVSS 3.1 评分为 8.1。为了成功利用此漏洞，未经身份验证的攻击者可以使用特制应用程序利用 KPSSVC 中的加密协议漏洞对目标执行 RCE。  
  
  
微软指出，此漏洞仅影响配置为 Kerberos 密钥分发中心 (KDC) 代理协议服务器的 Windows 服务器，域控制器不受影响。微软评估该攻击复杂度“高”，利用可能性“较大”。  
   
  
CVE-2025-49704  
  
  
是 Microsoft SharePoint 服务器中的一个远程代码执行 (RCE) 漏洞，其 CVSS 3.1 评分为 7.7。微软指出，Microsoft Office SharePoint 中的此漏洞是由于对代码生成（“代码注入”）的控制不当造成的，这会导致经过身份验证的攻击者通过网络执行代码。  
  
  
要利用此漏洞，经过身份验证的攻击者在基于网络的攻击中，只要拥有最低限度的站点成员权限，就可以在 SharePoint 服务器上远程执行任意代码。微软评估该攻击的复杂度“较低”，且“更有可能”被利用。  
    
  
  
CVE-2025-49695、 CVE-2025-49696、 CVE-2025-49697、 CVE-2025-49698、 CVE-2025-49702和CVE-2025-49703  
  
  
这些是 Microsoft Office 和 Microsoft Word 中的 RCE 漏洞。  
  
  
CVE -2025-49695和CVE-2025-49698漏洞是“释放后使用”(UAF) 漏洞，当 Microsoft Office 尝试访问已释放的内存时发生。CVE -2025-49696是 Microsoft Office 中的越界读取漏洞。  
  
  
微软评估认为，对于CVE-2025-49695和CVE-2025-49696漏洞，攻击复杂度“较低”，利用可能性“较大”。对于CVE-2025-49697、 CVE-2025-49698、 CVE-2025-49702和CVE-2025-49703，攻击复杂度“低”，利用可能性“较小”。  
     
  
  
CVE-2025-48822  
  
  
是 Windows Hyper-V 离散设备分配 (DDA) 中的一个 RCE 漏洞，CVSS 3.1 评分为 8.6。  
  
  
该漏洞属于 Hyper-V 中的越界读取漏洞，可能允许未经授权的攻击者在本地执行代码。微软评估该漏洞攻击复杂度“低”，且利用可能性“较小”。  
  
  
CVE-2025-47981  
  
  
是 SPNEGO 扩展协商 (NEGOEX) 安全机制中的一个 RCE 漏洞，CVSS 3.1 评分为 9.8。  
  
  
该漏洞是一个基于堆的缓冲区溢出漏洞，可能允许未经授权的攻击者通过网络执行代码。  
  
  
微软称，此漏洞会影响运行 Windows 10 版本 1607 及更高版本的 Windows 客户端计算机，因为这些操作系统默认启用了以下 GPO：“网络安全：允许向此计算机发送 PKU2U 身份验证请求以使用在线身份”。微软评估该攻击复杂度“较低”，且利用可能性“较大”。  
   
  
  
CVE-2025-49717  
  
  
是 Microsoft SQL Server 中的一个 RCE 漏洞，CVSS 3.1 评分为 8.5。  
  
  
该漏洞是一个基于堆的缓冲区溢出漏洞，可能允许未经授权的攻击者通过网络执行代码。不过，微软评估该漏洞“不太可能被利用”。  
  
  
CVE-2025-47980  
  
  
最后一个高危漏洞是 Windows 图像组件中的信息泄露漏洞，如果被利用，攻击者可以读取少量堆内存。  
  
  
微软评估该漏洞的攻击复杂度“较低”，且利用可能性“较小”。  
     
  
  
以下“重要级别”漏洞，微软已确定这些漏洞被利用的可能性“更大”：  
    
  
CVE-2025-49701：Microsoft SharePoint 远程代码执行漏洞  
  
CVE-2025-49724：Windows 连接设备平台服务远程代码执行漏洞  
  
  
新闻链接：  
  
https://www.securityweek.com/microsoft-patches-130-vulnerabilities-for-july-2025-patch-tuesday/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
