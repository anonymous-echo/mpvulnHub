#  7-Zip高危漏洞，攻击者可绕过安全机制远程执行代码   
 网络安全与人工智能研究中心   2025-01-23 08:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUSicwuicfUyAydJhQTRo5N6XPD9LxvGALWdC7ZZVI2R6skN0r8WUhrjcA/640?wx_fmt=gif&from=appmsg "")  
  
  
近日，流行文件压缩软件7-Zip被曝出一个新漏洞，编号为CVE-2025-0411，CVSS评分为7.0，严重程度较高，引发了广泛的安全担忧。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibz7jFXibIJ7JiawMfwc2zK7cU5gIDnfcu1IsVCjOxxwRDT96QL7SDb7Q1SJWMawUJNasKJsueOzbnyw/640?wx_fmt=jpeg&from=appmsg "")  
  
CVE-2025-0411漏洞允许远程攻击者绕过Windows的“网络标记”（Mark-of-the-Web, MOTW）保护机制，在受影响的系统上执行任意代码。  
  
  
**7-Zip代码执行漏洞详情**  
  
  
  
CVE-2025-0411漏洞源于7-Zip在处理带有MOTW标志的恶意压缩包时的不当操作。  
当用户使用存在漏洞的7-Zip版本解压此类文件时，解压后的文件不会保留MOTW标志。  
这一疏忽使得攻击者能够绕过防范恶意内容的关键安全检查，在当前用户权限下执行任意代码。  
  
  
利用此漏洞需要用户交互，例如访问恶意网页或打开恶意文件。在用户频繁处理来自不可信来源文件的环境中，尤为危险。  
  
  
此前，7-Zip还曾曝出另一个代码执行漏洞，编号为CVE-2024-11477，影响24.07版本。CVE-2024-11477漏洞允许攻击者在用户与恶意压缩包交互时，在当前进程上下文中执行任意代码。  
  
  
**受影响版本**  
  
  
  
CVE-2025-0411漏洞影响24.07及之前的所有7-Zip版本。  
用户被强烈建议升级到24.09版本，24.09版本修复存在的问题，并确保MOTW标记能够正确传递到解压后的文件中。  
  
  
- 2024 年10 月1 日：漏洞报告给供应商。  
  
- 2025 年1 月19 日：协调公开披露并发布修复版本。  
  
  
  
CVE-2025-0411漏洞对用户构成重大风险，因为它破坏了Windows的一项关键安全功能，这项安全功能主要被用于防止未经适当审查的不可信文件执行。攻击者可能利用此漏洞分发恶意软件或者未经授权访问系统，尤其是在用户具有管理员权限的环境中。  
  
  
**缓解措施**  
  
  
  
- 升级软件：用户应立即升级到7-Zip 24.09或更高版本。  
  
- 谨慎操作：避免打开来自未知或不可信来源的压缩包。  
  
- 启用额外保护：使用能够检测和阻止可疑文件活动的终端安全解决方案。  
  
  
  
尽管7-Zip长期以来一直是文件压缩和解压的可信工具，但即使是广泛使用的软件也可能存在漏洞。用户和组织应迅速采取措施，以减轻该漏洞带来的风险。  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUMk71re53Z8Xju62nS9agGCNgUNjPibQP7YZthr22UXppftxLN0kp97A/640?wx_fmt=png&from=appmsg "")  
  
来源｜“FreeBuf”公众号  
  
编辑｜音叶泽  
  
审核｜秦川原  
  
  
