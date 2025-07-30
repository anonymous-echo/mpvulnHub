#  微软警告六个Windows零日漏洞正在被积极利用   
原创 hackerson  黑客联盟l   2024-08-17 15:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWhqjlIpdACpYtdVvKD3OPyBmYA5brJN4sK34dYRQcSL3uKNsGNoib9fEN3CEGeChjIvOx8qClscs5w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dhzGXdxNSYvt7iaxBPsTS2nn0SclEp7Q1kKeLLTeckErDXQ5Up7rok19PVEGPGG6uQ7jWfVfApPCe6q9XsEhm4A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软的安全响应团队发布了有关Windows及其操作系统组件的近90个漏洞的文档，并标记了几个被积极利用的缺陷类别。  
  
微软周二警告称，六个Windows安全缺陷正在被积极利用，突显出其旗舰操作系统在零日攻击方面的持续挑战。  
  
Redmond的安全响应团队发布了有关Windows及操作系统组件的近90个漏洞的文档，引起关注的是，其中有六个被标记为“正在被积极利用”的类别。  
  
以下是有关六个新修补的零日漏洞的详细信息：  
  
CVE-2024-38178 — Windows脚本引擎中的内存损坏漏洞允许远程代码执行攻击。如果经过身份验证的客户端被诱骗点击链接，未经身份验证的攻击者就可以启动远程代码执行。根据微软的说法，成功利用此漏洞需要攻击者首先准备目标，使其在Internet Explorer模式下使用Edge。CVSS评分为7.5/10。此零日漏洞由Ahn Lab和韩国国家网络安全中心报告，表明它可能被用于国家级APT攻击。微软没有发布IOC（入侵指标）或任何其他数据来帮助防御者寻找感染迹象。  
  
CVE-2024-38189 — Microsoft Project中的远程代码执行漏洞通过恶意操控的Microsoft Office Project文件在禁用“阻止从互联网下载的Office文件运行宏”策略并且未启用“VBA宏通知设置”的系统上被利用，允许攻击者执行远程代码。CVSS评分为8.8/10。  
  
CVE-2024-38107 — Windows Power Dependency Coordinator中的权限提升漏洞被评为“重要”，CVSS严重性评分为7.8/10。微软表示，“成功利用此漏洞的攻击者可以获得系统权限。”然而，微软并未提供任何IOC或其他利用遥测信息。  
  
CVE-2024-38106 — 针对该Windows内核权限提升漏洞的攻击已被检测到，该漏洞的CVSS严重性评分为7.0/10。“成功利用此漏洞需要攻击者赢得竞态条件。成功利用此漏洞的攻击者可以获得系统权限。”此零日漏洞由匿名报告给微软。  
  
CVE-2024-38213 — 微软将其描述为一个正在被积极利用的Windows网页标记安全功能绕过漏洞。“成功利用此漏洞的攻击者可以绕过SmartScreen用户体验。”  
  
CVE-2024-38193 — Windows辅助功能驱动程序（WinSock）的权限提升安全缺陷正在被广泛利用。技术细节和IOC尚不可用。微软表示，“成功利用此漏洞的攻击者可以获得系统权限。”  
  
微软还敦促Windows系统管理员密切关注一批严重漏洞，这些漏洞可能使用户面临远程代码执行、权限提升、跨站脚本和安全功能绕过攻击的风险。  
  
这些漏洞包括Windows可靠多播传输驱动程序（RMCAST）中的一个主要缺陷，带来远程代码执行风险（CVSS评分为9.8/10）；一个严重的Windows TCP/IP远程代码执行漏洞，CVSS严重性评分为9.8/10；Windows网络虚拟化中的两个独立远程代码执行问题；以及Azure Health Bot中的一个信息泄露问题（CVSS评分为9.1）。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/dhzGXdxNSYu9NHeLQtcv3btw1zjO4LfzWI3eeGE0fkD9CaQEgDh4FHsKYk8iaVOjhRgGKfEbfRwZf64QibNxEmWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
关注【**黑客联盟**】带你走进神秘的黑客世界  
  
  
