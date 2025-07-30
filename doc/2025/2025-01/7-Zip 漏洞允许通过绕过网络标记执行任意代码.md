#  7-Zip 漏洞允许通过绕过网络标记执行任意代码   
 网安百色   2025-01-21 11:29  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo54FXOPefd5TZAibNyyZSgJoIiaLRrJibwcyicMTibGZMYXcyaksiav3mibLpxvib6p3P2HcpibwfBGJlibh6mQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
近期，安全研究人员发现了一个编号为 CVE-2025-0411 的高危漏洞，CVSS 评分为 7.0。该漏洞允许远程攻击者绕过 Windows 的“网络标记”（Mark-of-the-Web，MOTW）保护机制，从而在受影响的系统上执行任意代码。  
  
该漏洞源于 7-Zip 在处理带有 MOTW 标记的特制压缩档案时存在不当操作。当用户使用存在漏洞的 7-Zip 版本解压此类文件时，解压后的文件不会保留 MOTW 标记。这使得攻击者能够绕过旨在防范恶意内容的关键安全检查，在当前用户的上下文中执行任意代码。  
  
利用此漏洞需要用户交互，例如访问恶意网页或打开恶意文件。这对经常处理不受信任来源文件的环境尤其值得关注。此前，另一个编号为 CVE-2024-11477 的代码执行漏洞也影响了 7-Zip 版本 24.07。该漏洞允许攻击者在用户与恶意压缩档案交互时，在当前进程的上下文中执行任意代码。  
  
受影响的 7-Zip 版本包括 24.07 及之前的所有版本。强烈建议用户立即更新至版本 24.09 或更高版本，以确保正确传递 MOTW 标记至解压后的文件，从而修复此问题。该漏洞于 2024 年 10 月 1 日报告给厂商，并于 2025 年 1 月 19 日协调公开披露并发布修补版本。  
  
此漏洞对用户构成重大风险，因为它削弱了 Windows 旨在防止未经适当检查的文件执行的关键安全功能。攻击者可能利用此漏洞分发恶意软件或获取系统的未经授权访问，特别是在用户具有管理员权限的环境中。  
  
**缓解措施：**  
1. **更新软件**：用户应立即升级至 7-Zip 版本 24.09 或更高版本。  
  
1. **谨慎操作**：避免打开来自未知或不受信任来源的压缩档案。  
  
1. **启用额外保护**：使用能够检测并阻止可疑文件活动的终端安全解决方案。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
