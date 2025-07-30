#  微软Outlook严重漏洞   
 网安百色   2025-02-07 11:50  
  
 ![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo7mdYYXYymDib6vAaIrYMibkgAHaJ2dx9Yvm4dz8ahticv6N8r04x3kkibHt4La0NlicxMl9rAlrtMNT3A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞由 Check Point 漏洞研究员 Haifei Li 发现并跟踪为 CVE-2024-21413，该漏洞是由于使用易受攻击的 Outlook 版本打开带有恶意链接的电子邮件时输入验证不当造成的。  
  
攻击者获得了远程代码执行能力，该漏洞允许绕过受保护视图（该视图应该通过以只读模式打开来阻止 Office 文件中嵌入的有害内容）并在编辑模式下打开恶意 Office 文件。  
  
一年前修补 CVE-2024-21413 时，Microsoft 警告说，预览窗格是一种攻击媒介，即使在预览恶意制作的 Office 文档时也允许成功利用。  
  
这个安全漏洞（称为 Moniker Link）允许威胁行为者使用 file:// 协议绕过对电子邮件中嵌入的恶意链接的内置 Outlook 保护，并在指向攻击者控制的服务器的 URL 上添加感叹号。  
  
感叹号与随机文本一起添加到文件扩展名之后（在他们的示例中，Check Point 使用了“something”），如下所示：  
```
```  
  
  
CVE-2024-21413 影响多个 Office 产品，包括 Microsoft Office LTSC 2021、Microsoft 365 Apps for Enterprise、Microsoft Outlook 2016 和 Microsoft Office 2019，成功的 CVE-2024-21413 攻击可导致 NTLM 凭据被盗，并通过恶意构建的 Office 文档执行任意代码。  
  
  
CISA 和 Microsoft 建议立即采取措施来缓解此威胁：  
1. 应用安全补丁：确保所有受影响的产品都使用最新的安全补丁进行更新。  
  
1. 禁用 NTLM 身份验证：在可行的情况下，减少对 NTLM 身份验证的依赖，以防止凭据被盗。  
  
1. 监控网络活动：注意与攻击者控制的服务器的异常出站连接。  
  
1. 教育用户：培训员工识别网络钓鱼企图并避免可疑链接或附件。  
  
1. 启用高级威胁防护：使用 Microsoft Defender 等安全工具增强安全监控。  
  
来源：cybersecuritynews  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
