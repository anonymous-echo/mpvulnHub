#  Windows NTLM 哈希泄露欺骗漏洞   
 网安百色   2025-04-20 11:30  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
CISA）提醒注意积极利用新披露的 Microsoft Windows 漏洞，该漏洞被跟踪为 CVE-2025-24054。  
  
该漏洞会影响 Windows 的 NTLM 身份验证协议，为未经授权的攻击者通过欺骗漏洞渗透系统创造了机会。  
  
漏洞概述  
  
CVE-2025-24054，正式指定为“Windows NTLM 哈希泄露欺骗漏洞”，归类为 CWE-73：文件名或路径的外部控制。  
  
此漏洞允许威胁行为者从外部控制 Windows NTLM 使用的文件名或路径，这可能会导致通过网络连接无意中泄露哈希凭据。  
  
根据 Microsoft 的公告，与受害者位于同一网络上的攻击者可以利用此漏洞执行凭据欺骗。  
  
通过控制目标的文件名或路径，恶意行为者可能会获得对敏感系统的未经授权的访问或提升权限，所有这些都不需要事先授权。  
  
 Microsoft 发布的缓解：  
  
为所有受影响的 Windows 系统应用 Microsoft 提供的最新补丁和安全更新。  
  
查看并遵守 BOD 22-01 下的适用指南，尤其是对于云服务环境。  
  
如果没有可用的缓解措施或更新，请停止使用易受攻击的产品。  
  
受影响的联邦机构和承包商的截止日期为 2025 年 5 月 8 日，以确认漏洞的修复。不合规可能会导致凭据盗窃和后续入侵的风险增加。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
