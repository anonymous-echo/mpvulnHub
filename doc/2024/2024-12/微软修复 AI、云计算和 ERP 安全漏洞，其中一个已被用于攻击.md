#  微软修复 AI、云计算和 ERP 安全漏洞，其中一个已被用于攻击   
原创 技术修道场  技术修道场   2024-12-05 00:04  
  
微软近日修复了四个影响其人工智能 (AI)、云计算、企业资源规划 (ERP) 和合作伙伴中心产品的安全漏洞，其中一个漏洞已被用于实际攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT4ic36icMGWKhdHVHorEXdiaVqX5NxzqAzyicgNNmoSZ6iaDAoFH2iaMrPbhzKmicSFANjsy2VFISBOCf24icw/640?wx_fmt=png&from=appmsg "")  
  
图片来源于网络  
  
**已被利用的漏洞**  
  
被标记为“已检测到利用”的漏洞是 CVE-2024-49035（CVSS 评分：8.7），这是一个 partner.microsoft[.]com 中的权限提升漏洞。  
  
这家科技巨头在本周发布的一份安全公告中表示：“partner.microsoft[.]com 中的不当访问控制漏洞允许未经身份验证的攻击者提升网络权限。”  
  
微软对报告该漏洞的 Gautam Peri、Apoorv Wadhwa 和一位匿名研究人员表示感谢，但没有透露该漏洞如何在实际攻击中被利用的具体细节。  
  
**其他漏洞**  
  
微软还修复了其他三个漏洞，其中两个被评为“严重”，一个被评为“重要”：  
- **CVE-2024-49038**（CVSS 评分：9.3） - Copilot Studio 中的一个跨站脚本 (XSS) 漏洞，可能允许未经授权的攻击者提升网络权限。  
  
- **CVE-2024-49052**（CVSS 评分：8.2） - Microsoft Azure PolicyWatch 中的一个关键功能缺少身份验证漏洞，可能允许未经授权的攻击者提升网络权限。  
  
- **CVE-2024-49053**（CVSS 评分：7.6） - Microsoft Dynamics 365 Sales 中的一个欺骗漏洞，可能允许经过身份验证的攻击者欺骗用户点击特制 URL，并将受害者重定向到恶意网站。  
  
**修复措施**  
  
大多数漏洞已得到完全缓解，无需用户采取任何措施。但建议将适用于 Android 和 iOS 的 Dynamics 365 Sales 应用程序更新到最新版本 (3.24104.15)，以防范 CVE-2024-49053 漏洞。  
  
**在线版 Microsoft Power Apps 自动更新**  
  
在线版 Microsoft Power Apps 的更新将自动包含这些漏洞的修复程序。  
  
