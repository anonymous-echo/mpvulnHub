#  Planet Technology 工业交换机漏洞可导致设备被接管   
会杀毒的单反狗  军哥网络安全读报   2025-04-28 01:03  
  
**导****读**  
  
  
  
网络安全公司 Immersive 发现影响中国台湾网络设备制造商 Planet Technology 生产的网络管理工具和工业交换机的严重安全漏洞。根据该公司的博客文章，漏洞可能导致攻击者能够接管受影响的网络设备。  
  
  
Immersive 的安全研究员 Kev Breen 领导的团队在公司的工业控制系统中发现了多个漏洞。在 2024 年 12 月 CISA 在一份安全公告中将该公司的产品标记为易受攻击后，该团队启动了调查。  
  
  
研究人员从 Planet Technology 网站获取固件，并使用 BIX 格式（GZIP 的一种变体）压缩固件文件，以便轻松提取。研究人员使用了 UART 日志记录（捕获并记录通过通用异步收发器 (UART) 接口发送和接收的数据的过程）等技术以及 Binwalk 等工具来验证和理解所报告的问题。  
  
  
在研究过程中，除了 CISA 报告中提到的漏洞外，该团队还发现了其他此前未披露的严重漏洞。这些漏洞是通过检查 Planet Technology 的网络管理系统（用于远程监控众多 Planet 设备）和工业交换机（具体型号为 WGS-80HPT-V2 和 WGS-4215-8T2S）的内部软件发现的。  
  
  
已发现的漏洞包括：  
  
CVE-2025-46271  
    
（Planet 网络管理系统）  
  
CVE-2025-46274  
    
（Planet 网络管理系统）  
  
CVE-2025-46272  
    
（WGS-80HPT-V2 和 WGS-4215-8T2S 工业交换机）  
  
CVE-2025-46275  
    
（WGS-80HPT-V2 和 WGS-4215-8T2S 工业交换机）  
  
CVE-2025-46273  
    
（Planet 网络管理系统和所有受管设备）  
  
  
CVE-2025-46271 是网络管理系统 (NMS) 中的一个预认证命令注入漏洞，可导致完全控制。  
  
  
CVE-2025-46274 涉及 NMS 中硬编码的、可远程访问的 Mongo 数据库凭证，也会导致完全控制。  
  
  
CVE-2025-46273 泄露了 NMS 与受管设备之间硬编码的通信凭证，可导致远程拦截和配置更改。  
  
  
对于特定的工业交换机，CVE-2025-46272 是一个可授予 root 访问权限的后身份验证命令注入漏洞，而 CVE-2025-46275 是一个允许未经授权的配置修改和管理员帐户创建的身份验证绕过漏洞。  
  
  
所有这些漏洞都对受影响的 Planet Technology 设备构成了严重的系统完全入侵风险。  
  
  
根据 Immersive 的分析，黑客可以利用这些漏洞在设备上运行自己的命令，甚至绕过某些交换机的登录安全机制。  
  
  
他们还发现，网络管理系统隐藏了默认的用户名和密码（例如client:clientMQTT 的“ ”，planet:123456MongoDB 的“ ”），任何人都可以使用。这可能使攻击者能够查看网络上发生的一切，甚至更改设备的设置方式。  
  
  
研究人员利用Shodan和Censys等在线工具发现，许多联网的 Planet Technology 设备可能存在风险。  
  
  
Immersive 与 CISA 分享了他们的发现，CISA 帮助联系了 Planet Technology。该公司现已发布软件更新（补丁）来修复这些漏洞。  
  
  
CISA建议所有使用 Planet Technology 产品的用户尽快采取措施保护其网络。  
  
  
新闻链接：  
  
https://hackread.com/planet-technology-industrial-switch-flaws-full-takeover/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
