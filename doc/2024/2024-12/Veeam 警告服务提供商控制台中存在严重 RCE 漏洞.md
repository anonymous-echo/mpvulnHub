#  Veeam 警告服务提供商控制台中存在严重 RCE 漏洞   
会杀毒的单反狗  军哥网络安全读报   2024-12-04 01:00  
  
**导****读**  
  
  
  
Veeam 今天发布了安全更新，以解决两个服务提供商控制台 (VSPC) 漏洞，其中包括在内部测试期间发现的严重远程代码执行 (RCE)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFYjkuhehVdLqZ83uA1CicYIn37VTWpVLxPXZRTYlMFn8WEnyV8JhDiaxzlzQXJV0E9rp498AjmVbOQ/640?wx_fmt=png&from=appmsg "")  
  
  
该公司将 VSPC 描述为远程管理的 BaaS（后端即服务）和 DRaaS（灾难恢复即服务）平台，服务提供商控制台用来监控客户备份的健康和安全性，以及管理受 Veeam 保护的虚拟、Microsoft 365 和公共云工作负载。  
  
  
今天修复的第一个安全漏洞（跟踪为 CVE-2024-42448 并被评为 9.9/10 严重性分数）使攻击者能够从 VSPC 管理代理机器在未修补的服务器上执行任意代码。  
  
  
Veeam 还修补了一个高严重性漏洞 (CVE-2024-42449)，该漏洞可以让攻击者窃取 VSPC 服务器服务帐户的 NTLM 哈希，并使用获得的访问权限删除 VSPC 服务器上的文件。  
  
  
该公司在今天发布的安全公告中所解释说，只有在目标服务器上授权管理代理时，这两个漏洞才能被成功利用。  
  
  
这些漏洞影响 VPSC 8.1.0.21377 及所有早期版本，包括版本 8 和 7，但不受支持的产品版本也可能受到影响并且“应被视为易受攻击”，即使它们未经测试。  
  
  
Veeam 表示：“我们鼓励使用受支持版本的 Veeam 服务提供商控制台（版本 7 和 8）的服务提供商更新到最新的累积补丁。”  
  
  
“强烈建议使用不受支持的版本的服务提供商升级到最新版本的 Veeam 服务提供商控制台。”  
  
  
最近针对 Veeam 漏洞的疯狂利用表明，尽快修补易受攻击的服务器以阻止潜在攻击至关重要。  
  
  
9 月份披露的Veeam 备份和复制 (VBR) 软件中的一个 RCE 漏洞 (CVE-2024-40711)现在被利用来部署 Frag 勒索软件。  
  
  
在 Akira 和 Fog 勒索软件攻击中，同样的漏洞也被用来在易受攻击的 VBR 服务器上进行远程代码执行。  
  
  
Veeam Software是一家私营信息技术公司，为虚拟、物理和多云基础设施开发备份管理、灾难恢复和智能数据管理软件。   
  
  
其产品被全球超过 550,000 家客户使用，其中包括全球 2,000 强企业的 74% 和财富 500 强企业的 82%。  
  
  
**新闻链接：**  
  
https://www.bleepingcomputer.com/news/security/veeam-warns-of-critical-rce-bug-in-service-provider-console/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
