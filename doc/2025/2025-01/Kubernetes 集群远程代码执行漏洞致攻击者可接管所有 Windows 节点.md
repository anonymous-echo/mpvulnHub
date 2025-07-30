#  Kubernetes 集群远程代码执行漏洞致攻击者可接管所有 Windows 节点   
邑安科技  邑安全   2025-01-27 07:17  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sGx485CT7jIXYmsOqv263g9GtLt5I7A7YEMOXD5cmWs56vmOXBkSOKoiaTHh1vUic4L9JqvHR4aWVw/640?wx_fmt=png&from=appmsg "")  
  
  
在 Kubernetes 中发现了一个名为 CVE-2024-9042 的严重漏洞，使攻击者能够在 Kubernetes 集群内的所有 Windows 节点上以 SYSTEM 权限执行远程代码。  
  
Akamai 安全研究员 Tomer Peled 发现的此漏洞特别影响名为“日志查询”的全新测试版日志记录功能。  
  
该漏洞可通过简单的 HTTP GET 请求来利用，可能导致对受影响集群中所有 Windows 节点的完全控制。  
## Kubernetes 集群 RCE 漏洞  
  
问题在于 Kubernetes 的日志查询功能，该功能允许用户通过 Kubernetes API 查询远程节点上的系统日志。  
  
虽然此功能旨在方便操作，但无意中引入了命令注入漏洞。攻击者可以构建恶意请求，利用日志查询 API 参数中的输入验证不足。  
  
此缺陷允许在 Windows 节点上执行任意 PowerShell 命令。  
  
要利用此漏洞，请执行以下操作：  
  
1. 集群必须运行 Windows 节点。  
  
1. 必须启用 Log Query beta 功能。  
  
1. Kubernetes 版本必须低于 1.32.1。  
  
Peled 演示了精心设计的命令如何使用易受攻击的 API 端点将恶意命令注入系统：  
```
curl "<Kubernetes API Proxy server IP>/api/v1/nodes/<NODE name>/proxy/logs/?query=nssm&pattern=’$(Start-process cmd)’"
```  
  
这种攻击通过利用特定参数中缺乏清理来绕过传统的有效负载验证。  
  
CVE-2024-9042 的影响很严重：  
- **全节点接管**：成功利用此漏洞会授予攻击者对集群中所有 Windows 节点的系统级权限。  
  
- **集群范围的风险**：一旦节点遭到入侵，攻击者就有可能转向集群的其他部分。  
  
- **数据泄露**：在受影响节点上存储或处理的敏感数据可能会暴露。  
  
尽管该漏洞的 CVSS 评分为 5.9（中等严重性），但由于 Kubernetes 易于利用且在企业环境中广泛使用，因此其潜在影响非常大。  
  
该漏洞影响 Kubernetes 版本：  
- v1.32.0  
  
- v1.31.0 to v1.31.4  
  
- v1.30.0 to v1.30.8  
  
- <=v1.29.12  
  
### 缓解和修补  
  
为了解决这个问题，Kubernetes 发布了受影响版本的补丁：  
- **1.32.1 版**  
  
- **1.31.5 版**  
  
- **1.30.9 版**  
  
- **1.29.13 版**  
  
呼吁管理员立即将其集群升级到这些修补版本。  
  
此外，组织还可以实施以下缓解措施：  
- **禁用日志查询**：如果不是必要的，请完全禁用日志查询功能。  
  
- **限制访问**：使用基于角色的访问控制 （RBAC） 来限制对敏感 API（如 ./logs  
  
- **Monitor Logs**  
：审核集群日志中是否存在针对具有意外输入的终端节点的可疑查询。/logs  
  
为了检测潜在的漏洞利用，管理员应查看审核日志，以查找使用可疑模式或输入向终端节点发出的异常请求。  
  
虽然 Kubernetes 已经修补了 CVE-2024-9042，但组织必须迅速采取行动，通过应用更新和实施额外的保护措施来保护其集群。  
  
Peled 强调，虽然尚未观察到主动利用，但精心设计漏洞利用的简单性使得攻击者很可能在不久的将来将目标对准未修补的系统。  
  
  
原文来自:   
cybersecuritynews.com  
  
原文链接: https://cybersecuritynews.com/kubernetes-cluster-rce-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
