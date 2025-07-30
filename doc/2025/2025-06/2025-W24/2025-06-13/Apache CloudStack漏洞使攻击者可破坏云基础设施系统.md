#  Apache CloudStack漏洞使攻击者可破坏云基础设施系统  
邑安科技  邑安全   2025-06-13 02:12  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sVmibsmbia4yXKcwL3UUgmibqocibtWZjfJufIYYP6IP5xmM26IWyRk750ibE4T9W2Vv4wLEcZiafzLtNg/640?wx_fmt=png&from=appmsg "")  
  
Apache CloudStack 平台多个流行版本中存在严重漏洞，可能允许攻击者执行特权操作并破坏云基础设施系统。2025年6月10日发布的安全公告披露了五个不同的CVE漏洞，其中两个被归类为严重级别，可能导致资源的机密性、完整性和可用性完全受损。  
  
Kubernetes集群漏洞暴露API密钥  
  
最严重的漏洞CVE-2025-26521影响Apache CloudStack项目中的容器Kubernetes服务(CKS)集群。当用户在项目中创建基于CKS的Kubernetes集群时，系统会不恰当地将'kubeadmin'用户的API密钥和密钥暴露给可以访问该集群的其他项目成员。  
  
这一设计缺陷允许同一项目内的恶意行为者提取这些凭证并冒充集群创建者的账户。攻击者可利用该漏洞执行特权操作，可能导致基础设施完全被破坏。为缓解现有部署风险，管理员必须使用"项目Kubernetes服务角色"创建专用服务账户，并采用特定命名约定（如kubeadmin-<项目ID前八位字符>）。  
  
修复过程涉及使用kubectl命令更新Kubernetes集群中的CloudStack密钥：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sVmibsmbia4yXKcwL3UUgmibqvGBBwyJRVhjmb4konibk1JQbibn4XnRBlNQOIIpqYIS7xhZZOeU2wc4Q/640?wx_fmt=png&from=appmsg "")  
  
域管理员权限提升  
  
另外两个严重漏洞CVE-2025-47713和CVE-2025-47849允许ROOT域中的域管理员(Domain Admin)用户提升权限并控制更高权限的管理员(Admin)账户。CVE-2025-47713允许恶意域管理员重置管理员角色账户的密码，而CVE-2025-47849则允许未经授权访问同一域内管理员用户的API密钥和密钥。  
  
这些漏洞影响Apache CloudStack 4.10.0.0至4.20.0.0版本，涉及大量已部署的安装实例。攻击者可利用这些漏洞冒充管理员账户并访问敏感API，可能导致数据丢失、服务拒绝和基础设施可用性受损。补丁程序对角色类型(Role Type)层次结构实施了严格验证，确保调用方在对目标账户执行操作前拥有适当权限。  
  
补丁发布  
情  
况  
  
Apache CloudStack已在4.19.3.0和4.20.1.0版本中通过全面修复解决了这些漏洞。其他漏洞包括允许跨域边界未经授权枚举模板和ISO的CVE-2025-30675，以及影响4.20.0.0版本中配额(Quota)插件权限管理的CVE-2025-22829。  
  
安全改进引入了两个新的域级设置：  
  
role.types.allowed.for.operations.on.accounts.of.same.role.type  
  
（默认为"Admin, DomainAdmin, ResourceAdmin"）  
  
和allow.operations.on.users.in.same.account（默认为true）。这些配置提供了对跨账户操作和基于角色的访问管理的精细控制。  
  
特别建议当前使用早于4.20.0.0版本的用户完全跳过4.20.0.0版本，直接升级到4.20.1.0，以避免配额插件漏洞的风险。官方软件包可通过Apache CloudStack下载门户和各Linux发行版仓库获取。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/apache-cloudstack-vulnerability-2/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
