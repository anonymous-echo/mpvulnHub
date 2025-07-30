> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247524855&idx=1&sn=391abd98577d6ef93a97caf66c01a1b9

#  开源项目中的GitHub Actions安全隐患：MITRE与Splunk揭露关键漏洞  
邑安科技  邑安全   2025-06-19 08:48  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tVnDm6yGicvR4R9icBEorKicx5tJR06UyQOEHgCtw4kJ7q1XE1eTtPKJwKCpaiaHS5QEGWsH8TcsUhFA/640?wx_fmt=png&from=appmsg "")  
  
一项全面的安全调查揭示了主要开源存储库（包括由 MITRE 和 Splunk 等知名组织维护的 GitHub Actions 工作流）中的广泛漏洞。  
  
这一发现凸显了不安全的持续集成和持续交付 （CI/CD） 配置的一种令人担忧的模式，这些模式使这些项目面临潜在的供应链攻击和对敏感凭证的未授权访问。  
  
这些漏洞主要围绕滥用 GitHub Actions 的触发器，该触发器在处理来自外部贡献者的拉取请求时授予工作流访问存储库机密和提升的权限。pull_request_target  
  
与在沙盒环境中运行的标准事件不同，它在目标存储库的基本分支的上下文中执行，为攻击者提供了破坏整个项目基础设施的途径。pull_requestpull_request_target  
  
这种基本的设计差异创造了一个安全盲点，恶意行为者可以利用该盲点来未经授权访问 API 密钥、部署凭证和管理令牌。  
  
此安全问题的范围远远超出了孤立的事件，代表了影响许多备受瞩目的开源项目的系统性问题。  
  
Sysdig 分析师发现，这些漏洞源于存储库维护者对 GitHub Actions 安全模型的根本误解，导致配置无意中将关键基础设施暴露于外部威胁。  
  
研究团队发现，尽管多年来有关于这些风险的公开文档，但许多项目仍在实施危险的工作流模式，使攻击者能够直接访问生产环境和敏感的组织数据。  
  
攻击方法涉及提交恶意拉取请求，这些请求包含旨在在自动化工作流程中执行的精心设计代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tVnDm6yGicvR4R9icBEorKicxrGq6ic2JLfdBD822BtEoP3QoRKZekHOqwCmPYDU2SmB2LJG7XItrvRA/640?wx_fmt=png&from=appmsg "")  
  
memdump.py（来源 – Sysdig）  
  
当存储库利用事件，同时从贡献者复刻中签出不受信任的代码时，它们会创建一个执行环境，恶意负载可以在其中访问存储库密钥和高特权 GitHub 令牌。pull_request_target  
  
事实证明，这种组合特别具有破坏性，因为它允许攻击者提升权限、修改存储库内容，并可能将恶意代码传播到依赖于这些受感染项目的下游依赖项。  
  
这些漏洞的影响超出了单个存储库，威胁到更广泛的开源生态系统的完整性和可信度。  
  
依赖这些项目来获取关键基础设施组件的组织可能面临供应链攻击的风险，其中受损的存储库可能成为更广泛的组织漏洞的入口点。  
  
拉取请求目标利用机制  
  
这些攻击的技术基础在于 GitHub Actions 的触发机制，当与代码签出作结合使用时，该机制会创建危险的执行上下文。pull_request_target  
  
此触发器最初旨在使工作流程能够处理具有存储库密钥访问权限的拉取请求，但其实施在配置不当时会产生重大的安全风险。  
  
当工作流使用诸如 和 之类的参数显式签出不受信任的代码时，就会出现此漏洞，从而有效地允许外部贡献者将任意代码注入特权执行环境。github.event.pull_request.head.refgithub.event.pull_request.head.repo.full_name  
  
在 spotipy-dev/spotipy 存储库的情况下，研究人员通过修改项目文件以包含恶意安装命令来演示此漏洞。setup.py  
  
该漏洞利用 Python 的 setuptools 功能在软件包安装过程中执行任意代码，如以下代码片段所示，该代码片段从内存中提取密钥并将其泄露到外部服务器。  
  
恶意安装配置包括自定义安装命令，这些命令下载并执行内存转储脚本，从而有效地从工作流环境中收集所有可用的密钥和 GitHub 令牌。  
  
事实证明，在多个存储库中，利用过程非常简单，研究人员使用几乎相同的技术成功地破坏了 MITRE 的 Cyber Analytics Repository 和 Splunk 的安全内容存储库中的项目。  
  
每次成功的攻击都会导致提取具有全面写入权限的高权限 GitHub 令牌，包括对存储库内容、部署、软件包和安全事件的访问权限。  
  
此级别的访问权限使攻击者能够完全破坏目标存储库、修改源代码、纵版本，并可能将恶意内容注入软件分发渠道。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/insecure-github-actions-in-open-source-projects-mitre/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
