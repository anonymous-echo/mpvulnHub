#  Hazy Hawk DNS漏洞攻击：知名机构云资源被劫持，网络安全警报高涨   
知机安全  知机安全   2025-05-21 03:59  
  
### 1. Hazy Hawk威胁团伙利用DNS漏洞劫持知名机构云资源，进行网络诈骗  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMtwfuOoRHNM2TJT9NIYcESicc7q68P71yAib53ftO3aYvrploaHgAe9IzUslQM10uUfjAAoZoUvrwQ/640?wx_fmt=jpeg "")  
  
黑客组织Hazy Hawk通过DNS配置错误，非法获取并劫持了包括Amazon S3和Microsoft Azure在内的高知名度组织的云资源，利用这些资源托管恶意网站，通过TDS系统分发诈骗和恶意软件。该团伙已针对美国疾控中心等多个政府机构、知名大学和企业实施攻击，利用这些受害者的信任度提升诈骗成功率。Infoblox通过DNS威胁情报发现这一威胁，并建议受害者及时移除DNS CNAME记录，用户需警惕不明网站的推送通知请求。  
  
【标签】#  
Cloud resources  
 #  
DNS hijacking  
 #  
Scams  
 #  
Hazy Hawk  
 #  
Infoblox  
 #  
Phishing  
 #  
Cybersecurity  
  
【来源】https://thehackernews.com/2025/05/hazy-hawk-exploits-dns-records-to.html  
### 2. AWS默认IAM角色存在安全风险：可能导致服务接管和权限提升  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMtwfuOoRHNM2TJT9NIYcESbcHswiaXLyJBsq15u1Urj0bCXOxHnMPx3eXNrYeLQMVy4pqofozU7zg/640?wx_fmt=jpeg "")  
  
AWS的默认身份和访问管理（IAM）角色存在潜在安全问题，这些角色可能被攻击者利用，以获取服务访问权限、进行特权升级甚至完全控制AWS账户。研究员发现，这些角色通常在自动创建或在设置过程中被推荐，权限过宽，如全S3访问。这些默认角色无声地引入了攻击路径，允许攻击者在服务间进行横向移动和权限提升。AWS已回应漏洞，修改了涉及的默认角色策略。  
  
【标签】#  
AWS  
 #  
service takeover  
 #  
security  
 #  
IAM roles  
 #  
privilege escalation  
  
【来源】https://thehackernews.com/2025/05/aws-default-iam-roles-found-to-enable.html  
### 3. 2025年全球渗透测试报告：工具堆增，挑战与新思维  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMtwfuOoRHNM2TJT9NIYcESDCyrzqnxlyxT5Cb8j6NTKsKhicUhe2kAPAhr0qVstMCrQjxQJOM7UvA/640?wx_fmt=jpeg "")  
  
Pentera的最新报告《2025年全球渗透测试报告》揭示了企业如何面对大量安全警报、持续的渗透和不断增长的网络安全风险。尽管企业增加了75种不同的安全解决方案，但仍有67%的美国企业在过去24个月内遭遇过数据泄露。更多工具并不意味着绝对安全，反而在一定程度上带来了挑战。企业需要有效优先处理2000-3000周的警报，软件渗透测试因其可靠性和可扩展性成为主流，保险业的参与也正在改变企业安全策略。然而，对政府网络安全支持的信任度却不高。  
  
【标签】#  
cyber insurance  
 #  
government support  
 #  
security tools  
 #  
software-based testing  
 #  
penetration testing  
 #  
breach  
  
【来源】https://thehackernews.com/2025/05/the-crowded-battle-key-insights-from.html  
### 4. 斯里兰卡、孟加拉国和巴基斯坦遭遇SideWinder威胁，政府机构成为攻击目标  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMtwfuOoRHNM2TJT9NIYcESpMOzjOK33EhDxso31jeiapvkwlu6C0ElwicEliaHxjegtNkYsfAiaqkRsA/640?wx_fmt=jpeg "")  
  
高级政府机构在斯里兰卡、孟加拉国和巴基斯坦成为名为SideWinder的威胁行动的目标，攻击者通过伪装的电子邮件和地理定位payload进行，只针对特定国家的受害者。StealerBot等恶意软件被部署，利用Office远程代码执行漏洞进行持久性侵入。此次攻击凸显了SideWinder组织的持续性和精确性，目标选择和时间限制性强。  
  
【标签】#  
Microsoft Office vulnerabilities  
 #  
SideWinder  
 #  
government  
 #  
Sri Lanka  
 #  
malware  
 #  
cyberattack  
 #  
Bangladesh  
 #  
Pakistan  
 #  
spear-phishing  
  
【来源】https://thehackernews.com/2025/05/south-asian-ministries-hit-by.html  
### 5. Redis被加密矿工攻击：Go语言代码恶意脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMtwfuOoRHNM2TJT9NIYcES62l5XIBlNia888aoOco7IPpICf9o3icOlgicuyum6dhZDeIclQ0iaZozaA/640?wx_fmt=jpeg "")  
  
Redis遭到来自Datadog Security Labs的新型Linux加密货币矿工攻击，名为RedisRaider。该恶意软件通过合法的Redis配置命令在易受攻击的系统上执行恶意cron作业，最终目的是部署Go语言的主负载，激活XMRig矿工。RedisRaider使用自定义扫描器寻找互联网上的公开Redis服务器，并利用INFO命令检测是否在Linux主机上运行。一旦找到，它会滥用Redis的SET命令注入cron作业。这种策略在Redis服务器中植入矿工，同时通过配置更改和短生命周期时间（TTL）等手段隐蔽行踪，以降低追踪和分析难度。  
  
【标签】#  
XMRig  
 #  
Cryptojacking  
 #  
Redis  
 #  
Cron jobs  
 #  
Anti-forensics  
 #  
Linux  
 #  
Go malware  
 #  
Datadog Security Labs  
  
【来源】https://thehackernews.com/2025/05/go-based-malware-deploys-xmrig-miner-on.html  
### 6. PyPI发现恶意验证工具，威胁窃取TikTok和Instagram账户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMtwfuOoRHNM2TJT9NIYcESZf7IksJ6028K8pVvXm4oyZKyl9PSjwoyBWb32Ifcp8BY2FTqxeBGUA/640?wx_fmt=jpeg "")  
  
Python Package Index (PyPI)中发现了三个恶意Python包，它们作为验证工具，能通过发送请求验证TikTok和Instagram的API，获取关联的电子邮件地址是否真实存在账户。这些包已被下架，名为checker-SaGaF、steinlurks和sinnercore，它们可能被用于威胁行为，如威胁公开、虚假报告以账户暂停、密码填充攻击，甚至出售有效电子邮件列表以牟利。安全研究人员警告这些工具可能导致数据泄露和攻击链的加速。同时，ReversingLabs还报告了另一个名为dbgpkg的恶意包，虽然已不可见，但曾被下载约350次，与这些PyPI包有相似的后门技术。  
  
【标签】#  
Email Validation  
 #  
Instagram  
 #  
TikTok  
 #  
Malware  
 #  
Data Leakage  
 #  
Cybersecurity  
 #  
PyPI  
  
【来源】https://thehackernews.com/2025/05/malicious-pypi-packages-exploit.html  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
