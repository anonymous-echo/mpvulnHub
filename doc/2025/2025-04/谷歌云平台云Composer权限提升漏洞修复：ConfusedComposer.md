#  谷歌云平台云Composer权限提升漏洞修复：ConfusedComposer   
知机安全  知机安全   2025-04-27 02:41  
  
### 1. 谷歌云平台漏洞细节：云Composer中存在权限提升风险  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QGibgZhUnjfOc0oE8AMCklnH2WnibDr8kickrUNibT2IBAuxyMEm61052sgkT9vEv4S7iceQugLrJG0shdwo13ibgyoA/640?wx_fmt=gif "")  
  
网络安全研究人员发现了一个影响谷歌云平台(云平台)Cloud Composer工作流自动化服务的漏洞，攻击者可能利用该漏洞提升权限，获取到默认的Cloud Build服务账户，进而控制GCP服务如Cloud Build和存储、Artifact Registry。漏洞被命名为ConfusedComposer，是云服务间安全问题的典型体现，因为新服务的创建往往继承了现有服务的安全隐患。经过Tenable的安全研究员披露后，谷歌已于2025年4月13日修复了这个问题，通过改变安装PyPI包的方式避免了权限滥用。  
  
【标签】#  
Security Research  
 #  
Google Cloud Platform  
 #  
Cloud Composer  
 #  
Cloud Build  
 #  
Vulnerability  
  
【来源】https://thehackernews.com/2025/04/gcp-cloud-composer-bug-let-attackers.html  
### 2. 浏览器安全：企业面临的5大威胁与应对策略  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfOc0oE8AMCklnH2WnibDr8kicvPPmCMCVkTjxvVu2vG7omVybic60qXfyAGshicwtjP10bLyy3zolNm9Q/640?wx_fmt=jpeg "")  
  
随着SaaS和云原生的兴起，浏览器成为企业新的安全焦点，但其安全问题却鲜有关注。报告显示，70%的钓鱼攻击披着微软、OneDrive或Office 365的伪装，150+知名平台被滥用，AI带来的风险也不容忽视。企业需关注浏览器中的新攻击模式，如浏览器本地化和AI诱导风险，同时传统防御手段如DLP已难以应对。本文提出浏览器原生可见性和控制的必要性，以及如何应对浏览器中的威胁。  
  
【标签】#  
浏览器威胁  
 #  
AI风险  
 #  
企业安全  
 #  
浏览器原生防护  
  
【来源】https://thehackernews.com/2025/04/5-major-concerns-with-employees-using.html  
### 3. 利用Google基础设施的复杂钓鱼攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfOc0oE8AMCklnH2WnibDr8kicp7bw7XmrfwaO77ePnGVeyDUIVM2EbSMW1ibMZOicw0989C0v1uFggMdg/640?wx_fmt=jpeg "")  
  
一种精巧的钓鱼策略被发现，威胁者利用Google的基础设施发送伪装成合法的电子邮件，这些邮件通过了DKIM签名检查，甚至在Gmail中显示为安全警报，诱骗用户点击并访问伪造的Google支持页面。受害者被引导到一个假冒的Google账户登录页面，用于收集凭证。此次攻击被称为DKIM重播攻击，利用了Google账户和OAuth应用的设置。Google已采取措施阻止此滥用，建议用户启用双因素认证以防止此类欺诈。  
  
【标签】#  
Google  
 #  
DKIM  
 #  
Phishing  
 #  
Cybersecurity  
  
【来源】https://thehackernews.com/2025/04/phishers-exploit-google-sites-and-dkim.html  
### 4. 微软升级MSA和Entra ID安全，使用Azure VM加密签名服务  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfOc0oE8AMCklnH2WnibDr8kicyOiaVzyBXGcyguIC9Kk056ib2xicKp9qfpA4HWHGTVb4JZZ2MT9liczMLg/640?wx_fmt=jpeg "")  
  
微软宣布已将Microsoft Account（MSA）的签名服务迁移到Azure的保密虚拟机，并正在迁移Entra ID签名服务。此举是微软Secure Future Initiative的一部分，旨在加强身份服务的安全，应对之前Storm-0558攻击中的漏洞。公司已采取多种措施，如验证身份令牌、使用MFA、实施安全日志保留政策和保护生产代码，以减少安全风险。  
  
【标签】#  
Secure Future Initiative  
 #  
Entra ID  
 #  
MSA  
 #  
Cybersecurity  
 #  
Microsoft  
 #  
Azure  
  
【来源】https://thehackernews.com/2025/04/microsoft-secures-msa-signing-with.html  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
