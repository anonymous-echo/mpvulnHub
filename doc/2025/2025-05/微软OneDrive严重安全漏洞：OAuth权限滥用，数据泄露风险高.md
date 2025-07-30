#  微软OneDrive严重安全漏洞：OAuth权限滥用，数据泄露风险高   
知机安全  知机安全   2025-05-29 06:15  
  
### 1. 微软OneDrive文件选择器安全漏洞：潜在数据泄露风险  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMlArttvznzWOFFia9F1BN2iaOJLuc32J9FicZ3xZnn5ZHUgQBHHqgWB2PYggibEYSaXPBCic2FzPIEkUQ/640?wx_fmt=jpeg "")  
  
微软OneDrive的文件选择器存在安全漏洞，黑客可能借此获取用户整个云端存储内容，而非仅上传的文件，该漏洞源于OAuth权限过宽和误导性的用户许可。Oasis Research Team已对此报告，并警告这可能导致客户数据泄露和合规问题。受影响的包括ChatGPT、Slack、Trello和ClickUp等应用。微软已承认问题，但尚未提供修复，建议用户在等待解决方案时避免使用OAuth上传文件。  
  
【标签】#  
OAuth  
 #  
Cybersecurity  
 #  
Security Flaw  
 #  
Microsoft  
 #  
Data Leakage  
 #  
OneDrive  
  
【来源】https://thehackernews.com/2025/05/microsoft-onedrive-file-picker-flaw.html  
### 2. PumaBot Botnet利用嵌入式Linux IoT设备进行SSH暴力攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMlArttvznzWOFFia9F1BN2iamJia5ib89aYhp172Tto952g8HqG9KHdOI0j7joNHiaR6OdQ3TcfA0eF5Q/640?wx_fmt=jpeg "")  
  
PumaBot是一种新的Go语言编写的恶意软件，专门针对嵌入式Linux物联网(IoT)设备进行SSH暴力破解攻击，以扩大规模并分发更多恶意软件。这种攻击方式不同于扫描互联网，而是从命令与控制(C2)服务器获取目标列表，尝试暴力破解SSH凭证。一旦成功入侵，它会接收远程命令并利用系统服务文件实现持久化。  
  
【标签】#  
IoT  
 #  
Darktrace  
 #  
Cybersecurity  
 #  
PumaBot  
 #  
Botnet  
 #  
SSH  
  
【来源】https://thehackernews.com/2025/05/new-pumabot-botnet-targets-linux-iot.html  
### 3. 2025年账户与会话劫持经济：现代Stealer的24小时攻击链  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfMlArttvznzWOFFia9F1BN2ialNsYNiaic08nhXaWb1VVV6sNqe8MxcicbR8uTaHibkMBZZ41qjOB2WGSaA/640?wx_fmt=png "")  
  
2025年，Stealer不仅仅是窃取密码，它还能窃取实时会话，且攻击者行动速度远超以往。Flare的最新研究揭示了超过2000万Stealer日志，跟踪了攻击者在Telegram频道和暗网市场的活动。这些Stealer通过感染员工终端，以不到24小时的时间内窃取企业会话。  
  
【标签】#  
session hijacking  
 #  
enterprise security  
 #  
account takeover  
 #  
stealer malware  
 #  
dark web  
 #  
Telegram  
  
【来源】https://thehackernews.com/2025/05/from-infection-to-access-24-hour.html  
### 4. 浏览器中间攻击：理解与防范  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMlArttvznzWOFFia9F1BN2iaoT9I70dD7bLT3JV4yBaWultHzpPHGu6Zk4dpmxpp4RHu6xtIpNZRGQ/640?wx_fmt=jpeg "")  
  
浏览器中间攻击（Browser-in-the-Middle, BitM）是一种网络安全威胁，攻击者通过伪装成用户浏览器，窃取用户在目标服务上的数据，类似于中间人攻击，但更隐蔽。受害者在不知情的情况下，使用攻击者的浏览器进行活动，导致数据被篡改或窃取。这种攻击利用了session tokens，通常在多因素认证后存储在浏览器中，一旦被窃取，即使有MFA也无法阻止。防范策略包括用户警惕链接、浏览器扩展控制、强化token管理、实施CSP、行为监控和使用浏览器隔离。同时，密码仍然是保护网络安全的基础，加强密码策略和配合MFA如Specops Password Policy和Secure Access可以有效抵御BitM攻击。  
  
【标签】#  
Browser-in-the-Middle  
 #  
Session Tokens  
 #  
Cybersecurity  
 #  
MFA  
 #  
Passwords  
  
【来源】https://thehackernews.com/2025/05/how-browser-in-middle-attacks-steal.html  
### 5. 2025年5月日本云扫描活动：75个暴露点遭目标攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMlArttvznzWOFFia9F1BN2iadM2iafNR1HOqmuUkmxT0DM11vO61Q5VmsE7LuTm7wKNCNX5osxgAmicQ/640?wx_fmt=jpeg "")  
  
网络安全研究人员近日披露，本月早些时候，有一项协调的云扫描活动针对75个特定的‘暴露点’进行了攻击。这些恶意IP地址全部位于日本，由亚马逊托管。扫描涉及CVE漏洞利用、配置错误探测和情报收集行为，显示为临时租用的基础设施进行的一次单次行动。这次扫描针对的技术包括Adobe ColdFusion、Apache Struts、Apache Tomcat、Drupal等，表明攻击者不加选择地寻找任何可能的漏洞系统。  
  
【标签】#  
Japan  
 #  
Amazon  
 #  
cybersecurity  
 #  
cloud scanning  
 #  
vulnerability exploitation  
  
【来源】https://thehackernews.com/2025/05/251-amazon-hosted-ips-used-in-exploit.html  
### 6. Apple App Store五年阻止了900亿欺诈交易，2024年动作尤其大  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMlArttvznzWOFFia9F1BN2ianHH63EPG3rWa4n1z4X2mHPmoAYz7icxfvUdCR03vNvGkx6yNMSQggIw/640?wx_fmt=jpeg "")  
  
Apple公司透露，过去五年间App Store阻止了超过900亿美元的欺诈交易，其中2024年一年就阻止了20多亿美元。公司通过终止有问题账户、拒绝可疑应用和删除违规内容等手段，打击了假冒应用、欺诈支付、恶意评级和隐私侵犯等行为。  
  
【标签】#  
2024 Stats  
 #  
Security  
 #  
Fraud  
 #  
App Store  
 #  
Apple  
  
【来源】https://thehackernews.com/2025/05/apple-blocks-9-billion-in-fraud-over-5.html  
### 7. 容器安全：自我传播Docker马蜂窝  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QGibgZhUnjfMlArttvznzWOFFia9F1BN2iagB96YAicFgxpG010t0U9Qu5IPOjyY1BqsqLn8uqxvqGfJgiaQYcjI0TQ/640?wx_fmt=jpeg "")  
  
一种新的Docker马蜂窝病毒通过不安全的Docker API感染，利用Dero货币挖掘软件进行加密货币挖掘，且具有自我传播能力。Kaspersky的研究显示，攻击者通过漏洞获取初始访问权限后，会感染运行中的容器，并创建新的恶意容器进行网络攻击，进一步传播到其他网络。  
  
【标签】#  
Docker Malware  
 #  
Container Security  
 #  
Self-Propagation  
 #  
Cryptojacking  
  
【来源】https://thehackernews.com/2025/05/new-self-spreading-malware-infects.html  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
