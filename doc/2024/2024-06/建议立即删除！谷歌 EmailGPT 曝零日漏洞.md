#  建议立即删除！谷歌 EmailGPT 曝零日漏洞   
邑安科技  邑安全   2024-06-14 10:34  
  
更多全球网络安全资讯尽在邑安全  
  
> Google Chrome 浏览器扩展 EmailGPT 曝出高危零日漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8vdw4j3PNlj1zhvibfrXLWP09c0h5ibGMLKiaQCjjfQaAibqxYVgaLRU2BUojtq7Tm0OetA3TMhT7Y0rA/640?wx_fmt=jpeg&from=appmsg "")  
> EmailGPT 是 Google Chrome 的流行扩展程序，通过使用 OpenAI 公开提供的人工智能模型，帮助其用户在 Gmail 服务上撰写电子邮件（用户向该服务提供原始数据和上下文，接收人工智能反馈的内容，以此撰写电子邮件）。然而，最近的一项研究发现，该服务存在一个高危安全漏洞。  
  
  
据悉，安全漏洞由 Synopsys 网络安全研究中心的专家发现并上报，追踪为 CVE-2024-5184（CVSS 得分为 6.5），是一个 "提示注入 "类型的漏洞，允许威胁攻击者操纵服务并盗取敏感信息，可能引发知识产权泄露、拒绝服务和大额经济损失。  
  
CVE-2024-5184 安全漏洞的存在，使得 EmailGPT 在使用 API 服务时，可能会允许威胁攻击者注入第三方提示并操纵服务逻辑，导致泄露系统提示或执行不需要的命令。例如，威胁攻击者可以创建一个嵌入不需要的功能的提示，从而进行数据”挖掘“、使用被入侵的账户发送垃圾邮件或者为邮件列表创建误导性内容。![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8vdw4j3PNlj1zhvibfrXLWP0gSe3icn1Q7hvbg7mrKCE1F7S6eQR2icrVWKa8raTm3FwphiaGMIMLIwVw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Synopsys 方面表示，网络安全研究人员在公布 CVE-2024-5184 安全漏洞详细信息之前联系了 EmailGPT 的开发人员，但目前尚未收到任何回复。鉴于当下还没有办法缓解该安全漏洞，Synopsys 建议有关用户应立即从浏览器中删除 EmailGPT。  
  
SlashNext 电子邮件安全公司首席执行官 Patrick Harr 强调，必须对人工智能模型进行严格管理并实施额外的安全措施，以防止安全漏洞及其后续利用。此外，对于一些将人工智能整合到业务流程中的公司，更应该要求人工智能模型供应商提供真正的安全证明，避免安全事件的发生。  
  
原文来自: freebuf.com  
  
原文链接: https://www.itsec.ru/news/rasshireniye-emailgpt-dlia-pochti-google-soderzhit-neispravlennuyu-0day-uyazvimost  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
