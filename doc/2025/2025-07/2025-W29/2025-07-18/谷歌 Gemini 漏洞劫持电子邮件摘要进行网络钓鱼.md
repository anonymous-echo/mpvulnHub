> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583845&idx=1&sn=c90ced34d21a579bc3a5cc0f1a4541ff

#  谷歌 Gemini 漏洞劫持电子邮件摘要进行网络钓鱼  
胡金鱼  嘶吼专业版   2025-07-17 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
谷歌Gemini for Workspace可以被利用来生成看似合法但包含恶意指令或警告的电子邮件摘要，这些指令可能  
不使用附件或直接链接  
将用户引导到网络钓鱼网站。  
  
这种攻击利用隐藏在电子邮件中的间接提示注入，而  
Gemini  
在生成消息摘要时遵循这些提示注入。尽管自2024年以来一直有类似的快速攻击报告，安全研究人员也实施了防范措施来阻止误导性响应，但该技术仍然是防不胜防的。  
# Gemini漏洞攻击  
  
Mozilla的GenAI漏洞赏金计划经理Marco Figueroa（研究员）发现，谷歌的Gemini模型遭受了一次提示注入攻击。这个过程包括为  
Gemini  
创建一封带有无形指示的电子邮件。攻击者可以使用HTML和CSS将字体大小设置为0，颜色设置为白色，将恶意指令隐藏在消息末尾的正文文本中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibHI5v2icU6xagPAdV7RsrqwoFbrQ5W818mjuiac3SKDwqIiceYwUsibXUB5a1n3uFNibWXEbz8Z1beqibA/640?wx_fmt=jpeg&from=appmsg "")  
  
制作恶意邮件  
  
恶意指令不会在Gmail中呈现，并且由于没有附件或链接，因此消息极有可能到达潜在目标的收件箱。如果收件人打开电子邮件并要求Gemini生成电子邮件摘要，谷歌的人工智能工具将解析这个看不见的指令并服从它。  
  
Figueroa提供的一个示例显示Gemini遵循隐藏的指令，并包含关于用户Gmail密码被泄露的安全警告，以及支持电话号码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibHI5v2icU6xagPAdV7RsrqwibKq4atTomOTQhCCk3N8h6sxtkNwkXRTyiaAPdPxXILsysH5TWv1a1dA/640?wx_fmt=jpeg&from=appmsg "")  
  
Gemini漏洞  
  
由于许多用户很可能相信Gemini的输出是谷歌Workspace功能的一部分，因此很有可能将此警报视为合法警告，而不是恶意注入。  
  
Figueroa提供了一些检测和缓解方法，安全团队可以应用这些方法来防止此类攻击。一种方法是删除、中和或忽略被设计为隐藏在正文中的内容。  
  
另一种方法是实现一个后处理过滤器，该过滤器扫描Gemini输出以查找紧急消息、网址或电话号码，并标记消息以进行进一步审查。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/google-gemini-flaw-hijacks-email-summaries-for-phishing/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibHI5v2icU6xagPAdV7RsrqwUicQ7icXp0mmV4ZwEMNDr4Vy0GKy9wX669JBzhnQHO4ybGzDEaP54DvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibHI5v2icU6xagPAdV7RsrqwlOibtic3QC3J6xLOBoRjLqibA0ghoibWMKJuR6nAibc9ceMFNup0KDbUYfA/640?wx_fmt=png&from=appmsg "")  
  
  
