#  Google OAuth 漏洞使攻击者可以访问废弃的帐户   
会杀毒的单反狗  军哥网络安全读报   2025-01-15 01:01  
  
**导****读**  
  
  
  
研究人员发现谷歌“Sign in with Google”身份验证流程中的“缺陷”，该缺陷利用域名所有权的怪癖来访问敏感数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFBR1vOmgFPsUrgjsliboo6SdZic9EQ75IkEVmbnl9RrKNDRacdQDFQXJmgibW5gW36gBlUC3TISAyNw/640?wx_fmt=png&from=appmsg "")  
  
Truffle Security 联合创始人兼首席执行官 Dylan Ayrey在周一的一份报告中表示： “谷歌的OAuth登录无法防止有人购买失败的初创公司的域名并用它为前员工重新创建电子邮件帐户。”  
  
  
“虽然您无法访问旧的电子邮件数据，但您可以使用这些帐户登录组织使用的所有不同的 SaaS 产品。”  
  
  
这家总部位于旧金山的公司表示，只需购买与一家失败的初创公司相关的废弃域名，并未经授权访问与 OpenAI ChatGPT、Slack、Notion、Zoom 甚至人力资源系统等各种应用程序相关的旧员工账户，该问题就有可能使数百万美国用户的数据面临风险。  
  
  
“最敏感的账户包括人力资源系统，其中包含税务文件、工资单、保险信息、社会保障号码等。”艾瑞说。“面试平台还包含有关候选人反馈、录用和拒绝的敏感信息。”  
  
  
OAuth 是开放授权的缩写，是一种访问委托的开放标准，允许用户授权网站或应用程序访问他们在其他网站上的信息，而无需提供密码。这是通过使用访问令牌来验证用户身份并允许服务访问令牌所针对的资源来实现的。  
  
### Google OAuth 漏洞  
###   
  
当使用“使用 Google 登录”登录 Slack 等应用程序时，Google 会向该服务发送一组有关用户的声明，包括他们的电子邮件地址和托管域，然后可以利用这些声明将用户登录到他们的帐户。  
  
  
这也意味着，如果服务仅仅依赖这些信息来验证用户身份，那么也会为这样的情况打开大门：域名所有权的改变可能让攻击者重新获得对旧员工帐户的访问权限。  
  
  
Truffle 还指出，Google 的 OAuth ID 令牌包含一个唯一的用户标识符（sub 声明），理论上可以防止出现此问题，但事实证明这并不可靠。值得注意的是，Microsoft 的 Entra ID 令牌包含sub 或 oid 声明，用于存储每个用户的不可变值。  
  
  
虽然谷歌最初对漏洞披露的回应是，这是故意为之，但自 2024 年 12 月 19 日起，它已重新开启漏洞报告，并向 Ayrey 颁发了 1,  
  
337 美元的赏金。它还将该问题定性为“具有高影响的滥用相关方法”。  
  
  
与此同时，下游软件提供商无法采取任何保护措施来防范 Google OAuth 实施中的漏洞。  
  
  
“作为个人，一旦你离开一家初创公司，你就失去了保护这些账户中数据的能力，而且你将受到这家初创公司和域名未来命运的影响。”艾瑞说：“如果没有用户和工作区的不可变标识符，域名所有权变更将继续危及账户。”  
  
  
详细漏洞报告：  
  
https://trufflesecurity.com/blog/millions-at-risk-due-to-google-s-oauth-flaw  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/google-oauth-flaw-lets-attackers-gain-access-to-abandoned-accounts/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
