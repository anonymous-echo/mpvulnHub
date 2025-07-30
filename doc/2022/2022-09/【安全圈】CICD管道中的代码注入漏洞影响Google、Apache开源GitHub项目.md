#  【安全圈】CICD管道中的代码注入漏洞影响Google、Apache开源GitHub项目   
 安全圈   2022-09-08 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh9KTUhOiawbAykL7d26ibsC1j663EmRiawmQsyIPibAQCcqJzia1XWuiaA9KuSgGWjAkCDGLowL6rHGGGQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
CI/CD管道  
  
  
根据网站FreeBuf消息，CI/CD管道中存在安全漏洞，攻击者可以利用这些漏洞来破坏开发过程并在部署时推出恶意代码。  
  
  
近日，研究人员在Apache和Google的两个非常流行的开源项目的GitHub环境中发现了一对安全漏洞，可用于秘密修改项目源代码、窃取机密并在组织内部横向移动。  
  
  
据Legit Security的研究人员称，这些问题是持续集成/持续交付（CI/CD）缺陷，可能威胁到全球更多的开源项目，目前主要影响Google Firebase项目和Apache运行的流行集成框架项目。  
  
  
研究人员将这种漏洞模式称为“GitHub环境注入”。它允许攻击者通过写入一个名为“GITHUB_ENV”的GitHub环境变量创建一个特制的有效负载，来控制易受攻击项目的GitHub Actions管道。具体来说，问题存在于GitHub在构建机器中共享环境变量的方式，它允许攻击者对其进行操作以提取信息，包括存储库所有权凭证。  
  
  
Legit Security首席技术官兼联合创始人Liav Caspi补充道，这个概念是，构建Actions本身信任这些提交以供审查的代码，不需要任何人对其进行审查。更糟糕的是，任何对GitHub做出过贡献的人都可以触发它，而无需任何人对其进行审查。所以，这个一个非常强大且危险的漏洞。  
  
  
不要忽视CI/CD管道的安全性  
  
  
根据Caspi的说法，他的团队在对CI/CD管道的持续调查中发现了这些漏洞。随着“SolarWinds式”供应链缺陷的激增，他们一直在寻找GitHub生态系统中的缺陷，因为它是开源世界和企业开发中最受欢迎的源代码管理（SCM）系统之一，因此也是将漏洞注入软件供应链的天然工具。  
  
  
他解释称，“这些缺陷既体现了GitHub平台设计方式的设计缺陷，也体现了不同的开源项目和企业如何使用该平台。如果您非常了解风险并有意规避许多有风险的操作，您可能会编写一个非常安全的构建脚本。但我认为没有人真正意识到这一点，GitHub Actions中有一些非常危险的机制用于日常构建操作。”  
  
  
他建议称，企业开发团队应始终对GitHub Action和其他构建系统保持“零信任”原则，假设他们用于构建的组件都可能会被攻击者利用，然后隔离环境并审查代码。  
  
  
正如Caspi所解释的那样，这些缺陷不仅表明开源项目本身是供应链漏洞的潜在载体，而且构成CI/CD管道及其集成的代码也是如此。  
  
  
       好消息是，目前这两个漏洞都已得到修复。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh9KTUhOiawbAykL7d26ibsC1S4MnAGFXStHOcRsYLhO8jQ0uiafHl0iabRhibZC7NZ4onEX3Pcy6TchbQ/640?wx_fmt=jpeg "")  
[【安全圈】自制并销售免杀远控木马软件非法入侵互联网公司系统被判一年六月！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652016140&idx=1&sn=770d6f1c87458ca5b4ddad2e1267f5b9&chksm=f36fa24cc4182b5a3b02d130349dd011c43d3a5421882deafdab5529a56490c3265ec8cb1f41&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljqc0heK1ia6CxdrAF1BbBYbpmGnicpclIyo3aIoSpslmAcOehBVzwtoY2cNYpG1HOcoIKwYn3V4umQ/640?wx_fmt=jpeg "")  
# 【安全圈】印度法院要求交出盗版者的个人信息 Telegram称信息是加密的拒绝提供  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh9KTUhOiawbAykL7d26ibsC1ucbU84lQKbdtysXTc0KYHy8WfrTRMPe88mIVZqVhV10rZGxGRNJYCg/640?wx_fmt=jpeg "")  
# 【安全圈】洛杉矶联合学区遭勒索软件攻击 多项服务出现中断  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh9KTUhOiawbAykL7d26ibsC1iaONAqNUJz83JM7cOq8gqpWewicHOE2vSXpicKWxHKibCZaqLTrTSvIENg/640?wx_fmt=jpeg "")  
# 【安全圈】亚马逊云科技推出Amazon GuardDuty 恶意软件检测新功能  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
