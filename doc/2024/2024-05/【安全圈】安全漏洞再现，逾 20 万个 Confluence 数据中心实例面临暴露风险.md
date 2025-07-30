#  【安全圈】安全漏洞再现，逾 20 万个 Confluence 数据中心实例面临暴露风险   
 安全圈   2024-05-26 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，数十万个可能存在漏洞的 Atlassian Confluence Data Center 和 Confluence Server 实例暴露在互联网山，威胁攻击者能够在这些实例上远程运行任意代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgb7gI6hQwLo9MkiaPnUabOzN6PUbhIvqnJiclWovSU3qgUGtQtIibeiad3D3mbIFJdO1C1MXuUPHYAlA/640?wx_fmt=jpeg&from=appmsg "")  
> Atlassian 是一家澳大利亚裔美国软件巨头，为开发人员和管理人员提供产品，该公司拥有 10000 多名员工，2023 年报告的收入超过 35 亿美元。研究人员在两款 Atlassian 产品中发现了一个安全漏洞 CVE-2024-21683（ CVSS 得分为 8.3），经过仔细分析得出，威胁攻击者可以对受影响的系统实施远程代码执行 (RCE) 攻击。  
  
  
  
Cyber news 安全研究小组表示，鉴于很多企业正在使用 Atlassian Confluence Data Center 和 Confluence Server 服务，以帮助其团队协同工作和共享信息。这样的话，威胁攻击者就可以利用 CVE-2024-21683 安全漏洞侵入受影响的系统，并盗取受害者大量数据信息。  
  
  
更为糟糕的是，CVE-2024-21683 安全漏洞不仅允许未经验证的威胁攻击者执行任意代码，而且不需要用户交互。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgb7gI6hQwLo9MkiaPnUabOzdT0KS4HFwpIbtdbH6qeA9ngNr91ULgzATfYaeQg7RsibLCrVlMINMMQ/640?wx_fmt=jpeg&from=appmsg "")  
## 大量 Atlassian 实例暴露在互联网上  
  
  
值得一提的是，虽然 Atlassian 收到 根据 Cybernews 的勒索软件监控工具 Ransomlooker 的数据，平均赎金要求为 530 万美元，因此尽快修复任何具有 RCE 功能的漏洞至关重要。报告后，便立刻针对两个受影响的服务发布了修复程序。然而，其安全团队还是发现数十万个易受攻击的实例暴露在互联网上，不断”诱惑“威胁攻击者发动网络攻击活动。  
  
  
Cyber news 的安全研究人员指出，共有多达 224962 个数据中心和服务器实例暴露在互联网上，威胁攻击者可以利用 CVE-2024-21683 安全漏洞侵入受害者的网络系统中，一旦有了”立足点“，就可以轻松获得对系统的完全控制，随意安装恶意软件、访问敏感数据以及操纵系统配置。  
  
  
此外， Atlassian 暴露的实例还危及到很多普通用户。研究人员认为，威胁攻击者可以窃取受害者登录凭证，从而侵入 Atlassian 账户和其他重复使用相同凭证的账户。  
  
  
对此，研究人员强调，RCE 漏洞是高级勒索软件团伙经常使用的一种攻击载体，可以获得进入目标系统的初始入口，帮助勒索软件团伙开展攻击活动，（ Cyber news 勒索软件监控工具 Ransomlooker 的数据显示，勒索攻击事件平均赎金为 530 万美元）因此尽快修复任何具有 RCE 功能的安全漏洞非常重要。  
  
  
以著名勒索软件 Cl0p 为例， 该组织曾经利用 Progress 软件公司 MOVEit Transfer 软件中一个零日漏洞（现已修复），入侵了受害者的内部系统，非法访问、盗取大量敏感数据，数千家机构和数千万人受到影响，造成数千万美元的损失。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgb7gI6hQwLo9MkiaPnUabOzBqiciaTrsjwz7ceJArx2SpFQiaIr1ZmLOnulbrBaJnoDHNxteyicUy4yIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
最后，安全研究人员深入分析后发现，Atlassian Confluence Data Center 和 Confluence Server 出现安全漏洞后，仍旧有五个国家/地区托管了一半易受攻击的实例。其中，美国拥有最多的可能易受攻击的实例，为53195个，另有22007个易受攻击的实例被追踪到日本。  
  
  
与此同时，南非、法国和德国各自托管了超过 11000 个暴露的未打补丁的 Confluence 服务。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliat0SQUkfbJfGkczPiaAzqgUB1HSUj3LQMF11J8icQ3Bges56nzZNszLuiaR2OgWd9BWrjwgBWpeMlSA/640?wx_fmt=jpeg "")  
[【安全圈】二手iphone能恢复上一任机主的相册？苹果解释](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060547&idx=1&sn=28c3aa97c2adc63d464931c7b09c895e&chksm=f36e17c3c4199ed5ab890135abeb65e4c1247ff19cce7be05236fe5370b9094266b56e47e40b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgb7gI6hQwLo9MkiaPnUabOzPYH1vV1TNAjmsfZLzS2pBjSjibs1xpmE8PQd1WdnJS3FTCyWkOgdVUQ/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】6.5 万条个人信息被泄露！这一互联网巨头被查！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060547&idx=2&sn=e5540974ad4e946c95218fae669b9c02&chksm=f36e17c3c4199ed5cb34a43e5e6fb5c558c5acf93c1ad5a4832765379604878b488e7401f795&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgb7gI6hQwLo9MkiaPnUabOzXV4SG3Hrcp3OSkv8Z7aTYicwfUsuhqmP0baEIdu34qh7aBQcuMlaMmw/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】谷歌研究报告：企业发送钓鱼邮件“测试员工应急能力”多此一举，反而有害](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060547&idx=3&sn=312c1386346b7f022c5579f0ff6f3322&chksm=f36e17c3c4199ed5186c3af920cc46ff4b1be98f71cd89d59102e9231daa616c2f03664b3b25&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliat0SQUkfbJfGkczPiaAzqgUlO1b2ciccxmt9p0lo3gduMibLB7bhicMhP8lyevGDJ21JoBGluCBOdIFA/640?wx_fmt=jpeg "")  
[【安全圈】今年第 8 个零日漏洞，谷歌发布 Chrome 浏览器 125 紧急更新](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060547&idx=4&sn=b7a4eb251751fbdf14936fe290910b87&chksm=f36e17c3c4199ed53f521c451e72713741f6474a36fa62e012d33ca215eacc9a78311ba6b995&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
