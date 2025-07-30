#  【安全圈】谷歌 Bazel 面临命令注入漏洞威胁   
 安全圈   2024-02-03 19:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
黑客勒索  
  
  
  
最近，安全研究人员在 Google 的开源项目之一，即 Bazel，中发现了一个潜在的供应链漏洞。这个漏洞涉及到 GitHub Actions 工作流程中的命令注入问题，可能导致恶意行为者将恶意代码插入 Bazel 的代码库中。  
  
  
Cycode 的研究人员指出，这一问题的严重性可能对数百万项目和用户产生影响，涵盖了多个平台，其中包括 Kubernetes、Angular、Uber、LinkedIn、Databricks、Dropbox、Nvidia 和 Google 自身。从技术角度来看，这一发现主要与 GitHub Actions 有关，它是一个用于持续集成和持续交付（CI/CD）的平台。  
  
  
GitHub Actions 允许用户创建自定义工作流程，以自动化构建、测试和部署流程。然而，使用自定义操作作为独立工作流任务可能引入复杂性和潜在的安全风险。在最新的公告中，Cycode 特别强调了工作流程中广泛使用的依赖性，通常包括第三方操作，对软件供应链的安全性构成挑战。该公司的研究侧重于间接依赖项的漏洞，尤其是自定义操作，这些漏洞可能存在于不同的存储库和生态系统中，并由不同的维护者负责。本文探讨了 GitHub Actions 生态系统中自定义操作的潜在风险，尤其是复合操作，它将多个工作流程步骤组合到一个操作中。  
  
  
该通告进一步详细探讨了在 Bazel 的 GitHub Actions 工作流程中发现的漏洞情况，详细描述了从工作流程触发到注入点的步骤。其中一个关键问题是，由于复合操作中缺乏适当的输入验证，导致了注入和执行任意命令的能力。  
  
  
Cycode 研究团队于 2023 年 11 月 1 日通过 Google 漏洞奖励计划及时报告了该漏洞，几天后收到了确认。紧接着，Google 在 12 月 5 日之前采取了措施，解决并纠正了 Bazel 中的易受攻击的组件。他们实施了必要的修复措施，包括更新了工作流基础权限，并对相关操作进行了修改，以消除命令注入漏洞。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3aERot1joLyxQ5pAuhdebAnicXNgk78ofRz8WP3trhvVKV5EjYBFAlTmU7kHCic882yr6y6yAeWkg/640?wx_fmt=jpeg "")  
[【安全圈】ChatGPT被曝泄露私密对话，OpenAI称是其用户账号被盗所导致](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=1&sn=f2fb75dfe3876576b6b95f00dd24a862&chksm=f36e3394c419ba8291848dc4c11e437405beb6102f9af9b182a288c3632c38987e3d4ffcbe57&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3aERot1joLyxQ5pAuhdebJEJeXmJ7ZjYMPlaEaKwtT289PFNojvbjJHhFyb1emch1DpDasEpNicA/640?wx_fmt=jpeg "")  
[【安全圈】利用SIM卡交换窃取数百万加密货币，男子被判入狱](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=2&sn=3385508a5feab00efce273796c041a37&chksm=f36e3394c419ba820abd04c8ddf7ad9c1311cd1eade1c06a27f027c879358f164a81c45de3f2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3aERot1joLyxQ5pAuhdebyEzibxHhvOHdu6FaTWEyFvGUbsC5y6NrwbH7libO7wGZ1oRtc3iciaXSBA/640?wx_fmt=jpeg "")  
[【安全圈】花旗银行因数据安全性差被起诉](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=3&sn=861eb6bc239d60df518b413e8bd0ab67&chksm=f36e3394c419ba82b757d51c77215fa6612b2a846f1a2d9e42a93bf6f8df3ac8e458cf138f9d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj9s8WYsM8ZDUibNQPOb8Tlz8xcU6ficneAoWZJ36ADnTiaYoXtpyrY5hrgR36ERBtRxQwy4YtPjic0eQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】2700万美元的损失！江森自控遭受勒索软件攻击，影响较大](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=4&sn=58469ba5bee7bd65e8fef93d94ab1937&chksm=f36e3394c419ba824527839f449d2a23f74ffe318fd2a5b1288e2f4f74b59bb72df925fb11c9&scene=21#wechat_redirect)  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
