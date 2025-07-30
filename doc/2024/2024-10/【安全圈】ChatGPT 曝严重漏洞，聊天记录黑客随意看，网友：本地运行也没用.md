#  【安全圈】ChatGPT 曝严重漏洞，聊天记录黑客随意看，网友：本地运行也没用   
 安全圈   2024-10-02 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
ChatGPT  
  
  
ChatGPT**长期记忆功能**出现严重漏洞！  
  
黑客利用漏洞，一能给 AI 植入**虚假记忆**，在后续回答中出现误导信息。二能植入**恶意指令**，持续获取用户聊天数据。  
  
聊点啥都会被看光光。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLhH2ianFoYN9bf7vEaOWrYhRxA1x06aQcb4HYLIhb30kvCuspEZRFibtw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLlOzSL1orymzlxXPRHfcdyHHnlVwZfLowP2E9a6icPIQUZezHJzljqog/640?wx_fmt=jpeg&from=appmsg "")  
  
更可怕的是，即使开始新的对话，它仍阴魂不散，持续窃取数据。  
  
而当你直接问 ChatGPT 4o 有没有窃取数据，它一口一个 " 怎么会？我没有 "  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLKYfwKtYaWricD8ETCbAP3jVa0RQHDjibQIU7RHXtLS2ic1wknT9Vgttag/640?wx_fmt=jpeg&from=appmsg "")  
  
电子邮件、文档、博客文章等内容都有可能成为植入 " 恶意记忆 " 的媒介，一旦植入就是**长久性**  
的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLGqYTqPspwBibJcpz82Io602pBGCEwqIsEhQEHjYuM8ibgrGjR9n7fy4g/640?wx_fmt=jpeg&from=appmsg "")  
  
职业安全研究员 Johann Rehberger 被曝五月份就发现了这个问题，还向 OpenAI 私下报告了这个漏洞  
  
但没被当回事儿，据说 OpenAI 最初将这个问题简单地归类为安全隐患，而非技术层面的安全漏洞，并匆匆结束了调查。  
  
Rehberger 随即开发了一个概念验证程序，利用这个漏洞**持续窃取用户的所有输入信息**，OpenAI 工程师这才注意到这一问题。  
  
本月已发布了修复方案。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLpjOtOGEP2t7JfbbibVibprXVGL4EKE077LZmtabrw8nOoZvRAJHGfbJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
联系昨天 OpenAI 高层动荡内幕曝光，奥特曼被指不注重 AI 安全问题，为狙击谷歌紧急推出 4o，安全团队只能在 9 天极短时间内完成安全测试评估……  
  
  
这件事被曝出后引发网友热烈讨论。  
  
有网友建议咱大伙儿使用的时候都本地运行。  
  
还有网友觉得本地也没用：  
  
**大****模型无法区分****指****令和数据**。只要你允许任何不可信的内容进入你的模型，你就可能面临风险。  
  
你允许它读取你的电子邮件，那么现在就有一个攻击途径，因为任何人都可以给你发送电子邮件。允许它搜索互联网，那么现在就又有一个攻击途径，因为任何人都可以在网上放置网页。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLr7cA4XBUkCNgmKFldTN9Y0UdfXwavM2hBKJnrSaRbx33PBcXwkzC1w/640?wx_fmt=jpeg&from=appmsg "")  
  
长期对话记忆功能，OpenAI 今年在产品线中广为应用。  
  
它可以存储之前对话中的信息，并在所有未来对话中将其用作上下文。这样，语言模型就能意识到用户的年龄、性别等各种细节，用户无需在每次对话中重新输入这些信息。  
  
GPT-4o 发布时，就向所有 Plus 用户开放了记忆、视觉、联网、执行代码、GPT Store 等功能。  
  
最近高级语音 "Her"Plus 用户全量发布，也有记忆功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeL1UhHKgkDiaTqekwYZ0CKWeID9kBQeHnibGhiaXlK6U2tqag9OYlPiaibtkg/640?wx_fmt=jpeg&from=appmsg "")  
  
一开始记忆功能推出后不久，Rehberger 就发现了这一漏洞：  
  
用 "**间接提示注入**" 的攻击方法可以创建和永久存储记忆，使模型遵循来自电子邮件、博客文章或文档等不可信内容的指令。  
  
下面是 Rehberger 的演示。  
  
他可以成功欺骗 ChatGPT 相信目标用户 102 岁、生活在黑客帝国中、地球是平的。AI 会将这些信息纳入考虑，影响所有未来的对话。  
  
这些虚假记忆可以通过在 Google Drive 或 Microsoft OneDrive 中存储文件、上传图像或浏览 Bing 等网站来植入，这些都可能被恶意攻击者利用。  
  
Rehberger 在 5 月向 OpenAI 私下报告了这一发现，据说当月 OpenAI 关闭了相关报告。  
  
一个月后，研究员提交了新的披露声明，这次包含了一个概念验证程序。该程序可以使 macOS 版 ChatGPT APP 将所有用户输入和 ChatGPT 输出的**原文副本发送到他指定的服务器**。  
  
只需让目标指示 AI 查看一个包含恶意图像的网络链接，之后所有与 ChatGPT 的交互内容都会被发送到攻击者的网站。  
  
Rehberger 在视频演示中表示：  
  
真正有趣的是，这种攻击具有记忆持久性，提示注入将一段记忆插入到 ChatGPT 的长期存储中。即使开始新的对话，它仍在持续窃取数据。  
  
不过，由于 OpenAI 去年推出的一个 API，这种攻击**无法通过 ChatGPT 网页界面实现**。  
  
有研究人员表示，虽然 OpenAI 目前已推出了一个修复程序，但不可信内容仍可能通过提示注入，导致记忆工具存储恶意攻击者植入的长期信息。  
  
为防范此类攻击，语言模型用户应在对话中**密切注意是****否有新记忆被添加的迹象**。同时，**应定期检查存储的记忆，查看是否有可疑****内容**。  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljgmEqY5ibaPHSHyg8YpANFANFpGsoEe9bibHAdLk2FicwDCGicRQSoicEicrC7ibicXEcKAd2mrqtnjBg1Ww/640?wx_fmt=jpeg "")  
[【安全圈】抓获4人！五马公安打掉一侵犯公民个人信息犯罪团伙！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064805&idx=1&sn=3e1a10ff147945451eb100309654d979&chksm=f36e6065c419e9737fcd3753756d61f60005e04582147c1742a81beb4e3adb84e71c2c73985e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh1ic8iaW7Ot4yNWCZuJbhjeLocHC9qXnyaO9GzHrEtmoQXQIz1UmcWsV94MAKSFMKjPhGLfgtkghlg/640?wx_fmt=jpeg "")  
[【安全圈】这30个服务高危端口极易被攻击！你做了安全防护了吗？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064805&idx=2&sn=8aa77cdbaa952eb8920445289cf419af&chksm=f36e6065c419e973409f4d6167d0e39004e74325472a13562e5bbb30e23173545ce6fad96c6d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljgmEqY5ibaPHSHyg8YpANFAEqFacZ4QGsibDic6ppBEB9AIIFiapMOlMFStniaNfpyrEH9VferHPMPGQw/640?wx_fmt=jpeg "")  
[【安全圈】起亚修复高危漏洞：影响数百万车辆，攻击者几秒内可定位、开车门、启动引擎](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064805&idx=3&sn=41d291b0ddc00a4ac2d49d81a437a9ac&chksm=f36e6065c419e973ea4626e5bb937c8a79c560dbbfe291bd45c0e2531f52a59f23fa689a1f81&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljgmEqY5ibaPHSHyg8YpANFAIVmav93jSu7XCkib8OCIumrP5DTdp6oVNvIAIiamaqlc1Mnl840VMawQ/640?wx_fmt=jpeg "")  
[【安全圈】荷兰警方绝大多数雇员姓名、工作联系方式遭黑客攻击泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064805&idx=4&sn=986f51c05e34fc5e338882e4a3932481&chksm=f36e6065c419e9730382984d120215fa0aabd9aefacbcb5a150b325c1a5b46722adc4a351882&scene=21#wechat_redirect)  
   
  
  
  
  
  
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
  
  
  
