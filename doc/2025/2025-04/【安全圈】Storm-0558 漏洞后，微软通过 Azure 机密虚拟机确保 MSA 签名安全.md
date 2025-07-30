#  【安全圈】Storm-0558 漏洞后，微软通过 Azure 机密虚拟机确保 MSA 签名安全   
 安全圈   2025-04-22 11:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj9rS8Y0QfFof91FBmGvYmbvKTToJ4vdmtEkfBjTic1GiaA81RRz431FAXaSPc5uXu9icnSvdFpEQZYA/640?wx_fmt=png&from=appmsg "")  
  
微软周一宣布，已将微软帐户 (MSA) 签名服务移至 Azure 机密虚拟机 (VM)，并且也正在迁移 Entra ID 签名服务。  
  
大约七个月前，这家科技巨头表示已完成对公共云和美国政府云的 Microsoft Entra ID 和 MS 的更新，以使用 Azure 托管硬件安全模块 (HSM) 服务生成、存储和自动轮换访问令牌签名密钥。  
  
微软安全执行副总裁 Charlie Bell在发布前与 The Hacker News 分享的一篇文章中表示：“这些改进有助于缓解我们怀疑攻击者在 2023 年针对微软的 Storm-0558 攻击中使用的攻击媒介。”微软还指出，来自 Microsoft Entra ID for Microsoft 应用程序的 90% 身份令牌都通过强化身份软件开发工具包 (SDK) 进行验证，并且 92% 的员工生产力帐户现在使用防网络钓鱼多因素身份验证 (MFA) 来减轻高级网络攻击的风险。  
  
除了隔离生产系统并实施安全日志的两年保留策略外，该公司还表示，它正在通过存在证明检查使用 MFA 保护 81% 的生产代码分支。  
  
“为了降低横向移动的风险，我们正在试行一个项目，将客户支持工作流程和场景转移到专用租户，”该公司补充道。“所有类型的微软租户都强制执行安全基线，新的租户配置系统会自动在我们的安全应急响应系统中注册新租户。”  
  
这些变化是其安全未来计划 ( SFI )的一部分，该公司称其为“微软历史上最大的网络安全工程项目，也是微软同类项目中最广泛的努力”。去年，美国网络安全审查委员会 (CSRB) 发布了一份报告，批评这家科技巨头犯下了一系列可避免的错误，导致 2023 年欧洲和美国近二十家公司遭到名为 Storm-0558 的中国国家组织入侵，SFI 也因此获得了关注。  
  
微软于 2023 年 7 月透露，其源代码中存在验证错误，导致 Storm-0558 使用 MSA 消费者签名密钥伪造 Azure Active Directory (Azure AD) 或 Entra ID 令牌，从而渗透到多个组织并获得未经授权的电子邮件访问权限，随后泄露邮箱数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj9rS8Y0QfFof91FBmGvYmbPicOzZcOhsl6XBOsYA9QlticIvwiaB70HK3YUicoeNQlWDk2hG4eTrZTHQ/640?wx_fmt=png&from=appmsg "")  
  
去年年底，该公司还启动了Windows 弹性计划，以提高安全性和可靠性，避免造成系统中断，就像 2024 年 7 月臭名昭著的CrowdStrike 更新事件中发生的那样。其中包括一项名为“快速机器恢复”的功能，即使在机器无法启动的情况下，IT管理员也能在 Windows PC 上运行特定的修复程序。该功能内置于 Windows 恢复环境 (WinRE) 中。  
  
Patch My PC 的 Rudy Ooms上个月底表示： “与依赖用户干预的传统修复选项不同，当系统检测到故障时，它会自动激活。”  
  
整个云修复过程非常简单：它会检查是否设置了 CloudRemediation、AutoRemediation 以及可选的 HeadlessMode 等标志/设置。如果环境满足条件（例如可用网络和所需插件），Windows 就会静默启动恢复。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】英国软件公司泄露了1.1TB的医护人员记录](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069203&idx=1&sn=2768ea4db3b8e3857290bb74d9540ed8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Speedify VPN macOS 漏洞使攻击者能够提升权限](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069203&idx=2&sn=0a7182f2292919ed49c24fa4779a0b99&scene=21#wechat_redirect)  
  
  
  
[【安全圈】恶意 npm 软件包模仿 Telegram Bot API 在 Linux 系统上植入 SSH 后门](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069203&idx=3&sn=2a7db9749c001484ffbc2a0751f15fa4&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Interlock 勒索软件肆虐，全球企业面临数据加密与泄露双重风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069203&idx=4&sn=80556baf99d677bcf33851df6557989b&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
