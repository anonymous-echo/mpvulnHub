#  【安全圈】CocoaPods 曝关键漏洞，数百万 macOS 和 iOS 应用程序面临供应链攻击风险   
 安全圈   2024-07-08 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
最近，Objective-C 和 Swift 的著名依赖管理器 CocoaPods 的关键漏洞被曝光，使数百万 macOS 和 iOS 设备上的应用程序面临供应链攻击风险，可能会对一些苹果用户造成伤害。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylialEZnT2FwphdUlmjDyvbkhHCfC99BeFfX00HUcSLS3Q7rBc2zLaiaRKjDGicJDib2GEibhw4aLOl7U8g/640?wx_fmt=jpeg&from=appmsg "")  
问题出现在 CocoaPods 迁移到 Trunk 服务器时，导致数千个软件包无人认领，攻击者可以利用公共 API 获取 pod 和 CocoaPods 源代码中的电子邮件地址。（CocoaPods 被广泛用于管理 macOS 和 iOS 开发中的第三方库，可以自动化集成和解析，是一个广受欢迎的省时工具，因此被利用的风险很大。）  
  
然而，这些无人认领的软件包被暴露了近十年，直到 2023 年 10 月才被修补。  
  
Trunk 服务器作为 CocoaPods 基础设施的重要组成部分，负责管理 CocoaPods 库文件的分发和托管，对于库的版本控制、用户验证和发布流程至关重要。相关的安全问题可能会损害 CocoaPods 库的完整性，使攻击者能够向流行的数据包中注入有害代码。  
  
发现的关键漏洞包括：  
- CVE-2024-38366 (CVSS 10.0)，该漏洞影响电子邮件验证工作流程，可在 Trunk 服务器上执行任意代码。因此，合法软件包可能会被篡改或替换，给用户带来重大风险。  
  
- CVE-2024-38368 (CVSS 9.3) ，该漏洞利用了 "认领 Pods "功能，攻击者可以控制无人认领的软件包。这反过来又可以篡改源代码，对流行的应用程序进行未经批准的修改。  
  
- CVE-2024-38367 (CVSS 8.2)，该漏洞也涉及电子邮件验证，其中潜在的良性链接允许攻击者将用户重定向到恶意域，从而导致账户面临被接管或令牌被盗的风险。  
  
由于许多流行应用程序都依赖于 CocoaPods，此类漏洞威胁到整个 iOS 和 macOS 生态系统。利用这些漏洞的攻击者可以向合法应用程序注入恶意代码，通过可信渠道分发恶意软件，并破坏用户数据。  
  
虽然 CocoaPods 已经修补了这些漏洞，但有关这些漏洞如何被利用的细节尚未澄清。开发人员已被敦促审查安全实践并更新依赖项，以降低未来再次被利用的风险。  
  
据了解，这并不是 CocoaPods 第一次受到审查。2023 年初，安全研究人员发现了一个允许攻击者劫持子域的漏洞。最近发现的漏洞强调了依赖管理器和软件开发中安全性的重要性，安全研究人员需要积极主动地应对可能影响用户数据和应用程序的潜在漏洞。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylialEZnT2FwphdUlmjDyvbkhKFPBufiaChnE2M8CRfH3GShDE6ZfxEBtyRGgtq6H7PnAib9tyU4g04gg/640?wx_fmt=jpeg "")  
[【安全圈】谷歌拟允许独立 Web应用访问敏感的USB设备](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062645&idx=1&sn=cdc5038c3f959fd1b48b3fe6a50d680f&chksm=f36e6ff5c419e6e370edfaf4d3c6b6d6c9a74c22f1cd543a44e611d6adf87f8669e4c69f0182&scene=21#wechat_redirect)  
           
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhhhIj2uHnLF4jiao0zsoa5iahJpVupdFiamyVUjBZ08WWfUUb9XQk6PzNnfKs5XEZ3BRjaPOfmPDLXA/640?wx_fmt=jpeg "")  
[【安全圈】100 亿条密码汇编集合 RockYou2024 泄露，酿成史上最大密码泄露事件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062645&idx=2&sn=a59c5d92d213abb5bf6e91992f129e9b&chksm=f36e6ff5c419e6e3c76b428829cacf0451828e1c5a58809a01117de79d20cfe1bb22aa41ffe1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhhhIj2uHnLF4jiao0zsoa5iaVyNwEVxGgn3ib0x2muY9YsK0fxfutJJVeSon0yU4icoeViaibtwPwyTqGQ/640?wx_fmt=jpeg "")  
[【安全圈】LockBit 宣布攻击克罗地亚最大的医院 KBC-Zagreb](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062645&idx=3&sn=ab393751b39db04026efb9532d7ea439&chksm=f36e6ff5c419e6e3f65fb8b7f72009a3784ca388d8169817dd6d2581deffdd96082166e90a51&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylialEZnT2FwphdUlmjDyvbkhXmDpVlia0XUWy7K7B50hNqvrV6ibAPMIRiaaZWmRWCOnXZ75ICnTnRNzQ/640?wx_fmt=jpeg "")  
[【安全圈】新的 OpenSSH 漏洞可能导致 Linux 系统以 Root 身份进行 RCE](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062645&idx=4&sn=b35c2b28f3749760b6925f7494df5bd0&chksm=f36e6ff5c419e6e3063c05eb7d9e075ad55275d69a8d6fd7ed6fc9c0e2b406e5a0adf3ebc22b&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
