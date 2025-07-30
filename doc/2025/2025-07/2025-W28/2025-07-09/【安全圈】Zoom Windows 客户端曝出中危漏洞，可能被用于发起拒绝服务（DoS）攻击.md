> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070569&idx=1&sn=6d82b7ddc4c8cc451bc8ab54f4420e78

#  【安全圈】Zoom Windows 客户端曝出中危漏洞，可能被用于发起拒绝服务（DoS）攻击  
 安全圈   2025-07-09 11:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
zoom  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgIZ8pTYPudA7ZzJtiakMsU4SRKu4KtWJP1jGvQZkiciaEibyjcrsFyUSPial6ToCEqibZSnXZKItjCicfhQ/640?wx_fmt=png&from=appmsg "")  
  
近日，安全研究员 fre3dm4n 披露了 Zoom Windows 客户端中的两个漏洞，已被官方确认，并分别登记为 CVE-2025-49464 和 CVE-2025-46789。这两个漏洞均被评定为中危，CVSS 评分为 6.5，可能被攻击者利用发起远程拒绝服务攻击，影响客户端的可用性。  
### 漏洞概况  
  
两个漏洞均源于缓冲区溢出问题，攻击者无需用户交互、仅需低权限即可触发。这意味着，在特定网络环境下，攻击者可远程造成 Zoom 客户端崩溃或服务中断。漏洞主要影响 Zoom 的多个 Windows 平台产品，包括标准客户端、VDI、Rooms 以及 SDK。  
### 影响范围  
  
CVE-2025-49464 影响以下产品版本：  
- Zoom Workplace for Windows 6.4.0 之前版本  
  
- Zoom Workplace VDI for Windows 6.3.10 之前版本（不包括 6.1.7 和 6.2.15）  
  
- Zoom Rooms for Windows 6.4.0 之前版本  
  
- Zoom Rooms Controller for Windows 6.4.0 之前版本  
  
- Zoom Meeting SDK for Windows 6.4.0 之前版本  
  
CVE-2025-46789 影响以下产品版本：  
- Zoom Workplace for Windows 6.4.5 之前版本  
  
- Zoom Workplace VDI for Windows 6.3.12 之前版本（不包括 6.2.15）  
  
- Zoom Rooms for Windows 6.4.5 之前版本  
  
- Zoom Rooms Controller for Windows 6.4.5 之前版本  
  
- Zoom Meeting SDK for Windows 6.4.5 之前版本  
  
### 官方响应与修复建议  
  
Zoom 已发布修复补丁，受影响用户应立即升级至以下版本及以上：  
- Zoom Workplace：6.4.5  
  
- Zoom Workplace VDI：6.3.12  
  
- Zoom Rooms 及 Controller：6.4.5  
  
- Zoom Meeting SDK：6.4.5  
  
可通过 Zoom 官方网站（  
https://zoom.us/download）获取最新版安装包。  
### 安全建议  
1. 企业应尽快完成 Zoom 全客户端的版本检查和统一更新，避免批量影响。  
  
1. 对暂未能升级的设备，可通过访问控制或网络隔离手段降低被利用风险。  
  
1. 建议部署终端防护系统监控 Zoom 客户端的异常崩溃和行为。  
  
1. 建立关键软件（如 Zoom、Teams 等）版本合规制度，防止遗留版本滞后。  
  
### 总结  
  
本次 Zoom 漏洞虽未造成数据泄露，但其无需交互、低权限即可触发的特性，使其在攻击面上具备一定威胁。建议相关组织立即开展版本清查，并结合终端管理系统，提升软件更新响应能力，防范潜在服务中断风险。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】中国男子在意大利被捕 美方指控其涉疫苗间谍活动](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=1&sn=6202ead586d7e2b376c3fcd1d53d31e0&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Hunters International 勒索组织宣布关闭，重塑品牌为 “World Leaks” 专注数据勒索](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=2&sn=de13272b722142292b64c67f3b92c93f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】勒索软件团伙 SatanLock 宣布关闭，声称将泄露所有被盗数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=3&sn=5266c0ef59045ec30e5bb45ac8a72972&scene=21#wechat_redirect)  
  
  
  
[【安全圈】《使命召唤：二战》曝严重漏洞，PC玩家遭远程黑客攻击，游戏被紧急下线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=4&sn=a0045b414dc83b5ccab5d88ec4c10558&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
