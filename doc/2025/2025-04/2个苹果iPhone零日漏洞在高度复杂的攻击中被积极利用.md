#  2个苹果iPhone零日漏洞在高度复杂的攻击中被积极利用   
邑安科技  邑安全   2025-04-17 03:32  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8s4uxniarPYcc3rE3qI6We2O1RSmQRiafY3Cia8RhDlLZIPn3ia2ZsRElZdzvDt2IlPyK5IpXeXvGpIjw/640?wx_fmt=png&from=appmsg "")  
  
Apple 发布了 iOS 18.4.1 和 iPadOS 18.4.1，以解决两个关键的零日漏洞，这些漏洞在针对特定个人 iPhone 的高度针对性、复杂的攻击中被积极利用。  
  
在 CoreAudio 和 RPAC 组件中发现的漏洞可能允许攻击者在受影响的设备上执行任意代码或绕过安全保护。  
  
2个主动利用下的零漏洞  
  
CoreAudio 漏洞  
  
第一个漏洞被跟踪为 CVE-2025-31200，位于 CoreAudio 中，这是一个负责 iOS 和 iPadOS 设备上音频处理的框架。  
  
根据 Apple 的说法，处理恶意制作的媒体文件可能会触发内存损坏问题，从而可能导致代码执行。  
  
“在恶意制作的媒体文件中处理音频流可能会导致代码执行。Apple 获悉一份报告，称此问题可能已被利用，用于针对 iOS 上特定目标个人的极其复杂的攻击。  
  
Apple 与 Google 的威胁分析小组合作，证实了针对特定 iOS 用户的高级攻击利用了此漏洞的报告。  
  
RPAC 漏洞  
  
第二个漏洞 CVE-2025-31201 会影响 RPAC（面向返回的编程攻击对策），这是一种旨在防止漏洞利用的安全机制。  
  
此缺陷可能允许具有任意读写能力的攻击者绕过指针身份验证，指针身份验证是一项防止代码纵的功能。  
  
“具有任意读写能力的攻击者或许能够绕过指针认证。Apple 获悉一份报告，称此问题可能已被利用，用于针对 iOS 上特定目标个人的极其复杂的攻击。苹果说。  
  
Apple 指出，此问题也在同一目标活动中被利用，并且已通过删除易受攻击的代码得到缓解。  
  
受影响的设备和缓解措施  
- iPhone XS 及更新机型  
  
- iPad Pro 13 英寸  
  
- iPad Pro 13.9 英寸（第 3 代及更新机型）  
  
- iPad Pro 11 英寸（第 1 代及更新机型）  
  
- iPad Air（第 3 代及更新机型）  
  
- iPad（第 7 代及更高版本）  
  
- iPad mini（第 5 代及更新机型）  
  
针对性攻击凸显日益增长的威胁  
  
虽然 Apple 尚未披露有关这些攻击的具体细节，但该公司将其描述为“极其复杂”并针对特定个人，这表明可能存在国家资助或资源丰富的威胁行为者。  
  
这种零日漏洞利用利用以前未知的漏洞，由于其复杂性和成本，经常被用于间谍活动或有针对性的网络活动。  
  
Apple 强调其政策，即在补丁可用以保护用户之前不披露安全问题。  
  
该公司于 2025 年 4 月 16 日发布的安全发行说明提供了有关漏洞和受影响设备的详细信息。有关 Apple 安全实践的更多信息，用户可以访问 Apple 产品安全页面。  
  
如何更新  
  
要安装 iOS 18.4.1 或 iPadOS 18.4.1，请前往设备上的“设置”>“通用”>“软件更新”。Apple 强烈建议所有符合条件的用户尽快更新，以确保免受这些漏洞的影响。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/2-apple-iphone-zero-day-vulnerabilities-actively-exploited-in-extremely-sophisticated-attacks/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
