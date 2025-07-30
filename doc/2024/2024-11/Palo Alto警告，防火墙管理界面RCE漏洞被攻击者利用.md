#  Palo Alto警告，防火墙管理界面RCE漏洞被攻击者利用   
 E安全   2024-11-19 01:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6wb7UQK35lUEQnrcXgPKPKzmeYDW0ZVlyj88HgPMNr3TXBNlqhAq1XOt1x70aicpvI0aNIugXh66Ng/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6wb7UQK35lUEQnrcXgPKPKzxRPKV1N4SeF0rAd89ib8Ky5nOEflM3iaQ0ict65XAic6NoM8xsFicB0k4EQ/640?wx_fmt=png&from=appmsg "")  
  
  
**E安全消息，近期网安巨头Palo Alto Networks发布安全警告，关于其防火墙产品管理界面中关键的远程命令执行（RCE）漏洞被利用。**  
  
  
这个缺陷允许未经认证的攻击者在受影响的系统上执行任意命令，在有限的案例中观察到，这些防火墙管理界面暴露于互联网。  
  
  
**该公司已将漏洞的严重性提升至关键级别，CVSSv4.0基础得分为9.3。**这提示未遵循建议的安全实践的组织面临的高风险。  
  
  
Palo Alto Networks正在积极调查此问题，并已确认威胁行为者已经开始在野外利用这个漏洞。  
  
  
**该漏洞主要影响可以从互联网访问的防火墙管理界面。**Palo Alto Networks强烈建议客户立即检查其防火墙配置，并确保根据最佳实践指南，只有受信任的内部IP地址才能访问这些管理界面。  
  
  
公司强调，Prisma Access和Cloud NGFW 服务不受此漏洞影响，这减少了使用这些产品的用户的担忧。然而，对于其他防火墙系统，Palo Alto Networks警告说，如果无法保护管理接口，可能会使它们容易受到攻击。  
  
  
“目前，我们认为那些未按照我们推荐的部署最佳实践指南进行管理界面访问保护的设备面临更高的风险，”公司在其公告中表示。  
  
  
为了帮助客户识别可能易受攻击的设备，Palo Alto Networks通过其客户支持门户提供了指导。**用户可以按照以下步骤操作：**  
  
- **1.** 访问客户支持门户的Assets部分。  
  
- **2.**查找标记有PAN-SA-2024-0015的设备，这些设备面向Internet的管理界面。  
  
如果没有列出这样的设备，这意味着Palo Alto的扫描未检测到该账户的任何公开接口。客户被敦促手动双重检查他们的配置。  
  
  
尽管在有限的案例中观察到活跃的利用，Palo Alto Networks尚未提供具体的入侵指标（IoC）。**建议客户监控异常活动，例如无法识别的配置更改或不熟悉的用户登录。**  
  
  
作为其持续响应的一部分，Palo Alto Networks正在准备补丁和威胁预防签名以缓解这个漏洞。这些修复预计将很快发布。  
  
  
与此同时，保护对防火墙管理界面的访问仍然是最有效的防御措施。公司将继续更新其公告，以获取新信息。  
  
  
对于持续的更新和通知，客户可以通过其支持门户订阅Palo Alto Networks的安全RSS源或电子邮件警报。  
  
  
  
**精彩推荐**  
  
  
微软11月补丁星期二：修复91个漏洞，包含4个零日漏洞  
2024.11.15  
  
[](http://mp.weixin.qq.com/s?__biz=MzI4MjA1MzkyNA==&mid=2655347993&idx=1&sn=029f276994bab0e5572dded3d81f223c&chksm=f02e1952c75990441ba555d82104c4a49a754017b7a324c29c1f426b0ba9b2c5532f2309e0dd&scene=21#wechat_redirect)  
  
  
五眼联盟警告，零日漏洞利用正在成为“新常态”  
2024.11.14  
  
[](http://mp.weixin.qq.com/s?__biz=MzI4MjA1MzkyNA==&mid=2655347981&idx=1&sn=4ea51d5d9163381c229194d6dcce6833&chksm=f02e1946c75990504d5c8aba874223a013df25f97a7399a96e053033c4a67526600c836b13c1&scene=21#wechat_redirect)  
  
  
微软提醒，Windows 11更新导致SSH连接中断  
  
2024.11.13  
  
[](http://mp.weixin.qq.com/s?__biz=MzI4MjA1MzkyNA==&mid=2655347969&idx=1&sn=ed6a6add2d02c63baf08709733174da0&chksm=f02e194ac759905cc685de82cc6684b857df90e665990ebfe05a0cb81aac29e9c5fe2076f46e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xuwKC3XZa5PZwOfyW4oy9y2uKJLHcg0LnRAXiaicvdMTgLgKoxoVJZfmQxUensppSZJSmnIbX3dNiaQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xuwKC3XZa5PZwOfyW4oy9ypIV3ItH0hiazjtk1Qe8wQJHLiaMTtfDZD9UnHrctGwbbbx9NLsQibCa0Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/QmbJGbR2j6xuwKC3XZa5PZwOfyW4oy9ynjicbtVrTnA8w5v2sLoAjkictk1u5uVGJZ9MMouKDLUqsqXRZjkhU84A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
注：本文由E安全编译报道，转载请联系授权并注明来源。  
  
