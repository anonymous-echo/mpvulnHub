#  【安全圈】注意！ScreenConnect 漏洞正被广泛利用于恶意软件传播   
 安全圈   2024-02-26 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
影响 ConnectWise 的 ScreenConnect 远程桌面访问产品的严重漏洞已被广泛利用来传播勒索软件和其他类型的恶意软件。  
ConnectWise 于 2 月 19 日通知客户，它已发布针对关键身份验证绕过缺陷和高严重性路径遍历问题的补丁。该安全漏洞当时没有 CVE 标识符。第二天，该公司警告说，它已经意识到野外的利用企图。  
  
CVE 标识符现已分配给这两个漏洞：CVE-2024-1709 为身份验证绕过漏洞，CVE-2024-1708 为路径遍历漏洞。  
  
威胁检测和响应公司 Huntress（将这些缺陷称为SlashAndGrab）在概念验证 (PoC) 漏洞利用已经可用后，于 2 月 21 日披露了技术细节。  
  
身份验证绕过漏洞允许攻击者创建具有管理员权限的新帐户。然后可以利用路径遍历来执行任意代码。  
  
有几份报告表明 CVE-2024-1709 被广泛利用，但尚不清楚 CVE-2024-1708 是否也被利用。  
  
Huntress报告称，看到 SlashAndGrab 被利用来传播 LockBit 勒索软件、Cobalt Strike、SSH 隧道、远程管理工具和加密货币挖矿程序。该公司确定的受害者包括地方政府、应急系统和医疗机构。  
  
Sophos 还报告称看到了LockBit 勒索软件的传播，考虑到该网络犯罪企业最近成为了一场极具破坏性的执法行动的目标，这一点很有趣。  
  
Sophos 表示：“尽管针对 LockBit 采取了执法行动，但一些附属机构似乎仍在运行。”  
  
该网络安全公司还发现通过利用 ScreenConnect 漏洞传播 AsyncRAT、各种信息窃取程序和 SimpleHelp 远程访问软件。  
  
非营利网络安全组织 Shadowserver 基金会报告称，截至 2 月 21 日，已发现超过8,200 个暴露于互联网且易受攻击的ScreenConnect 实例。易受攻击实例的比例最高的是美国，其次是加拿大和英国。  
  
Shadowserver 表示：“CVE-2024-1709 在野外被广泛利用——迄今为止，我们的传感器已发现 643 个 IP 受到攻击。”  
  
CISA 已将 CVE-2024-1709 添加到其已知被利用的漏洞目录中，并指出该机构已意识到勒索软件攻击中的利用情况。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMWicFykmfj75gC2lfxhhAVeV4O4mfgVbPibRPNVsWB3URV2fZWRarfB0yr2YRuhQaBzwGXLB9zNxA/640?wx_fmt=jpeg "")  
[【安全圈】首个“人脸劫持“银行木马诞生：收集面部信息，窃取你的财产](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054495&idx=1&sn=6b322116aaed619f7cb3cef22442d961&chksm=f36e0f9fc41986892b1fc5e7dac3ff9137cdf95fa62e6ad7430191af0e9e3930bf274bbffe0d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljc4R6mqShBQSm7gpcEXKJRh0WYlVESPyrvymYB1mVkoibKEgEhxHgiceCmXHLfOdne4lRIvWRekqQg/640?wx_fmt=png&from=appmsg "")  
[【安全圈】警告！ConnectWise 漏洞正被广泛利用，数千台服务器面临危险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054495&idx=2&sn=9a62c38f083509de6baf57d55e58e03d&chksm=f36e0f9fc4198689a8f6c08a651dfcefac3e886e0fdb0dd59153ba35b41661c320edf3517c5e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMWicFykmfj75gC2lfxhhAVicoT91yW6vv9lIL5ia5HRew6nYb8ttpsZwO8PiaANAzRA3s1HpJ65hPfw/640?wx_fmt=jpeg "")  
[【安全圈】不付费就不保护用户隐私？Meta公司为收集数据再出“霸王条款”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054495&idx=3&sn=37ed9891c07a40390a7bf012be57940b&chksm=f36e0f9fc4198689f4213eeed5338e74c19c616d4dd3038ed414360ec74a5809cb150b362710&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgliav9nRhJpn54X9ndTPw1FwLicwo5YYhRIKiaGOtwCTYBguSRdfOB8k0esWSxTZH2n9f1RRKicvho0g/640?wx_fmt=png&from=appmsg "")  
[【安全圈】微软：PopCnt 确实导致了 Win10 Photos 等应用出现错误](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054495&idx=4&sn=56db53c0f0705b7358bebe652bb24b1e&chksm=f36e0f9fc4198689ea8dcce73f9d4d518ddfeb96663608705420bdfac9f2bc6654b7653fc2c2&scene=21#wechat_redirect)  
  
  
  
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
  
  
