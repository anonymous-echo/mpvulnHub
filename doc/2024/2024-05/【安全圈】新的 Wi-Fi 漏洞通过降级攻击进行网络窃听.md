#  【安全圈】新的 Wi-Fi 漏洞通过降级攻击进行网络窃听   
 安全圈   2024-05-17 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
网络窃听  
  
  
据英国TOP10VPN的一份最新研究报告指出，一种基于 IEEE 802.11 Wi-Fi 标准中的设计缺陷能够允许攻击者诱导用户连接至不安全的网络，进而对用户进行网络窃听。  
  
报告指出，该缺陷是基于CVE-2023-52424 SSID 混淆攻击的漏洞利用，涉及所有操作系统和 Wi-Fi 客户端，包括基于 WEP、WPA3、802.11X/EAP 和 AMPE 协议的家庭网络和网状网络。  
  
TopVPN表示，攻击者可以通过发动 “中间人”（AitM）攻击，欺骗客户端连接到一个不受信任的 Wi-Fi 网络，而不是它打算连接的网络。比如当用户想要连接到网络 TrustedNet 时，攻击者会诱骗它连接到使用类似凭证的另一个网络 WrongNet。因此，用户客户端会显示连接到了 TrustedNet，而实际上却连接到的是 WrongNet。  
  
换句话说，即使在连接到受保护的 Wi-Fi 网络时——密码或其他凭证经过了相互验证，也不能保证用户连接到的是他们想要的网络。  
  
研究人员指出，之所以能够利用这一缺陷，一个重要原因是目前的Wi-Fi网络依靠 4 路握手来验证自己和客户端的身份，并协商加密连接的密钥。4路握手需要一个共享的配对主密钥（PMK），根据Wi-Fi版本和所使用的特定认证协议，PMK可以以不同的方式获得。  
  
问题在于，IEEE 802.11 标准并未强制要求在密钥推导过程中包含 SSID。换句话说，当客户端设备连接到 SSID 时，SSID 并不总是认证过程的一部分。在这些实施过程中，攻击者有机会设置一个恶意接入点，欺骗受信任网络的 SSID，并利用它将受害者降级到信任度较低的网络。  
  
攻击者要利用这一弱点，必须具备某些条件，即只在可能拥有两个共享凭证的 Wi-Fi 网络的情况下起作用。例如，环境中可能有分别有一个 2.4 GHz 和5GHz 网络频段，每个频段都有不同的 SSID，但具有相同的验证凭据。通常情况下，客户端设备会连接到安全性更好的 5 GHz 网络。但如果攻击者足够接近目标网络以实施中间人攻击，就可以粘贴一个与 5 GHz 频段具有相同 SSID 的恶意接入点，然后就可以利用恶意接入点接收所有验证帧并将其转发到较弱的 2.4 GHz 接入点，让客户端设备与该网络连接。  
  
值得注意的是，在某些情况下它还可能使 VPN 保护失效。研究人员表示，许多 VPN，如 Clouldflare’s Warp、hide.me 和 Windscribe在连接到受信任的 Wi-Fi 网络时可以自动禁用 VPN。他们指出，这是因为 VPN 根据 SSID 识别 Wi-Fi 网络。  
  
TOP10VPN也指出了了针对SSID混淆攻击的三种防御措施：  
1. 更新IEEE 802.11标准，以强制执行SSID身份验证；  
  
1. 妥善存储接入点定期发送的信标，以在客户端连接时能检测 SSID 变化；  
  
1. 避免在不同的 SSID 之间重复使用凭证。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/xULr3vhGN2Zia3huEv0RuQ51iaYrqlcXEpBFB2JtiaHUYiaGyQarlKl1wlgQOw8iafeiahgIXChTicxL37nBmZJAHpicTA/640?wx_fmt=jpeg "")  
[【安全圈】淄博警方破获一起侵犯公民个人信息案](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059982&idx=1&sn=b1def6971f4986fec0dcd6e9101bc142&chksm=f36e150ec4199c18f40ce3c6d509559582cf97db8c90ed07c9a7b32ce72abe34d27b86b5874c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgd3t5gQXHGPx7PYXoWkeIgyXBict2K2jzaibOC55Eaic071u4Rmt7y9MD5jfIticeicFjUG70nQKvyKDA/640?wx_fmt=jpeg "")  
[【安全圈】泰国 DITP 50 万用户数据库遭泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059982&idx=2&sn=c32a8cc31ab41095de56609aed01a5b9&chksm=f36e150ec4199c18545a474a0076ef266b687fc8a16baefc810ca9e427e171bd56a44621910d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgd3t5gQXHGPx7PYXoWkeIgwu9dVYsn6TicIBKMSlria8cQfIPia1wycf4jgKPv686DwoN3pJALkOmlg/640?wx_fmt=jpeg "")  
[【安全圈】微软2024年5月补丁日多个产品安全漏洞风险通告](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059907&idx=3&sn=875dbf3fc68fc701c90d985a43e78db0&chksm=f36e1543c4199c550315bc3370ad6ac6457e99f3b5d93f02a2e707b9e8864d2dea0d46857cda&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgd3t5gQXHGPx7PYXoWkeIg78gCvFCvmJ4yWwqRWGWStWIcVn9J6JMhB6fAYxzTJHdCicOxToCLnWw/640?wx_fmt=jpeg "")  
[【安全圈】安全公司 Zscaler 否认遭黑客入侵，但承认有测试环境暴露于网络](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059907&idx=4&sn=c880e5b2d1157a2f2fe8746cef2c8d04&chksm=f36e1543c4199c55ff65488a48632e2f6ca8d55a457b2040f0610b5dd8602537ef96daa15a8e&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
