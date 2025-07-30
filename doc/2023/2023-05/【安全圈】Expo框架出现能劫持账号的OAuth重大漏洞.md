#  【安全圈】Expo框架出现能劫持账号的OAuth重大漏洞   
 安全圈   2023-05-28 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
漏洞  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylhjAZ9rV0l8I7tTIx7riaMtDHNMUWJNn27SicllbXkJIGolNZjGvdxeWESCYh64pvYgI8mRCGQsQBTw/640?wx_fmt=jpeg "")  
  
  
安全研究人员发现，用于数百线上服务的知名开发框架Expo出现可劫持账号的重大漏洞。  
  
  
Expo框架主要是用于开发移动应用程序，提供一组工具、函数库及服务，让开发人员得以利用单一程序代码基础（codebase）开发iOS、Android及Web应用程序。它其中一项服务是OAuth，让开发人员能将社交登录（social sign-in）组件集成到网站，像是以脸书或Google账号单一登录各种网站。目前Expo框架全球用户高达65万人，许多知名线上服务，包括Facebook都以它来实例OAuth安全验证及其他功能。  
  
  
Salt Labs研究人员发现的Expo漏洞编号为CVE-2023-28131，位于用于社交登录的AuthSession重导向代理服务器（auth.expo.io）服务中，这个服务让用户通过中介服务（如Facebook、Google）验证网站或App，让用户不必再记忆不同网站或App的密码。新发现的漏洞能让攻击者劫持使用该服务的应用程序／网站的用户账号，并窃取其登录凭证。一旦受害者点入恶意连接就会发生，攻击者可以通过电子邮件、文本消息或其他方式发送攻击者控制的恶意网站连接。成功攻击的结果包括诈骗、窃取信用卡或个人信息等后果，恶意攻击者还可能冒用Facebook、Google、Twitter或其他线上平台的用户身份为非作歹。  
  
  
CVE-2023-28131风险值被列为CVSS 3.1的9.6，属于重大漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylhjAZ9rV0l8I7tTIx7riaMtDQBHLgRSRAibaPoXB9AQ3z6sfxUfYKrD7oqA4TUPeFmFxsn8A0HZgicyA/640?wx_fmt=jpeg "")  
  
  
接获通报后，Expo维护单位已发布hotfix暂时缓解攻击风险，且指出目前没有漏洞攻击的证据。但Expo认为App应直接和第三方验证供应商注册直接连接，而不应使用中介服务，不只因为安全，也较为稳定。因此Expo建议使用AuthSession模块中useProxy选项的App/网站，未来应转移以免除风险。  
  
  
Expo已经在最新SDK 48版及auth.expo.io服务的AuthSession模块移除useProxy选项。此外，虽然目前没有紧急转移的必要性。但如果用户希望从useProxy和auth.expo.io服务改成使用直接连接，Expo也提供指引。  
  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgibXEAXiapGDIjicyELHOEb4A90C1o7FnibcZ4ObX9iaSGibcbtOCJJlA7ibTZwibND8bCjPzibQvcVhKgibSg/640?wx_fmt=jpeg "")  
[【安全圈】研究发现，可能有数以百万计的Android手机和电视盒子设备预装了恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035369&idx=1&sn=e106964b0f4669c5dd474ac9b2d75497&chksm=f36ff569c4187c7f521757faf22db4216df901e9db2d821e1ef9a97693d1d53c71802bc496e7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgibXEAXiapGDIjicyELHOEb4AIl7ibceoscVgMvzNn0A1yn1MQjA0qOtVEiavVgdyyVkVkDYBeZfVYsVA/640?wx_fmt=jpeg "")  
[【安全圈】Windows XP 正版密钥算法被破解：随意离线激活](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035369&idx=2&sn=a1017a7aaab2f5f4fba5cb457d96712e&chksm=f36ff569c4187c7f0b922f7c0567fa94053a736f603b60d2379e3bc4893780e916ee45e39cff&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0GRk0G2QBST43lVjYE1blrMgN1zV8FHGgXw8JU96hPDjLo5kiba0mkYIS1GAZxPAY2Nztfv2tiaHYLqwibcmmr5w/640?wx_fmt=png "")  
[【安全圈】不输密码也能转走你的钱，手机这个功能建议关闭！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035369&idx=3&sn=4354e568918a5d72518a34b083b36615&chksm=f36ff569c4187c7f5aace4c88e52843a46bdfe9815402a717f2ed022c28e23a8c8d54ebf6604&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgibXEAXiapGDIjicyELHOEb4AYaQhzsMUrjw14AFdTlHcgfTict3pMqmvBD53icIrtSvoiaprq6vyoxMiaw/640?wx_fmt=jpeg "")  
[【安全圈】免费 VPN 服务 SuperVPN 泄露 3.6 亿用户隐私](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035369&idx=4&sn=743ad7b43a172437ff5b6d56b76daf5a&chksm=f36ff569c4187c7f207e76839345cd9fb7d914c07fcb90165f3c9230a9fa3fa6cf86144f5586&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
  
  
