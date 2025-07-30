#  【安全圈】JetBrains TeamCity存在安全漏洞，需尽快更新以避免服务器被黑客攻击   
 安全圈   2023-09-26 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliarDdSzzdz3iaw9hnmSu19TF1IzX1J92JkeBokAICZvB55GVoFjcMelhNqIKakZTLQrrJCiaxMQLCXw/640?wx_fmt=jpeg "微信图片_20230913094808.jpg")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
     
  
etBrains TeamCity是一款由JetBrains开发的流行且高度可扩展的持续集成（CI）和持续交付（CD）服务器。JetBrains是一家以开发者工具闻名的软件开发公司。TeamCity旨在自动化软件开发过程的各个方面，包括构建、测试和部署应用程序，并提供广泛的功能和集成来支持协作开发。  
  
Sonar的漏洞研究团队发现了一个严重的安全漏洞，该漏洞被跟踪为CVE-2023-42793（CVSS评分为9.8），影响TeamCity。该漏洞是一种身份验证绕过问题，影响TeamCity的本地版本。攻击者可以利用这个漏洞窃取目标组织的源代码、存储的服务密码和私钥。通过注入恶意代码，攻击者还可以破坏软件发布的完整性，影响所有下游用户。  
  
Sonar发布的文章中写道：“TeamCity服务器版本2023.05.3及以下存在身份验证绕过漏洞，允许未经身份验证的攻击者在服务器上执行远程代码（RCE）。这使得攻击者不仅可以窃取源代码，还可以窃取存储的服务密码和私钥。更糟糕的是：通过访问构建过程，攻击者可以注入恶意代码，破坏软件发布的完整性，影响所有下游用户。”“这种攻击不需要任何用户交互。”  
  
根据Shodan的数据，超过3000个本地服务器暴露在互联网上。该漏洞影响本地版本2023.05.3及以下，JetBrains通过发布版本2023.05.4来修复了该漏洞。该问题不影响TeamCity Cloud。  
  
JetBrains发布的公告解释道：“安全补丁插件只能解决上述RCE漏洞。我们始终建议用户将其服务器升级到最新版本，以获得许多其他安全更新的好处。”“如果您无法将服务器升级到2023.05.4版本，我们还发布了一个安全补丁插件，以便您仍然可以修补您的环境。安全补丁插件可在TeamCity 8.0+上下载并安装。它将修补上述特定的RCE漏洞。对于TeamCity 2019.2及更高版本，插件可以在不重启TeamCity服务器的情况下启用。对于早于2019.2版本的版本，在安装插件后需要重新启动服务器。”  
  
安全补丁插件的链接适用于TeamCity 2018.2至2023.05.3版本和TeamCity 8.0至2018.1版本。  
  
Sonar没有公开该漏洞的详细信息，因为它很容易被利用。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliarDdSzzdz3iaw9hnmSu19TFzW6OuqD7viaLfJj4uZqc3PGbkssCIJ5f8nb9LuxZfYmPh13kO7ic7OvQ/640?wx_fmt=png "")  
[【安全圈】诱惑！为博取“美女”好感，男子竟为其窃取涉密敏感信息！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045227&idx=1&sn=2cb35336155a65da5020b597d9602b57&chksm=f36fd3ebc4185afd9384355024dcd8c81bbe8636d810add55f525b7158bcf26f7b4722a6855f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliarDdSzzdz3iaw9hnmSu19TFkoGvnRSZibnR3gKyxgscHUZYLDkQRibeN0t8qLr7GiaOHTv6kvibvngFzQ/640?wx_fmt=png "")  
[【安全圈】可怕！上千万部老年机被远程控制……](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045227&idx=2&sn=e39b174aab2d71aa7fa16551e0fe5b11&chksm=f36fd3ebc4185afd282aa87467b4ee9fd79412bc7c459760f5f2a50538d990c07c1352d2afa4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliarDdSzzdz3iaw9hnmSu19TFluTHXu03ibrxHrEcicLHS71DzodBEwTBsIibfqicGAHRol74BOzjY6aWHw/640?wx_fmt=png "")  
[【安全圈】12306账号内出现陌生人信息？官方回应](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045227&idx=3&sn=684b420da89913ac6ab6cb2734e6e883&chksm=f36fd3ebc4185afd44b26ce85d45e92ad2f18d127252092efc08b5d33631fcf4aea5a440f647&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliarDdSzzdz3iaw9hnmSu19TF2Ffhjm0k5oaibN7OGiar8OiaUvicYKTrrN6wzTVtrsqCgl2sS6f5gypa3Q/640?wx_fmt=png "")  
[【安全圈】Temu 名人视频骗局充斥 TikTok，多人中招](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045227&idx=4&sn=6344a51aa391848eb80ed55014f9690b&chksm=f36fd3ebc4185afddfa326bfa4a67140e8c56940fe342ff72edc43cab6459fad8a8bc9cea3fc&scene=21#wechat_redirect)  
  
  
  
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
  
  
