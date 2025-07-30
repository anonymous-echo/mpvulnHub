#  【安全圈】Facebook企业账号危机:Salesforce漏洞成黑客入侵新通道   
 安全圈   2023-08-08 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
黑客入侵  
  
  
    
  
  //    
  
      近期黑客挟持企业的facebook帐号的攻击行动，有不少是通过脸书广告，打着提供生成式AI机器人应用程序的名义，散布窃资软件来进行，但最近出现了更为复杂的手法。有人透过云端CRM平台Salesforce的漏洞下手，并将钓鱼网站架设于脸书脸书内嵌应用程序平台的域网域上，从而回避系统的侦测，并骗取受害组织的脸书帐号。  
  
      云平台的系统管理工具有可能遭到滥用，因此成为黑客的“木马程序”, 研究人员揭露利用AWS EC2系统管理工具System Manager的攻击手法，攻击者有可能透过这项工具管理其他组织的AWS EC2实体。  
  
      已被用于攻击Citrix NetScaler系统存在的零时差漏洞CVE-2023-3519，有研究人员揭露初步调查结果，他们找到640台服务器已被部署了后门，并强调这可能仅是受害范围的冰山一角。  
  
  
     Guardio揭露CRM平台Salesforce的漏洞PhishForce，黑客借此漏洞绕过该CRM平台的寄件人验证措施，并滥用脸书内嵌应用程序平台，来大规模发送钓鱼邮件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6xrXyKk5X4nsMfksNaoWwHErFNNSqdFeCNrOS00AuzrmTCmxMlicoPYPNTVJXrvBTUv5CQicmAyibV1A/640?wx_fmt=png "")  
  
      研究人员指出，黑客滥用了Email-to-Case的功能，该功能主要是让组织能将客户寄入的电子信件转换为Salesfoce系统传递的处理工单，但黑客将其用来设置新的工作流程，进而控制Salesforce产生的电子邮件信箱，并产生 salesforce.com 域的内部信箱，且将其设置为组织全局的电子邮件信箱，然后用于发送钓鱼邮件， 而能绕过Salesforce的验证措施，以及组织设置的邮件安全系统。  
  
      在其中一起攻击行动里，黑客假借Meta的名义，声称收信人的脸书帐号出现异常，一旦依照指示点选信中链接，就会被带往架设在脸书内嵌应用程序平台（apps.facebook.com）的钓鱼网页。  
  
      对此，Salesforce获报后着手修补漏洞，Meta移除钓鱼网页，并着手调查黑客如何滥用该脸书内嵌应用程序平台。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh4BzsbEW794ahMwkd7DGoQfLJOdiaVX2RbYer0II4YBhMxTHoDJpJd69b8ZJVpOsSeV5kxPArnn4Q/640?wx_fmt=png "")  
[【安全圈】黑客组织Clop发动零时差漏洞攻击，近600家企业遭殃](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041451&idx=1&sn=6f5bd9b3a6801ab469fbc602a5998ecf&chksm=f36fdcabc41855bd943a95afcae93ee70122e56d148dedcbc9a4889c3111c7efeeec4e43b48c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh4BzsbEW794ahMwkd7DGoQlNEeoTx9FrP3nJZM4O7Iqw9kTZXOo1t8CvibmyIPiaEYvibCQQdpjOtRw/640?wx_fmt=png "")  
[【安全圈】上海警方抓3名嫌疑人！远程操控物流公司电脑 非法获取物流面单](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041451&idx=2&sn=7faed7f03ac1359ae53b0f0d153fcd0f&chksm=f36fdcabc41855bdcafad5beff6c3a2ebea1a305c4894501954bb43f79a77d7d2f412a0b872a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh4BzsbEW794ahMwkd7DGoQAIlUqvA9dxAR39bk76kGWNyLWibuTyHKgnicONevVugN0ia8UDQEEYVaA/640?wx_fmt=png "")  
[【安全圈】中央政法委：依法从重打击境外电信诈骗 深挖彻查与境外勾结犯罪团伙](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041451&idx=3&sn=71056e796967c86dbee8c1b710a76beb&chksm=f36fdcabc41855bd34a2449124fa7c2f7facb36a04806b99225784251dc0e1e7b9084214700a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh4BzsbEW794ahMwkd7DGoQ7JyZbektlTfqH3kde7rCnaDtVeRZ41fx9QlZLtD2skDxLzg8uyZ4ww/640?wx_fmt=png "")  
[【安全圈】谷歌：安卓恶意软件通过版本控制潜藏在Google Play商店](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041451&idx=4&sn=d24730f8db11926409315adf2b506820&chksm=f36fdcabc41855bd1244d0ae7838f98640e61a1e4c409b43718163b607099f5945fa74645b03&scene=21#wechat_redirect)  
  
  
  
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
  
  
