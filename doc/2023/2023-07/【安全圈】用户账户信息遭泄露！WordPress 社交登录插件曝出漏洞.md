#  【安全圈】用户账户信息遭泄露！WordPress 社交登录插件曝出漏洞   
 安全圈   2023-07-01 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
  
The Hacker News 网站消息，miniOrange 的 WordPress 社交登录和注册插件中出现了一个关键安全漏洞，该漏洞可能使潜在网络攻击者登录用户帐户。（任何用户提供的有关电子邮件地址信息都是已知的）  
  
  
  
据悉，漏洞被追踪为 CVE-2023-2982（CVSS 得分：9.8），身份验证绕过漏洞影响包括 7.6.4 之前在内的所有插件版本。2023 年 6 月 2 日，相关组织负责任地发布了 7.6.5 版本，CVE-2023-2982 漏洞问题已于 2023 年 6 月 14 日得到解决。  
  
  
Wordfence 研究员 István Márton 表示 CVE-2023-2982 漏洞使未经身份认证的网络攻击者有可能获得对网站上任何账户的访问权，甚至包括用于管理网站的账户，但前提是攻击者知道或能够找到相关的电子邮件地址。  
  
  
此外，CVE-2023-2982 安全漏洞问题的根源在于用户使用社交媒体账户登录时，用于保护信息安全的加密密钥是硬编码，因此导致了攻击者可以使用正确加密的电子邮件地址创建有效请求以识别用户的情况。值得一提的是，存在漏洞的插件在 30000 多个网站上使用。  
  
  
**LearnDash LMS 插件也曾出现其它安全漏洞**  
  
##   
  
****  
发布 CVE-2023-2982 漏洞公告前，安全人员发现一个影响 LearnDash LMS 插件的严重漏洞（CVE-2023-3105，CVSS 得分：8.8），该插件是一个拥有超过 100000 个活动安装的 WordPress 插件，可以允许任何拥有现有帐户的用户重置任意用户密码，甚至包括具有管理员访问权限的用户密码。好消息是，漏洞已于 2023 年 6 月 6 日发布的 4.6.0.1 版本中完成了修补。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38WKgc8Iib3wia2tBEXkc64xRYI0RvniaAKib8XMwcWjic9JicPnQA29deQqYXIujyEkqxciaqyzr6veKdqw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
几周前，Patchstack 也曾详细介绍 UpdraftPlus 插件中的一个跨站点请求伪造（CSRF）漏洞  
（CVE-2023-32960，CVSS分数：  
7.1），该漏洞可能允许未经身份验证的攻击者窃取敏感数据，并通过诱骗具有管理权限的用户访问特制的 WordPress 网站 URL ，以此来提升自身权限。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljofKBrBGTlJZVX4yty2slOW2toXQNjL0TNODU9kEDD8iaDhpfsgibWibWAGT9GwqfXUTtYWyJuJicIdw/640?wx_fmt=jpeg "")  
[【安全圈】被勒索7000万刀！台积电疑似被攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038228&idx=1&sn=c8c6b74ba45b02908c716eed686c93ac&chksm=f36fc814c41841024407d1ca97ad1c567e25a66a028e167709032f83f1109bb6612051f8cf93&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljofKBrBGTlJZVX4yty2slOsyLHgwNbJRP9ic5F2EhO6MfCcRhcMVhffDWfMWHyHCiatiaq9IkeUM2Jw/640?wx_fmt=jpeg "")  
[【安全圈】数据跨度10年，Android 监控应用遭重大数据泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038228&idx=2&sn=8c3d26c26992c26d2d9cde37eefb31f8&chksm=f36fc814c41841020a5ce34d5b046a0ae887a07f0c18d60f346a680b78644e25bbd792578d08&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhUPBlicslE7HS0aDEjdvPRXy5fb8taFOyD9dAGJZDlYDE4d9T53D1OexEJEibvxlJDx48cv7YdW5Qg/640?wx_fmt=png "")  
[【安全圈】WPS一崩，打工人也崩溃！官方：逐步恢复](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038228&idx=3&sn=0ff678281998a10ca32525225b851d5f&chksm=f36fc814c4184102425fd4c9d4e87c562c765b75dad3a569264eafeceaddfaa24743f037613a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljofKBrBGTlJZVX4yty2slOicLbx5kKJzA1ibVRQFSD50PTxv1NibD65Niah95Ho3ZnicZicfsKpqs4uuog/640?wx_fmt=jpeg "")  
[【安全圈】预计未来基于Flutter的安卓恶意软件，会瞄准东亚市场](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038228&idx=4&sn=460a201456ea3e1716f06b288ef0baa2&chksm=f36fc814c4184102862c26dc373fd5121337b1c2c09586df64a0da0fd7823b41aeffec706d94&scene=21#wechat_redirect)  
  
  
  
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
  
  
