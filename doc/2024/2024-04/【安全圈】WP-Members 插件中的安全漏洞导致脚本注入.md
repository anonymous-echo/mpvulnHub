#  【安全圈】WP-Members 插件中的安全漏洞导致脚本注入   
 安全圈   2024-04-04 10:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
根据安全公司 Defiant 的建议，攻击者可以利用 WP-Members Membership WordPress 插件中的高严重性跨站脚本 (XSS) 漏洞将任意脚本注入网页。  
  
  
该漏洞编号为 CVE-2024-1852，是输入清理和输出转义不充分造成的结果，允许攻击者创建将恶意脚本存储为用户 IP 地址值的帐户。  
  
  
攻击者可以使用 WP-Members 会员资格的用户注册功能来填写并提交注册表，然后使用代理拦截注册请求，并修改它以包含 X-Forwarded-For 标头，其中包含脚本标记中的恶意负载，Defiant 的Wordfence研究团队表示。  
  
  
问题是，如果请求中存在 X-Forwarded-For 标头，则插件将使用其值来存储依赖注册表单的任何用户的 IP 地址。  
  
  
警报称：“由于 HTTP 标头可以被操纵，并且输入未经过净化，因此用户可以提供任何值，包括将存储为用户 IP 的恶意 Web 脚本。”  
  
  
恶意脚本存储在用户的配置文件中，如果管理员编辑或查看用户帐户，则负载将包含在页面加载时生成的源代码中。  
  
  
Wordfence 补充道：“重要的是要了解，此恶意代码将在管理员浏览器会话的上下文中执行，并可用于创建恶意用户帐户、将网站访问者重定向到其他恶意网站并执行其他恶意操作。”  
  
  
在版本 3.4.9.2 中包含部分修复后，WP-Members 会员版本 3.4.9.3 修复了该漏洞。建议用户尽快更新其安装。  
  
  
WP-Members是一个用户会员插件，拥有超过 60,000 个活跃安装，允许网站所有者轻松设置和管理用户注册、登录和配置文件、设置限制等。  
  
  
本文转载自：   
https://www.securityweek.com/security-flaw-in-wp-members-plugin-leads-to-script-injection/  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/c7fmJfCyKMmrdWTbFgLl6D1ocptLowsTnTFY0QqmQMSY7Qt1yD2U7Xu2Kicib3MowsOo84breJQEtJpR1TRNAGVg/640?wx_fmt=other "")  
[【安全圈】编写脚本程序入侵计算机，贵阳市一名黑客落网！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057257&idx=1&sn=d72e6e8fb2c3d274e8dff8ac2eb0b112&chksm=f36e02e9c4198bff1625ab7ff3139cf2859bb7bd33929e692d092e233a0a39fcb334fff772ab&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056774&idx=1&sn=2bdce37ef19cbb17edb08149a506bf1d&chksm=f36e0086c4198990902d2df2a6420f357d41ced1151117f025ddd9d62e30ad399dee606057d8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliad3cKFic8TVELV3KNB2wiaCuavtibXrL9hYAeuiamm1VzicAgWXTRE8OIDR3a5ePggeYFzcfNdNEjUrXg/640?wx_fmt=jpeg "")  
[【安全圈】网络攻击背后的大国较量：美国与中国之间的网络安全斗争！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057257&idx=2&sn=ec611ef564541d17cec5362501d160d5&chksm=f36e02e9c4198bffb217770e42925d33f6453338797fdd61d89bec6495dadccb6944bc544438&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliad3cKFic8TVELV3KNB2wiaCuWnt2rzH8GoPYgpggC0SDZntX347hc7H0yqL4F7iaZTWkCutjs8fk77A/640?wx_fmt=jpeg "")  
  
[【安全圈】聊城警方破获全市首例虚拟币传销大案 涉案金额近亿元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057257&idx=3&sn=73e243d6bc1acd335254f9da4d0878f8&chksm=f36e02e9c4198bffa11e0b7e9ae5e175e3e82f7438803dc090d76258b6e38e59e148f79a0060&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliad3cKFic8TVELV3KNB2wiaCuKqjk5WxOOGB8t3iaYbIyckPZBeVJY6K4sANriavekgrplXOFLgJ1BLaQ/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】黑客滥用谷歌虚假广告传播恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057257&idx=4&sn=39fc80a4862f8708831ac4c3fabaaada&chksm=f36e02e9c4198bff9cb447253280b85bc47f28405465b5ebf25befc0100a1c366a459174b3eb&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
  
  
  
