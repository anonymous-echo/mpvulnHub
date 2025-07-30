#  【安全圈】HTTP/2 协议被曝安全漏洞，被黑客利用可发起拒绝服务攻击   
维克多  安全圈   2024-04-08 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统  
漏  
洞  
  
  
网络安全研究员 Bartek Nowotarski 于 1 月 25 日报告，发现 HTTP / 2 协议中存在一个高危漏洞，黑客利用该漏洞可以发起拒绝服务（DoS）攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljTKIBjnWKrr6VMaeAIhLXeAkc4BwmxALnMeaBXOrRoeC2SJNvCbsYjpKNkJt5eSM3icoW3WdzlurA/640?wx_fmt=jpeg&from=appmsg "HTTP / 2 协议被曝安全漏洞，被黑客利用可发起拒绝服务攻击")  
  
Nowotarski 于 1 月 25 日向卡内基梅隆大学计算机应急小组（CERT）协调中心报告了这个发现，该漏洞被命名为“HTTP / 2 CONTINUATION Flood”。  
  
该漏洞主要利用 HTTP / 2 的配置不当实现，主要是未能限制或净化请求数据流中的 CONTINUATION 帧。  
  
CONTINUATION 帧是一种用于延续报头块片段序列的方法，允许在多个帧中分割报头块（header block）。  
  
当服务器收到一个特定的 END_HEADERS 标志，表明没有其他 CONTINUATION 或其他帧时，先前分割的报头块就被视为已完成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljTKIBjnWKrr6VMaeAIhLXeW8GbP84j3CLNzwkzibjxtDw8zuDicAwaNKpBmV3teqYyX1DsPUV333Mg/640?wx_fmt=jpeg&from=appmsg "HTTP / 2 协议被曝安全漏洞，被黑客利用可发起拒绝服务攻击")  
  
如果 HTTP / 2 实现不限制单个数据流中可发送的 CONTINUATION 帧的数量，就很容易受到攻击。如果攻击者开始向未设置 END_HEADERS 标志的易受攻击服务器发送 HTTP 请求，该请求将允许攻击者向该服务器持续发送 CONTINUATION 帧流，最终导致服务器内存不足而崩溃，并导致成功发起拒绝服务 (DoS) 攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljTKIBjnWKrr6VMaeAIhLXet8PZRGDpACDvTOHxZOYib2ia2Kic43NAWwu4br5bya0xzHhBj0kV3cX3A/640?wx_fmt=jpeg&from=appmsg "HTTP / 2 协议被曝安全漏洞，被黑客利用可发起拒绝服务攻击")  
  
HTTP / 2（原名 HTTP 2.0）即  
超文本传输协议第二版，使用于万维网。HTTP / 2 主要基于 SPDY 协议，通过对 HTTP 头字段进行数据压缩、对数据传输采用多路复用和增加服务端推送等举措，来减少网络延迟，提高客户端的页面加载速度。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ibZBtVZJdx2Yg91aCwibdpqbnoiaDalX1udEoy28iczXCUJh1MMNfc6ODucLmucKiaCNEuZu6xwZG3gG1dzCjPy087Q/640?wx_fmt=jpeg "")  
[【安全圈】涉百位当红明星！19岁幕后黑客被抓获](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057486&idx=1&sn=67de20fb6b8614be1b1684667671a59a&chksm=f36e03cec4198ad877c8d0f8c7233ae603e474ada5ccb54774fac4ff2ef4d243d2570a5dc009&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056774&idx=1&sn=2bdce37ef19cbb17edb08149a506bf1d&chksm=f36e0086c4198990902d2df2a6420f357d41ced1151117f025ddd9d62e30ad399dee606057d8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgVDE4NL8l9KnXiaGB8Ut2Tp7kwt9ZYlIVrxicvZdoZSvjVWtzMkBYyckCEFjpQVGzQib5Rh6ZCXXRTg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】男子利用网络漏洞刷取游戏金币，非法获利413万，被判刑三年六个月](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057486&idx=2&sn=9b2fe9c936492d052e96683f6c334db6&chksm=f36e03cec4198ad8ce2fdac5656b608aad3c6f77652628a0e71a316000343a684930b615f730&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljTKIBjnWKrr6VMaeAIhLXe9DuficBFJKPwwXsjjEoibbib054dTC3jBrvd27t7hvbfOgO7fJuFRhTnA/640?wx_fmt=jpeg "")  
[【安全圈】尼泊尔黑客 1 小时内入侵 Facebook](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057486&idx=3&sn=821e5714c1cb6c486879845b328ef3ee&chksm=f36e03cec4198ad8ecd4a82e058b882f5880bcd8d8094d888aadc0fedffa7977aef1df093894&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljTKIBjnWKrr6VMaeAIhLXe8wZibEUgFLsuicEpa4A9CuqicaF9zKNDc7GGDsoYUwvxsnOgp7qYXlia4Q/640?wx_fmt=jpeg "")  
[【安全圈】洛杉矶国际机场 VIP 客户成为大规模黑客攻击的受害者](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057486&idx=4&sn=7f5f152a15f01a3c9a24d4c64ed08314&chksm=f36e03cec4198ad8a43a9a673501e32fd7c8e20aa9133eaa4270d91c20e927d9bf1b7edfdf0c&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
  
  
  
  
  
  
  
  
