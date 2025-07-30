#  【安全圈】CNNVD关于Apache ActiveMQ安全漏洞的通报   
 安全圈   2024-05-08 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Apache ActiveMQ安全漏洞（CNNVD-202405-256、CVE-2024-32114）情况的报送。成功利用漏洞的攻击者，可能在未经身份验证的情况下使用Jolokia JMX REST API与代理交互，或使用Message REST API向消息队列和主题中发送消息、接收消息、删除消息队列和主题等。Apache ActiveMQ 6.0.0-6.1.1版本均受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
**一、漏洞介绍**  
  
Apache ActiveMQ是美国阿帕奇（Apache）基金会的一套开源的消息中间件，它支持Java消息服务、集群、Spring Framework等。Apache ActiveMQ存在安全漏洞，该漏洞源于程序未对 Jolokia JMX REST API 和 Message REST API 添加身份校验，导致攻击者可能在未经身份验证的情况下使用Jolokia JMX REST API与代理交互，或使用Message REST API向消息队列和主题中发送消息、接收消息、删除消息队列和主题等。  
  
**二、危害影响**  
  
Apache ActiveMQ 6.0.0-6.1.1版本均受此漏洞影响。  
  
**三、修复建议**  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方参考链接：  
  
https://github.com/apache/activemq/tags  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gxj5St2T0y0cRIcf8qX64K0qtB5MDyxZWru4r60jXAI37mK5Jiay0d5bVibkuicsgF3OAyBl3V8eiabj6NPSicl36pA/640?wx_fmt=jpeg "")  
[【安全圈】非法收集个人信息超26万条！这样的行为真“刑”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059393&idx=1&sn=66a25a933439719f3dbbc5785ebdbb00&chksm=f36e1b41c419925736e61add3b86037622dc31a713e055eeca1dd72ba07b8a003ccf8939d1d2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhfL9zA7iaxOXqFYT3uNWfjx3IfetkylmrkEy2JTknibiaGYzrlL6LBqHyLtbxhPDbCBpoiao5lN2tj6w/640?wx_fmt=jpeg "")  
[【](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059337&idx=2&sn=53e48250f5af3dc07b506c82b5f8b6ca&chksm=f36e1a89c419939fd2ac016458fc56936471ddf1f1bed7628daafd451622f85201c05ac30ee2&scene=21#wechat_redirect)  
[【安全圈】微软披露严重安全漏洞，受影响App安装量超40亿](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059393&idx=2&sn=3248937a939063fb6ee6d17c4068af0f&chksm=f36e1b41c4199257facc9ca787f15d28f3d44b1927bbf0f473e0d8ff294ed54208f760740649&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2rD1anDdJmnpC30hYLiajhKo3N9lT9qaGmsAnSePoBVWXR6cXhMNq7uA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】开源编程语言 R 曝光存在 8.8 分代码执行漏洞 CVE-2024-27322，可引发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059393&idx=3&sn=5643ee0278b70287a5d11765458f2825&chksm=f36e1b41c4199257c57851b2eaeb948156b1bb5df1322b88bf00c784cb3bfad54547c2b62c74&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhfL9zA7iaxOXqFYT3uNWfjxbtslcBwbibS7TLKxW96xhmGRqBNgv633eYvreezBsByDxb8ksHmGH1Q/640?wx_fmt=jpeg "")  
[【安全圈】Tinyproxy 曝出严重漏洞，影响全球52000 台主机](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059393&idx=4&sn=f6952adeaf1b5050f2c2afdfd8ab153c&chksm=f36e1b41c4199257950ca001f004d8d72295bd573123ad2f16169e1d2d13d8e418f5418d00db&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
