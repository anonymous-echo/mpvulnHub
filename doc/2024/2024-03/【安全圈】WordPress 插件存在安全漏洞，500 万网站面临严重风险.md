#  【安全圈】WordPress 插件存在安全漏洞，500 万网站面临严重风险   
 安全圈   2024-02-29 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
WordPress 的 LiteSpeed Cache 插件中披露了一个安全漏洞，未经身份验证的用户可能会利用该漏洞升级其权限。  
  
该漏洞被跟踪为 CVE-2023-40000，已于 2023 年 10 月在版本 5.7.0.1 中得到解决。  
  
“这个插件存在未经身份验证的站点范围存储的[跨站点脚本]漏洞，并且可能允许任何未经身份验证的用户通过执行单个HTTP请求来窃取敏感信息，在这种情况下，通过执行单个HTTP请求来提升WordPress站点的权限，”Patchstack研究员Rafie Muhammad说。  
  
用于提高站点性能的 LiteSpeed Cache 安装量超过 500 万次。该插件的最新版本是 6.1，发布于 2024 年 2 月 5 日。  
  
WordPress 安全公司表示，CVE-2023-40000 是缺乏用户输入清理和  
转义输出  
的结果。该漏洞根植于名为 update_cdn_status（） 的函数，可在默认安装中重现。  
  
  
“由于XSS有效载荷是作为管理员通知放置的，并且管理员通知可以显示在任何wp-admin端点上，因此任何有权访问wp-admin区域的用户也很容易触发此漏洞，”穆罕默德说。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhBpS95kZxq2jzRT5McklMKgiazZficZhKKLBbia4USQtQzZhyKs14lUm1XAiawRhU7kl6ZKON4zS2nAQ/640?wx_fmt=other&from=appmsg "")  
  
四个月前，Wordfence 在同一插件中发现了另一个 XSS 缺陷（CVE-2023-4372，CVSS 分数：6.4），原因是用户提供的属性的输入清理和输出转义不足。该问题已在版本 5.7 中得到解决。  
  
István Márton说：“这使得具有贡献者级别及以上权限的经过身份验证的攻击者可以在页面中注入任意Web脚本，这些脚本将在用户访问注入的页面时执行。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhBpS95kZxq2jzRT5McklMKksjuc1GJE3IRbgeG8a6WK4N2VvqvFk98BTdr2MSPaySYI9UqpLzNMg/640?wx_fmt=jpeg "")  
[【安全圈】黑客销售盗版软件以此获利，被判两年十个月，罚3万元！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054796&idx=1&sn=a44d3fa5dd5060a1b340546fc42ee103&chksm=f36e094cc419805a4f59b5ab814c74f2e3e8836b99ab9b3e376b0720191e6afcf6a5398bad9c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhBpS95kZxq2jzRT5McklMKSmpN5G7MqQhFERXAmHCcgQNDaDOibDLToibNibtRUicsQ2DwgQjyxaFylQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】20多万条网约车司机信息被售卖，一人被抓](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054796&idx=2&sn=fa979d9bc0184c351103770b70ef3d80&chksm=f36e094cc419805aad3346380f39429ffd9330be8061ae26afa9e1f5b0ec6a8f9a247d54c60b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhBpS95kZxq2jzRT5McklMKiaibzPtafzTSu5OJ1HDJ4ZqJ9GUxgyVmBRibiawQqXeJdkIYutCeFfNCTw/640?wx_fmt=jpeg "")  
[【安全圈】8800个域名被滥用，以使数百万封电子邮件通过垃圾邮件过滤器](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054796&idx=3&sn=3ef0246279e7beae6ab6e0694328bdb9&chksm=f36e094cc419805a10211c108a8d9c31817f27f579c99a197e5c52d6a12e888d7d117a1c4dc1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhBpS95kZxq2jzRT5McklMKVwKdibkvA5eribhas0F2BnfbdziaWgXdXHODSKQV7MymglJp481WkJFCw/640?wx_fmt=jpeg "")  
[【安全圈】美国一租赁网络遭到黑客攻击，6.7 万客户数据遭泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054796&idx=4&sn=30a605d32b0ae8a5d349cb1a86f71732&chksm=f36e094cc419805a24fc978598cf1e35d95038f4b9f6bef589f5294053be18388f28ed3cc2d2&scene=21#wechat_redirect)  
  
  
  
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
  
  
