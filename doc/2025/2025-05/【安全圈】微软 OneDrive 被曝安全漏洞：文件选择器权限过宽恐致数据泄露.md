#  【安全圈】微软 OneDrive 被曝安全漏洞：文件选择器权限过宽恐致数据泄露   
 安全圈   2025-05-30 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
网络安全团队 Oasis Research Team 于 5 月 28 日发布博文，报告称微软 OneDrive 文件选择器（File Picker）存在严重安全漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz/aBHpjnrGyliaibE8QWRb72Bq9qA2RvXhSV2W9TN33RbWkHfNLuBjnPnvW2actiataHBxBx3kicB8RSwegM9JVVfTzw/640?wx_fmt=other&from=appmsg "微软 OneDrive 被曝安全漏洞：文件选择器权限过宽恐致数据泄露")  
  
IT之家援引博文介绍，该团队表示这个漏洞的根源，**在于文件选择器请求的权限过于宽泛，缺乏精细化的 OAuth 权限范围控制**  
。即便用户仅上传单个文件，文件选择器，也会要求对整个云存储驱动器的读取权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz/aBHpjnrGyliaibE8QWRb72Bq9qA2RvXhSVnRQYziahmlBJJAJTBNtwWHwC3xMA2BdpfW5UmchkLjoCRL9Yv4e4yAQ/640?wx_fmt=other&from=appmsg "微软 OneDrive 被曝安全漏洞：文件选择器权限过宽恐致数据泄露")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz/aBHpjnrGyliaibE8QWRb72Bq9qA2RvXhSVoA0cwUeMkvKU57iaMuDq6icD24LjO6NABcHic0G3s9njrCL44GDAQgYPg/640?wx_fmt=other&from=appmsg "微软 OneDrive 被曝安全漏洞：文件选择器权限过宽恐致数据泄露")  
  
这样的设计让用户难以分辨哪些应用是恶意索取全部文件访问权限，哪些应用只是因为缺乏安全选项而被迫请求过多权限。更糟糕的是，用户在上传文件前的授权提示模糊不清，未能明确告知实际授权范围，增加了安全风险。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz/aBHpjnrGyliaibE8QWRb72Bq9qA2RvXhSVVhuFcW6jkvB1QSoicuoIricPsxj4rKFO3Tt1za37vtjxQODrFbzyUtQg/640?wx_fmt=other&from=appmsg "微软 OneDrive 被曝安全漏洞：文件选择器权限过宽恐致数据泄露")  
  
Oasis 团队警告，授权过程中使用的 OAuth 令牌常以明文形式存储在浏览器的会话存储中，极易被攻击者窃取。此外，部分授权流程还会发放 refresh tokens，允许应用在当前 tokens 过期后无需用户再次登录即可获取新 tokens，从而持续访问用户数据。  
  
这种机制进一步放大风险，可能导致个人及企业用户的数据长期暴露。目前，微软已收到漏洞报告并确认问题，但尚未推出修复措施。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】微软OneDrive文件选择器漏洞曝光：网站可窃取用户全部云存储数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069879&idx=1&sn=2b0d058ac337d26093a5ae849717e3dd&scene=21#wechat_redirect)  
  
  
  
[【安全圈】僵尸网络入侵 9,000 多台华硕路由器，添加持续 SSH 后门](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069879&idx=2&sn=abf9e6d63b21d2585d9f6b3c0cb32256&scene=21#wechat_redirect)  
  
  
  
[【安全圈】PumaBot恶意软件瞄准Linux物联网设备](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069879&idx=3&sn=b0a9e08b3f0746f8950bd9293c8b600b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】WordPress TI WooCommerce Wishlist 插件漏洞使 100,000+ 网站遭受网络攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069879&idx=4&sn=457158cecc79f277656b8bad13f79e3f&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
