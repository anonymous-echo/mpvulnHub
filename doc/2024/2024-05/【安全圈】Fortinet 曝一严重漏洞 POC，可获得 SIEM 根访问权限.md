#  【安全圈】Fortinet 曝一严重漏洞 POC，可获得 SIEM 根访问权限   
 安全圈   2024-05-30 19:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
Fortinet FortiSIEM 产品的一个关键漏洞出现了一个可行的攻击（PoC），这为更广泛的攻击提供了更多机会。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaUISDxYRPp7NjXKKuF2Viahd6e4HgNibs43806YbGh05g96DC8LPKnOft5ic3z53mTZULWibPzUN3wKw/640?wx_fmt=jpeg&from=appmsg "")  
  
该漏洞被追踪为 CVE-2024-23108，于今年 2 月披露并修复，同时修复的还有与其相关的另一个漏洞 CVE-2024-23109。这两个漏洞在 CVSS 评分系统中的最高严重性评分均为 10 分，都是未经身份验证的命令注入漏洞，攻击者可能利用伪造的 API 请求实现远程代码执行（RCE）。  
  
据 Horizon3AI 的研究人员称，该漏洞被他们称为“NodeZero”，允许用户“以 root 身份在受影响的 FortiSIEM 设备上盲目执行命令”。在 PoC 中，他们使用该漏洞加载了一个用于后继活动的远程访问工具。  
  
FortiSIEM 是 Fortinet 的安全信息和事件管理（SIEM）平台，用于支持企业网络安全运营中心。因此，如果该平台被攻破，攻击者可以以此为跳板进一步入侵企业环境。  
  
受漏洞影响的 FortiSIEM 版本包括 7.1.0 至 7.1.1、7.0.0 至 7.0.2、6.7.0 至 6.7.8、6.6.0 至 6.6.3、6.5.0 至6.5.2 以及 6.4.0 至 6.4.2，用户应立即打上补丁，以避免受到威胁。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaUISDxYRPp7NjXKKuF2ViahsZ984L26GUgl40MPIOeicZz5pnVqbNCia09FeYPDo5gdzCGJCt0icIbibw/640?wx_fmt=jpeg "")  
[【安全圈】非法销售VPN软件获利约10万，贵阳一人被警方行政拘留](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060737&idx=1&sn=a066276db6dd166d01c06413e8c51fb8&chksm=f36e1001c419991724a61c471751a3500240a40d72c40f4c4667e2bb280cf0baeabc569d9481&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaUISDxYRPp7NjXKKuF2ViahFGiazVOPd8lTo7pLeGiaCIKPDsDToguU6MIM3oaNd4du0F3PKSOXldBg/640?wx_fmt=jpeg "")  
[【安全圈】影响之前所有版本，TP-Link 路由器曝出满分漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060737&idx=2&sn=46fe85b6166c5bda4eb62e527782404a&chksm=f36e1001c4199917cc4c748b367f18c329e03ce872fbdc08ff00374b22cff612125f24aa5aab&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKZxaBPjry6AKh6bXqyhjz7iafLib305V9zaoFgfIzOUZ9lb9pRQKpnh6A/640?wx_fmt=png "")  
[【安全圈】AI 平台 Replicate 曝“跨租户攻击”安全隔离漏洞，用户自训练人工智能模型可被黑客入侵](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060737&idx=3&sn=bcb1e61b20c0aaf8bf3dd485b50dacaa&chksm=f36e1001c41999171680ebbe7d3253337712e51f3aa612306326b575f389587f4745bfb321d4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaUISDxYRPp7NjXKKuF2ViahFpr6TWibhjjwGJm3H40CM25dNic5eicrNHHecRXx59nvllj1MAZMOltyQ/640?wx_fmt=jpeg "")  
[【安全圈】最大的快递公司之CDEK 遭黑客攻击，导致业务全面停摆](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060737&idx=4&sn=12b341632392ffdfba18f7fba99e89c2&chksm=f36e1001c419991745db83ae262665bfec1ab97e4df07eb87b0aa6999c6eefb932e26793608f&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
