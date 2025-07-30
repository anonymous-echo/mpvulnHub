#  【安全圈】微软审查发现Perforce Helix Core Server四个漏洞   
 安全圈   2023-12-19 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaueJ5iaMrdZd96GWXqDfsgENdlJ4l02TEDQekO8UnNlcoy2ibZjeQibEpSEe7jNsia6XGWyr7NKsjn1A/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
  
最近，Perforce Helix Core Server 披露了四个安全漏洞，其中一个被评定为“关键级别”的漏洞。  
  
  
**4个漏洞——**  
  
CVE-2023-5759（CVSS 评分 7.5）：通过滥用 RPC 标头，实现未经身份验证 （DoS）。  
  
CVE-2023-45849（CVSS 评分 9.8）：作为 LocalSystem 执行未经身份验证的远程代码。  
  
CVE-2023-35767（CVSS 评分 7.5）：通过远程命令进行未经身份验证的 DoS。  
  
CVE-2023-45319（CVSS 评分 7.5）：通过远程命令进行未经身份验证的 DoS。  
  
  
微软分析师审查旗下游戏工作室产品时，发现了这些漏洞，并于2023年8月下旬向Perforce报告了这些漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia4LyuKUyD3bQxr5LZQQjo9oqUmia5L0ZgWiatbdAaUqyfekBZpWESuqqhCjXTFsTKDicryIjaAR1Hqw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软指出，尽管目前没有迹象显示这些漏洞已被黑客利用来发起攻击，但仍建议使用该产品的用户更新至2023年11月7日发布的2023.1/2513900版本，以减少潜在风险。在微软最近发现的这四个漏洞中，主要问题是拒绝服务（DoS）攻击，其中最严重的一个漏洞允许攻击者在没有进行身份验证的情况下，以LocalSystem的身份远程执行任意代码。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia4LyuKUyD3bQxr5LZQQjo97klrovNqHYRngrJUFYFdhJsR2duicxvhnZupWNngYgB2QEvBeWROaTA/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】5名男子搭建国际版虚假购物网站实施诈骗被提起公诉](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050816&idx=1&sn=2c921466c0b0e946d24c2f25797b88e8&chksm=f36e39c0c419b0d6f5d66068b686f9f3e00c2d2ab8b7ffd406df7f63e97d512ee3cc0c25105d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia4LyuKUyD3bQxr5LZQQjo9XicISBDkQ4cuCrp3RVTFzrsSTvEJT7dRbfx9D2DB9ZQ2s5gRN3assyQ/640?wx_fmt=jpeg "")  
[【安全圈】苹果iOS17.2更新，明显遏制 Flipper Zero攻击iPhone效果](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050816&idx=2&sn=055dfcf9dc79b11b3dca1764db6b998f&chksm=f36e39c0c419b0d69074fc621993c0c299ecb1c4dafa4cd5e038af3b77b19b9e11852ffe0f46&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia4LyuKUyD3bQxr5LZQQjo9TU5mWydCYcosyHLd5EkHia3cdrqr5mhhMIsDzyKzNBOT8NNbcUniaVww/640?wx_fmt=jpeg "")  
[【安全圈】微软警告注意Storm-0539—节日礼品卡欺诈背后逐渐崛起的威胁](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050816&idx=3&sn=8af748d97d55b7a72d84a274fd9aa5d6&chksm=f36e39c0c419b0d64ddaf9928a74115b93cb3b4a8e6b65ea936a5fb2da0a675808568b2b16db&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia4LyuKUyD3bQxr5LZQQjo9CyqxBPbSr9eicPoRCQuv3Uics4MQm7QA8gibHKPIiaqbJuUd2PvhwJvrGw/640?wx_fmt=jpeg "")  
[【安全圈】WordPress 主机托管服务被谷歌钓鱼广告“盯上”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050816&idx=4&sn=e19e3ef969c98fe7e5694a8f01815f1a&chksm=f36e39c0c419b0d6f6a0c1362ece9d52de8cca48cb806019ec0525b3c75ed9d524f46cdda13c&scene=21#wechat_redirect)  
  
  
  
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
  
  
