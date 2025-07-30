#  【安全圈】苹果 Safari 全屏模式曝中间人攻击漏洞   
 安全圈   2025-05-30 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
**安全研究人员披露苹果Safari浏览器存在设计缺陷，攻击者可利用全屏模式实施“浏览器中间人攻击”（BitM）窃取用户凭证**  
。该漏洞源于网页通过Fullscreen API进入全屏模式时，Safari缺乏明确警示机制，使恶意窗口得以隐藏地址栏并伪装成合法登录页面。  
  
网络安全公司SquareX指出，攻击者通过滥用全屏API实现三重欺骗：  
1. 利用noVNC等开源工具在受害者会话层叠加远程控制浏览器  
  
1. 通过赞助广告/社交媒体推送伪造目标服务登录页链接  
  
1. 当用户点击登录按钮时激活隐藏的BitM窗口  
  
典型案例显示，攻击者伪造Steam和Figma登录页诱导用户输入凭证。由于登录过程实际发生在攻击者控制的浏览器中，受害者仍能正常登录账户，难以察觉信息泄露。值得注意的是，此类攻击能规避端点检测（EDR）及安全访问服务边缘（SASE/SSE）等防护方案。  
  
浏览器防护机制对比显示：  
- Firefox/Chrome/Edge进入全屏时强制弹出警示框  
  
- Safari仅显示易被忽略的滑动动画  
  
SquareX研究人员强调：**“尽管所有浏览器均受影响，但Safari因缺乏视觉警示使攻击更具欺骗性。”**  
  
苹果公司收到漏洞报告后回应称“无意修复”，认为现有动画提示已足够。目前安全社区正推动苹果重新评估该决定。  
  
  
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
  
  
