#  【安全圈】开源字体渲染库 FreeType 出现高危漏洞，可被黑客利用发起攻击   
 安全圈   2025-03-15 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
3 月 14 日消息，Facebook 旗下的安全研究实验室日前透露，  
FreeType 在 2.13.0 以前的版本中存在安全漏洞  
，该漏洞代号为 CVE-2025-27363，漏洞评分为 8.1/10 分，评级为高风险。  
  
注：FreeType 是一款开源的字体渲染库，该渲染库可以将字符栅格化并映射成位图。Android、macOS 等操作系统及各种游戏引擎都有应用该字体渲染库。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljzC1zvXWt8qKKAhn8FEJVmlE2Xt0qY9TcWoasIibq0VIQOicY2OicvBZvuIic7IjP0QFvp6m0Zq60MMg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞的详情如下：  
  
  
FreeType 2.13.0 及以下版本在解析 TrueType GX 和可变字体文件的字体子字形结构时存在越界写入漏洞。问题代码将有符号短整型数值赋给无符号长整型变量，随后叠加静态值导致数值回绕，进而分配过小的堆缓冲区。该漏洞允许在缓冲区外写入多达 6 个有符号长整型数值，可能引发任意代码执行。  
  
  
虽然该漏洞已于 2023 年 2 月 9 日在 FreeType 2.13.0 中被修复，但鉴于目前仍有很多用户在使用旧版本的操作系统或软件，同时可能有黑客已经在利用该漏洞展开攻击，Facebook 建议所有用户将他们的系统或将 FreeType 单独更新到最新版本以避免可能的安全风险。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】利用 OAuth 重定向进行帐户接管的 Microsoft365 主题攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068486&idx=1&sn=28409a82f26e66dae1a415d3ecd571f8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Tenda AC7 路由器漏洞使攻击者能够通过恶意负载获取 Root Shell](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068486&idx=2&sn=a1a3a144476d291506c6e2ada3ac4e29&scene=21#wechat_redirect)  
  
  
  
[【安全圈】GitLab 警告多个漏洞可让攻击者以有效用户身份登录](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068486&idx=3&sn=49a253062081aae290f02f07ac4704a2&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】SuperBlack 攻击者利用两个 Fortinet 漏洞部署勒索软件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068486&idx=4&sn=0c958e3ed4260fbf4a7e0e8de17dafc3&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
