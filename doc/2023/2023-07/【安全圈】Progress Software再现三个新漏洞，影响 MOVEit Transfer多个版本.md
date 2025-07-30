#  【安全圈】Progress Software再现三个新漏洞，影响 MOVEit Transfer多个版本   
 安全圈   2023-07-10 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
  
今年6月，文件共享工具MOVEit Transfer曾曝出SQL 注入漏洞，能让远程攻击者访问其数据库并执行任意代码。最近，MOVEit Transfer 母公司Progress Software又披露了三个新漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia5BIlzOfqGmrDZo84b1R0LFL7ZJOZWiaokOkPUNy8CtjWH7I1WiaicVz668AfIXpm91Vq30s8uoFlEg/640?wx_fmt=jpeg "")  
  
这三个漏洞分别是 CVE-2023-36932、CVE-2023-36933 和 CVE-2023-36934，其中CVE-2023-36932和 CVE-2023-36934都和SQL 注入漏洞漏洞有关。  
  
SQL 注入漏洞能让攻击者利用它操纵数据库并运行他们想要的任何代码。攻击者可以将专门设计的有效负载发送到受影响应用程序的某些端点，从而更改或暴露数据库中的敏感数据。  
  
这其中最为严重的漏洞为CVE-2023-36934，能够无需登录即被利用，意味着即使没有有效凭证的攻击者也有可能利用该漏洞，但到目前为止，还没有关于攻击者积极利用此漏洞的报告。  
  
而CVE-2023-36932能让登录的攻击者利用该漏洞来获得对 MOVEit Transfer 数据库的未经授权的访问；CVE-2023-36933 则是一个允许攻击者意外关闭 MOVEit Transfer 程序的漏洞。  
  
MOVEit于今年6月披露的漏洞显示它们已经被Clop 勒索软件组织利用，数千家使用该服务的企业组织受到影响。一直在跟踪局势的 Emsisoft 威胁分析师布雷特·卡洛 (Brett Callow) 表示，至少有 20 所美国学校和超过 1750 万人的信息受到影响。  
  
其他企业，石油巨头壳牌曾在6月15日证实自己受到了MOVEit漏洞的影响，英国广播公司BBC 和英国航空公司 (BA) 、南非零售巨头Clicks等企业也表示自己是受害者。  
  
此次新批露的漏洞影响多个 MOVEit Transfer 版本，但目前均已被MOVEit Transfer修复。Progress Software 已为所有主要 MOVEit Transfer 版本提供了必要的更新，强烈建议用户更新到 MOVEit Transfer 的最新版本，以降低这些漏洞带来的风险。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylia5BIlzOfqGmrDZo84b1R0LeVNuwponsWprkHy4tzLfibVz9Rv6DEsr0zE64wMM6mnW2lJunmibUKZQ/640?wx_fmt=png "")  
[【安全圈】境外黑客组织对我金融等领域实施网络攻击窃密，已侦办多案](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039014&idx=1&sn=18e675c1f1cd118e2893aac997f6a14d&chksm=f36fcb26c4184230ad1cb6d38963dc48b8ac122278db512a02ab62b2c7cbf18eb4e4fb2f32f2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylia5BIlzOfqGmrDZo84b1R0LJJVENLVOA3zibal3oGbuHFSicFZrkAJ1WibFpfkTGfEJ5NTjRfVeic83wA/640?wx_fmt=png "")  
[【安全圈】LockBit勒索软件索7000万美元赎金，台积电指责供应商](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039014&idx=2&sn=237ea1f9aa8d85caf0a9f165e07f3d54&chksm=f36fcb26c418423010ca30352581ad4cb4d1a3700fff26fb4b206cecdb94c454be25b45033f7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia5BIlzOfqGmrDZo84b1R0Le8FokcQe9ibUPE2miccv32gDpWZJsg9eqmLPh6x73EoibhGder6jGTKdg/640?wx_fmt=jpeg "")  
[【安全圈】黑客“蜂窝”勒索1.3亿不成反被FBI捣毁](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039014&idx=3&sn=f8237ebca0c910e1081a03726d94c2f2&chksm=f36fcb26c41842300abb2c14aabe2d91f0ad1a41739fb55c9c83fe9bd6b4bc971610b6a16573&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylia5BIlzOfqGmrDZo84b1R0LwIO9vpdRVlfhVsia7vG0VQicI6nW9OXKuJaPE6qzBQU3Ss3UuedOoPibg/640?wx_fmt=png "")  
[【安全圈】Windows Phone Link成为窃取iPhone数据的新工具](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039014&idx=4&sn=718c57bb8d81c8e733270db733c0275c&chksm=f36fcb26c4184230b4381ef9dd4a447d6be7eda52d656f37e1bcce551390267fbf8fc6d31ec4&scene=21#wechat_redirect)  
  
  
  
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
  
  
