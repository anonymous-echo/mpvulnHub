> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247551050&idx=1&sn=4c6ccc148d8bf2a0e85c334d1c3519a7

#  记一次某edu证书站奇葩sql注入（逻辑缺陷导致未授权访问看到sql报错界面）  
原创 zkaq-zzzrrr  掌控安全EDU   2025-07-21 04:00  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  zzzrrr 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
### 前言：  
  
废物毕业生因面试问有没有证书而发奋去挖证书站，结果运气好到爆五分钟出 sql，听我细细讲解那些年前辈们错过的洞  
  
挑一个新出的证书站正常搜集信息后开测，网页  
www.aaa.edu.cn/bbb打开跳转登录[www.aaa.edu.cn/bbb/login](http://www.aaa.com/bbb/login),正常登录口随即测弱口令和  
 sql 注入，可我不管怎样输入都是显示学号不存在。之后就是经典步骤看源代码，findsomething 以及 wappalyzer,依然是什么都没有，说实话此时已经有点烦了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBW5XOzBWbQ4tUN8ic172icmEfiaeCm6BNzqKst0zpplfGsNPeCyJ8WsCjw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBkGwHgibIJH0PEthxmQicP8ItOtdibq5zjutKYyOLWDQgkkXiaQKKgPINEw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxB3DL1JMW52PABoRbQpElibolicun2778yiaic5nTa5gQZ8gYEQLNwXzFI4Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
### 转机：  
  
想着先去搜集学号，回来再测，但是估计也是很难出（此处坏习惯不要学），随后想起刚刚打开是跳转登录界面就返回了上一级目录，发现此时没有跳转而且好像出现了未授权，出现了很多试卷，但是没什么敏感信息，不过此时已经茅塞顿开了。于是立即返回测sql，如是复现上述操作，最后返回上级目录看到注出数据库用户名。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBVL5EUlSxkvgoYOdsFXgzlCYwK3mgYOftSBKho2QQicW5aRWzt7vqicNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBM8bBWXruYUGc0m8b6Etmb1Fm62NnYb1OpKGhPZQzsKibMStNBUnIaVQ/640?wx_fmt=png&from=appmsg "")  
  
  
随后使用万能命令闭合语句后同样方法进入后台，此时卡了很久，不过内心狂喜，因为此时卡得越久证明进去后可以看到的信息更多，进去后果然出现了大量信息，不过都是些试卷，没什么敏感信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBjUm7YMmCauVU74eXgyR3IgWAVwNjfJq3GS1icfmibFdBcXToCETFBntA/640?wx_fmt=png&from=appmsg "")  
  
### 复盘：  
  
漏洞是发现了，可是为什么会出现这种情况呢？我们学习漏洞不仅仅要学习漏洞发现，更要明白其中的道理，增加经验，于是我去看返回上级目录时发送的数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBhsThWHL2d88k9IkaRyzlXwFUWNqeKf4lUwt27FKPZDZZgG9SMauNkg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到访问上级目录时候，即  
www.aaa.edu.cn/bbb  
 ，会发送一个post包，而这个post包会携带先前登录口输入的信息，这里携带的是报错注入mssql版本信息的payload，加载完后也是成功触发显示出该数据库的版本等信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBibfLhmSgDUia4icJgtncBAhILWrV8iaJaPFKhib6HrcXyHSItpAL3dRmicYQ/640?wx_fmt=png&from=appmsg "")  
  
分析上述 post 包的请求与回显信息，猜测先前登录界面是有处理的，若未登陆成功或出现异常报错则统一显示用户不存在，同时报错页面也被拦截，而后因为浏览器有缓存存在导致再次访问上级目录的时候没有跳转最初登录口，而是直接对先前输入数据发包到后面的查询接口，并且此处没有做任何处理成功带入数据库查询，从而使得报错信息未被处理回显，成功注入。整体流程图如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBU0ic07JEYRQ4sJoP1RsicwtW1G4aqicnLIGqBbJvnX4aMgHvsO1LX23qw/640?wx_fmt=png&from=appmsg "null")  
  
  
本次漏洞已提交至相关平台进行修复，切勿再进行任何的渗透测试，后续任何违法行为与本人无关，本文章只作为思路分享，仅供参考！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqBq6TWZolJ2etQrp9PtoxBmkxFbD2tGZ2BT8ZcibnvfJSVofOibjPj4WfGJcyrM3CPzpxaWEMwzbhg/640?wx_fmt=png&from=appmsg "")  
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**  
哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
**回顾往期内容**  
  
[我与红队：一场网络安全实战的较量与成长](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550558&idx=1&sn=589aa46a61b9ab02ab953ccb9539b1d3&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
  
  
