#  记信息泄露到RCE   
原创 zkaq - 杳若  掌控安全EDU   2024-03-02 12:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
本文由掌控安全学院 -杳若 投稿  
## 打点  
  
开局一个登录框  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrJGwYjNvCUVX779oIeYDsck9v0spFzQOHmcKtqWq1mcicrdXuGgE4ngNOzibAN8vJibt5nb9Ciangedw/640?wx_fmt=png&from=appmsg "")  
## 信息收集  
  
发现了一处接口泄露了部分信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrJGwYjNvCUVX779oIeYDscNuTENA4ibsG2z9cTfjfWzNAT3oXk0veTiaFYFcfe78HnC3zV9koVk6dA/640?wx_fmt=png&from=appmsg "")  
  
不过只有支付宝密钥的信息无法扩大危害，此时尝试寻找了一下其他同类型系统同样的接口，查看一下是否泄露的信息相同  
```
因为如果相同就说明是静态的，没有价值
```  
## 横向收集  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrJGwYjNvCUVX779oIeYDscaziaqiaOGxwS4SEm5s3M2Fbtwg6YglHeWXiamxELib7iaEmpJT6NQs2zvcQ/640?wx_fmt=png&from=appmsg "")  
  
此时访问其他系统，发现里面有不一样的东西，包含了数据库的账号以及密码  
```
说明不是静态的
```  
## 利用尝试  
  
此时回到之前的系统，扫了一下端口，发现确实开放了数据库端口  
  
利用工具Sylas https://github.com/Ryze-T/Sylas/releases/tag/beta  
  
直接RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrJGwYjNvCUVX779oIeYDschoknLNcVcNCVguMKPyKQIl9heM5o8JXzpR4vrQMJFCFbfzacfDYdnw/640?wx_fmt=png&from=appmsg "")  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**没看够~？欢迎关注！**  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+靶场账号**哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
******分享后扫码加我！**  
  
  
  
**回顾往期内容**  
  
  
[Xray挂机刷漏洞](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247504665&idx=1&sn=eb88ca9711e95ee8851eb47959ff8a61&chksm=fa6baa68cd1c237e755037f35c6f74b3c09c92fd2373d9c07f98697ea723797b73009e872014&scene=21#wechat_redirect)  
  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[代码审计 | 这个CNVD证书拿的有点轻松](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247503150&idx=1&sn=189d061e1f7c14812e491b6b7c49b202&chksm=fa6bb45fcd1c3d490cdfa59326801ecb383b1bf9586f51305ad5add9dec163e78af58a9874d2&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
  
  
