> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550983&idx=1&sn=ad9b1e11354dac3d5d34a5516f979560

#  记一次某学校AKSK泄露拿下中危漏洞  
原创 zkaq-eden  掌控安全EDU   2025-07-15 04:02  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  eden 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
# 前言  
  
这个资产是偶然在漏洞报告平台上看到得一所教育局直属院校，所以就以 Web+微信小程序+微信公众号去进行资产收集，扩大资产暴露面，以便进行渗透测试。在官方公众号当中的电费充值网站，通过渗透测试，发现存在 AKSK 敏感信息泄露。  
# 信息收集  
  
1、找到目标资产  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpv93EljMWWiaazQjvl6EK2a9ydAic4uCT0bULQCPXX7zcZGzpFGuhvazJDaWZISLNTZhSwI0kSiabDA/640?wx_fmt=png&from=appmsg "")  
  
  
这里我们需要进行测试得功能网站是“电费充值”  
  
下面这是电费充值得登录栏  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpv93EljMWWiaazQjvl6EK2at9RVnhbdDmAp2zUtuVUx5UJXgjAIUODy90sjPtSY2BrPhfiaboiaCkSg/640?wx_fmt=png&from=appmsg "")  
  
# 测试  
  
2、通过 BurpSuite 抓包进行观察网站得所有流量，在众多流量当中存在一个 config 得文件流量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpv93EljMWWiaazQjvl6EK2aqSgqpA1S25qqBq1qTpzXz09p3zflCzs1JKZqvzECze9TwjjcAZ2OUg/640?wx_fmt=png&from=appmsg "")  
  
  
在流量当中得一个/static/config.js 当中存在一个 corpid 和 appkey 以及 appsecret，这里就是 AKSK 泄露得地方，泄露得是钉钉的 AKSK  
  
钉钉的 AKSK 的特征是前四个字符是 “ding”  
  
3、通过使用工具获取到钉钉得 token 这样就可以进行接管钉钉的管理员账户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpv93EljMWWiaazQjvl6EK2aibef0155qUd7Z5B9LVFicVfeKy0alqFO47l29vJvjaFibDib3ibpcHXuOYg/640?wx_fmt=png&from=appmsg "")  
  
  
进行接管账户的时候会因为 X-Forwarded-For 未知而造成接管不成功，这里只需要填写
```
*.*.*.*
```

  
即可接管账户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpv93EljMWWiaazQjvl6EK2aR4vrWSYsMY8FHgzkc8XNVyDFzlBX9sWeergV3LWEnzR9VosKVLVxUQ/640?wx_fmt=png&from=appmsg "")  
  
# 总结  
  
这次渗透主要考察的是渗透时的细心，要观察每一个流量包，看看流量包当中是否存在敏感信息泄露（如：默认账号密码、AKSK 泄露等信息），在做资产收集时不要只局限于 Web 或者微信小程序端，有时在官方微信公众号也会有意想不到的收获  
  
本次漏洞已提交至相关平台进行修复，切勿再进行任何的渗透测试，后续任何违法行为与本人无关，本文章只作为学习思路进行学习，仅供参考！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpv93EljMWWiaazQjvl6EK2aPbPE9QaNMeQjOJ2kJ1EJDQUufA7rxqW1TnSuxaia5XMlh1MlkqqOGnA/640?wx_fmt=png&from=appmsg "")  
  
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
  
