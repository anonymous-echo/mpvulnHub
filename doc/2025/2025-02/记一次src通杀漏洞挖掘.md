#  记一次src通杀漏洞挖掘   
原创 zkaq - 98k  掌控安全EDU   2025-02-18 04:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  98k 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 0x1 前言  
  
这是我第一次写漏洞分享的文章，主要是最近跟着几个厉害的师傅一起学习，挖了几个比较简单的漏洞，今天拿出来给大家分享下。这里我是有目的地去对某机构或者某学校进行渗透测试漏洞挖掘的，之前在网上看到很多文章说可以直接去edusrc官网的漏洞排行榜上去找，可以去看一些开发商排行榜以及某些高校大学的排行榜，里面有很多的该公司或者该学校的漏洞提交情况以及修补情况。  
## 0x2 信息收集/资产测绘  
  
就比如说可以去找一些修复率不是很高的开发商去挖，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPoUibo5Tomp6hJic16bqmkibQMrQU2tib2SJpMfKW09BaJJcls5icsQCdJIA/640?wx_fmt=png&from=appmsg "")  
  
然后多去找找该开发商的一些资产，特别是哪些学校使用了该系统的资产，可以使用空间引擎，FOFA、鹰图等，还可以使用一些企业查询的网站，比如企查查、爱企查等免费的在线查询网站。  
  
比如下面的使用空间引擎FOFA进行检索相关企业的系统信息，然后去找相关漏洞，比如常打的nday  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPMm7wMmHticgvR1JC5UZHDuEO6h7egj2FBS9euFFOXicBJaG8N6GCelyw/640?wx_fmt=png&from=appmsg "")  
  
下面就是使用爱企查进行的查询，里面一看就是学校使用的一些系统，然后再挨个进行信息收集，多使用网上的资源，搞不好就打了个通杀呢  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPzibOeEA5pQib007WVXXA89LciamRqY1sBA8rafA3Men59BDlXKHWaACicw/640?wx_fmt=png&from=appmsg "")  
## 0x3 渗透测试/漏洞挖掘  
  
下面这几个edusrc漏洞都已经成功提交，且都已经通过了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPDIxl1icTHMXrHh12rc74ZL7vYCKEBHniaJHZDeOHV20sMxy2qic6LFAlQ/640?wx_fmt=png&from=appmsg "")  
  
我开始是先通过弱口令登录进去的，然后不甘于只提交一个弱口令，就想着在里面多测下，提高危害，多那几个rank值。下面我就拿一个案例来复现，然后给师傅们分享下思路吧，这也算是一个中危漏洞的通杀了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPCNGysmul4M8bOzEYyQrA8MOpWGbnV5l9f1WM5HWMWR9NhR6ib3fCJYQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到先通过弱口令进去的，泄露了好几千条学生、老师的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPHoI87B6zQjcnM1ArV1SicwicZlVlicGRibO2RCA5wibyjT9PJicFWW6654xA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPicJRAnEJmH6oRnK0XTbXJjYuL5r5a3dNic9MXopjST42vV9esX085LMQ/640?wx_fmt=png&from=appmsg "")  
  
这里这个漏洞就是**session会话固定不过期**这是我们开始利用admin:admin888登录成功的cookie值，下面我们修改下密码，然后再登录看看cookie有没有改变  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPiaicoEHbekrH3P9QK06vJHfr7Hnk1k8ADZwrE7DFibtk5SGM9YWfOHwhA/640?wx_fmt=png&from=appmsg "")  
  
修改密码为admin666，但是可以通过对比下发现cookie值并没有发生改变，admin管理员cookie如下：  
```
Cookie: thinkphp_show_page_trace=0|0; PHPSESSID=8f00d7c83c621327b25224babf288713; admin_username=admin
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPwfug1gAemMpzAc8aJPB7FqNA9FSvHzQNRb2GwtDiaXk6KyLEnodYpFg/640?wx_fmt=png&from=appmsg "")  
  
那session会话固定不过期的话，那么我们就可以把里面某个功能点的数据包保存，就算是学校把该密码改了，我们还是可以进行数据修改，或者保留密码修改的数据包，因为cookie值是一直不变的。  
  
就比如下面的这个，我是改密码前（admin888）的时候保存的数据包，现在照样可以使用，因为这个cookie值一直不变。  
  
然后我们还可以使用这个数据包进行创建用户，而且还创建成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPYHKxgVegSfg2l2h57u6M9X7cicGXyqm1AibibJFz4lMDDdGdKcEMLG3yQ/640?wx_fmt=png&from=appmsg "")  
  
下面修改admin管理员账号密码的数据包也可以一直使用，  
  
哪怕是以后修改了密码，禁用了弱口令，只要cookie值不变，我们还是可以进行利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqg6KZiaCV1N2Fp62mVh8kZPRZokHqSycp7liatMblhHXn4oa265ryQuCRvf4KKI9dCgceHjic6Ss5mw/640?wx_fmt=png&from=appmsg "")  
## 0x4 总结  
  
上面的漏洞思路也不算太难，主要是开始通过弱口令进去的后台，然后再通过后台里面的功能点去测试，多使用bp抓包，多看数据包，很多时候数据包里面可以发现很多意想不到的东西。  
  
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[记某地级市护网的攻防演练行动](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247543747&idx=1&sn=c7745ecb8b33401ae317c295bed41cc8&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&scene=21#wechat_redirect)  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
```
```  
  
  
