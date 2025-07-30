#  EDUSRC | 两个证书站小程序漏洞挖掘思路及方法   
zkaq-满心欢喜  掌控安全EDU   2025-05-20 04:02  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  满心欢喜 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
# 一、信息收集思路及技巧  
  
注：这一段信息收集思路及技巧是笔者借鉴我大湘安无事的大佬--沫颜 WEB 安全的思路。具体的可以看这个链接[Edu教育src证书信息收集思路及技巧（二）](https://mp.weixin.qq.com/s?__biz=Mzk1NzY0MjY2NA==&mid=2247483963&idx=1&sn=1ed5067bfb400db8904d8899d01d444e&scene=21#wechat_redirect)  
  
  
每个小程序是需要备案后才能上架的。那我们想要查询到这些小程序的信息就需要用到下面这个网站：  
  
https://beian.miit.gov.cn/  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfZOu94W8EcTIsJMvBc1DC6PWaDcgMPU5I2t5Mc9phibtkcR9LciceqhvQ/640?wx_fmt=png&from=appmsg "null")  
  
  
好用示例：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf3eibtk3snTTSGSe98hlu7VHMlFUMUaAFTicGqs9EyU269wAS05yqLyrQ/640?wx_fmt=png&from=appmsg "null")  
  
  
直接在 wx 中搜索清*大学小程序，杂七杂八而且很多其他大学或者公司的小程序。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfVWmoVQtdC132Xxs5dAcscHTfCqOMog28BTtGTicsebWTia35FssDHxAg/640?wx_fmt=png&from=appmsg "null")  
  
  
在这个网站能直接查询到 42 条小程序信息。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfzNkjX5Fuen2icVR85HrrOExVpAorCXzIxg5zLF1Fsf2glGFebVnNuEw/640?wx_fmt=png&from=appmsg "null")  
  
  
比如说这个 清  
选 这个小程序，你在微信里翻到底，翻到 g 都找不到的。但是这时候我们如果自己手动去搜这个清  
选名字，能搜到，而且是标注了清  
大学事业单位的所以百分比是属于清  
大学的漏洞的。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfibATP8JXSsuKLhY8tER1mcibGr2p3qh6R0yzo4I4dM04BvJ1q4t4Dzww/640?wx_fmt=png&from=appmsg "null")  
  
  
这就是**出洞的关键所在，去找一些边缘资产，去挖一些别人没碰过的站点。出洞的几率会大大提升！！**  
# 二、第一个证书站小程序  
### （1）任意账户登录  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfM6unZSshW2HKWEVKcsRuW7licIWy8d2CK32Sm8m7SQRW0zhBicUvV9ibg/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfwJ509MxI2Pg0G0aaxEiceDrAakRLUc2xrwGprPWEzzG8k5pSEWAp1Tw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfLFibXTOeBASpEf3ROibhI6skiaFtwgXhfywzwoeoib6RNe35XliaQslibAbQ/640?wx_fmt=png&from=appmsg "")  
  
点击登录并 BP 抓包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfoWRLnu1uQdoFWK8ApvZgJ4Yciay5YFiaHic70lUB3JxJLcdkffHbvUCHQ/640?wx_fmt=png&from=appmsg "null")  
  
  
像 wx 小程序，这种授权一键登录的，有漏洞的几率很大。它就是获取微信绑定的手机号，然后根据手机号返回账户信息。像 session_key、iv、encrydata 三要素泄露，账户接管等等这些漏洞就经常在这里产出。  
  
这里我们虽然只有 encry 和 iv 但是不影响，直接拦截返回包，可以看到 phoneNumber 和 purePhoneNumber 就是我们 wx 绑定的手机号 18*********。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf7ctkKGCDKpKHbS7z7GqWZE7vOTfYAFuq514pnX6braWS922KLTz5pQ/640?wx_fmt=png&from=appmsg "null")  
  
  
将phoneNumber和purePhoneNumber参数修改成其他手机号,放包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfu8j9kkWbHAfGXrzXYQr6UEw5lJ96F1zuPOcgOP9C3E5VE3TwHA3UbQ/640?wx_fmt=png&from=appmsg "null")  
  
  
下一个数据包我们的手机号就变了  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfpeA3c3EsVoVXCgpoQmEmQ0Kl3wWQRrtLLwZJPzkdCDbPn0fD7icgdjA/640?wx_fmt=png&from=appmsg "null")  
  
  
再下一个数据包账户信息和手机号都变了，到这里我们的任意账户漏洞其实已经基本完成了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf77Q7d3Rgiaw2LwGOkEicw5ficoCqP9pVOxWVUgtpys63rxxoXnuyry0zg/640?wx_fmt=png&from=appmsg "null")  
  
### （2）验证码转发漏洞  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfmGGDfkAiaSvZe1RLiagmbnOIiaGKqWibe1yCiaZHbcgQnfk0NLiaw7t4lAbA/640?wx_fmt=png&from=appmsg "null")  
  
  
这里我们原本是 18 开头的手机号，点击更换手机号。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfB0yGjjUWQ79sQicZACRUQPofGqoah7t0pwG48WrlI5tXK8m9d4XD4Iw/640?wx_fmt=png&from=appmsg "null")  
  
  
输入 19 开头的新的手机号码。点击下一步并抓包。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfBx7s0o0oib1OksCcJuOnNMpeQMicXbYV0PbbpzLPkJj9JQ1W1YiaSLOwA/640?wx_fmt=png&from=appmsg "null")  
  
  
这里应该是确认更换的手机号为 19 开头的  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfKXCJgaofetyv35BZvn3431u3UNtp9U4bs6qTumNuQFRibNzOHlXSxwg/640?wx_fmt=png&from=appmsg "null")  
  
  
这个数据包，就是发送验证码的数据包，关键就在这里，将 mobilePhone 改成其他手机号。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf7RoLyj25wgy1rhjlJicBtu9bK3xlaJTyEb538E6hUqBN7E7xTbD2ib3g/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfaO8cEibqiaf4rtpsEGhRB9yicgwx0m4icGM09uLqSTA53hdeaEemicaF1Og/640?wx_fmt=png&from=appmsg "null")  
  
  
成功接收，非 19 开头手机号码接收到验证码。这里后期我也测试过，我怕 18 开头的手机号是我原本的手机号它本来就能接收验证码，所以我拿朋友 的手机号验证了，确实是存在验证码转发，只要第一个数据包的手机号不变，那么修改的手机号就不会变，第二个数据包就是验证码转发的关键。  
# 三、第二个证书站小程序  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf5OCAXetSvNPMUaWzVdcO7wQQ2CdeXoF71DH8ZFtUonA9PjwiaJGyMKw/640?wx_fmt=png&from=appmsg "null")  
  
### （1）账户接管漏洞  
  
分享一个收集教师手机号码的方法  
  
site:edu.cn "微信同号"/“联系电话” filetype:xls/doc/pdf  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfMYZZLqKefqCHcdTjtHL7QzJQLsKUS9Dia0HJ2u6lxD1eibcnJWYfv97w/640?wx_fmt=png&from=appmsg "null")  
  
  
这里我就找到了很多老师的联系电话  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfxe7xdLpRmRcibEWUJicJNiahPQGbNacbFJ0lic6WzaouzlC5UrhHyGnEuQ/640?wx_fmt=png&from=appmsg "null")  
  
  
这里的一键快捷登录不一样，因为它下面标识了，仅支持客户用户内部使用，所以我们是快捷登录不了的，这就是我找教师联系电话的原因。  
  
点击一键快捷登录并抓包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf1BHNsY9TN2Nny9bzWiclfeZZlTnzKJqJ030t4Vcfld82ek1aMcRA52Q/640?wx_fmt=png&from=appmsg "null")  
  
  
、  
获取到这个数据包后，将 mobile 替换成教师手机号  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfn4h2ricAgnmLhyeo6A6B2AUDS0eotyWqegibsjLvrShukL9aumwn4hIw/640?wx_fmt=png&from=appmsg "null")  
  
  
因为我测试过程中登录失败了很多次，所以出现这个数据包的时候我就知道出货了，360 为用户 id 号（这也是后面的一个漏洞做了铺垫）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfJyPAbso7effsS7fPV2p1SMPQBpBEM8Xh3iaNUZ6x5G8DEckrAxkkuLA/640?wx_fmt=png&from=appmsg "null")  
  
  
直接接管用户。一堆信息泄露。  
### （2）越权漏洞 1  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfqPEafu8PVibtTj8SnOYn6PD5vvaTSsNC5lgAQXn4246ibXkQRGWH0sOQ/640?wx_fmt=png&from=appmsg "null")  
  
  
点击我的并抓包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfyNicNhrUNeJ2mviaREKzFYEUnPic5dTLXypxdeVUTr9hXJQxVrBNCVNZg/640?wx_fmt=png&from=appmsg "null")  
  
  
将 360 也就是用户 id 号替换成其他数字即可获得其他账户信息  
  
这里替换成 366  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjffELLHicXrucUveEkkBEj0fY56IqXctujVtPbllw8JvU2DEVicz5heKsg/640?wx_fmt=png&from=appmsg "null")  
  
  
这里信息已经变了，之前是女，现在是男至于其他信息不好露出，见谅见谅。  
### （3）越权漏洞 2  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfic9qtrFbWRicWSdicoE8GHJxm90wE6ibgB5L4R7WR6TguuNDOlAWuFSwaw/640?wx_fmt=png&from=appmsg "null")  
  
  
上传签章处，本来想测试文件上传，但是测完一遍发现无货呀，但柳暗花明又一村  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfsDiaId8mqcqkhZOGOia2bSAyuSu9uhZ1npNrQEQBa6iaIrbjfCO1r92Vw/640?wx_fmt=png&from=appmsg "null")  
  
  
点击预览签章  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfMl8bHRtVJc03DnC4SPgNUznRdISEtMql2cTHXXjvzPC8ibMH1XetZrg/640?wx_fmt=png&from=appmsg "null")  
  
  
发现也是 36*用户 id 控制的  
  
直接替换即可越权获取他人电子签名  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf95aO7HkaBBcdHB0JHt0hjmuRgsqic4KI8nibibJwxPFJZ1JoYuQfEibdnA/640?wx_fmt=png&from=appmsg "")  
  
盗用签名的危害也是很大的。  
  
可能会有经济、名誉、法律责任等损失，所以这个漏洞危害也是很大的。  
  
   
  
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
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
