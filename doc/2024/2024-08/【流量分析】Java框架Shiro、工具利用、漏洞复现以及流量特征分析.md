#  【流量分析】Java框架Shiro、工具利用、漏洞复现以及流量特征分析   
原创 仙草里没有草噜丶  泷羽Sec   2024-08-25 10:10  
  
##### ~加入安全交流群，一起成为网安大佬~  
  
### 前言  
  
～为 python 炒饭添砖 java，自学 java月薪过万～  
  
靶场：https://vulfocus.cn/  
  
Shiro（Apache Shiro）是一个强大且灵活的开源安全框架，专为Java应用程序提供安全性解决方案。它由Apache基金会开发和维护，广泛应用于企业级应用程序和Web应用程序中。Shiro的设计目标是简化应用程序的安全性配置和开发过程，提供易于使用的API和丰富的功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0rApw8ZlKIR9R7rzu5Vavla6ybKuqJyp2yQgjpORic0dWX2JbN82GWQQ/640?wx_fmt=png "")  
  
本文主要介绍了Java框架Shiro和shiro工具的流量特征，流量分析，以及**Shiro-550**漏洞的复现，我很菜，不喜勿喷。  
### CVE-2016-4437  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0zbXnpEn1TsGNRaqUl30kiaIUKKIJIZtvjqMZJ7ykmJMvSxJzkGxsvuQ/640?wx_fmt=png "")  
登录界面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0KeicrPgFMskZKrHwibv6EU5QGVQWQBe34mcjicl2xVbniazDBQ3GK58wdQ/640?wx_fmt=png "")  
  
image-20240820145112169  
### 正常的流量包  
  
返回包set-Cookie⾥没有 deleteMe字段的，返回包甚至都没有set-Cookie  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0xfXHcqv0wUibcLyuHicfz0J7iaY0BPtJRXL4aicWRfZibCumicOfVSshbIBg/640?wx_fmt=png "")  
  
image-20240820192051239  
### 登录失败的流量特征  
  
看到一个结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh09OCDpxo615iaTEw7Gicpz8fuffyEKtxPWvJeVOgiajPRgSDXkeWwaf8sA/640?wx_fmt=png "")  
  
image-20240820145250040  
  
抓包，输入错误的密码，他就会返回一个rememberMe=deleteMe，那么百分百是**shiro**框架，不管是否勾选记住密码，返回包都会有rememberMe=deleteMe字 段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0GFhOcIoicszSGogTZjTQVhJ0wlsnJ4wnoOiafLGoW3GJDPcQwn0ib7ZUQ/640?wx_fmt=png "")  
  
image-20240820163100507  
### 登录成功的流量特征  
  
从给定的用户中登录成功一个的流量分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh03f8cALT7ZZrzkaRQsQk4C1poRxl7pMT7eFxdpicdAAK4cz4DU3q9ibDQ/640?wx_fmt=png "")  
  
image-20240820190749089  
  
这时候再去请求别的页面就会有这个cookie特征，未登陆的情况下，请求包的cookie中没有**rememberMe**字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0AXzeWND50HEXyHfCHw2PJuj5NjjmRdtyRgTut3ytsSH9AcpcTQotibQ/640?wx_fmt=png "")  
  
image-20240820164428402  
  
没有登录的情况下，请求包的cookie中没有**rememberMe**字段，返回**set-Cookie**也没有**deleteMe**字段  
  
不勾选RememberMe字段，登陆成功的话，返回包**set-Cookie**会有**rememberMe=deleteMe** 字段。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0uibic3Dsibic8cYA5t5pdqOlxqOI0tgX8P9yB5Fl5YQLcibA1HZCBcMPNnA/640?wx_fmt=png "")  
  
image-20240820192904683  
  
但是之后的所有请求中Cookie都不会有rememberMe字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0Fmw0klbBicTMSzWJvePNEDcV1m9zibBePxpnGQodicnuNEjunAyKZq0cA/640?wx_fmt=png "")  
  
image-20240820193157179  
  
勾选**RememberMe**字段，登陆成功的话，返回包**set-Cookie**会有**rememberMe=deleteMe**字 段，还会有**rememberMe**字段，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0lxdjcWoRpqn5rWdlVnyxYZNkrUzNN1z64aKgSEA5BbibRttAKugbjyg/640?wx_fmt=png "")  
  
image-20240820193331380  
  
之后的所有请求中Cookie都会有**rememberMe**字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh01fgQwHjNEODJiakZXkep7ibsMo2kxa1EBj9diaTHviabxDeTf3fMm4XhRQ/640?wx_fmt=png "")  
  
image-20240820193502353  
### 工具爆破的流量特征  
  
工具的第一步就是去判断网站是否使用了shiro框架，开始之前，先设置工具代理，把流量转发到**burp suite**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0NWBSZlLUVF3kMYSGS6lZ01rE1ias53yg2JAmVicibHDgaplSAzhqrXW5g/640?wx_fmt=png "")  
  
image-20240820195409246  
  
就可以得到如下数据包，它添加了一个Cookie: rememberMe=yes  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0hDWe60mjQpXVCsV2okr8icQgDicOhOYHgs2Tpfo6xyPXdGDmylVywNZQ/640?wx_fmt=png "")  
  
image-20240820195957611  
  
看看返回数据包，他也有一个Set-Cookie：rememberMe，也就是登录失败，通过这个值来判断是否是shiro框架  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0d0CictdvmF9UGWZ28iaYuiaXzhJLe4FIKCZ5k72W5K9Vdlgib8OZFBiciaow/640?wx_fmt=png "")  
  
image-20240820200329510  
  
密匙爆破流量分析，当成功之后就会有一个设置一个**cookie：rememberMe**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0V4zIrqeBeyFhwVpUtVk6Q3PYWsTLc3soLjIwoVBWHJTLyoNdvmxNmA/640?wx_fmt=png "")  
  
image-20240820201413181  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0xYUsGicqPDv4eZsXZDPnxQ4319Xq6ft7KpneEayqTicnOMrkibVC1PVFg/640?wx_fmt=png "")  
  
image-20240820201704358  
  
我在cookie中随便添加几个字母/数字，他也会提示Set-Cookie: rememberMe=deleteMe，密匙爆破失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0mgbzqTEwb8yicHuxlmVIVgF4ZRLicXtcQFpzOaaia5Hf9rlic7P3o2uBow/640?wx_fmt=png "")  
  
image-20240820202514146  
  
成功后，还不能直接获得webshell，还需要爆破利用链和回显  
### 利用链爆破流量分析  
  
如果在秘钥正确的情况下，进行利用链爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0Vw5M4gFzAjaCO27Ex1H8V6XxX8ibMfuw8G8xiaejxASGr0rfjlU3ll7g/640?wx_fmt=png "")  
  
image-20240820195825657  
### 利用链爆破失败流量  
  
和密匙/浏览器登录流量一样，只要登录/爆破失败就会返回一个Set-Cookie：rememberMe=deleteMe  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0Pd2K26MmbhETYaCu4y2gtl0KqtufqJ7kXAViba6Wg7fJlhRF5bER5qQ/640?wx_fmt=png "")  
  
image-20240820204241985  
### 利用链爆破成功流量  
  
当cookie非常长的时候。如果在研判 中发现cookie非常长，并且返回包状态码为200，那就要考虑网站是否被入侵了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0dlO7gvsCwOO7Hk56mXGgoeBCZ8FPFMwkE2E5CTwUaEXw8hWCgcdAeA/640?wx_fmt=png "")  
  
image-20240820204149009  
  
成功之后才能执行系统命令，获取flag  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0dUqNwibpJDRop4ia0JmM8NhKwm0KAvdickxIsPO8qgXzf6aSZIgoopicfg/640?wx_fmt=png "")  
  
image-20240820154057801  
### 系统命令流量分析  
  
执行命令时候的流量特征就是，rememberme 非常长，并且返回值是加密的，执行命令ls，在响应包中会出现**三个$**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0zZJTmMOTKtVz6mcQvPWtrkDvE3FXN9zTMUGb6iclYm7mpPwAwvQ7FtA/640?wx_fmt=png "")  
  
image-20240820205004956  
  
ls -a  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0twsia3WyeTpAvib7KIlibMiaHyNhHwia4pOsEQW90l9O31jicpD5RXspwBcw/640?wx_fmt=png "")  
  
image-20240820205137667  
### 注入内存马流量  
  
上传蚁剑一句话马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0heBAp5IUVDOSnliagQRyItN7rSDQj55NrBMLArjJRajpabJibNolCibXw/640?wx_fmt=png "")  
  
image-20240820154131935  
  
上传的过程流量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh0ibZNCeuhIG4OBjFJ50TvpKnRVibxz5wx2XtL0hLZ8k02b7PRmeWwDARg/640?wx_fmt=png "")  
  
image-20240820213245120  
  
正常连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGyibrRdXc8ratAbO8Fatwh07icDsRWgsR5phvibia7JywWhl5yomNkfIz8ywtZiakppduRmQRrsUy8tuA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5975bXHXfWHjKaLcicf4x0Tt5ZwZeKIHtv64aMGjtlfJAJbLvjnaTpQmsGlvoxDDpR8Y9jd3rdKBC3ROHfmOZrg/640?wx_fmt=jpeg "")  
#### 往期推荐  
  
[【渗透测试】12种rbash逃逸方式总结](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247489669&idx=1&sn=64e9bf9674fd0dbb24c16c8100bcebc8&chksm=ceb28388f9c50a9e33cdfc045964d350cab4c9ea9c93290cb8a1794760ea256c5f15bdefa38d&scene=21#wechat_redirect)  
  
  
[DC-2综合渗透，rbash逃逸，git提权，wordpress靶场渗透教程](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247489570&idx=1&sn=cb60c97e91776c610be8ee662fb77f21&chksm=ceb2832ff9c50a394e5e575403c324dbd6bbca854184612c462adf26b0bd39faf8e8d6f2feab&scene=21#wechat_redirect)  
  
  
[Linux中Find命令也能提权？提权方式一文通透](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247489432&idx=1&sn=1e61df92da30aa2dc5e0c0e2218104e5&chksm=ceb28c95f9c50583d2212bbfcb0b537fc21849c2f4f0ff65d10a046e52433338eba15ce1b02c&scene=21#wechat_redirect)  
  
  
[DC-1综合渗透从外网打到内网，msf后渗透，权限提升，入侵痕迹清除](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247489231&idx=1&sn=3fda189fca68250136384c280c74708c&chksm=ceb28dc2f9c504d4bfd1d86979caccf560e68975cf5292e1ae7d1b28ee17a802db6230224898&scene=21#wechat_redirect)  
  
  
[信息收集10大技巧，4k文案超详细解析——渗透测试](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247486332&idx=1&sn=f1bf17b3677d0dc2b8762c9ded406107&chksm=ceb29071f9c51967da01132a8de8fa2bbc1c56f164b3f5dcbb909c48fe5950eb4509b0241064&scene=21#wechat_redirect)  
  
  
  
  
  
