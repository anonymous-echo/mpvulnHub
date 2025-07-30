#  实战 | 记一次实战中SelfXSS+CSRF+越权漏洞的组合拳   
 Z2O安全攻防   2024-10-22 22:13  
  
**0x01 前言**  
  
  
在渗透测试中，经常能够遇到这样一种XSS漏洞，它通常存在于比较隐私的个人信息配置等等功能中，有一个非常鲜明的特点就是“只有自己可见，别人不可见”，XSS漏洞只能攻击自己自然是毫无价值的，因此此类Self-XSS几乎不会被SRC所接受。本文通过对一个在线游戏平台的测试经历，提供一种攻击思路，把原本无害的Self-XSS漏洞与其它漏洞结合起来打组合拳，从而实现无害漏洞从无害到高危的利用。  
  
  
**0X02 比较有“含金量”的Self-XSS**  
  
  
为什么说这个Self-XSS有含金量，且听我慢慢道来。信息搜集的时候我发现一个游戏玩家中心，用于编辑各种个人信息的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodicibXx7zqz6icOEOnwpYibDlTQGtKIXulhp8NnWULeFcicotYG0v6b3kFGA/640?wx_fmt=png "")  
  
  
秉着有框就插并且不影响正常业务的原则，我自然而然的把目光投向了“详细地址”这个输入框（其实是因为真实姓名和联系电话都严格过滤所有特殊符号导致无法XSS），既然是联系方式，想来应该是所有玩家都能看见的吧，如果被我找到XSS，那就是存储型XSS到手了，美滋滋。至少当时我是这么想的。  
  
  
在这个框里输入test1111，然后在页面源代码中Ctrl+F搜索test1111定位其输出位置。算是找XSS的常规操作吧  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodDaFDFsS2xOFpe9K8LFLAIQjB5fYITfGUoR4DlKzwseiaBJgFJUxGjjw/640?wx_fmt=png "")  
  
  
看这样子一下就反应过来这玩意是输出在JS代码里，是被<script>标签所包裹的，那简单闭合一下不就完事了，只需要用 ’; 闭合前半部分，再用//注释掉后面的特殊符号，最后在中间填入JS代码，不就完成了吗，构造test11111’;alert(‘1’);// 毫无技术含量可言！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticody1ovydyMgg6uQ64ChibJG6fuVFcCrEicRX4u1F51DmC9Pa2YGTdTv1BQ/640?wx_fmt=png "")  
  
定睛一看，我就知道  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodbJheVCDsHBzENCfqY6VH4lfEwV9Kq2U0OsI887iciadyKzL7dCwXLbUw/640?wx_fmt=png "")  
  
  
  
没关系没关系，不就是墙吗。我们来FUZZ一下看看它拦什么，试试eval()。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodPWNPqZ9CBI8fMv8LG0m33gnpQ2QxALGWml8VGAiae7DaRLS7yGvzGBg/640?wx_fmt=png "")  
  
  
还是寄，这就只能拿出我的压轴绝活了。输出在<script>标签内时，有一种绝活。JS有一个特性是Function()(); 你没看错，大写的Function和小写的function其含义有所不同。  
  
  
对于Function()来说，写在其第一个括号内的JS语句会被直接执行。比如说我们可以试试  
```
Function(alert(‘1’))();
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodfCwDt138ia35JFJLdaARACF3zpU44Rw1kV9ubRV2gTtdPib8GSGTmvEg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticod5ayKZh9Y6EzcAXC4zK5Rzj7sTWYot5yVee5a7l1AdgJKHoicANYF8Fg/640?wx_fmt=png "")  
  
是不是会发现，这个特性的用法和eval();不能说是十分相似吧，至少也可以说是一模一样。  
  
  
不过360肯定是不允许alert堂而皇之的出现的，有没有办法把它隐藏起来呢。既然都能使用类似eval()的功能了，我们还怕这个？直接使用atob();函数，它的作用是把base64编码后的内容还原，我们直接把alert(1) base64编码一下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodjyhL4UO1ZeIuYicMXTTlvImzXlx5JdDtanfPGUqL2vb2UXyibhQM42KQ/640?wx_fmt=png "")  
  
  
注意，这里有个坑点，这个base64编码后的字符串填入atob中时，必须要去掉最后面的等于号，不然会失效  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodABvDoPB6iacibXI6tTVCubfdcySs7LanNCe5w2jfAU3YXemicU1lIlk0Q/640?wx_fmt=png "")  
  
  
可以看到还是成功了，说明这个payload是可用的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodkNRypRm63ef3okAcowch6e87bAaZBAxanJwWgVMF5u5eW7VmpghIKw/640?wx_fmt=png "")  
  
  
为了防止360再拦，还是要做的周全一点，还有一个小技巧就是反引号其实可以用于代替括号使用，为了让效果更炸裂一点，我们把alert(1)换成alert(document.cookie)。所以我们最终可以构造这么一个语句  
  
```
';Function(atob`YWxlcnQoZG9jdW1lbnQuY29va2llKQ`)();//
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodJhWDmsHWhzVjNriaFkVxffNocuibgkCydW8iaOYDpeS5qjPqzMibTwwW0w/640?wx_fmt=png "")  
  
这时候可以看到已经成功绕过并且成功弹出COOKIE了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodu0kydzicbPg6GFyE1pP2IbajmCbxonWDotSUhdxGsyDrpePNEib9lKCQ/640?wx_fmt=png "")  
  
能弹COOKIE对于一个在线游戏平台来说肯定是极其危险的，到这里我已经开香槟了。但是万万没想到  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticod1WdNnKg1Xf7xmJfEeYicpD7hciaxzzecjTicXMkNKnBqNOelxiapWQl6og/640?wx_fmt=png "")  
  
  
啊这，难道是Self-XSS？！我又回去重新看了一下功能，发现这个点别的用户还真就看不到，我去，联系方式不就是给其它用户看的吗，其他用户看不到，你设计这个功能干啥啊！  
  
没招了，只能想想有没有别的办法。  
  
  
**0x02 搞这么多CSRF防御机制，有用？**  
  
  
最最经典的结合Self-XSS漏洞进行攻击的手法就是CSRF，两者结合即可变成XSRF甚至是XSRF蠕虫。它的实现原理基本上是这样的：攻击者构建一个POC.html，它的功能是往用户的页面中嵌入恶意的JS语句，这时候我们就可以脱离存储型和反射型XSS的范畴了。只要诱骗目标访问了我们的CSRF POC，再跳转到上文提到的用户攻击，XSS攻击就完成了。  
  
  
说干就干，我们看看这个修改个人信息的点会不会有CSRF漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodhUfMS58YC2VHiaVmiaaicdiaKiawkQRnLa1tzXUib4zJoFrh7ZV7VWBV3c2Q/640?wx_fmt=png "")  
  
乍一看，这可太吓人了。又有Origin又有Referer，这个CSRF是不是又要裂开了。然而，实战中要绕过这类验证最好的方法就一个字，删！直接把他们的信息删掉看看能不能过，有些粗心的开发者光顾着判断值对不对，却没有考虑值是不是为NULL。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodWUoqbibHNtSbHXg2YqaS2fr2Dv2f8Df2bJYXicoAb2v5kYgTBxqajT8A/640?wx_fmt=png "")  
  
  
发包成功，看来目标并没有校验Origin和Referer是否为空。那看看我们的信息有没有被修改成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodczcGXo3MqTWD8Xm5mqmMFdcxmTFDAia2dtHbko9mL0fkqcQjYYtThZw/640?wx_fmt=png "")  
  
  
不就成了，直接用burp造一个CSRF POC出来，把其中的address的值改成XSS语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodgqQia1M1DdnKLsMftyBPD7D11mjckJtmXaL9EPn3FXd0wiaIQmpP2xmw/640?wx_fmt=png "")  
  
  
登上另一个测试账号的情况下，试试我们的CSRF POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou8DtYr2EKUUsUTod2l9jxV6YqLZ9ALplon1eUUAsJSIMPZ23Tia1RFxMfhH7tLz76qJYSkWdcbfVag/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodND8RjkJP7bLw8xI17urrKR0oZXlp3Kgl6bMzicU5D3aO0lsIOvhuJYA/640?wx_fmt=png "")  
  
  
这个测试账号2也弹窗了捏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodicmR5rbeKNlCHrlhHmQArrcD1sWVgtEpjVJnoiaCyicx3zqkdot0G2SZQ/640?wx_fmt=png "")  
  
  
这下总算结束了，提交一波。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodYBJYIiaYtmVuw64cVFFaOEtTIF8MgkXRdIRIgNtA16pIsRwv4bypicSg/640?wx_fmt=png "")  
  
  
拳头硬了  
  
  
**0x03 意外收获的平行越权**  
  
  
还得找找有没有别的漏洞来组合着打。看来看去我发现了他们这个类似论坛的网站还有一个评论的功能，不知道这个评论的用户身份是由什么进行控制的。抓个包看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodmPqvtLDYcAcSEVTM1aLNu7Fib2hKOqkBBEBRoROGibptf8HcfwXGzgEQ/640?wx_fmt=png "")  
  
  
评论这个行为会调用非常多的接口，故而会产生好几个数据包，我在http history中筛选了一会，突然发现一个数据包不太对劲  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodVrXqM3lbAM3yAhNjBINOoLSe97neB6jYHWfAhRRUgaVk4bqysbuz7g/640?wx_fmt=png "")  
  
这个数据包，它似乎传递的是用户名、uid、sid、用户头像。这个uid就引起了我的注意，你们不会在用uid来表示用户的身份吧。那我改几个试试？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodovNCNxQD9EXdvibeazic7AuHKzkbEHdwQbc6m8IW36SANSQMOlfEymLA/640?wx_fmt=png "")  
  
  
真是太有趣了，既然评论这里在用uid控制，那么刚刚的更改个人信息的功能点，会不会也有类似的接口传递uid控制呢，我马上回去翻了一下http history，终于看到一个数据包也在传递类似的uid  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodenLur70bzGL4NUDsfXyMJbbgwawHOM0pY7192ibXCJLNxPHnPiaCvCug/640?wx_fmt=png "")  
  
  
  
重新登陆后发现email已经修改成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9r7h6gTcz78fpjth8iaticodfyM49nYotPz2Hb71C3sCzm8VVZ72p5ZSib4vwKMQQibNUic1riaurwMq2w/640?wx_fmt=png "")  
  
  
这就更是一个大洞了，只要我利用这个越权漏洞，放到burp里去批量爆破别人uid，并且把address换成我们刚刚的XSS payload，那么全站用户的个人信息都会被写入恶意JS代码。基本就等于我们直接获取了全站账号的登陆权限，该网站是一个比较大型的在线平台，旗下多个子域名的百度权重都在7以上，该站账号还是比较值钱的。对于一个大型在线平台来说，这无疑是非常致命的一个漏洞。  
  
  
**0x04 结语**  
  
  
本文主要通过一个漏洞挖掘的实战案例来分析了一下实战中遇到Self-XSS该如何设法将其转换为有利用价值的漏洞，属于是帮大伙挖SRC赚钱的一个小TIPS。  
  
  
其中还提到了一些比较好玩的思路  
  
  
例如：使用Function()();来替换eval()从而绝杀输出在<script>中的情况、置空Origin和Referer来尝试绕过这种防御CSRF的机制、结合CSRF与XSS进行攻击、结合平行越权与XSS进行攻击。  
  
  
所以实战中遇到低危漏洞千万不要气馁，一定要想方设法的打组合拳将其危害最大化，还有就是  
**测某个功能点的时候一定要记得看HTTP History**  
，很多功能需要多个接口分多个步骤进行处理才能实现，**养成分析HTTP History的习惯**  
可以让你发现许多隐蔽的接口，从而发现更多的漏洞！  
  
  
one more thing  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOABrvjQvw6cnCXlwS05xyzHjx9JgU7j83aReoqqUbdpiaMX2HeudxqYg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOPsqyLbibqOAbrHSWfeEntqxwqCE3lPT8tlovWlw8Hkr8lXfRw38v0NQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
