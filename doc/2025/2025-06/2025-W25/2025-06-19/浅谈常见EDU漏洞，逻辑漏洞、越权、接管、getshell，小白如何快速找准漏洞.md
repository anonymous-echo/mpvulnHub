> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247491912&idx=1&sn=74dd7b8a525955965457628ed711e635

#  浅谈常见EDU漏洞，逻辑漏洞、越权、接管、getshell，小白如何快速找准漏洞  
薛定谔不喜欢猫  神农Sec   2025-06-19 01:02  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：薛定谔不喜欢猫  
  
文章来源：https://forum.butian.net/share/4291  
  
  
**浅谈常见EDU漏洞，逻辑漏洞➡越权➡接管➡getshell**  
  
  
  
今年对某高校进行了渗透测试，发现了一些比较经典的漏洞，写一下和师傅们一起分享。  
## 1.教务系统登录处短信轰炸  
  
![11).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNPtfEJbue6qmJStRMJJ0UURHq7ia64D8zia8gMC9JBSziae6I2FSiaPQe6A/640?wx_fmt=png&from=appmsg "")  
  
学校的教务系统登录处，发现有一个手机验证码认证  
  
![kappfra2).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNibSaKfG2hVHtNbqB02IcJGzIZ2QMIXGL6a9XnVGG8zxKnBmsrfQ26OQ/640?wx_fmt=png&from=appmsg "")  
  
这里会发送一个验证码  
正常来说，每发送一次短信验证码，这个校验码就会自动更新一次，然后会报错：“验证码错误”。  
但是这里抓包之后，发现能抓到两个数据包  
  
![attach-1e1244475c6dff0e2087e23915db3711aab85810.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xN6ykcBIpJXecmXhPF2HnI94qjckHKxy8h1oj1FYBfBqm9Q2hAUDiciaEg/640?wx_fmt=png&from=appmsg "")  
  
这是第一个数据包，可以发现是对验证码的验证，我们把第一个数据包通过之后，拿到第二个数据包：  
  
![3).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNyX3Y0o2aCGHtzBDQIX4WjAK9xh7n6wHoBGeXJTrJtGlMEocZ57mgjw/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们的手机号出现在了第二个数据包中  
我们点击放到repeater，然后点击send，可以发现一直发送：  
  
![111.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNMTPMDqypaF59axzQofZPdCaNHMR3C4j7tnatoRdic9Lqr0cqahxEwicw/640?wx_fmt=png&from=appmsg "")  
  
**原理**  
：正常来说校验码的验证和发送短信应该是在同一个数据包中，这里不严谨的设置，将校验码的验证和发送短信的数据包分成了两个，我们输入正常的验证码，通过第一个验证的数据包，拦截第二个发送短信的验证码，即可实现短信轰炸。  
  
这里分享一下短信轰炸的几种绕过方式：  
#### 1.手机号前面加空格进行绕过  
  
这是挖某专属src时遇到的  
  
![213122.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNPsDPLQFxfQZzkNuyEY8XAbdKX69LP0xiaAKbrufC2sU7ic3Aib8cR0TRQ/640?wx_fmt=png&from=appmsg "")  
  
account为手机号，正常情况下，一个手机号短时间内只能发送一条验证码。  
在account中的手机号前面每加一个空格可以突破限制进行多发一次验证码，  
  
![attach-d5386ba03170c8b2e6603e5c0ad7bc221338a481.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNJGsNSo8cAP28lFJtmE8JfIKd8JsKazj1icGB2zsUzBNtSAu95JZEsVg/640?wx_fmt=png&from=appmsg "")  
  
burp设置两个载荷  
  
第一个载荷用于填充空格，设置为50（这样设置，一个手机号就可以发送成功50条短信）  
  
第二个载荷用于循环遍历手机号，可以设置遍历10万甚至更多的手机号  
#### 2.加字母等垃圾字符绕过或者+86  
#### 3.伪造XF头  
## 2.校内某实训平台任意用户注册、任意用户登录、修改任意用户密码、验证码爆破  
  
![5(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNwkpfF3C8kA9ia7djDxVNvBPibOQqClJiaEGgGaQGibP2W5jfrs6icQXjT2g/640?wx_fmt=png&from=appmsg "")  
  
这是校内某实训平台，我们先点击注册功能点。  
  
![111P(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNedc3ia8ttOtpXjuQKlzV0MVHegqEmDLOAdBOPjzicZyTaLfHicKeTlWxw/640?wx_fmt=png&from=appmsg "")  
  
我们点击获取验证码，然后进行抓包：  
  
![12312GR(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNkxhCVKg9QnQaB6k5UVYgeN7NyS0VuFbM2Xribav2zFqvERxEQjrjr0Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到手机号被编在了url里，我们这里使用“,”去拼接手机号，这样就可以把验证码同时发送给两个手机号，并且收到的验证码相同。好比我知道你的手机号，拿你手机号去注册，我根本不需要知道你的验证码，因为验证码也会发到我手机上。  
  
![1233213123zCywpV(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNT2kicyZhm5zFuA9E64bsTgbZQlkBqCicJ2sgdPEmRYoXQicY1eoYHPtqw/640?wx_fmt=png&from=appmsg "")  
  
![123321(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNCKkhvMJLYXF88eyLQdjeQlrvmWr1TFqCSd6Q0HNkvkcxyudMciaPDUg/640?wx_fmt=png&from=appmsg "")  
  
修改密码功能点也是相同，我这里不进行过多赘述  
#### 验证码爆破  
  
![ka12332132123123)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNwgvobM6VVfMAT9zt4aibMTRaPZkj6iaicBkO9TC2hhg288eGQnCwNTibAA/640?wx_fmt=png&from=appmsg "")  
  
正常发送验证码，然后在填写验证码的地方，随意输入四位数  
  
![attach-f9667d233ce6573b5439c68f327ddd189343fee5.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNIIHMoC1sLzBecdIUAJ1DlhvO57PxkzibVe6U4CLE7ADZDiblibcv2wuhA/640?wx_fmt=png&from=appmsg "")  
  
![3213121322131)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNr4x7Mjjv3jM6jJSZQynx9zurJc9g6ncxyiapgZh9vCVJiaVicYeos7T9A/640?wx_fmt=png&from=appmsg "")  
  
可以看到在7710的时候，长度不一样，成功登录进去了。  
  
**修复建议：**  
：对验证码输入次数进行限制  
## 3.越权查看所有学生和教职工个人信息，数万条记录  
  
![2222.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNyb4ibT2N0F3I2OAHYQnoxr8tkjhsIH5Kp3kHfiawQgn6RpMwicsMJoQiaQ/640?wx_fmt=png&from=appmsg "")  
  
教务系统个人中心处有一个查看最近登陆记录的功能点，发现右上角有个查询，我们抓包尝试：  
  
![1322222)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNVhoicHTWTcc2sH16mtwdxsKbOsa8xHybNIH1gChuhKXKQib7ibSRgMDdQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里可以看到我们的登陆情况，我们尝试去修改value的值，看看能不能直接越权查看别人的登录信息。但是发现无论修改成什么都会提示登录信息错误。  
修改成0、1、-1都不可以，但经过我的尝试发现，只有一个值可以，那就是null！  
  
我们让value=null  
  
![31232213Vq(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNe7wswL1zjCVlcclGUib0MoHbibKpJuCVab3LudOBr4af8FOUIoLctk4A/640?wx_fmt=png&from=appmsg "")  
  
但是登录的记录明显有点少，而且观察发现好像都是登录失败的记录，这时我发现有个name字段，我把userid改成*：  
  
![123312(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNPLwyf1XbMJ0xYlDSzxqicytPeqkKUamAeg96kQtg8SauWROQNUjBqJw/640?wx_fmt=png&from=appmsg "")  
  
拿下所有学生和教职工的个人信息，包括姓名、手机号、身份证号、学号、教职工编号、登录ip等  
## 4.教务系统绕过手机验证码换绑手机号  
  
![12332132(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNbEVWl6miboicFToY5OiaBDtiawvZ8jZtK1RCeL0QjvUfp4orWoDhEBmmtQ/640?wx_fmt=png&from=appmsg "")  
  
也是这个教务系统，安全中心有一个换绑手机号的功能点，我们点击发送验证码  
  
![3333.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNiacNomH0j0RIgwiaiaYDC9RDTNBJbBf6DkL2OEnc2uFtjsWicPeSrzV9Xw/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到是修改195开头的那个手机号，然后我们forward  
  
![123312(1111)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNCYFdR526icYmMXFwiaemN9nTEaekjgITacbmm9Le32lmxIwyENQXJ0Hg/640?wx_fmt=png&from=appmsg "")  
  
之后弹出一个验证码，我们输入验证码点击确定  
  
![1231232.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNIPbMSruooxkMzRLWJRaOdNpO5qMrOibohVS0hEibtWlsLCbfgSLbv6kQ/640?wx_fmt=png&from=appmsg "")  
  
这里的验证码就做的很好，和发送短信的验证码数据包放在一起了，杜绝了短信轰炸。但是我们这里把195开头的手机号修改成我自己的手机号。  
  
![1312BtK(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNYZXXMqNVruAZjo92eibDPVsn4bibd4iavbicHhzA2jUKpUpDBYJsf2Pb6g/640?wx_fmt=png&from=appmsg "")  
  
成功让自己的手机号收到验证码，以为皆大欢喜了，结果。  
  
![1111e(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNeuer2Tfgf151emibgv2kekxoq3KeX3WQaicO7BsLaw6OOGrfa59v1VTQ/640?wx_fmt=png&from=appmsg "")  
  
显示验证码错误，这是为什么呢？  
  
我们继续审一下错误的数据包，也就是我们抓输入完短信验证码，点“下一步”的那个数据包  
  
![111.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNOToUZZUITOhDwkWJmO5ZY7YFeEvFfmHxLgHSJOUBTicNO3WfEjm7uPw/640?wx_fmt=png&from=appmsg "")  
  
可以看到居然在“下一步”的地方，对手机号又进行了一次验证，我们将这里的phone改成我自己的手机号，然后forward  
  
![211221O(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNO9SyNtib9Iia1gic4VdF2nicPJxVUmFRUIIWskXGIiagBTHkMz5e0Z4J66g/640?wx_fmt=png&from=appmsg "")  
  
成功到达绑定新手机的界面，成功绕过了验证码认证，可以换绑任意用户的手机号。  
## 5.校内某平台druid未授权访问，导致泄露用户session，可以实现任意用户接管  
  
![111Bc(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNgkMQtpmlcYlFRIhFbcQFumHicKcPeVQqIKZVBqFbibCIFiaXzVJiakygoQ/640?wx_fmt=png&from=appmsg "")  
  
这是校内的一个实习平台，url为“https://xxx.edu.cn/shixi/”  
  
然后之前读文章读到了一个druid的未授权拼接，/ / druid /  
 /  
  
于是尝试拼接 ：“https://xxx.edu.cn/shixi/druid/index.html”  
  
![2221)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNHQMfmFnd0vq9aDlCiamU1VVftqYpZuXXzibbhe2MUEmzmo1EntSCf16w/640?wx_fmt=png&from=appmsg "")  
  
可以看到是有druid的未授权访问，这里会泄露很多东西，比如数据库信息，数据库查询语句、访问记录等等。我们这里搞一下session。  
  
可以看到有一个session监控：  
  
![3333hPXD(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNhJ3whov72ia73pVG1lSDicoibibne7yNcziajZChVNDexCuA7DFtcQYxLibw/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里有登录过系统的用户的session，我们要做的就是把session收集起来。这里我有个比较好用的方法，可以ctrl+a复制全页，然后粘贴到excel里，然后选中session列，就可以快速的把session复制到txt里了。  
  
![44444Zc(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNmfmRtUSccLRVq3NiavsficRSBdqyllDOh2UHqWQNGmiasjiaAFcRH5xvIg/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们把session这样收集到了txt里，然后打开yakit  
  
把txt导入到yakit的pyload里，然后去抓一下登录窗口的数据包：  
  
![5555tPEr(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNhKxc2yvVS92bicKDZ9XNCylxqEmnTMBTvCRLibfaXsAcLzgC3UJ2nMGg/640?wx_fmt=png&from=appmsg "")  
  
可以看到cookie有个jessionid，我们把他的值设置成标签，然后去拼接刚才的session的payload去批量访问：  
  
![666666(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNDhbiaUM7oxibEZSKict5fPfia2vvemFoBCc3KELIyW26QOXib8XwcDz64ww/640?wx_fmt=png&from=appmsg "")  
  
可以看到有很多200成功访问的，也有一些无法访问的，无法访问的原因主要是因为session是具有时效性的，长时间后这个session可能就会失效，但是只要源源不断的访问这个系统，我们就可以源源不断的盗取新的session。  
  
我们找一个200正常访问的数据包，把里面的session复制下来。  
  
![77777A(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNaia0NqhfeLyKGLLDKu5BKBKpE6nruq3XkR7FaaCD9KajXAVupzp2eVA/640?wx_fmt=png&from=appmsg "")  
  
然后回到网页，打开f12里的存储，替换里面的jsessionid  
  
![1231231.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNdo6cysbia04dkamX6qjaWh6o2EqgM7WHPu479V0TTmJbW2ewQtQW8fg/640?wx_fmt=png&from=appmsg "")  
  
然后刷新页面：  
  
![1111111).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNPmDQLFjjY86MDqFiamXl1r4scBhA7UnLdkeEgiaxatdiafYx1O3FtUIwA/640?wx_fmt=png&from=appmsg "")  
  
可以发现直接接管了别人的账号，登录进了系统。  
## 6.内部系统存在sql注入导致rce  
  
![333.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNFo75oRbWaiaYN1qYfs79EUYnibjvac1JP9DY22icFZ01hPxmXdVlLqc0Q/640?wx_fmt=png&from=appmsg "")  
  
学校新出的一个平台，还是挺重要第一个平台，负责校内事务和档案的，应该还是个通用，很多学校都购买了这个平台。  
我在那个平台抓包的时候，这个数据包偶然出现在我的burp里，我一看，居然直接把sql语句写出来了，这不就可以直接利用了吗？  
  
![1233121)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNYIsYzzELOXgNWCwKDbqKgj6mwCVtu3VrJqLp0WCl0FHK0UH4yXW0icQ/640?wx_fmt=png&from=appmsg "")  
  
直接执行select user，可以看到右边直接进行回显了。那个user字段的内容就是回显的。  
  
后来我写报告的时候，怎么找也找不到这个包在哪抓的，没办法，只能转化思路去找js接口。  
  
![123321Vi(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xN5KBZ6Or9SBVaYA0DggZccSQ2UwzKcALa2OxXefGU1ApCofCgfllbBA/640?wx_fmt=png&from=appmsg "")  
  
可以看到这个data里有sql:t  
  
成功找到了这个接口，然后还有意外收获！  
  
![1111)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNHJQ0bp5GUS0Y7OoEhEMltOyvjQAr1iciapv4F20A62ib7X5nzachUAUxA/640?wx_fmt=png&from=appmsg "")  
  
![222bqB(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNtXVhNH1OtfgCApqEicIQ4NDTGeLc2wuw8FibEEjTiac2JEZFRe5Zd2G0A/640?wx_fmt=png&from=appmsg "")  
  
找到了近400个接口，这400个接口基本上都和上面的一样，直接写出了sql的语句，都可能存在sql注入！  
  
那么多接口，第一想法就是爬出来测一下未授权和越权。  
然后写了个爬虫python脚本去爬js  

```
import requests  
import re  
\# #proxy={'https':'127.0.0.1:8080'}  
\# url=&#34;&#34;  
\# headers = {  
\#     'cookie':'',  
\#     'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',  
\#     'Username':'',  
\#     'Accept':'\*/\*',  
\#     'Te':'',  
\#     'Priority':'u=',  
\#     'Sec-Fetch-User':'',  
\#     'Sec-Fetch-Site':'',  
\#     'Sec-Fetch-Mode':'',  
\#     'Sec-Fetch-Dest':'',  
\#     'Upgrade-Insecure-Requests':'',  
\#     'Referer':'',  
\#     'From':'dzj-pc'  
\# }  
\# def get\_html(url):  
\#     res = requests.get(url = url,verify=False,headers=headers,allow\_redirects=False)  
\#     # return res.content  
\# #  
\# html = get\_html(url = url)  
\# print(html.decode(&#34;utf-8&#34;))

```

  
爬出来之后，使用正则去检索我们所需要的东西：  

```
file = open('C:/Users/xxx/Desktop/111.txt','r')  
lines = file.read()  

apis=re.findall(&#34;url:\\&#34;(.\*?)\\&#34;&#34;,lines)  
for api in apis:  
if'?' in api:  
print(api.split(&#34;?&#34;)\[0\])  
else:  
print(api)

```

  
. 表示除\n \r 之外的任意单个字符  
* 匹配零次或者多次  
? 指定为非贪婪模式  
  
然后我们将收集到的api，放到burp里去批量访问  
  
![12(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNvTDU5iaw3o16gI8R8HGeMSHD42cnBMbJ9l321w5Q92scAx46b3Z3gdg/640?wx_fmt=png&from=appmsg "")  
  
但是没有跑出来，应该是没有未授权漏洞，做了全局验证，逐个删除cookie字段，但还是不行，没有cookie就被深信服的设备拦住了。  
  
那我们回到最开始的sql注入，该如何扩大危害呢？  
首先我们要判断数据库类型，于是我继续看js  
  
![122121GO(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNQCuxL3kCjpyszG058PERHnAZOq2E3Hib0Z4MJmMHVM8UWI2gNATNLgQ/640?wx_fmt=png&from=appmsg "")  
  
一开始看到了from dual，我以为是oracle数据库，然后尝试了oracle数据的sql语法，发现总是报错。  
后来再翻js数据包的时候，发现了这个包：  
  
![11111g(1)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNriaYfiblxgUWgorWyKyYfGW4GAXjxyyEz7oPP9Z9UAsV6XTiaUsE2FFMg/640?wx_fmt=png&from=appmsg "")  
  
这个数据包不仅直接暴露了usr_bsp，重要的是告诉了我们这个是postgresql数据库，这个数据库不太了解，我去百度了一下sql语法。发现他和mysql的语法差不多。  

```
select table_name from information_schema.tables where table_schema=''

```

  
![1111111)(1).png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNMnx0FTL4ZQq2icf10rSORoynLsYoBIMn6GhP5sISJBIX8r3XcMD9Gbw/640?wx_fmt=png&from=appmsg "")  
  
成功注入。然后在征得校方同意后，可以使用postgresql数据库的集成利用工具直接进行rce。  
  
至此，渗透告一段落。  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoMttntYglBBjtL5tbEeyjQxaibiablKM26xoGibI1Rc1QgOrQbDvia1suXA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUQdYy8cbrelcrYLiaUicG5xNN1VsWVsibmlskEib5RoAIMbglD8bhCXskoc3OSIiblzb5JAZkIfFeKMxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
