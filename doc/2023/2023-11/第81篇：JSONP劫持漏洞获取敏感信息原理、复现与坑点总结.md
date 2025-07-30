#  第81篇：JSONP劫持漏洞获取敏感信息原理、复现与坑点总结   
 迪哥讲事   2023-11-27 23:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9LbcCCMJ6Af2WYicgMPA32IwibF8mI2ibC9h8jaHkhxnZzZuqctMLRTxDudicA/640?wx_fmt=png "")  
##  Part1 前言   
  
**大家好，我是ABC_123**  
。今天我们研究一下JSONP劫持漏洞，早些年这个漏洞主要被攻击者用来窃取个人信息，如姓名、身份证号、家庭住址等，**现在更多的用于蜜罐之中，间接溯源红队攻击者的个人身份**  
。好多朋友至今对这个漏洞理解不深刻，能发现能利用，但是就是不明白原理，有时候别人能复现成功，但是自己却怎么都复现成功。今天ABC_123搭建一个tomcat环境，用java代码写了几个servlet复现并讲解一下这个漏洞，收获不少，也踩了不少坑。  
  
**注：**  
关于javascript的同源策略问题，我很久之前的一篇文章《[第40篇：CORS跨域资源共享漏洞的复现、分析、利用及修复过程](http://mp.weixin.qq.com/s?__biz=MzkzMjI1NjI3Ng==&mid=2247484757&idx=1&sn=f0ca932aa275de2b86516920221c2d8c&chksm=c25fca2ef5284338b328519c32e62ae90beecbbb93ef94f0e7735f44cf5633bd18733302aaa9&scene=21#wechat_redirect)  
》写的很清楚，大家可以重新阅读一下，这里就不过多叙述了。  
##  Part2 技术研究过程   
- ## JSONP基础知识  
  
首先，JSON与JSONP是两个概念，JSON是一种比较流行的数据格式，用于在不同应用程序之间传输和存储数据。JSONP是在CORS出现之前，解决跨域请求的技术，可以让网页从不满足同源策略的其它域名获取数据；JSONP是json的一种使用方式，可以让当前网页跨域从别的域名获取数据，**它利用了<script>标签的src属性不受同源策略影响的特性**  
。  
  
当网站通过JSONP方式传递用户的敏感数据时，攻击者可以搭建一个第三方网站，网页内部嵌入JSONP链接，并嵌入恶意的JS代码，一旦受害者用户浏览此网站，自己的敏感信息会在毫不知情的情况下被攻击者事先构造好的js代码窃取，这就是今天我们要讲解的JSONP劫持漏洞。  
  
- **环境搭建过程**  
  
##   
  
首先编写一个servlet页面，可以让用户使用用户名密码登录并会保存cookie，模仿生产环境中用户登录后的状态。JSONP劫持要想获取受害者敏感数据，受害者前提一定要登录过网站，并且没有注销登录，这样在攻击者在实施JSONP劫持攻击时，浏览器会自动带上用户的Cookie，从而获取敏感数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelvuxv3AaQfLYJ26NDtE80JIgeuVU2wkpL3btmwSibbeBboewklOPomew/640?wx_fmt=png&from=appmsg "")  
  
  
编写一个GetUserInfo页面，返回JSONP格式的数据，其中包括用户的敏感数据身份证号、姓名、密码等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelsapTShjdxHKt0FhjlAWWXTpZpLvDpYt2uO8wTfck9neuhiapUmVWUeQ/640?wx_fmt=png&from=appmsg "")  
  
  
如下图所示，生成war包并部署到tomcat中，浏览器中输入用户名密码admin:123456，提示登录成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blel2ic31lN8CnswPztQX5h878Dpvzv46MXyoeLs34E6VpYzMpVXiaWFtViaw/640?wx_fmt=png&from=appmsg "")  
  
  
访问以下URL路径，模仿正常网站，返回我们自己填入的个人信息。  
  
http://192.168.237.1:9999/Servlet/GetUserInfo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelXatEd50JfZE55driaBIRicQ725pQxaC1kiaHeSiaByysxW1IQKxNV2AVRg/640?wx_fmt=png&from=appmsg "")  
  
  
接下来我们传入**callback**  
参数，正式模仿JSONP劫持，发现当前JSONP页面返回了一个符合javascript标准的代码格式，test111()相当于一个JS函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelEpJMqXmpUicghdV5TQPVxBaKLplwoQVibCGmJohqeickwZtZ2YxNlQgGA/640?wx_fmt=png&from=appmsg "")  
  
- **JSONP劫持漏洞测试过程**  
  
接下来模仿攻击者构造一个JSONP劫持漏洞测试页面，如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelFV395xkicfNeC2VXpYo3upuJOICnibebogiaXm7MhvMKMCpXECicicXjkmg/640?wx_fmt=png&from=appmsg "")  
  
  
其中user111222是要回调的函数，  
  
<script src=”http://192.168.237.1:9999/Servlet/GetUserInfo?callback=user111222”>   
  
  
这里相当于加载了一段JS代码，而这段JS代码就是  
  
user111222({"identitycard":"370688022919880819","password":"P@ssw0rd","username":"李四"})  
  
  
随后js引擎会继续在当前页面寻找user111222函数，顺便带入执行  
alert(JSON.stringify(dat  
a));  
代码。  
  
  
**很多文章没有给出上述描述，造成很多新手始终不理解JSONP劫持漏洞原理**  
。  
于是我们用谷歌浏览器chrome测试一下，发现返回空白页面，并没有弹出用户的敏感数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blel1w1UHj6Gw648icV06SxmbZia8J5ZibYpeqJgyctp6kID6mIoRjmicEWe5w/640?wx_fmt=png&from=appmsg "")  
  
  
这是为什么呢？ABC_123从头到尾检查了一遍代码，发现应该是没有问题。**于是我用抓包软件抓了一下数据包，发现http请求包居然没有cookie**  
，在没有cookie的情况下，当然不会返回敏感数据了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelSzrtCVJ34LKWpXSydXxicf1lhgPia7jZddEQdnWNKKbNAMR0LMdcZpQA/640?wx_fmt=png&from=appmsg "")  
  
  
联想到之前测试CORS跨域资源共享漏洞，猜想是不是谷歌浏览器对JSONP劫持做了防范。于是我换了一个老版本的firefox浏览器测试一下，发现JSONP劫持漏洞测试成功，我作为一个受害者，访问了攻击者的  
http://192.168.237.128:8888/jsonpHack.html  
页面，弹出一个信息框，说明我的个人信息可以被获取。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelCaibP2ibXoOLRsRGicTa5KQcccW6zr7VGXpnsvQoI9h8A00glrQovZd0A/640?wx_fmt=png&from=appmsg "")  
  
  
此时我们用抓包软件抓取一下数据包，发现对于Firefox老版本的浏览器，会自动带上cookie的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelOva89R7RKSxciaYibqI3qvSuopGrHw18TDHIlCxHYA3oHc6Cpib17bCmA/640?wx_fmt=png&from=appmsg "")  
  
  
接下来再测试一下IE11，发现仍然JSONP劫持漏洞仍然可以测试成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelcfG94muNxQK3iajLWmtuQkU4gGibwypibAmYWGPLtP1dLQ8kfza1PPv0Q/640?wx_fmt=png&from=appmsg "")  
  
  
综上所述我们发现，**对于JSONP劫持漏洞，较新的浏览器或者部分浏览器从根源上进行了防范**  
，这种漏洞的危害性在不久的将来会逐步减低。  
##   
- ## JSONP劫持漏洞修复建议  
  
**1.**  
 接受请求时检查referer来源。  
  
**2.**  
  在请求中添加token并在后端进行验证。  
  
**3.**  
  严格过滤callback函数名及JSON里数据的输出。  
  
**4.**  
 使用CORS替换JSONP跨域功能。  
  
**5.**  
  严格过滤callback函数名及JSON里数据的输出防止产生XSS漏洞。  
  
**6.**  
严格安装JSON格式标准输出Content-Type及编码（ Content-Type : application/json; charset=utf-8 ）。  
  
**7.**  
在callback输出之前加入其他字符(如：/**/、回车换行)这样不影响 JSON 文件加载，又能一定程度防御JSONP劫持攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CX9kdZP7gu0Wgoqez0blelboKhrFGiaNZl4PZnlK4ZH6CVeTQvU29VMvqyXjrXHEE5ibfP3AvWBZDA/640?wx_fmt=png&from=appmsg "")  
  
##  Part3 总结   
  
**1.**  
  最新版的谷歌浏览器Chrome对于JONSP劫持攻击做了防范，这也是为啥很多JSONP劫持漏洞别人能复现成功，而有的人却始终复现不成功的原因。这标志着JSONP劫持和CORS跨域资源共享漏洞危害性会逐步降低。  
  
**2.**  
  想要理解一些web漏洞原理，还是得自己搭建环境，自己写代码从头到尾梳理一遍，从根源上理解这个漏洞，踩过坑后才发现原来是这么回事。  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
