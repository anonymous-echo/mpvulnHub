#  浅析渗透实战中url跳转漏洞   
 船山信安   2024-12-15 17:00  
  
# 前言  
  
最近在一些厂商项目中开始接触到一些url任意重定向，虽然是低危，奖金较低，（虽然国外已经是几百$）但是一旦找到突破点，几乎整个站的url跳转都可以bypass，一个厂商所有点的url跳转加起来奖金也比较可观，所以将自己挖掘过程中一点点心得分享一下。  
# 简介  
  
先走个流程说些废话，url重定向漏洞也称url任意跳转漏洞，网站信任了用户的输入导致恶意攻击，url重定向主要用来钓鱼，比如url跳转中最常见的跳转在登陆口，支付口，也就是一旦登陆将会跳转任意自己构造的网站，如果设置成自己的url则会造成钓鱼，浅析危害。  
```
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> <form method="get" action="url.php"> <br><br><br><br> username: <input type="text" name="username"> <br><br> password: <input type="text" name="password"> <input type="submit" value="登陆" name="password"> </form> <?php $url=$_GET['redict']; echo $_GET['username']; if ($_GET['username']&&$_GET['password']) { header("Location:$url");exit; } ?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwmnFiaPb5NAhQJvPkSZXIgIEDiaa8c9chBjxLKD3vw8xnwQia3gOXIYztA/640?wx_fmt=png&from=appmsg "")  
  
最简单的代码实例，也是很贴近真实渗透的案例，登陆跳转，后面通常是加上自己业务的url，一旦存在url任意重定向，发送给用户，会毫不疑问的输入账号密码登陆，然后跳转到我们想要他跳转的url，比如：  
  
我们发送给用户这样的url，  
```
http://127.0.0.1/url.php?username=&password=&redict=http://127.0.0.1/fish.php
```  
  
用户正常输入账号密码登陆点击登陆。跳转到构造的页面。(我可真是个钓鱼鬼才)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwpXziafXq2UNWq2FibquHCjAaEDHKP5SLeSwEmThAHFAFkBIzGicvWN7pA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwNpZTrPP7Q2vBLicrCWIibGRRBgDd8ZAMnmQbFOlKL9CHCzkeCHNmPbXA/640?wx_fmt=png&from=appmsg "")  
  
当然钓鱼界面可以伪造一切你想获取的信息。  
# bypass  
  
其实bypass没什么新的套路(我暂时没)，都是网上有的，师傅们可以百度到的，我整理一下，利用上面的代码简单测试，都是本地测试通过的。www.xiaozhupeiqi.com是服务器要求跳转的url。  
  
1.最常用的一条：@绕过。  
```
http://127.0.0.1/url.php?username=1&password=1&password=1&redict=http://www.xiaozhupeiqi.com@www.baidu.com //ssrf也可用
```  
  
2.绕过一些匹配特定字符。  
  
？绕过  
```
http://127.0.0.1/url.php?username=1&password=1&password=1&redict=http://www.baidu.com?www.xiaozhupeiqi.com
```  
  
#绕过  
```
http://127.0.0.1/url.php?username=1&password=1&password=1&redict=http://www.baidu.com#www.xiaozhupeiqi.com
```  
  
3.斜杠/绕过  
```
http://127.0.0.1/url.php?username=1&password=1&password=1&redict=http://www.baidu.com/www.xiaozhupeiqi.com
```  
  
或者反斜线  
```
http://127.0.0.1/url.php?username=1&password=1&password=1&redict=http://www.baidu.com\www.xiaozhupeiqi.com
```  
  
4.白名单匹配绕过  
```
比如匹配规则是必须跳转，xiaozhupeiqi.com 域名下，?#等都不行的时候，如果匹配规则为xiaozhupeiqi.com，可以尝试百度inurl:xiaozhupeiqi.com的域名，比如 aaaxiaozhupeiqi.com，这样同样可以绕过。接下来实战中会用到，
```  
  
5.xip.io绕过  
```
http://127.0.0.1/url.php?username=1&password=1&password=1&redict=http://www.xiaozhupeiqi.com.220.181.57.217.xip.io
```  
  
会跳转到百度  
  
6.理想化方法  
```
如果有机会在自己的页面设置url跳转，比如目标网站的bbs论坛自己的资料页面设置url跳转，既然是服务器的网站，那么url是不会限制的，可以用一个漏洞去构造另一个漏洞。
```  
  
7.白名单网站可信  
```
如果url跳转点信任百度url，google url或者其他，则可以多次跳转达到自己的恶意界面。
```  
  
8.协议绕过  
```
http与https协议转换尝试，或者省略 http://127.0.0.1/url.php?username=1&password=1&password=1&redict=//www.xiaozhupeiqi.com@www.baidu.com http://127.0.0.1/url.php?username=1&password=1&password=1&redict=////www.xiaozhupeiqi.com@www.baidu.com//多斜线
```  
  
9.xss跳转  
```
这种就没啥说的了，就是XSS造成的跳转，下面也有案例，在有些情况下XSS只能造成跳转的危害。 <meta content="1;url=http://www.baidu.com" http-equiv="refresh">
```  
# fuzz几个参数  
```
redirect url redirectUrl callback return_url toUrl ReturnUrl fromUrl redUrl request redirect_to redirect_url jump jump_to target to goto link linkto domain oauth_callback
```  
# 实战几个案例  
  
1.最常见的登陆跳转  
  
登陆跳转我认为是最常见的跳转类型，几乎百分之七八十网站都会url里设置跳转，所以在登陆的时候建议多观察url参数，通常都会存在跳转至于存不存在漏洞需要自己测试。  
  
上面的类型四,  
  
漏洞url ：  
```
https://xx.xxx.com/User/Login?redirect=http://xxx.com/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwNP3icGKpBqOe3FZu4WMSYuGQstoP6Y1CTFRNpO3ldtjMW8CCa4NFX6Q/640?wx_fmt=png&from=appmsg "")  
  
为登陆页面，如果登陆成功那么跳转  
http://xxx.com/，但是所有方式都无法绕过，但是发现可以跳转aaxxx.com，也就是匹配规则为必须为xxx.com的网址，但是aaxxx.com同样也可以。  
  
方法：  
  
百度 inurl:xxx.com，即可百度到很多域名包含xxx.com的url，即可实现跳转,不小心百度到一个黄域，正好证明危害登陆跳XX网。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzw6IuRtxr6JiaicOvdb1jHMsJLhMkWu8arvoFU1b5HUoCh6nJRQPRDB4RA/640?wx_fmt=png&from=appmsg "")  
  
还有一些花里胡哨的base64加码了的跳转，解码就是需要跳转的url,其实本质都一样，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwVCla8hCk9Esx3OnZ75q3lbOaNGUquNDRCqryJ8WLXYfI91GOYnR6QQ/640?wx_fmt=png&from=appmsg "")  
  
2.@绕过  
  
@是最常见的一种绕过。  
  
漏洞url  
```
https://xx.xxx.com/user/goToLogin?toUrl=https://xx.xxx.com@www.baidu.com
```  
  
这种跳转在chrome浏览器可以直接跳转，但是在火狐会弹框询问，但是并不影响它的危害。  
  
火狐下@的跳转。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzw0qxXuazbpUfnHn44tG1wrcPXwjxwCgmBwmgvzkfbHiadu6swicDJ4WJg/640?wx_fmt=png&from=appmsg "")  
  
还有一些是跳转目录的，  
  
如：  
```
https://xx.xxx.com.cn/?redirect=/user/info.php
```  
  
修改为  
```
https://xx.xxx.com.cn/?redirect=@www.baidu.com
```  
  
这种情况通常@也可以跳转，大胆的去尝试  
  
3.充值接口跳转  
  
通常充值接口都会进行跳转，如充值成功会跳转到充值前访问的页面，因为充值接口需要充值才能知道到底存不存在漏洞，所以测试的人相对少一些，大胆去尝试，单车变摩托，充值完成后还可以提现其实并不影响，不嫌麻烦就多测测。这些都是跳转成功的案例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwpOJARWUw2afOy9SJsW90g46wuwBxeH1WYxePUrsvSIMQzdKJiaicjPtw/640?wx_fmt=png&from=appmsg "")  
  
4.xss造成的url跳转  
  
在一次渗透测试中，碰到一个站点，对<>"这些字符都是进行了过滤。且没有其他姿势配合，基本上告别了XSS等漏洞。如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwxZBJiaNNibux6Q6J7xY7gKDAEOlZGzG4XnIhFE4w3icavtWGiaYeueHVMQ/640?wx_fmt=png&from=appmsg "")  
  
可以发现我输入了xsstest<>"，但是<>被直接删除过滤掉了，但是发现双引号还在，先看下源码是怎么处理的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwYZJXc7KhwTqgT6BEmgypg6OFlx1ZEtz7L1NwSgMwhvZeBZnzdyjS9A/640?wx_fmt=png&from=appmsg "")  
  
乍一看双引号也被转义了，输入的xsstest 搜索有十七处，大部分被实体化了，还有一部分双引号被url编码了，但是此时突然发现我箭头指的一处并未对双引号进行转义或者过滤，虽然<>已经完全被过滤掉了。  
  
此时构造meta的url跳转。  
  
payload：  
```
http://xxx.com/search?w=1;url=http://www.baidu.com" http-equiv="refresh&fsearch=yes
```  
  
其中输入  
```
1;url=http://www.baidu.com" http-equiv="refresh
```  
  
最终闭合掉得到的源码为。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwhz3XwjgugxiciacdkLic6v2AdwHvm4pJQxnxkiamX9icKwUwHuYicoA0btRQ/640?wx_fmt=png&from=appmsg "")  
  
最终点击payload会跳转百度页面，其实这个严格意义上来说算XSS造成的跳转，构造应该也可以XSS。  
  
5.业务完成后跳转  
  
这可以归结为一类跳转，比如修改密码，修改完成后跳转登陆页面，绑定银行卡，绑定成功后返回银行卡充值等页面，或者说给定一个链接办理VIP，但是你需要认证身份才能访问这个业务，这个时候通常会给定一个链接，认证之后跳转到刚刚要办理VIP的页面。  
  
通常这个点都会存在跳转至于存不存在任意跳转，师傅们自测,有些跳转业务不好码就不发了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwrnrGnXpsibtsw6nZ1D3ngyBMnNDs95bfMSkg0icMRuAiaWH1tWdvHPCIQ/640?wx_fmt=png&from=appmsg "")  
  
6.用户交互  
  
在一些用户交互页面也会出现跳转，如请填写对客服评价，评价成功跳转主页，填写问卷，等等业务，注意观察url。  
  
问卷调查提交跳转。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzw1y5RS7vJ91e0qrdvNvME2YeFhTQU4x6FNFAHqLXBL0NeoeVHfb2boA/640?wx_fmt=png&from=appmsg "")  
  
7.漏洞构造漏洞  
  
一次渗透测试中碰到一个任意文件上传漏洞，但是不幸的是没办法解析任何后端语言，没办法进一步利用，只能前端造成一点危害，但是存放文件的服务器一般比较偏远，此时可以利用我们任意文件上传的html，然后来进一步利用，绕过本来无法绕过的url跳转漏洞。因为存放文件的域名肯定是符合网站跳转范围。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwhkQCy1gU8QVOpKke0zkv7F93OXaV9ADSmfQOr4trltwhxXLT9ANrUA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNETZINR2lxmkzGopmMDSzwUWUbLiaJkmNPnqibiahmdMPnvmbModgxRB5HGa2N1hk44ibFwYWicma69ow/640?wx_fmt=png&from=appmsg "")  
  
最终构成url跳转漏洞，当然可以获取cookie造成更多的危害，本文仅讨论url跳转。  
  
来源：https://xz.aliyun.com/  感谢【  
小猪佩琪  
】  
  
