#  【干货总结】浅谈src漏洞挖掘中容易出洞的几种姿势   
 Z2O安全攻防   2024-10-28 20:58  
  
**0x1 前言**  
  
  
### 浅谈  
  
这篇文章主要是想跟师傅们聊下企业src包括平常的渗透测试和众测等项目中的一个拿分点，特别是如何让新手在挖掘企业src的过程中可以挖到漏洞呢，难点的或者好挖的漏洞都被大佬给交走了，那么小白挖src的方向在哪呢，还有冷门的漏洞挖掘方式怎么样，是不是可以挖掘到漏洞呢。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXtA6ehmIzsWeWib0Q9fZPRTsW3fYg76T5VdqKcw59B6oXjYm6QyiaGibSA/640?wx_fmt=png "")  
  
这篇文章也是和我那几个厉害的师傅那交流来的，然后主要是针对src小白在跟别的特别厉害的师傅一起搞漏洞挖掘或者众测的时候，比如我们小白可以有适合自己的一些”冷门漏洞”挖掘一套流程，然后去走相对简单的，可能这样的漏洞对于企业src来说危害不高，大多是个中危、低危，但是对于刚入手的小白来说还是可以去尝试下的！  
  
**0x2 漏洞一：SPF邮件伪造漏洞**  
  
  
### 一、SPF邮件伪造漏洞简介  
## SPF 记录是一种域名服务（DNS）记录，用于标识哪些邮件服务器可以代表您的域名发送电子邮件。  
  
  
SPF 记录的目的是为了防止垃圾邮件发送者在您的域名上，使用伪造的发件人地址发送邮件。  
  
原理:未设置spf导致的邮件任意伪造，可以用来钓鱼社工，本身就是高危  
  
若您未对您的域名添加 SPF 解析记录，则黑客可以仿冒以该域名为后缀的邮箱，来发送垃圾邮件。  
  
    
### 二、漏洞危害  
  
可以用未进行安全配置的网站域名，发送邮件。  
  
比如：www.baidu.com有这个漏洞，你就可以伪造HR@baidu.com给受害人发邮件进行钓鱼。  
  
src收的少，但是重测和渗透测试项目可以交。  
  
●  
注意：  
如果没有  
v=spf1  
或者  
没spf  
就存在邮件伪造漏洞。  
  
●-all 不能伪造，~all可以伪造  
  
### 三、测试漏洞  
### 我们直接拿baidu.com的域名来给大家演示下，用kali的nslookup 工具测试下  
  
可以看到下面的回显，存在spf记录，是-all参数，说明不能任意伪造。  
  
┌──  
(  
root  
-  
kali  
)  
-  
[~]          └─#   
nslookup  
-  
type  
=  
txtbaidu  
.  
com  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXZy2a8zJiayWBPgcJXTK96Smqc8Q8E2SzgUCK8RLYpkVuMwS0ympvhLw/640?wx_fmt=png "")  
  
还可以使用dig -t命令来测试      
  
┌──  
(  
root  
-  
kali  
)  
-  
[~]          └─#   
dig  
-  
ttxtbaidu  
.  
com  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXrAibZhu6RiaribmbuBdkqhMoWEvUePZdYlVF3icg9bBNblWzyib5ozOYG5Q/640?wx_fmt=png "")  
  
    
### 四、SPF解析不当导致绕过  
### 把下面的spf配置记录复制下来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXq0MVAQPMsFMlENqmfWktbpxpibIx1ibyjkOWBwcyjoWeTNugXhicKWuicQ/640?wx_fmt=png "")  
  
测试地址如下：  
  
SPF Query Tool  
 ：https://www.kitterman.com/spf/validate.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXH4bgDWjFnD7kGicoQJDAPu8vaF0A3bDccoRnVn3tGvICuMgTPHAc6PA/640?wx_fmt=png "")  
  
这里显示spf解析配置正确  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXFkiarn1MfVca8jApK3qCEP0BjEHjKrfouZwAQZwf9iaWN1zmAbernibVQ/640?wx_fmt=png "")  
  
下面拿一个存在spf解析错误的案例来演示下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXqOAK4yEfrDISTP8j4As6Jdxl0CO357Jz7c3jLy3h4n5Or2YmicBazMQ/640?wx_fmt=png "")  
  
SPF记录报错，在这条SPF记录中，存在多个IP段，但只有开头的一段ip用了ipv4，这就导致了语法错误。因为这个错误，将导致整个SPF记录完全失效，因为SPF无效，邮件接收方的SPF检测功能也就失效了。  
  
### 五、swaks测试  
### 使用kali自带工具swaks 测试      
  
swaks --body "helloword" --header "Subject:testT" -t 自己的邮箱 -f test@baidu.com          body为内容          Subject为标题          -t为目标邮箱          -f为伪造的发送方，这里我们伪造加了cn字眼，这里伪造改不明显字眼等都会进垃圾箱  
            
  
我们先申请一个临时邮箱：  
  
http://24mail.chacuo.net/书签：  
临时邮箱、十分钟邮箱（10分钟)、临时邮、临时Email、快速注册Email、24Mail--查错网  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXniahloNfFk5yhofFUyetYROsQQwephssNMiaxXBd7Z7aHaDsjKT518bg/640?wx_fmt=png "")  
  
  
然后我们使用kali自带的swaks 工具进行测试，结果如下  
  
┌──  
(  
root-kali  
)  
-  
[  
~  
]  
          └─  
# swaks --body "【2024年8月1日】 检测到您教务系统长时间未修改密码，请及时修改密码确保账户安全 手机管家@163.com  
          【该邮件自动监测请勿回复】  
" --header "  
Subject:vivo"   
-t  
 vioxzs43016@chacuo.net   
-f  
 customers@alexz.com  
            
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXA7QJwf6huPx2Jwc9TbcPUynib444oY2HIdcR3lGGP20Tic9IdgqohzQA/640?wx_fmt=png "")  
  
看到这里，我们要是对标题和内容进行改进，那么我们是不是就可以尝试钓一波鱼了呢？  
  
            
     
### 六、浅谈  
### 综上，当我们在查看一个域名的SPF记录时，它其实不只是一条解析记录，更是一种邮件安全的策略，SPF记录配置不严或SPF解析错误，就容易导致大量本该被拦截的邮件直接被放进来，而绕过的策略就隐藏在这条SPF记录里面。  
  
  
**0x3 漏洞二：sourcemap文件泄露漏洞**  
  
  
### 一、漏洞原理  
  
在日常测试时，经常会遇到以  
js.map  
为后缀的文件          这是jQuery中的一个新功能，支持Source Map          非常多  
Webpack  
打包的站点都会存在js.map文件          通过  
sourcemap  
可还原前端代码找到API，间接性获取  
未授权访问漏洞  
  
  
什么是Source map？           
简单说，Source map就是一个信息文件，里面储存着位置信息。转换后的代码的每一个位置，所对应的转换前的位置。         有了它，出错的时候，除错工具将直接显示原始代码，而不是转换后的代码,这无疑给开发者带来了很大方便。  
  
   
### 二、shuji工具还原前端代码  
### 使用nmp安装  
  
npm install --global shuji  
            
      
  
shuji  
命令执行  
  
shuji app.js.map -o desfile  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXk7Iiaf9XkjibrIMTEI6t46BD8MhuXbl3UgwxpsrJ5A6pbcCkHsd3RgGg/640?wx_fmt=png "")  
  
  
还原之前的js文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaX99M07N7pzbpgmH2C3lkJdapInWQJmFicWLgUXvty1rwgh5jrpGIJdibw/640?wx_fmt=png "")  
  
  
还原后的文件如下：  
  
那么后面我们就可以分析js代码，然后找找有没有什么js接口泄露，然后导致敏感信息泄露的漏洞，那么我们不就可以提交src或者众测了嘛      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXiaOibN8OzhcukHJECNDNHDFdFlf1YjYcSQZqM5Vo16alhPjYsvRiavt9Q/640?wx_fmt=png "")  
  
             
### 三、油猴sourcemap-searcher脚本  
### 功能：自动搜索网页有无sourcemap文件泄露  
  
油猴脚本：  
F12  
控制台输入  
sms()  
，如果存在会提示，然后打开看能否下载下来，能下载下来的话可以使用我们上面的  
shuji  
工具或者使用  
nodejs  
进行反编译，然后可以分析里面js接口去找别的漏洞，但是这个  
sourcemap文件泄露漏洞  
也是可以直接提交的。  
  
油猴sourcemap-searcher脚本安装位置如下：  
  
https://greasyfork.org/zh-CN/scripts/447335-sourcemap-searcher书签：  
sourcemap-searcher  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXb9kQsOcibeFVpmBEd4NAe7KODmr7VHPLFssTeBmiblUzma6KwGnK0fXA/640?wx_fmt=png "")  
  
  
这样就是按照该脚本成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXUdMrKgtIqAI5ncw9aoib11mFOUwdck7Q6WHVIbSP1BvbW4AQKuOxC5w/640?wx_fmt=png "")  
  
            
    
  
下面是我之前在挖src的时候，挖到的sourcemap的js.map文件泄露的漏洞  
  
然后就可以使用  
nodejs  
进行反编译了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaX6ib2lQXVnicZibN0bgLXibcgW2oBsDsFibLMcZMArGxic1bTUMGfh9QkibHyQ/640?wx_fmt=png "")  
  
     
### 四、src漏洞报告编写  
  
1.  
漏洞危害：  
Source map  
就是一个信息文件，里面存着位置信息。转换后的代码的每一个位置，所对应的转换前的位置。有了它，出错的时候，除错工具将直接显示原始代码，而不是转换后的代码，这无疑给开发者带来了很大方便。  
Webpack打包  
的站点会存在  
js.map  
文件,通过  
sourcemap  
可还原前端代码找到API，间接性获取未授权访问洞。  
  
2.  
漏洞复现：  
按照刚才的案例每一步都写好，怎么下载、怎么反编译、反编译出来的东西有啥敏感的都写清楚  
  
3.  
修复建议：  
删除web站点保存的  
.js.map  
后缀的文件。  
  
             
  
**0x4 漏洞三：jsonpxss漏洞**  
  
  
### 一、jsonp简介  
  
JSONP  
是服务器与客户端跨源通信的一种方法  
  
  
基本流程：网页通过添加一个script元素，向服务器请求JSON数据。服务器收到请求后，将数据放在一个指定名字的回调函数里传回来。可简单理解为jsonp是带有回调函数callback的json。  
  
局限性：仅支持GET请求，目前该方法已被主流废弃  
  
备注：其他解决跨域问题的方法——  
CORS、中间转发层、Nginx反向代理  
  
      
  
**使用工具：**  
burp插件jsonphunter  
JSONP(JSON with Padding)：JSONP是一种利用 <script>  
 标签加载外部资源的技术。它允许网页从不同的域中获取数据并进行交互，绕过了浏览器的同源策略限制。然而，由于缺乏安全验证机制，攻击者可以将恶意代码注入到返回的JSONP响应中，从而导致安全漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXYG2o12qeyOYWWsm9wLGoOm4Eg6VpyAdJRlD2BqzuXMFbPpnhq80Hicw/640?wx_fmt=png&from=appmsg "")  
  
  
### 二、jsonpxss漏洞条件  
### 条件一：返回content-type为text/html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXcDL49Mf5A2owHX11440ibyUrfRQTmQH5UjE5kL4sX0e664b9hB7xIag/640?wx_fmt=png&from=appmsg "")  
  
  
**条件二：get或者post中的callback参数可控**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaX27cYzO7g2RNNJhFv8picUW3iaeXehQRK8yuRSRIuVZ4rBrgtBtdO6cTg/640?wx_fmt=png&from=appmsg "")  
  
  
工具下载：https://github.com/p1g3/JSONP-Hunter  
  
参考文章：https://zone.huoxian.cn/d/318-burpjsonpcors  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXvWnjW5ictvndYCkDXzwKXjwRZeK7Nia5c7pQrCwTMicTvewhyT7AHp0HQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**0x5 图片验证码失效**  
  
  
### 一、图片验证码直接显示在返回包里面  
  
下面的修改密码的系统的可以看到下面的这个点击发送验证码，然后可以在那个返回包中可以看到直接返回了验证码字段，可以直接提交漏洞了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXxnShTRg78bZdC5eOjIp6SFN5C9njAlhg92A9yHSmDQnJAxAhcwiahibQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXzozTpmsl8wCXPhjjzf0iaaUbFGPnwAXUHx7MFMZlmCeib8FTylwicAY5g/640?wx_fmt=png&from=appmsg "")  
  
  
### 2、图片验证码字段可以删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXdrDegwR07qck9A7EHdibJMiaP4cmCPjvCOicWvC8wSS0CKWib4UQxgWP0g/640?wx_fmt=png&from=appmsg "")  
  
  
将数据包中的type字段改为0，并且删掉validCode=x5qs，即可发送短信
绕过了图片验证码机制，进行短信轰炸  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXeyWc17iaic9mDqGz6ZUYc3Aw3EJIF1QPgE8DwlRFZJWC5vHdOSTl6oUQ/640?wx_fmt=png&from=appmsg "")  
  
  
### 三、图片验证码永不失效  
### 图片验证码不失效，可进行爆破：该案例中第一次将图片验证码填写正确后，输入任意账户密码，点击登录进行抓包，报文中的code字段为图片验证码，直接爆破即可，此处图片验证码可无限复用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXoCXJdClsiaVyMqDQJ3NKQoXTI2KJFLaXebS7CGOygMVs7QRviapememg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXPNz7kBUEPibqWuS9YKDeoYnTqqtX4nK2TdviciasVGlicMZk4fHzgULx5w/640?wx_fmt=png&from=appmsg "")  
  
### 四、图片验证码拒绝服务漏洞（验证码dos）  
### 漏洞原理：  
  
开发者在网站开发过程中为了图片验证码能够适应网站在显示过程中的大小，从而加入了隐藏参数，当这个参数被攻击者猜测出以后攻击者就可以修改图片验证码、二维码的大小，让服务端返回的验证码无限放大，最终导致服务端生成的图片超级大然后网站停止服务。  
  
#### 如何测试：  
- 1、点击图片验证码进行抓包  
  
- 2、在请求后面拼接隐藏参数：height、width、size、mergin、h、w等实战过程中以h、w、height、width居多  
  
- 3、逐步增加大小例如：第一次:height=111 第二次:height=222，看burp会不会延时，或者直接看burp响应中的Render模块图片有没有变形  
  
**0x6 短信轰炸/验证码可爆破**  
  
  
### 一、短信轰炸  
###   
  
在注册页面，挂好代理，点击发送验证码，利用bp抓包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaX1moGJ9UArbNtOYGhiaeIWkCeWiaw51AFFKQJH0CK0R355gwrM1GZ85QA/640?wx_fmt=png&from=appmsg "")  
  
  
我们先go一下，发现验证码接收成功，但是第二次就显示短信发送过于频繁了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXqwiborxONGQBFV1Ta3ial8gnQ3Y0QO2Rf9hXV4Ceo4nRnUMtictX8ym7A/640?wx_fmt=png&from=appmsg "")  
  
  
但是经过测试发现，可以通过@、空格、+86、逗号等进行绕过，从而达到短信轰炸的漏洞危害：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXjj6feKibKcot0mTqMyXEv6XVBX7LFCcjR9bsNdlNiaib69Tg7vWIT5O8Q/640?wx_fmt=png&from=appmsg "")  
  
  
我们如果要把危害加大，达到一分钟短信轰炸达到几十条，那么我们就要利用bp的爆破了，我们手动添加多个绕过字符，然后爆破：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXD90VEffF0r052nicexsbKa6EUdib19h8aW65qElialAEdhLmLR3Ctu9icQ/640?wx_fmt=png&from=appmsg "")  
  
  
### 二、验证码可爆破  
### 查看我们接收到的短信，发现都是四位数，可以进行验证码爆破：  
  
经过burp的四位数验证码爆破，成功爆破验证码7774：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXbV3S7PyJwQgovcSzAMcOcJfDMBCAD3vOUINT5aJzI0QetOua50WLQQ/640?wx_fmt=png&from=appmsg "")  
  
  
### 三、、修复方案  
###   
1. 验证码绑定手机号：确保验证码只能发送到注册时提供的手机号，而不是通过其他途径发送。这可以防止攻击者利用特殊字符绕过验证码发送的限制。  
  
1. 限制验证码发送频率：在一定时间内限制同一手机号接收验证码的次数，防止短时间内发送大量验证码，从而防止短信轰炸攻击。  
  
1. 增加验证码有效期：确保验证码的有效期不宜过长，通常建议在几分钟至十几分钟之间。这样即使攻击者能够获取验证码，也有限制时间内使用。  
  
1. 加强验证码复杂度：增加验证码的复杂度，例如增加验证码位数、使用字母、数字和特殊字符的组合，以增加验证码被破解的难度。  
  
1. 限制相同IP地址或设备的访问频率：检测并限制来自同一IP地址或设备的验证码请求频率，以防止攻击者通过自动化工具进行暴力破解。  
  
##   
  
  
**0x7 任意用户注册漏洞**  
  
##   
  
我们先在注册页面，随机输入一个很随意的手机号用户，进行注册，然后利用bp抓包，我们需要抓两个包，一个是有手机号和需要输入验证码功能的包，还有一个就是利用手机号发送验证码的包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXFLHk37WXBTh32WnbsFfa2V1p4a0aNcWPscxtcywSXx8j2LE5pX4JQA/640?wx_fmt=png&from=appmsg "")  
  
  
  
下面这个是有手机号和需要输入验证码功能的包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXSWoFTNuDhcG8CObFT6yOI3MXAOAIMicwFEbT4z9pHP8jHuKlWeOHXkg/640?wx_fmt=png&from=appmsg "")  
  
  
  
下面这个数据包是利用手机号发送验证码的包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXOnIhRdibWKfa8JXTSyRmtM0EfIDgLOjme1VwI2FwtxH331YibYwuTHOA/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后就是发送验证码，并且利用bp抓的需要输入验证码的那个包进行验证码四位数爆破：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXoP7rZW6cibdLicgykeAJA33Ld25H4f5K3gC3B3EEwVkPZ2rV0JbeNSBA/640?wx_fmt=png&from=appmsg "")  
  
  
  
可以看到下面随便输入的手机号以及验证码code已经成功爆破出来了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXo9gPL4UtYTkwTxtDZUwISjrkfMpciarrh89CMzktYibfSicqzh6Apy1Sw/640?wx_fmt=png&from=appmsg "")  
  
  
  
可以发现，我们开始随便输入的一个手机号用户注册成功了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXzn8j1NypicnFv3xsJbJzJcsGpeNf7wMaJHcWXNpjwFMx6aML9bVA67w/640?wx_fmt=png&from=appmsg "")  
##   
  
  
**0x8 云安全存储桶相关漏洞**  
  
  
### 一、常见的ak/sk特征  
  
下面我给师傅们介绍下常见的几个厂商的 Access Key 内容特征，然后就能够根据不同厂商 Key 的不同特征，直接能判断出这是哪家厂商的 Access Key ，从而针对性进行渗透测试。其中我们云服务器常见的就是阿里云和腾讯云了，我主要给师傅们介绍下面两种Access Key的特点。  
#### 阿里云  
  
阿里云 (Alibaba Cloud) 的 Access Key 开头标识一般是 "LTAI"。  
```
```  
- Access Key ID长度为16-24个字符，由大写字母和数字组成。  
  
- Access Key Secret长度为30个字符，由大写字母、小写字母和数字组成。  
  
#### 腾讯云  
  
腾讯云 (Tencent Cloud) 的 Access Key 开头标识一般是 "AKID"。  
```
^AKID[A-Za-z0-9]{13,20}$
```  
- SecretId长度为17个字符，由字母和数字组成。  
  
- SecretKey长度为40个字符，由字母和数字组成。  
  
### 二、OSS存储桶接管漏洞  
  
比如常见的OSS存储桶漏洞，还有泄露ak/sk的相关敏感信息泄露的漏洞，然后可以看看是云安全OSS相关的敏感泄露，然后可以尝试下面的工具进行一个OSS劫持  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXGs0Mictpf1ZKg1rbGehiaNJ6MLVawJqWrbQoID4LiauiawoR6f1AvFn2dg/640?wx_fmt=png&from=appmsg "")  
  
比如在某配置详情里面找到了这个东西，这个也是OSS储存桶相关的漏洞，下面的url可以访问下，然后要是有回显的话，然后尝试使用下面的access-key和secret-key进行密钥登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXSib4UBonibnuIu1BuP11Q3Mp8rmyuaibAOFFYEkohk5QGmDLQsyppMMicQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
可以看到这里我直接就登录成功了，且里面都是云空间里面的存储东西，下面可以看到里面的日志信息等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXED7m42rDljIibibWHlVsxbnxUySF0nTB8icJmoeCorb3N6Q8ribHdqMDkw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXgMQxPUyTodaKaicFOLL3YJnLSu3BubTqlol8uwFgWZGD0605AstNEsw/640?wx_fmt=png&from=appmsg "")  
  
  
**然后还可以使用阿里云的OSS接管工具，如下：**  
  
https://github.com/aliyun/oss-browser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaXhWQyaZOpuGFoSvS8fyfU7vZaiavHNHoFYOUJxOONh0tjuqo4NOHXbAg/640?wx_fmt=png&from=appmsg "")  
  
直接输入泄露的access-key值，直接使用OSS连接工具就可以直接连接成功了  
  
里面有很多的该云主机泄露的信息，后面的内容就不给师傅们分析了，主要是接管云环境的一个思路的分享。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXX7S8NpcFRyia0td6w0oTiaX6QeLZ4zS8qJGwP11l6kfZribxrqZxjzXvPZ0paxdANA4oXlNjYTibuEw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x9 总结**  
  
  
## 无目标随便打，有没有自己对应的SRC应急响应平台不说，还往往会因为一开始没有挖掘到漏洞而随意放弃，这样往往不能挖掘到深层次的漏洞。挖到的大多数是大家都可以简单挖到的漏洞，存在大概率重复可能。所以在真的想要花点时间在SRC漏洞挖掘上的话，建议先选好目标。  
  
那么目标怎么选呢，考虑到收益回报与付出的比例来看，建议是从专属SRC入手，特别在一些活动中，可以获取比平时更高的收益。  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
