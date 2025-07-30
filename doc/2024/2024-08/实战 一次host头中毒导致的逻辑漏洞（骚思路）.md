#  实战| 一次host头中毒导致的逻辑漏洞（骚思路）   
 橘猫学安全   2024-08-07 14:51  
  
翻到某安全公众号时，发现的一个骚思路。  
  
  
有些网站开发者会提取request包里的host头来获取域名信息，但是host头可以被修改，是不可信的。  
于是攻击者可以通过构造host头来进行投毒攻击。  
  
例如发送包含受害者网站域名链接的功能，像是密码找回、发送验证链接等，只要业务上利用了类似于域名提取的功能，都可以尝试利用该攻击方法。这里以密码找回为例，进行一次host头投毒攻击。  
## 示例  
##   
## 某网站存在密码找回功能，本例使用host头中毒来实现任意用户密码重置。打开密码找回界面，填写受害用户的邮箱，在最后的提交按钮用burpsuite截断，把host头更改成自己的服务器IP：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSEM3XSnU9ZJLoAoicuuFqPjmYsdSm6vYcM5yga3bUDr8TsjAye7ibapRC4EyMFib3vTKVy6q8icOC8Zcw/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
之后放行数据包，会提示找回密码邮件发送成功的信息，此时受害者邮箱会收到一封邮件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSEM3XSnU9ZJLoAoicuuFqPjmIMiavoKIa4QfGzU7sHiakicZBAcGG0eGYTUIpVJnxNSbTibBDXqzhw6giag/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
可以看到，域名已经改成了我们在host头填写的服务器地址。这时受害者如果访问该链接，则会在我们的服务器上留下一条记录：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSEM3XSnU9ZJLoAoicuuFqPjmfrQ25gWtwuA0GL3Y1PzRMmnlJelSc4L1fvvVKjQV2Y37Q18T7FFiazw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
在把原域名和日志抓取到的url拼接一下，就能得到受害人的密码重置链接了。  
## 后记  
## 这个漏洞是1click的任意密码重置漏洞，利用了host头中毒的思路，我个人感觉还是比较新颖的。不过像大厂安防策略都会对request头数据进行检验，遇到不在白名单的域名直接会拒绝访问。  
  
## 补充阅读  
##   
## 这个漏洞是1click的任意密码重置漏洞，利用了host头中毒的思路，我个人感觉还是比较新颖的。不过像大厂安防策略都会对request头数据进行检验，遇到不在白名单的域名直接会拒绝访问。  
  
# 什么是HTTP Host头？  
#   
# 从HTTP/1.1开始，HTTP Host头就是强制性的请求标头。比如我们要访问这个URL时 http://www.xxxx.com/web 浏览器会编写个Host标头的请求，"GET"请求的是页面的相对路径，"Host"就是主机头，请求的是域名或服务器地址：  
```
GET /web HTTP/1.1
Host：www.xxxx.com
```  
#   
# HTTP Host头有何用处？  
#   
# HTTP Host头的目的是帮助识别客户端想要与哪个后端组件通讯。  
  
伴随云和虚拟主机的普及，单个Web服务器可以托管多个网站或应用程序。尽管这些网站都  
有各自不同的域名，但很有可能共享服务器同一个IP地址，这种情况下就需要通过Host头来进行区分了。  
# 如何利用Host头来进行攻击？  
#   
# 如果网站没有以安全的方式来处理Host值的话，就极易受到攻击。一般Web应用程序通常不知道它们部署在哪个域上，当它们需要知道当前域时，很有可能会求助于Host头。如果服务器完全信任Host头，没有验证或转义它的值，攻击者可以把有害的Payload放入其中，当应用程序调用的时候，有害的Payload可能就会传导进去造成“注入”。  
  
而这种漏洞可以造成包括：  
  
**Web缓存中毒、特定功能的业务逻辑缺陷、基于路由的SSRF、SQL注入等**  
# Bypass  
#   
# 通常来说，很少有站点会出现上面这种完全放开的现象，一般或多或少都有些过滤机制，但如果过滤做的不好，就会存在被绕过的可能性。  
```
1.忽略端口的检验
某些过滤检查只验证域名，会忽略Host头中的端口。如果我们可以在Host头中写入非数字端口，就可以通过端口注入恶意Payload。
GET /example HTTP/1.1
Host：Website.com:bad-stuff-here

2.允许任意子域
如果应用系统允许其域名下任意的子域通过，在这种情况下，可以通过子域来绕过验证。
GET /example HTTP/1.1
Host：hacked-subdomain.Website.com

3.注入重复的Host头
有的时候我们可以添加多个Host头，而且一般开发者并没有预料到这种情况而没有设置任何处理措施，这就可能导致某个Host头会覆盖掉另一个Host头的值
GET /exampleHTTP/1.1
Host：Website.com
Host：bad-stuff-here
如果服务器端将第二个Host头优先于第一个Host头，就会覆盖掉它的值，然后中转组件会因为第一个Host头指定了正确的目标而照常转发这个请求包，这样就能绕过中间组件将Payload传递给服务器。

4.提供绝对URL
正常情况下，"GET"的请求航采用的是相对地址，但是也允许使用绝对地址，就是将原本Host的值拼接到相对地址前面构成绝对地址，这样就可以利用Host头进行注入。
GET http://Website.com/ HTTP/1.1
Host：bad-stuff-here

5.添加换行
有时候还可以通过使用空格字符缩进HTTP头来进行混淆，因为有些服务器会将缩进的标头理解为换行，而将其视为前面头值的一部分，有些服务器会完全忽略缩进的HTTP头，因此不同系统处理HTTP头可能会存在不一致的现象。
GET /example HTTP/1.1
Host：bad-stuff-here
Host：Website.com
如果前端忽略缩进的头部，这个请求会被作为普通请求来处理。假设后端忽略前导空格优先考虑第一个Host头，这种不一致性会导致Payload的注入。

6.利用可覆盖Host的请求头
有一些请求头的值是可以覆盖Host的值的，比如X-Forwarded-Host，当我们发出这样的请求时就会触发覆盖
GET /exampleHTTP/1.1
Host：Website.com
X-Forwarded-Host：bad-stuff-here
可以达到相同目的的还有这些头
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
```  
# 如何预防Host头攻击？  
#   
# 要防止HTTP Host头攻击，最简单的方法就是避免在服务器端代码中完全使用Host头，不进行任何引入。如果确实要使用Host值的话，还有些其他的方法：  
```
1.保护绝对URL
2.验证Host头
3.不支持Host覆盖头
4.白名单允许的域
5.小心使用仅限内部访问的虚拟主机
```  
```
转自博客：https://k1nm0com
HACK学习呀
作者：洞爷湖
```  
  
如有侵权，请联系删除  
  
**推荐阅读**  
  
[实战|记一次奇妙的文件上传getshell](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495718&idx=1&sn=e25bcb693e5a50988f4a7ccd4552c2e2&chksm=c04d7718f73afe0e282c778af8587446ff48cd88422701126b0b21fa7f5027c3cde89e0c3d6d&scene=21#wechat_redirect)  
  
  
[「 超详细 | 分享 」手把手教你如何进行内网渗透](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495694&idx=1&sn=502c812024302566881bad63e01e98cb&chksm=c04d7730f73afe267fd4ef57fb3c74416b20db0ba8e6b03f0c1fd7785348860ccafc15404f24&scene=21#wechat_redirect)  
  
  
[神兵利器 | siusiu-渗透工具管理套件](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495385&idx=1&sn=4d2d8456c27e058a30b147cb7ed51ab1&chksm=c04d69e7f73ae0f11b382cddddb4a07828524a53c0c2987d572967371470a48ad82ae96e7eb1&scene=21#wechat_redirect)  
  
  
[一款功能全面的XSS扫描器](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495361&idx=1&sn=26077792908952c6279deeb2a19ebe37&chksm=c04d69fff73ae0e9f2e03dd8e347f35d660a7fd3d51b0f5e45c8c64afc90c0ee34c4251f9c80&scene=21#wechat_redirect)  
  
  
[实战 | 一次利用哥斯拉马绕过宝塔waf](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495331&idx=1&sn=94b63a0ec82de62191f0911a39b63b7a&chksm=c04d699df73ae08b946e4cf53ceea1bc7591dad0ce18a7ccffed33aa52adccb18b4b1aa78f4c&scene=21#wechat_redirect)  
  
  
[BurpCrypto: 万能网站密码爆破测试工具](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495253&idx=1&sn=d4c46484a44892ef7235342d2763e6be&chksm=c04d696bf73ae07d0c16cff3317f6eb847df2251a9f2332bbe7de56cb92da53b206cd4100210&scene=21#wechat_redirect)  
  
  
[快速筛选真实IP并整理为C段 -- 棱眼](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495199&idx=1&sn=74c00ba76f4f6726107e2820daf7817a&chksm=c04d6921f73ae037efe92e051ac3978068d29e76b09cf5b0b501452693984f96baa9436457e4&scene=21#wechat_redirect)  
  
  
[自动探测端口顺便爆破工具t14m4t](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495141&idx=1&sn=084e8231c0495e91d1bd841e3f43b61c&chksm=c04d6adbf73ae3cdbb0a4cc754f78228772d6899b94d0ea6bb735b4b5ca03c51e7715b43d0af&scene=21#wechat_redirect)  
  
  
[渗透工具｜无状态子域名爆破工具（1秒扫160万个子域）](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495099&idx=1&sn=385764328aff5ec49acddab380721af0&chksm=c04d6a85f73ae393ffab22021839f5baec3802d495c34fb364cbdd9b7cb0cf642851e9527ba7&scene=21#wechat_redirect)  
  
  
  
**查看更多精彩内容，还请关注**  
**橘猫学安全**  
  
  
**每日坚持学习与分享，觉得文章对你有帮助可在底部给点个“**  
**再看”**  
  
