#  渗透测试之RCE无回显利用方式   
 渗透安全团队   2023-11-25 10:10  
  
前言  
  
在测试的过程中，经常会遇到RCE漏洞没有回显的情况，这种不能直接在页面上看到命令执行的结果，本篇文章来看看遇到这种情况如何去利用。  
  
由于本人水平有限，文章中可能会出现一些错误，欢迎各位大佬指正，感激不尽。如果有什么好的想法也欢迎交流~~  
## RCE无回显常见利用方式  
- 反弹shell  
  
- dnslog外带  
  
- http请求外带  
  
- 页面返回时间判断  
  
- 盲写webshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHg4UUVDQFpPB6KXNuotW2cIXy7UkNlE6ckWVU0CXfF6bRrSTlIaiaq4IHzHLfz53l2rjTToDxESfQ/640?wx_fmt=jpeg&from=appmsg&random=0.6883624271724502 "")  
## 反弹shell  
  
无回显的命令执行，最常见的方式就是反弹shell。因为它虽然不会将命令执行的结果输出在屏幕上，但实际上这个命令它是执行了的，那我们就将shell反弹到自己服务器上，然后再执行命令肯定就可以看到回显了  
  
关于反弹shell，不同的操作系统反弹方式也是不同的，总体来说linux上比较简单，而win上则稍微麻烦一点。  
  
在linux下可以使用下面的命令进行反弹shell  
```
```  
  
win下的反弹shell可以看这篇文章：https://www.freebuf.com/articles/network/375572.html  
## http外带信息  
  
可以使用wget或者curl命令去访问一个http服务，把要执行的命令隐藏在header头或者数据包的其它地方，在被访问的服务器中去查看该条日志。  
  
如下：使用wget将命令回显信息通过包头数据字符串User-Agent传输至攻击服务器上，xargs echo代表去掉各个分隔符，换行符等符号输出  
```
```  
  
此时就可以去查看web日志或者dnslog平台上的http请求记录，可以看到请求的数据包，数据包中就包含执行的命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHg4UUVDQFpPB6KXNuotW2cUqWZH4ksibiaibxibhHQA9eJ6NxTEAWm105Xvle4k5NibV5KqSQuEU52TGw/640?wx_fmt=jpeg&from=appmsg&random=0.19702789087034156 "")  
## DNSlog外带  
  
有的服务器是不允许http协议访问外网的，但是一般不会对DNS协议做限制，可以使用DNSlog日志外带数据，  
缺点就是dnslog一般只能带出一条数据，需要对结果进行编码等操作。  
  
dnslog就是我们发起请求的目标不是IP地址而是域名的话，就一定会发生一次域名解析，那么假如我们有一个可控的二级域名，那么当它向下一层域名发起解析的时候，我们就能拿到它的域名解析请求。这就相当于配合dns请求完成对命令执行的判断。  
  
不同的操作系统对命令的解析方式不同  
```
```  
  
对命令进行编码  
```
```  
  
如下面的操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHg4UUVDQFpPB6KXNuotW2c1ledbXeafmxssza7Lgqia5y48SGju10O8oxemD1tEu2UEyBmI3edhCg/640?wx_fmt=jpeg&from=appmsg&random=0.20134242706173255 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHg4UUVDQFpPB6KXNuotW2cndMSosox0nuR7PAdvJc0yZnRAnv5bicl4mTmxicu5WBeSD1BZZaZ0uSA/640?wx_fmt=jpeg&from=appmsg&random=0.26028183258781046 "")  
  
在win上常用的系统变量如下，可以先外带这些环境变量然后再进一步进行利用  
```
```  
## 页面返回时间判断  
  
无回显时还可以通过页面的返回时间来进行判断，一般我们在sql注入中经常见到这种方式，在RCE漏洞中也可以使用。  
  
如下面的命令：  
```
```  
## 盲写webshell  
  
如果上面的方式都不能用，我们也可以考虑盲写一个webshell。  
  
我们知道webshell如果想要使用，就  
必须知道webshell的绝对路径，然后实际情况下我们往往不知道路径。那么此时要怎么去操作？  
  
这里一个思路就是  
首先在系统中找到一个可以访问的静态资源，一般为图片，如flag.png，我们可以根据系统命令去查找这个文件所在的位置，然后将webshell写入到与此静态文件相同的目录中。  
  
linux下盲写的命令  
```
```  
  
win下盲写命令  
```
```  
  
如下图，可以往该目录下写入一个php文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHg4UUVDQFpPB6KXNuotW2cvU0Z0WNdEC5eVp8HbXtRq0xf5yMNYK4sg28oSeibSAfKYOBSbLvfqXA/640?wx_fmt=jpeg&from=appmsg&random=0.6630852038892017 "")  
## 总结  
  
除了上面的一些常见的方式以外，还有其它的如ICMP协议外带等等，一般最常用的就是dnslog外带以及反弹shell。  
## 参考链接  
  
https://cloud.tencent.com/developer/article/1956480  
  
https://www.freebuf.com/articles/network/321428.html  
  
```
来源: https://www.freebuf.com/articles/web/382776.html
```  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CKksEIzZyEb3tEFGzGYSXfribrG4jKOkRKGKYb7zk7MTNZPT6Wp3bLd2BPhuFHddIL6sqrg1d2qHQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8D0bS8ibc3XhFcDYkVusFvc3c6onthQpPGZn4v32rpOp7CeFiamGdeC7JBk0mGVsiciazLp3z0SIJAtnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
