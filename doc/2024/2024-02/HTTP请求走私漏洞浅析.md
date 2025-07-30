#  HTTP请求走私漏洞浅析   
原创 zkaq - sumor  掌控安全EDU   2024-02-12 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
本文由掌控安全学院 -  sumor 投稿  
## 0x00 前言  
  
HTTP请求走私漏洞(HTTP Request Smuggling)是发生  
协议层的一种攻击，最早于2005年就被发现并提出。漏洞发生的主要原因是不同的服务器，对于RFC标准的具体实现不一而导致的。  
## 0x01 漏洞原理  
  
HTTP 1.1协议相对于1.0主要引入了两个新的特性:   
Keep-Alive和  
pipline  
  
1、Keep-Alive特性具体是指在HTTP请求头中，添加一个参数  
```
Connection: Keep-Alive

```  
  
告诉服务器在收到这个请求后不要关闭连接，后面再次发起请求时，继续使用这个TCP连接。  
  
2、pipline特性是指在一次TCP连接中，可以连续不断地发送多个HTTP请求，而不必等待服务器响应。服务器会根据顺序进行处理。  
  
有了这两个特性之后，HTTP 1.1相对于 HTTP 1.0来说，传输效率更高，如今HTTP 1.1也应用最为广泛。  
  
在RFC 2616中规定，一个完整的数据包中需要在请求头部分包含”Content-Length”或者”Transfer-Encoding”来对数据包的长度进行说明。  
  
1、Content-Length: 指明数据包的内容长度，一个字符长度为1，回车(\r\n)长度为2。如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79Jo1zztJ0tclMnsO42BviaJ1dkqLVTKuSB5YpB1nMNlI47jLBjGwP1ibBg/640?wx_fmt=png&from=appmsg "")  
  
这个数据包的请求长度为10:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79J5W9NqAh95lZY9Bwsth0UJ6gHTiaK1Sp4AeC8KMEF920b5z964BhZiaEQ/640?wx_fmt=png&from=appmsg "")  
  
2、Transfer-Encoding: 当值为chunked时，服务器在读取到  
```
0\r\n\r\n

```  
  
后就会认为该请求已经结束。  
  
而之后的内容会存在于服务器的缓存中，和下一个请求一起发送给服务器。  
  
HTTP请求走私漏洞的核心就在于前端和后端对于请求的长度判断不一而引起的。  
  
如当前端使用Content-Length来判断，而后端使用Transfer-Encoding:chunked来判断时，我们构造一个请求如:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79J5HHKU2404WibeMuPjkkl5pJ448fiaFO4PChnubIGOq4t01Be9zYJRGFg/640?wx_fmt=png&from=appmsg "")  
  
前端认为请求长度为6，会将所有内容转发给后端，而后端读到”0\r\n\r\n”后就认为请求已经结束，因此最后一个”G”就会留到缓存服务器中，被拼接到下一个请求的开始，如  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JzXVnmbpAYx24x7ibEZZibiakRj4oyXetibjtlWYWjt3C51CJNDv2vCSDcA/640?wx_fmt=png&from=appmsg "")  
  
这样当下一个正常用户发起请求时，就会返回错误，因为服务器并不认得”GPOST”是什么请求方式。  
  
这就是一个简单的HTTP请求走私攻击的例子。  
  
上面这个例子中，前端使用Content-Length判断，后端使用Transfer-Encoding:chunked判断，因此属  
于CL-TE类型，与之对应的还有  
TE-CL、  
TE-TE。  
## 0x02 漏洞复现  
  
利用工具:Burpsuite  
  
需要在Repeater中关闭更新Content-Length  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JdkjAMuQhxau7cB4NIa2kEqicFezYhiaLKRgVz1hVs0ibO37hxMqcrJFeA/640?wx_fmt=png&from=appmsg "")  
  
以burp靶场CL-TE为例 : https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te  
  
正常访问:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JFF1acjshAGSNUNuiamibX7JicI30VbeON1bCpQ7qBfy7arBemxjnnWLUw/640?wx_fmt=png&from=appmsg "")  
  
开启抓包，将请求改为POST方式  
  
构造请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79J8Ix2NEf1So5X12gvIGnDVInfdicSZSufMDNK9EQoHaj3K14gchs1AoA/640?wx_fmt=png&from=appmsg "")  
  
放包。当下一个用户访问这个页面时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79J6t1d8YxibWvD8YrA5rEw8O8lD2Q7EEebv5FOdYNBopibOqAcEzoR5hlQ/640?wx_fmt=png&from=appmsg "")  
## 0x03 扩展  
  
根据以上原理，我们可以更改下一个正常访问用户的请求内容，包括Cookie信息等。因此可以扩展出危害更大的攻击，如获取服务器敏感信息、获取用户登录信息、能交互的反射型XSS等。  
## 0x04 缓解措施  
  
对于前端，对所有请求进行规范化，避免模糊请求。  
  
对于后端，拒绝掉一切模糊请求。  
  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**没看够~？欢迎关注！**  
  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+靶场账号**哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[Xray挂机刷漏洞](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247504665&idx=1&sn=eb88ca9711e95ee8851eb47959ff8a61&chksm=fa6baa68cd1c237e755037f35c6f74b3c09c92fd2373d9c07f98697ea723797b73009e872014&scene=21#wechat_redirect)  
  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[代码审计 | 这个CNVD证书拿的有点轻松](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247503150&idx=1&sn=189d061e1f7c14812e491b6b7c49b202&chksm=fa6bb45fcd1c3d490cdfa59326801ecb383b1bf9586f51305ad5add9dec163e78af58a9874d2&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
