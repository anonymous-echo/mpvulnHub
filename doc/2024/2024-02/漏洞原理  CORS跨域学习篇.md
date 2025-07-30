#  漏洞原理 | CORS跨域学习篇   
原创 zkaq - 帆先生  掌控安全EDU   2024-02-15 12:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
本文由掌控安全学院 - 帆先生 投稿  
# 0x01：原理  
  
**1、 什么是CORS**  
  
全称跨域资源共享，用来绕过SOP(同源策略)来实现跨域访问的一种技术。CORS漏洞利用CORS技术窃取用户敏感信息  
  
**2、 同源策略简介**  
  
同源策略是浏览器最核心也是最基本的安全功能，不同源的客户端脚本在没有明确授权的情况下，不能读写对方的dom、cookie、session、ajax等操作的权限资源。同源有三个条件：协议、域名、端口相同  
  
**3、 同源检测的示例**  
  
检测成功的之后同协议、同域名、同端口![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgy3viblquiaUCj2u8scCQibicwkQic5W13XTIa1El3d3yP28ybODNOXsBSofQ/640?wx_fmt=png&from=appmsg "")  
**4、 漏洞产生原因**  
  
由于配置不当，Origin源未严格，从而造成跨域问题。Origin用于检测来自哪个域  
  
**5、 两种跨域的方式**  
  
JSONP跨域请求    只能通过浏览器发送GET包，是一种利用HTML中<script></script>元素标签，远程调用json文件来实现数据传递技术，它的特点是可以跨域读取数据。  
  
CORS跨域请求  
  
    Cors允许浏览器向跨域服务器发出XmlHttpRequest请求，COSRS和JSONP的区别：CORS是JSONP的升级版，JSONP只能通过get方式请求，CORS支持get，post，head请求  
  
**6、 CORS的两种请求方式**  
  
简单请求浏览器直接发出CORS请求，即浏览器自动在请求的header中加上Origin字段，告诉浏览器这个请求来自哪个源。服务器端收到请求后，会对比这个字段，如果这个源在服务器端的许可范围内，服务器的响应头会加上以下字段  
```
 ·Access-Control-Allow-Origin：(这里的值为Origin的值)
 ·Access-Control-Allow-Credentials:true
```  
  
非简单请求  
  
预检请求，请求方式为OPTIONS，这个请求是来询问的，请求头要包含以下字段  
```
 ·Origin：请求源
 ·Access-Control-Request-Method：cors请求会用到的请求方式
 ·Access-Control-Request-Headers：cors请求会额外发送的请求头字段
```  
  
服务器收到预检请求后会检查上面三个字段的值确定是否允许跨区请求，如果任意一个字段不满足要求，都不允许进行跨域访问  
  
**7、 返回包头部的ACAO根据请求报文Origin生成**![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyfM9BH7dJmEZQqBVCTWlKLHZHJuou3jrNicg8IuXRN7IgZUic20dvEicXA/640?wx_fmt=png&from=appmsg "")  
  
  
**8、 CORS漏洞与CSRF漏洞**  
  
    相同点  
  
       (  
1  
)都需要借助第三方网站   
  
        (2)都需要借助ajax的异步过程  
  
        (3)一般都需要用户登陆  
  
    不同点  
  
        (1)第三方网站可以利用CORS漏洞读取到受害者的敏感信息  
  
        (2)第三方网站可以利用CSRF漏洞替受害者完成诸如转账等敏感操作  
  
**9、 简单的检测漏洞的方法**  
  
(1)选中Origin方法![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyntH9aDylibXzCjfjsQEXsg4sOjAt6DvVNLv19SibpGEpIfM5V1xTE0fg/640?wx_fmt=png&from=appmsg "")  
  
(2)然后来到历史，点击筛选器把方法写到红框处，进行筛选Access-Control-Allow-Origin: foo.example.org，剩下的就是可能存在CORS漏洞。发送的origin和返回的origin一样，acao为true，就存在漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyAYbIWVh2X1Sfwh0gPGzjfnbFmK86FEZtQnERH4Z7qoZEVDd2hRAicSA/640?wx_fmt=png&from=appmsg "")  
  
(3)Referer检查，这种情况下可以通过某处的xss漏洞进行绕过检查  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgydFL8unjKOMgclLGrrnrubwY3ia0sHfUyF9K2p3obplUhXA5Ro4BJhhA/640?wx_fmt=png&from=appmsg "")  
  
**10、 常见的漏洞点**  
  
    (1)互联网厂商的api接口    (2)聊天程序的api接口    (3)区块链厂商    (4)App的api  
  
补充：    CORS的规范中还提到了“NULL“源。触发这个源是为了网页跳转或者是来自本地HTML文件。    目标应用可能会接受NULL源，并且这个可能被测试者利用，任何网站很容易使用沙盒iframe来获取null源  
  
**11、 为什么服务端会有这样的漏洞**  
  
    开发人员开发，调试，测试代码一般都在本地,有时候他们会调用线上服务器数据,所以这样的问题很隐蔽也很常见。  
  
**12、 CORS防御**  
  
    (1)不要配置”Access-Control-Allow-Origin”为通配符”*”，而且更重要的是，要严格校验来自请求数据数据包中的”Origin”的值    (2)避免使用”Access-Control-Allow-Credentials:true”    (3)减少”Access-Control-Allow-Methods所允许的方法”  
# 0x02 本地环境搭建，获取信息  
  
我在本地写了4个文件其中demo1_1.html和demo2_1.php是本地服务器，demo3_1.php和sava.php是攻击者的脚本，需要钓鱼配合使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyxUSjgSYWS7nd1OtLPmHJRia2zurWhrGN2DPkw4xSSibQfXIjSI1kyTicw/640?wx_fmt=png&from=appmsg "")  
  
demo3_1.php代码  
  
第一个箭头下的链接是攻击者保存的地址第二个箭头下的链接是本地服务器的地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgym388cTkzhWic1wiclxETJBH5gUIcdT6vygukj8p23obiamibewPC2BKibWQ/640?wx_fmt=png&from=appmsg "")  
  
我到demo3_1.php去登陆  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyBMiahvUY7E7ia0uzmdZ1DRaHdovCCG4nG1fyhKA4ibkjuabrmyXxrU8pA/640?wx_fmt=png&from=appmsg "")  
  
他会跳转到demo2_1.php下，cookie也会带着到这里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgy60IDpicLrmmF7c9S7CEFNTMMvSY7GS3So5M4d9ZJslicDZZ6HW0APo8A/640?wx_fmt=png&from=appmsg "")  
  
这时就可以构造钓鱼邮件发送给受害者去点击刷新  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgy6G6TcWVxZISXIF3Hmqkdv4ibOxF2lpoVVicfhndQmBkCvX2RfmpHicCQQ/640?wx_fmt=png&from=appmsg "")  
  
F12查看，可以看到向外发起请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyeKBh30PDcNMlyb2NvjH1jAdpBQkVgsjdpRqOhDUWBicRjgibm8ick68Ng/640?wx_fmt=png&from=appmsg "")  
  
再回到文件处，发现创建了一个文件，这个文件里面就包含了所窃取的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyib2m5QDGib0gCfibgZ5AQHYIptPsK1wtDWQpKVgcmpXDlhFegXJfh0pEg/640?wx_fmt=png&from=appmsg "")  
# 0x03 实战演示  
  
Wordpress cors1、 复现过程  
  
影响版本：wordpress5.2.4。首先打开首页，抓包查看响应  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyYgXj6tj3HtQ9TI1JGZgYG4OdtIKSDTCLXaOFkYWknXsRZU8cDTAD6g/640?wx_fmt=png&from=appmsg "")  
  
看到返回包的内容，返回了wp-json链接，然后复制这个链接，补全这个url，可以看到返回出来的json数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyydrxTBK6npHAeppEpnyNZDfI3OkITk6W1DxZibnRpcrw33OchVYNtBw/640?wx_fmt=png&from=appmsg "")  
  
在请求包中加入origin头192.168.10.31，再次发送，发现响应消息中ACAO已经变成了origin的头，并且ACAC为true。从而证明了是存在cors跨域漏洞的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyTbxiaZGicCV5cZyxFs3pySWTBewHJGrRQia32taGRCGommm0YggZgM8yA/640?wx_fmt=png&from=appmsg "")  
  
生成一个HTML内容，放入vps下，起一个名字。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyuibeD03ibLWicrW29txah5uS07iabZHLQgNaCbuAWiaqzUOOFFJyl0nM0rg/640?wx_fmt=png&from=appmsg "")  
  
然后诱骗受害者点击，就会把json数据发送到你的服务器，从而获取对方的敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrLsmSTTQkHcicPe8yPoiaNgyibichWhmAfHuW7gMo4hxarOZ97dXFAgicN3A7iaFd5P3Gib8vgfv6d8DuOg/640?wx_fmt=png&from=appmsg "")  
  
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
  
  
