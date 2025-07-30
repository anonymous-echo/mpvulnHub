#  【Web渗透】SSRF漏洞原理   
Whoami  晨曦安全团队   2023-11-30 23:50  
  
 1、漏洞简介  
  
   
SSRF  
(Server-Side Request Forgery：服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的  一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。正是因为它是由服务端发  起的，所以它能够请求到与它相连而与外网隔离的内部系统。  
#### 1.1 漏洞原理  
  
 SSRF形成的原因大都是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与 限制。 通过控制功能中的发起请求的服务来当作跳板攻击内网中其他服务。比如，通过控制前台的请求远程地  址加载的响应，来让请求数据由远程的URL域名修改为请求本地、或者内网的IP地址及服务，来造成对 内网系统的攻击。  
#### 1.2 漏洞危害  
  
 1、扫描内网开放服务 2、向内部任意主机的任意端口发送payload来攻击内网服务 3、  
DOS攻击  
（请求大文件，始终保持连接Keep-Alive Always） 4、攻击内网的web应用，例如直接SQL注入、XSS攻击等 5、利用file、gopher、dict协议读取本地文件、执行命令等  
### 2、检测与绕过  
#### 2.1 漏洞检测  
  
假设一个漏洞场景：某网站有一个在线加载功能可以把指定的远程图片加载到本地，功能链接如下：  
http://www.xxx.com/image.php?image=http://www.xxc.com/a.jpg  
 那么网站请求的大概步骤应该是类似以下： 用户输入图片地址->请求发送到服务端解析->服务端请求链接地址的图片数据->获取请求的数据加载到 前台显示。 这个过程中可能出现问题的点就在于请求发送到服务端的时候，系统没有效验前台给定的参数是不是允 许访问的地址域名，例如，如上的链接可以修改为：  
http://www.xxx.com/image.php?image=http://127.0.0.1:22  
 如上请求时则可能返回请求的端口banner。如果协议允许，甚至可以使用其他协议来读取和执行相关 命令。例如   
http://www.xxx.com/image.php?image=file:///etc/passwd  
   
http://www.xxx.com/image.php?image=dict://127.0.0.1:22/data:data2  
 (dict可以向服务 端口请求data data2)   
http://www.xxx.com/image.php?image=gopher://127.0.0.1:2233/_test  
 (向2233端口发送数 据test,同样可以发送POST请求) 对于不同语言实现的web系统可以使用的协议也存在不同的差异，其中：php:  http、https、file、gopher、phar、dict、ftp、ssh、telnet... java:  http、https、file、ftp、jar、netdoc、mailto...  判断漏洞是否存在的重要前提是，请求是服务器发起的，以上链接即使存在并不一定代表这个请求是服  务器发起的。因此前提不满足的情况下，不需要考虑SSRF。  
http://www.xxx.com/image.php?image=http://www.xxc.com/a.jpg  
 前端获取链接后，是由js来获取对应参数交由window.location来处理相关的请求，或者加载到当前的 iframe框架中，此时并不存在SSRF ，因为请求是本地发起，并不能产生攻击服务端内网的需求。  
#### 2.2 漏洞出现点  
  
分享 通过url 地址分享文章，例如如下地址：  
http://share.magedu.com/index.php?url=http://127.0.0.1  
 通过url参数的获取来实现点击链接的时候跳到指定的分享文章。如果在此功能中没有对目标地址的范围 做过滤与限制则就存在着SSRF漏洞。  
  
 图片加载与下载 通过URL地址加载或下载图片   
http://image.magedu.com/image.php?image=http://127.0.0.1  
 图片加载存在于很多的编辑器中，编辑器上传图片处，有的是加载本地图片到服务器内，还有一些采用 加载远程图片的形式，本地文章加载了设定好的远程图片服务器上的图片地址，如果没对加载的参数做 限制可能造成SSRF。  
  
 图片、文章收藏功能   
http://title.magedu.com/title?title=http://title.magedu.com/as52ps63de  
 例如title参数是文章的标题地址，代表了一个文章的地址链接，请求后返回文章是否保存、收藏的返回 信息。如果保存、收藏功能采用了此种形式保存文章，则在没有限制参数的形式下可能存在SSRF。  
  
利用参数中的关键字来查找 例如以下的关键字：share wap url link  
  
src source target u 3g display sourceURl imageURL domain ...  
#### 2.3 漏洞绕过  
  
部分存在漏洞，或者可能产生SSRF的功能中做了白名单或者黑名单的处理，来达到阻止对内网服务和资 源的攻击和访问。因此想要达到SSRF的攻击，需要对请求的参数地址做相关的绕过处理，常见的绕过方 式如下：  
  
 场景1：限制为  
http://www.xxx.com  
 域名时 可以尝试采用http基本身份认证的方式绕过，  
http://www.xxx.com@www.xxc.com  
。在对@解析域名 中，不同的处理函数存在处理差异，例如：  
http://www.aaa.com@www.bbb.com@www.ccc.com  
， 在PHP的parse_url中会识别  
www.ccc.com  
，而libcurl则识别为  
www.bbb.com  
。  
  
场景2：限制请求IP不为内网地址 即限制访问所有内网IP，可采用短网址绕过，短网址转换。可以使用在线进制转换,  127转换16进制为7f，系统中表示16进制前面要加0x，8进制前加0  可以解析为127.0.0.1采用进制转换，127.0.0.1八进制：0177.0.0.1。十六进制：0x7f.0.0.1。十进制：2130706433  
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTrnjIMiatqB6Zgx0CXNk4wBCX5aY0QTNLoGYMXtasGn9vN5Qy7hze3CXw/640?wx_fmt=png&from=appmsg "")  
  
      
  
场景3：限制请求只为http协议 采用302跳转，百度短地址，或者使用短地址生成其他  
  
场景4：利用句号绕过 127。0。0。1 >>> 127.0.0.1 其他绕过形式可以查看：  
https://www.secpulse.com/archives/65832.html  
   
### 3、查看是否存在SSRF漏洞  
1. 排除法：浏览器F12查看源代码看是否是在本地进行了请求 举例：该资源地址类型为   
http://www.xxx.com/a.php?image=  
（地址）的就可能存在SSRF漏洞。2、Dnslog等工具进行测试，查看是否被访问 生成一个域名用于伪造请求，看漏洞服务器是否发起 DNS 解析请求，若成功访问在   
http://DNSLog.cn  
 上就会有解析日志。3、抓包分析发送的请求是不是由服务器的发送的，如果不是客户端发出的请求，则有可能是，接着找 存在HTTP服务的内网地址。4、访问日志检查：伪造请求到自己控制的公网服务器，然后在服务器上查看访问日志是否有来自漏洞 服务器的请求。5、扫描工具  
  
### 4、Pikachu演示  
#### 4.1 SSRF（curl）  
  
 首先我们大概了解一下在PHP中curl函数是用来干什么的。curl是一个库，能让你通过URL和许多不同种  的服务器进行交流，并且还支持许多协议，重点是可以用来请求Web服务器。curl可以支持https认证、 http  post、ftp上传、代理、cookies、简单口令认证等等功能。  
  
   
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTrqDIlFXxqJ2rLvevjPJCljy4XIoibnVf2R41oHrUic3XBAZUxm3PAMr0Q/640?wx_fmt=png&from=appmsg "")  
  
      
  
观察URL，发现它传递了一个URL给后 台  
  
我们可以把 url 中的内容改为百度   
http://127.0.0.1/vul/ssrf/ssrf_fgc.php?url=https://www.baidu.com  
   
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTr7LjLTM0aicgFicLvMcoVVwW58V2J4HtoVPC9WeZbtzOXibjcRsLJpBCkQ/640?wx_fmt=png&from=appmsg "")  
  
      
  
还可以利用file协议读取本地文件  
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTrkRSsnVxdnGf2609oYOjdB1xjhkIMJsJgZlheoPDyGumYlxYVskjmEw/640?wx_fmt=png&from=appmsg "")  
  
      
  
http://10.0.0.7:81/vul/ssrf/ssrf_curl.php?url=file:///etc/passwd  
  
#### 4.2 SSRF（file_get_content）  
  
file_get_contents() 函数把整个文件读入一个字符串中，是用于将文件的内容读入到一个字符串中的首  选方法。如果操作系统支持，还会使用内存映射技术来增强性能。php://filter：是一种元封装器， 设计用于数据流打开时的筛选过滤应用。 对于一体式（all-in-one）的 文件函数非常有用，类似 readfile()、 file() 和  file_get_contents()，在数据流内容读取之前没有机会应 用其他过滤器。php://filter  目标使用以下的参数作为它路径的一部分。复合过滤链能够在一个路径上指定。详细使用 这些参数可以参考具体范例。  
PHP: php:// - Manual  
  
  
file_get_contents里面带有php://filter 我们用这个就可以来读取php源码，所以我们来构造URL：  
  
http://127.0.0.1/vul/ssrf/ssrf_fgc.php?file=php://filter/resource=ssrf.php  
   
http://127.0.0.1:8000/vul/ssrf/ssrf_fgc.php  
? file=php://filter/read=convert.base64-encode/resource=ssrf.php  
  
直接使用 resource 指定 ssrf.php 文件，可以看到访问成功  
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTrFScTo00nUA5FCXdX0uQYRetiaQRKOXDyXNnZ5zUIIPHqYPgeQibz7pcQ/640?wx_fmt=png&from=appmsg "")  
  
      
  
但是php文件被解析了，我们希望拿到网站的源代码，那么我们需要对代码做一层编码，不让他解析， 拿到之后我们再进行解码，这样就拿到了网站的源代码；在read参数中加入 convert.base64-encode   
PHP: 转换过滤器 - Manual  
  
http://127.0.0.1:8000/vul/ssrf/ssrf_fgc.php?file=php://filter/read=convert.base64-encode/resource=ssrf.php  
  
然后网页出现了base64编码的代码  
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTrU0nB3QWBiaJubeouQ1rhGChLKGjOl0wo0rU47nTEKDk21cIJNagh1uQ/640?wx_fmt=png&from=appmsg "")  
  
      
  
利用解码工具或hackbar:  
  
       
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklygHzK0oc1Bdc1xoQ2MGMhTrNVia9QZib0WJerzbTtBRvBk9qAzXXoZicmSicT5a9WAtw2e70iaviaZaglug/640?wx_fmt=png&from=appmsg "")  
  
      
```
文章来源于互联网，只做学习交流，如有侵权请联系删除！原文链接：https://blog.csdn.net/Williamanddog/article/details/128816546
```  
  
      
  
