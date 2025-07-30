#  ssrf漏洞简单学习解析   
原创 【白】  白安全组   2024-01-13 10:49  
  
首先，ssrf漏洞是利用对方服务器执行，其漏洞的形成原因一般是因为web服务取引用了外部的文件或者url，服务器对于数据没有过滤或者检测是否合法性的话，这里黑客可以通过修改外部引用的东西实现ssrf攻击。  
  
案例1：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbpS49wo0M27wOFtib16SwHib5EFqeiaaJiaf7HhdKO6wxichO5M4Gdy2XZmYKbj9mZFiby8XibkwlIoHHjA/640?wx_fmt=png&from=appmsg "")  
  
这里是网站正常的url中引用了一个图片，我们这里可以修改为我们的一个外部服务器的图片地址，成功读取出来，那么这里就存在ssrf的漏洞，我们下一步就可以测试是否可以执行命令，比如ping一下dnslog，也可以替换图片达到一个钓鱼的效果  
  
  
案列2：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbpS49wo0M27wOFtib16SwHibRWHUzXpj9bJqNZibJmnb3Gp8obiaoyf03a3qRTAZBrx6AAJTqFTAEXVw/640?wx_fmt=png&from=appmsg "")  
  
上图中，百度翻译的软件，会引用外部的网址，然后进行翻译，这里我们就可以尝试ssrf漏洞  
  
  
总结：  
  
1、能够对外发起网络请求  
  
2、从远程服务器请求资源  
  
  
漏洞利用：  
  
ditc协议：  
  
本地利用：crul -v 'ditc://127.0.0.1:3306'  
  
实战运用，如果目标存在ssrf，我们就可以利用该协议进行  
  
远程使用，例：http://ip:8080/vul/curl.php?url=dict://ip  
  
  
file协议：  
  
file协议可以用来远程文件读取  
  
远程使用。例：   
http://ip:8080/vul/curl.php?url=file:///etc/passwd  
  
  
gopher协议：  
  
这个协议比较万能使用  
  
Gopher 是一种分布式文档传递服务。利用该服务，用户可以无缝地浏览、搜索和检索驻  
  
留在不同位置的信息。因为我们在有些场景下无法通过 get 的方式进行发起请求，但是我  
  
们又无法直接利用 ssrf 通过 http 协议来进行 post 请求，这种情况下一般就得利用  
  
gopher 协议来发起对内网应用的 POST 请求了，gopher 的基本请求格式如下。  
  
  
gopher://<host>:<port>/<gopher-path>_<TCP 数据流>  
  
正常构造，我们就使用：  
  
gopher://127.0.0.1  
/_POST /flag.php HTTP/1.1  
  
  
SSRF 在php中，以下函数使用不当就可能会存在ssrf  
  
curl_exec()  
  
从前端传来url，被后台的这个函数进行请求，然后再返回给前端  
  
Windows：file://c:\windows\win.ini  
  
Linux:    file:///etc/passwd  
  
  
file_get_contents()  
  
文件内容读取，支持php伪协议  
  
php://filter/read=convert.base64-encode/resource=fgc.php  
  
可以读取php的源码，通过base64模式进行读取  
  
  
fsockopen()  
  
这个函数的用处是打开一个网络链接，比如加载一个外部的网站，或者unix套接字的连接  
  
  
  
无回显测试：  
  
1、使用burp自带的一个检测  
  
该方式类似于dnslog，不过是burp自带的一种  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbpS49wo0M27wOFtib16SwHibYmOiboia0Iiclu9x3jfiaibJtuWwTxHULc0obCNHdSnnybCY9NcTyUk3y0g/640?wx_fmt=png&from=appmsg "")  
  
然后我们点击copy  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbpS49wo0M27wOFtib16SwHibKySUaic5SJoHb3Dun9u8EIONM51u70CeS3TdlDUzKGmicLUiaafbtkRlA/640?wx_fmt=png&from=appmsg "")  
  
我们会复制出来一个网址，应用就可以和dnslog使用的方式一样  
  
rrmu0u5axos7rcqfcr3zeh6fa6gx4m.burpcollaborator.net  
  
这种地址，我们使用之后，点击poll now就可以刷新出来  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbpS49wo0M27wOFtib16SwHibX0eVgN2fibnYO6OdR508lXIrg9z1DyypqIvlN2BA49Cnicic9oZYSJ6CA/640?wx_fmt=png&from=appmsg "")  
  
  
2、dnslog方式  
  
这里不多介绍，可以简单查询。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUZRz6ce7VYbFId6pibTLvH8a0T02O3BuGXiaZjHsN8zyMU1N7XxqzBpm9aZowpA64gluiao6ubSbkfsg/640?wx_fmt=jpeg "")  
  
  
  
  
**扫描二维码关注我们吧！**  
  
  
  
  
  
