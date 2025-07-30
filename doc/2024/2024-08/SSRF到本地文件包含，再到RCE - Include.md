#  SSRF到本地文件包含，再到RCE - Include   
原创 M1n9K1n9  APT250   2024-08-10 20:53  
  
## TryHackMe - Include  
  
使用服务器利用技能来控制 Web 应用程序。  
  
  
1.SSRF（服务器端请求伪造） SSRF（Server-Side Request Forgery）是一种网络攻击方式，攻击者利用应用程序的功能直接向服务器发起请求。此类攻击通常通过欺骗应用程序去访问内部或外部资源，从而获取敏感信息或影响服务器行为。  
  
2.本地文件包含（LFI） 攻击者构造请求来访问本地文件。这种类型的攻击被称为本地文件包含（LFI，Local File Inclusion）。通过LFI，攻击者可以读取服务器上的敏感文件，获取环境变量，用户凭证等。  
  
3.远程代码执行（RCE） 如果攻击者成功利用LFI，并且应用程序允许特定文件（如PHP文件、日志文件）被执行，攻击者可能还会进一步实现远程代码执行（RCE，Remote Code Execution）。这意味着攻击者可以在服务器上运行任意代码，从而完全控制目标系统。  
## 外部主动信息收集  
### nmap  
  
循例nmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAz3THbYT7WNRFlic4NCPj2IktBicFLJpE13VgBCBYetGGpRjkmxfiaeBLw/640?wx_fmt=png&from=appmsg "null")  
## Web枚举  
### 4000端口 - 目录扫描  
  
feroxbuster扫  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkALKNUgrllHA9tQZXgj47gticicPfW9Z9vfxmXbKRcaP3m9f8Kzrv8JlGA/640?wx_fmt=png&from=appmsg "null")  
### 50000端口 - 目录扫描  
  
feroxbuster扫  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAgB8oD18OaqaHhWhpGcMnKzcpLQ1sXLHny4HVe1LyUlblEPpEmHqvCg/640?wx_fmt=png&from=appmsg "null")  
### 4000端口 - 越权  
  
可以通过直接修改url的id访问到其它用户信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAtbJEp6dmTukdubLiaEuasdMjyEvRwKIOjmRtpnujvZjj7zQIticK3zTQ/640?wx_fmt=png&from=appmsg "null")  
  
不过这并没有提供更多信息，但有一个引人注目的字段属性isAdmin  
  
但很遗憾我们已知的三个用户都不是admin  
  
经过id枚举也依然没有枚举出更多用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAMVG6KpmA34whvasoCUtd2fBYuZgnIumwBpnkVIVyTzrZOknXEjXZlg/640?wx_fmt=png&from=appmsg "null")  
  
在profile的最下面有一个表单，随便输点东西并提交它，发现可以新增字段，并且可以修改原有的字段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAdIiaR6mPjibeaDib6332N50fkI2pGGicreU6qOMKzyaoQ3FBuAJqBibJYVg/640?wx_fmt=png&from=appmsg "null")  
  
那么接下来就是常规操作，直接修改guest的isAdmin字段为true，看看权限是否发生变化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAbjITNOtjVzDxPTGyTYXPmCRm33icPEwmmmLxQfibdE286pricBXD9QnZw/640?wx_fmt=png&from=appmsg "null")  
  
当我们刷新页面后，我们的页面右上角将会出现我们期待的东西  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAHtuewzAZDaH0oaE974tZicWaNNVReQgUOwBh37vxTrFBCHECpZPZF8A/640?wx_fmt=png&from=appmsg "null")  
## SSRF  
  
有个开在内网的api  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAQjMibmJSIeVf0nvaNS9jj17MkvC5pH4slu97QqCDzN8N8GmMtnSibicyQ/640?wx_fmt=png&from=appmsg "null")  
  
在setting中可以看到可以设置url，服务端将访问url下载image  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkA731lrLIocdcoZoQ5ttCMMKOHnScWl5npW1Rsm71sGBNxo31CaIZt8Q/640?wx_fmt=png&from=appmsg "null")  
  
随手开个nc，没有问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAzBcMte0ibpRKADJG5eiakJXDU9nibxZP9hPJibGkuol5fPUXYEwcnL6I8A/640?wx_fmt=png&from=appmsg "null")  
  
给个.php文件，发现它把文件内容读了出来，并且进行base64  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkASuCg06b4u1xsKtiaylOWibpzkxvZgQpEF2zCn1KUgttudQObAmaGOWtw/640?wx_fmt=png&from=appmsg "null")  
  
那么思路也很显而易见了，直接访问internal api获取administrator的密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAjTXAkZYGciaUHMiabXjksItCKIWFojPyndRFpW5Wickhrb3AKQxVia5GtA/640?wx_fmt=png&from=appmsg "null")  
  
有了它我们能够访问50000端口的sysmon，同时拿到第一个flag  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkA83tys6IPPH05xGLghXicKkqXX69srG99PKaEq6rQYzGRnDG09npMQwQ/640?wx_fmt=png&from=appmsg "null")  
## LFI -> RCE  
  
burp logger可以看到profile.png图片是通过文件包含出来的  
  
但这里有过滤，不过只是简单的进行了两次的../replace，进行三次../就能绕过去  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAD22KjYGxrjBTmKexxzpPffZicl0c1Egly2h6giadtcJ2LiatKLUeoagog/640?wx_fmt=png&from=appmsg "null")  
  
但没有日志  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAwoQe8q1Tg1nWg6Xib5yAHs46xGzlEnr3y7hu6YVf164JbBXAibIpmqAA/640?wx_fmt=png&from=appmsg "null")  
### RCE  
  
在最初的端口扫描中，存在smtp、pop3、imap那一堆服务，并且在最开始我尝试用户枚举但并没有什么结果  
  
现在我们可以尝试读smtp的日志文件/var/log/mail.log  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAj3c2fDdI8OPBe2BKZO2V1iaFpiaJibxwrCkSwFcnUiaBbUIfrqkGQRVa3A/640?wx_fmt=png&from=appmsg "null")  
  
没有问题，接下来就是常规的登录恶意用户名达到控制log文件内容从而实现rce  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAoLssZ9LKyVaugpHIZkERLaPgPEPic8Hkarosiasia7UgTpGiaeXmicpIxNQ/640?wx_fmt=png&from=appmsg "null")  
  
php代码能够被解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkAaFFgnv05icJwYQg1K9WTIL3QWzBic4eYk6Fkw0hpEoxoblqGEWPxOl1A/640?wx_fmt=png&from=appmsg "null")  
  
直接读flag下机  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/loXw5QEJ2z6UM2ib7q8fQI3lIIawPibvkALWCZxvicYo0gqWvP0TeFX3tZlKymF4d6STzkmHteHf9hTzTicvWb3mDA/640?wx_fmt=png&from=appmsg "null")  
  
  
