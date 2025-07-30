#  DVWA靶场保姆级通关教学   
原创 Z1eaf  泷羽Sec-Z1eaf   2025-02-20 13:36  
  
# DVWA介绍  
  
DVWA(Damn Vulnerable Web Application)  
一个用来进行安全脆弱性鉴定的PHP/MySQL Web 应用，旨在为安全专业人员测试自己的专业技能和工具提供合法的环境，帮助web开发者更好的理解web应用安全防范的过程。  
  
另外，DVWA 还可以手动调整靶机源码的安全级别，分别为 Low，Medium，High，Impossible，级别越高，安全防护越严格，渗透难度越大。  
# Brute Force  
  
一个登录页面，先随便输入账号密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL41kJQMLHMVW0ttl2ypXibpqs5qAbsaVxYc0e2a4yxebNN0P3BgPEHPEQ/640?wx_fmt=png&from=appmsg "")  
## Low  
  
使用burpsuite拦截数据包，发送到Intruder  
模块，在username  
和password  
处添加playload，然后载入字典，开始攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4r4ruqnpOpAnvxXmcRibv4r7LewHylNQibqtwLjnjlcp01o3vCDUZ3wIg/640?wx_fmt=png&from=appmsg "")  
  
爆破成功，账户/密码：**admin/password**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ic1FnvU4D67yYqy2iadKDyTZQ7uiaPA1aSPxib7ZVcKTjsWJ8HzJSYO38g/640?wx_fmt=png&from=appmsg "")  
## medium  
  
这一关的操作步骤与Low  
的是一样的，使用burpsuite拦截数据包，发送到Intruder  
模块，在username  
和password  
处添加playload，然后载入字典，开始攻击  
  
区别就是：源码中增加了mysql_real_escape_string函数  
，这个函数会对字符串的特殊符号进行转义，基本上能抵御SQL注入。此外，该关卡的爆破速度明显下降，这是因为有sleep()函数  
，在破解失败后，程序会停止运行两秒钟。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4WA07bibC8gibhEtPibMYpPDoibeAvr4aIVwLR1q72SlWPeRLxibCk8icyW5w/640?wx_fmt=png&from=appmsg "")  
## High  
  
输入账号admin  
，密码随意，然后使用burpsuite拦截抓包![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4MfTJicXibvk8l8lCoibfyyUXZLrbicz5V04jW3va30Cvdhicl96ktxkYX9A/640?wx_fmt=png&from=appmsg "")  
拦截包，对其进行查看，我们可以发现存在token  
验证的情况![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4nu2BU74ibJYPT0fEMkQBQqhfZGq0sia6J5yPlSMnPa4L7Bhxar07rNuw/640?wx_fmt=png&from=appmsg "")  
  
### 设置playload位置  
  
数据包被拦截后，发送到Intruder  
模块，添加playload位置，选择攻击模式：Pitchfork  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4hQ037ZAfJG6DjSPeTkGMBiczhqDqODaNNUvFGQG24gtrwgKnVRocL2Q/640?wx_fmt=png&from=appmsg "")  
### 载入playload1  
  
playload1位置为密码  
，我们载入密码字典  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4lzXvooBvFwX4LMCKmIjhhUrBXMjgr8I4UI3NGF59xQY1IiaRV6TwIrw/640?wx_fmt=png&from=appmsg "")  
### 载入playload2  
  
playload2位置为token  
，我们选择递归提取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4mbEFBxcC3sB3E2icS8xicV4EUk53hsxLmmG8oE7MLLNDnxDdYiaAEQjIw/640?wx_fmt=png&from=appmsg "")  
  
然后，我们去该模块设置处，找到检索-提取  
，点击添加  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Wic2icbwSMwBKOUxljq2yVgW26nmWHQ2aHibpj6DCQY0NichyhhTYkz6dw/640?wx_fmt=png&from=appmsg "")  
  
接着点击获取响应  
，找到token  
的value值  
，选中它且复制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4uofA5gul0aZSCibicjCjPZJY1ZF7qm6Y7hMiaIwjhRcb3KQmLjbutCuyA/640?wx_fmt=png&from=appmsg "")  
  
回到playload2处，我们将复制的value值粘贴  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4fCJR5mWJRFUBFexu2jCRYmhM8DSMrZGahApkhnctO1zJJiaMuFs9icYw/640?wx_fmt=png&from=appmsg "")  
### 设置线程  
  
然后在爆破模块的options  
设置好网络重试次数为0，避免token错位  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4bfkibDZP5ovYE5c0VgABmK4bRoKI7AQpQF2yO2XcmsXDDicDQtiaUD5yA/640?wx_fmt=png&from=appmsg "")  
  
然后设置好重定向  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4dQk808KaO0N7SI7ibIHC4pCRRMsF9HKogMM6Rib8IQvgWeCVWDODtgKg/640?wx_fmt=png&from=appmsg "")  
  
紧接着，在资源池  
设置好最大并发数为1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4dQk808KaO0N7SI7ibIHC4pCRRMsF9HKogMM6Rib8IQvgWeCVWDODtgKg/640?wx_fmt=png&from=appmsg "")  
  
开始攻击，完成爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4cUZTrvCBdIyKp10tTzzWv6UicUkaCkeCCx2uW9Gic570EsqLOblJekYQ/640?wx_fmt=png&from=appmsg "")  
# Command Injection  
## Low  
  
观察页面，让我们输入IP地址，对其进行ping  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4DkguBeKE9PGlFfPTRB14Y6RxetemWXhKlDPO8Yk3xxJwPPmC9mtib4w/640?wx_fmt=png&from=appmsg "")  
我们输入127.0.0.1  
，点击提交，发现返回的数据和我们在cmd执行命令：ping 127.0.0.1  
回显基本一样。 乱码原因可能是网页编码问题  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4lVulUolvhrewXR7GiacD0y1YeYfaicP3f3ia9Ofp63ENclDmCliaB3ISJg/640?wx_fmt=png&from=appmsg "")  
### 解决乱码方法  
  
打开根目录，找到dvwa/inclides  
目录下的的dvwaPage.ini.php  
文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4VJ1dWv5ACgGE8w2ENhjk6kMgHmdHBZp20pl9BD97AOjTmlwFG2BbZw/640?wx_fmt=png&from=appmsg "")  
打开文件，搜索utf-8  
，将其替换成GBK  
或GB2312  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4D6HzkoLU5DjoRIicrxfDRxROlR6YXk3ibUVoxb3BpWfQulDYHC6IqrEg/640?wx_fmt=png&from=appmsg "")  
刷新页面，解决乱码情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4x0HNl4YTvFaHqVBLiakaf2L3picrEhnbXgZ9DpWMvUU3Z87zph0f14fw/640?wx_fmt=png&from=appmsg "")  
### 回到关卡  
  
我们知道这是执行ping  
命令，所以我们使用命令连接符来进行执行命令注入。  
  
**常见的命令连接符**  
- &  
 ：前面一个命令无论是否执行，后面的命令都能执行，两个命令都执行  
  
- &&  
：前面一个命令执行成功后，才能执行后面一个命令，两个命令都执行  
  
- |  
：前面一个命令无论是否执行，后面的命令都能执行且只执行后面一个  
  
- ||  
：前面一个命令不能正常执行后，才能执行后面一个命令  
  
我们使用“|”符号作为连接符让计算机做出除ping以外的操作实现命令注入  
```
127.0.0.1|dir
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ZbRqmLBRVLibQoQCUX53qY4ooiaiazWA6GoeicLLh2P1hdfa4KdY9QDAJg/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
我们分析一下源码，看看和Low级的关卡有什么区别  
  
我们可以看到源码把&&  
和；  
过滤了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4K4OFfqbuJGqyHBNGaUOQibeia0cOPZI7T9lglROIzDJ4psw0RBUWqxgw/640?wx_fmt=png&from=appmsg "")  
那我们使用&  
或|  
还是可以的  
```
127.0.0.1&dir127.0.0.1|dir
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4dkCQic0mNtFUZpsrndYJ6pmUnCKnMRV9xHQ9jBum3E4rHQ8HjN98PJQ/640?wx_fmt=png&from=appmsg "")  
## High  
  
老套路，分析源码  
  
我们仔细观察可以发现在过滤|  
时，后面接了一个空格，所以过滤的是|   
，这意味着这个过滤其实是是没有用的，因为，我们只需要在|  
后接上命令，不保留空格，我们依然可以使用这个命令连接符进行命令注入![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4BxnYuykkyv3O9iaGW3eFk8iaFxnwl3gba397EcBP8BcubaBbD7kVXsqQ/640?wx_fmt=png&from=appmsg "")  
  
```
127.0.0.1|dir
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ZTxgUib0OZibE87ibRPuhtmdLoFHDGN9IpyNtiblT2Z1mhakKRTP8tria8g/640?wx_fmt=png&from=appmsg "")  
# CSRF  
## Low  
  
这一个的网站是让我们修改密码，那我们先输入密码，点击提交  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL45EpRg8icUwHtDnAtsBHFKmDhswHNx1Sf9aNZP6zTnsfGRcbSlwEiclwg/640?wx_fmt=png&from=appmsg "")  
  
提交后，使用burpsuite抓包，我们分析数据包，发现是Get  
请求，URL显示password。![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4kahIupocFPGAaVcYBfrL8N6oUYD53YP5GIyBYWBoWr455b9QSiaBsqw/640?wx_fmt=png&from=appmsg "")  
  
  
为了更直观的利用CSRF漏洞，我们复制这个URL，然后修改password  
```
dvwa:9998/vulnerabilities/csrf/?password_new=456789&password_conf=456789&Change=Change#
```  
  
然后在新标签中输入修改后的URL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4NXegh2tichA8uhzhgeAQLX9K3iaPNpCxE9d70SLdqdpsLWABRaIk0rMA/640?wx_fmt=png&from=appmsg "")  
  
修改密码成功，CSRF攻击完成  
  
网站的本意是希望用户在网站内更改密码，而我通过控制url的传参就能使我能在网站之外执行更改密码的操作。那么当我知道一个网站有csrf漏洞后也可以通过构造url的方式让别人点击执行他意想之外的行为  
## Medium  
  
查看源码，发现多了一处验证，通过验证Referrer  
字段来验证请求是否从网站本身发起的，若不是就不执行后续操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4WpWvJ7BjbrdwndDlDQ6qVvKG7HxWpicc7Hc4YHlHF6cbGpgdA9riciasw/640?wx_fmt=png&from=appmsg "")  
  
输入账户密码，然后使用burpsuite进行抓包，分析数据包，我们可以看到referrer字段是网页路径![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4l4S1HkQmVbeGZOWZEICYNZuq3Lmar4k0BeCVec02cuxMSS410IibEPg/640?wx_fmt=png&from=appmsg "")  
  
  
既然如此，那我们就构造一个页面，在html文件内放入一个a标签，链接为：修改密码的URL。当被害人点击时就会触发更改密码的操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL42UjGUGlWQs2nZ5q5ze4lo4nBuNqicuYm9ibgnfvK2IIEGcqPxXKCFjZg/640?wx_fmt=png&from=appmsg "")  
  
打开文件，点击链接![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4nibGEnynjmJNQvVTzrklA0jpSeLTmHZAbVhORZLPhOSpoMmqiaSCBsSg/640?wx_fmt=png&from=appmsg "")  
使用burpsuite抓包，然后在请求头添加referrer字段：  
```
Referer: http://dvwa:9998/vulnerabilities/csrf/?password_new=passwd&password_conf=passwd&Change=Change
```  
  
重放，密码修改成功![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4HCBZjrd56DXTLZoUDgPcJBc76O1iaNpEeiciapk0W75Pmf8hL5llzT8ZQ/640?wx_fmt=png&from=appmsg "")  
  
## High  
  
我们分析一下源码，可以看到源码中多了token  
校验，每次登录都会校验token是否正常，如果想要执行更改密码操作，那我们就必须要知道正常用户的token值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4fwNXG4K60taX4kL63EFasHgoXXer4SarCMHT5OILVQeSsL6ibVEwojA/640?wx_fmt=png&from=appmsg "")  
  
**获得用户token的方式有两种：**  
- 构造一个页面让用户点击，点击之后偷偷的读取用户登录网站的token，把token加到自己构造的更改密码的表单上做让用户点击完成攻击，但由于同源策略，一半无法获得token，也有解决方法，但那个更繁琐，这里不赘述了  
  
- 如果用户网站上刚好有存储型漏洞，可以利用存储型漏洞与csrf漏洞配合，即通过存储型漏洞获得token再利用csrf漏洞结合拿到的token完成攻击  
  
因此，为验证漏洞，我们假设是通过存储型XSS漏洞获得user_token：57ccfed74284e085d0297ae4523567f  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4jX91fmZSfPibrR1m1XKUq4oLg14xer81baFWTgpseYTCyFHGDiatHoyg/640?wx_fmt=png&from=appmsg "")  
  
然后我们还是使用前面的构造的html文件，点击链接后，使用burpsuite抓包，将token值拼接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4lArFLTic991B5aEwgicNuibV5jibkgx52b3Ng3qCTibmGib6yr9gnY3Pty9w/640?wx_fmt=png&from=appmsg "")  
  
发送请求，回到页面，发现密码修改成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4JShYv5CckjiaHfzG5O0mWRg2yRAZcroTUah7zxe7flDiab2Ob7oic7TVQ/640?wx_fmt=png&from=appmsg "")  
# File Inclusion  
## Low  
  
进入关卡，我们可以看到有3个php文件链接![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4iabhibFWfHhzN4MbMOUXhhzfqgAcU7fs2ibicTEf62QAVQtgoUZZN52ebg/640?wx_fmt=png&from=appmsg "")  
点击其中一个查看，可以看到页面，没有返回文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4koQZjVqhLmnck56rV2qjibcOzDguReFpIlRA4t2I4b8E5SUKeM6pGkg/640?wx_fmt=png&from=appmsg "")  
  
为了验证漏洞，我在WWW文件夹  
内创建了一个flag.txt  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4o6jtMMd8rh4libORibLS7PJAlPdCoViaeYkPdJAAcbrzoOGFDr6qwUvqg/640?wx_fmt=png&from=appmsg "")  
  
一开始，我们是不知道文件具体路径，但是我们可以先随便输入几个../  
，回显报错信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ghmgLicmFf9MGBw9xY6Q3GSFhT9icOWJXRwkRwMwsiaBiaJzibv6geVw2Uw/640?wx_fmt=png&from=appmsg "")  
  
根据报错信息，那我们构造playload获取flag  
```
../../../flag.txt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ANdxpIfOoLeOSds4MPpQTibZnWpnf7dY4piciaXuIkIVhuiaEKiaKwyg3MA/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码，我们可以发现http://  
、https://  
、../  
、..\  
被过滤掉了  
  
那只能构造playload，利用双写绕过  
```
....//....//....//flag.txt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4a846NZ3Fib55HgK5roJTcN6dTcaZ2UhDB7KiaxLuSXylvgYzoRKNw0Yg/640?wx_fmt=png&from=appmsg "")  
## High  
  
分析源码，使用fnmatch()函数  
对page参数进行过滤，要求page参数的值必须以file开头，这样服务器才包含相应文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Y9Wf4k8VWHcNryGF16VAmwu6eMsUIJGQydDLf0wPOZbPliafUSAOX4Q/640?wx_fmt=png&from=appmsg "")  
  
既然如此，那我使用file伪协议结合文件路径构造playload  
```
file://E://phpstudy_pro//WWW//flag.txt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4v241EicaZq1mq7rDge164dicfzhwyeanWlzkDMB7Oiap8ge2lpj0ehrzg/640?wx_fmt=png&from=appmsg "")  
# File upload  
  
因为是文件上传，我们先创建一个.php文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ic8RB6Zq7oLWOw7UST4DaEibOoIP7aUw6h6FFKTFoj8OUgTyic57xF7rw/640?wx_fmt=png&from=appmsg "")  
## Low  
  
我们先直接上传文件，可以看到，.php文件  
已经成功上传，没有任何验证机制  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL40F3SjWLVrqJyTAn1iaJUS64p5cStNViax4yfCicdWO7VXRfzfJv79dr7g/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码，我们可以看到验证机制主要是检查请求中的上传文件类型是否为image/jpeg  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4hUaSzb7vlPQNjnrrjxFfnJ5t9XjpDfkgpqhxt5OomHUXs7icxbbD43Q/640?wx_fmt=png&from=appmsg "")  
  
先将muma.php  
改为muma.jpg  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4cll4zicoxOuibdrF7njib7Y2v5icEOjhTLXR43FH2iahzjExdChjORQfeiaQ/640?wx_fmt=png&from=appmsg "")  
然后在页面上传文件，使用burp suite抓包，再将muma.jpg  
改为muma.php  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4nNzQuahMoib9qsAyRZe3NuMYa6ZdG4AINkf21JXZ9QPEibN7IjymW9qA/640?wx_fmt=png&from=appmsg "")  
  
  
修改后放行，上传成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4TQWiamt9DiaF4mDB1JMCHkCExibFbYWW5AqZvkaNibPEfrichNAAVdyiaovg/640?wx_fmt=png&from=appmsg "")  
## High  
  
这一关，我们得制作图片马进行上传  
  
先打开cmd，输入命令  
```
copy muma.php+1.png 666.jpg
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4LuLQIPWHs05Xs5cj0D84IggFN3Y3k7TuEntQZlPgOnmLgiaHJt72Oiaw/640?wx_fmt=png&from=appmsg "")  
  
然后将图片上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4QWa3EgE7TWLicBib3jOzp725Vicfnz2tbRGXUf70pciaO3OMQ6R5h6icHnw/640?wx_fmt=png&from=appmsg "")  
  
回到文件包含的low关卡，在URL载入playload  
```
http://dvwa:9998/vulnerabilities/fi/?page=../upload/666.png
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4D0JhIxohjnSeoBkrh5iaiaYiaVW5t5r9pelicfHtwczQX7q03eticXBz2Gw/640?wx_fmt=png&from=appmsg "")  
# Insecure CAPTCHA  
## Low  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4nbBibjjcbevpSicic0zxLCNfVZmrtHh74EEXf4l1Ito1MicAhSAxkGz1xQ/640?wx_fmt=png&from=appmsg "")  
  
服务器将密码修改操作分成两步进行。首先，服务器检查用户输入的验证码，如果验证通过，服务器返回一个表单。然后，客户端提交POST请求，服务器完成更改密码的操作。但是，存在一个逻辑漏洞，即服务器仅通过检查Change  
和step  
参数来判断用户是否已经输入了正确的验证码。  
  
因此，攻击者可以通过修改HTTP请求中的参数来绕过验证码验证，达到修改密码的目的  
  
输入密码和确认密码，点击提交。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4zBs1csldN5gN0E2zY6Es8oantamibqb8sL2foQs6EwnooHhx5LibiaDGQ/640?wx_fmt=png&from=appmsg "")  
  
然后使用burpsuite抓包，将step=1  
修改为step=2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL41Wuia9HQG2ic104jwzBwfC3k1wAUHNwtSr9fdCp4Wicd2PF6RP2db6c4w/640?wx_fmt=png&from=appmsg "")  
  
修改好，将数据包放行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Jk4ZhhGIsXhTqNeS1qzqw5p0RjlPysWHciaOydOfNPajIaGHw6G4Qpg/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Unp8XNfIr0F90r7eA8wwBics6ACA70ePWA12NpnJSNkTM67HI8XYBkw/640?wx_fmt=png&from=appmsg "")  
  
在中等安全级别的代码中，第二步处理逻辑增加了对验证码是否通过（passed_captcha）的判定。如果passed_captcha  
为true  
，则认为验证码正确。通过修改HTTP请求中的参数，攻击者同样可以绕过验证码验证  
  
输入密码和确认密码，点击提交。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4zBs1csldN5gN0E2zY6Es8oantamibqb8sL2foQs6EwnooHhx5LibiaDGQ/640?wx_fmt=png&from=appmsg "")  
  
然后使用burpsuite抓包，将step=1  
修改为step=2  
、passed_captcha=true  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4iarMHVFpjXFRkY4oeA8H3f9uJOHcT5hExicvd4WkdTRJzdOaXe5icmRwg/640?wx_fmt=png&from=appmsg "")  
  
修改好，将数据包放行![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4sSSZXiayJvUL1qVrOEv7awWJroQC4Re2pglroIxtGmOdvsp08N787WA/640?wx_fmt=png&from=appmsg "")  
  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Ou5ULibnkaJAp2NHQm4Y5tK4U4x6NsNJNx0RrawyibEVczSIDj5PHAjw/640?wx_fmt=png&from=appmsg "")  
  
在高安全级别的代码中，服务器的验证逻辑是当谷歌返回的验证结果（$resp）是false，并且参数g-recaptcha-response不等于特定值（hidd3n_valu3），或者HTTP请求头的User-Agent参数不等于reCAPTCHA时，就认为验证码输入错误。反之，则认为已经通过了验证码的检查。  
  
因此，攻击者可以通过修改HTTP请求中的g-recaptcha-response  
和User-Agent参数  
来绕过验证码验证  
  
输入密码，进行提交  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4zBs1csldN5gN0E2zY6Es8oantamibqb8sL2foQs6EwnooHhx5LibiaDGQ/640?wx_fmt=png&from=appmsg "")  
  
然后使用burpsuite抓包，修改g-recaptcha-response=hidd3n_valu3  
和User-Agent=reCAPTCHA  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4urVvXf4o7Am32cIwO8X6mnoCr1ZicLS5OEMyzsSlYYzibicvUHCaYia6lA/640?wx_fmt=png&from=appmsg "")  
  
修改好，将数据包放行。页面回显修改成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4uouiaO7vW5DMg4AAJnia99OKYuhviaFcpDicMiaguG8MaBPoYYzicomwCvnA/640?wx_fmt=png&from=appmsg "")  
# SQL Injection  
## Low  
  
可以看到输入ID，回显用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Yf3fxQRY6GLIFK2icx2qqm7JQ4yQWQG3Yiaf6brT37jVltkCT30LIgaA/640?wx_fmt=png&from=appmsg "")  
  
输入1’  
，页面回显报错信息。根据判断信息可以知道形成注入的符号是单引号  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4rHbiayVyaqtOicGpsicicAOPvyibQvoRJ0GEvrRKy00mic3bf1ClibYeX7qQQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用万能密码  
```
1' or 1=1#
```  
  
成功爆出所有用户信息![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4wg6LmQIfViccztj7f0v7XVvNwNtmibWxS7YO6sRbpEN05F8Kn4kguHVg/640?wx_fmt=png&from=appmsg "")  
  
## Medium  
  
这一关不能进行语句输入，而是使用复选框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ffWdDL1iaTLMDsa6phicia3kyMBOPaPF5XnOHjy23BS8MleVUiaAlvw56Q/640?wx_fmt=png&from=appmsg "")  
  
点击Submit  
，然后使用burpsuite抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL41Jfun5JhOGZwRIgMicSVBShctqlHPpoYlJNJvvuuzT1sJ8Iwf58Ufqg/640?wx_fmt=png&from=appmsg "")  
  
将数据包发送到重放器模块，重新构造语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL40Mic9aicgyNxHFcBzcicacwiaicCCIuOCO4M3NoiclE9aGyiaKXPz6eqX2dKw/640?wx_fmt=png&from=appmsg "")  
  
将1  
修改为1'  
，然后发送。回显报错信息，根据报错信息可以确定是一个数字型注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4EeLIzLORU35gnxWIbsiaicwziay9kQSxn86JDc3GzoV11MkibMBoBpZRnw/640?wx_fmt=png&from=appmsg "")  
  
然后构造playload  
```
1 or 1=1#
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4y80R9uEOibrbRo115abCHUtDumMjVRk6icCP9y1lTfvpSg96W26gV9JA/640?wx_fmt=png&from=appmsg "")  
## High  
  
页面与前面不一样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4zSXhiceBSxiaWLVFqHwJhAyqIPH17spy0gXKt837HMAFFtk2RKmvPSOA/640?wx_fmt=png&from=appmsg "")  
  
点击链接会弹出另外一个页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4dJYVmla7Wc4OOic1VCWDmMGLUaxW61ic36MCk1upAeicFianZMDMO92ibUA/640?wx_fmt=png&from=appmsg "")  
  
输入id后提交，回显用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ssfWibOiakTTRwKiaTe24oQtXwLzWeVeWYxGGThJ5yEjibYUKbtcnByxSQ/640?wx_fmt=png&from=appmsg "")  
  
先判断注入型，输入1'  
，页面报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4yp64rFTpbuUzglA2GjuRk5RBiczVelh8FFAKl7ZeSObE7e3JicAGSJBg/640?wx_fmt=png&from=appmsg "")  
  
然后构造playload![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL44rIt48MRIc46DjKpTgLgGG3pyKOl4bMjogpOfw4ibwu73xdlBDplRyg/640?wx_fmt=png&from=appmsg "")  
  
# SQL Injection (Blind)  
## Low  
  
页面输入1  
，回显数据存在页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL40EvwJzJCicMicGduYGfCd1ulrlR29MCWTtibjHIVWqqWVP2xqVPbPibHzQ/640?wx_fmt=png&from=appmsg "")  
  
页面输入1'  
，回显数据不存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4toTtMRIUYAAeIpo4JVJ100TicadwhAG4OOjkkYPO1UU8t67uttHNW0Q/640?wx_fmt=png&from=appmsg "")  
  
没有报错信息回显，我们使用布尔盲注  
### 判断注入点  
```
1' and 1=1#
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4FShLcofsrKbeKmXldEFzWZglgdgonVibmX8hpWgmiaz7EjSZPXMaq96w/640?wx_fmt=png&from=appmsg "")  
### 判断数据库名长度  
```
1' and length(database())=4#
```  
### 爆数据库名  
  
使用substr()函数  
，逐一判断为：**dvwa**  
```
1' and ascii(substr(database(),1,1))>97#
```  
### 判断表名长度  
```
1' and length((select group_concat(table_name) from information_schema.tables where table_schema=database()))>1#
```  
### 爆表名  
```
1' and ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>1#
```  
### 判断列名长度  
```
1' and length((select group_concat(column_name) from information_schema.columns where table_name="user" and table_schema=database()))>1#
```  
### 爆列名： user和password  
```
1' and ascii(substr((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'),1,1))>1#
```  
### 爆数据  
  
然后再使用二分法猜解user字段  
的值：（用户名）  
```
1' and ascii(substr((select user from users limit 0,1),1,1))=xxx#（第一个字符）1' and ascii(substr((select user from users limit 0,1),2,1))=xxx #（第二个字符）      ......                                 
```  
  
猜解password字段  
的值：（密码）  
```
1' and ascii(substr((select password from users limit 0,1),1,1))=xxx #（第一个字符）.....
```  
## Medium  
  
这一关使用的是复选框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4z23jZkqaicYwcHGpiallHAiceiadQcgUqIYfc706tEgW8Ku4anoU5lt76w/640?wx_fmt=png&from=appmsg "")  
  
点击提交，使用burpsuite抓包，然后判断注入点  
```
1+and+1=1#
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ia8cbUBAxHB5sAypNHRKCQXO5HhfcDRoicUp2sZYYPP3wmbUCicZjMznw/640?wx_fmt=png&from=appmsg "")  
  
页面回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4x4gqgHjXCVWdBxASE3cPSwEuB57P58G8DJpuntArYajr8icdIncM6TQ/640?wx_fmt=png&from=appmsg "")  
  
说明还是可以使用布尔盲注的手法，和Low关卡一样  
## High  
  
分析源码![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4BzkVaEIUiaiaxA4RVQbwpfEFORlwicIK0ZwCaEW78XQzKGExO5g8RJ2Ew/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到，High级别的代码利用cookie传递参数id，当SQL查询结果为空时，会执行函数sleep(seconds)，目的是为了扰乱基于时间的盲注。  
  
同时在 SQL查询语句中添加了LIMIT 1，希望以此控制只输出一个结果。但是我们可以通过#  
将其注释掉。  
  
因此，和前面的SQL注入一样，但由于服务器端执行sleep函数，会使得基于时间盲注的准确性受到影响，这里我们只能使用基于布尔的盲注。具体步骤可以参考Low关卡。  
# Weak Session IDs  
## Low  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4CzOCxQRic3dVVfpSAZP06icQQPBqpRyc6gAFHAQGicDwbr2SX2SnqffRw/640?wx_fmt=png&from=appmsg "")  
  
在低级别，会话ID是通过递增的方式生成的，这种方式容易被攻击者猜测，从而增加了会话劫持攻击的风险。  
  
攻击者可以通过观察会话ID的变化来预测下一个有效的会话ID  
## Medium  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4rAIJMRcjjibKmO4S9E9592FhIyUvYEIiaLkasneoRRblzkOvB9LZq5Vg/640?wx_fmt=png&from=appmsg "")  
  
在中级别，会话ID是基于时间戳  
生成的。虽然这增加了猜测的难度，但如果攻击者能够预测受害者在特定时间点进行操作，仍然可能发起会话劫持攻击  
## High  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ia1JmcfxOyZGw3mY3aXC3pt9RXwvSOO9p6TszzZXRITuiawglgkRtq3w/640?wx_fmt=png&from=appmsg "")  
  
高级别使用了md5函数对会话ID进行加密处理，这增加了攻击者直接猜测会话ID的难度。但由于会话ID仍然是以可预测的方式递增，通过md5解密工具仍有可能被破解。  
# XSS(DOM)  
## Low  
  
页面显示一个复选框，我们选择English![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4djs8lplLWAdIofbxHqeXd0K9zKTVr9FySEiaUWiaDhQnpvfaU3wpiazmg/640?wx_fmt=png&from=appmsg "")  
  
  
使用开发者工具查看源码和观察Url  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ltHXgVubJub9ms4ZEkqk74gF1UOOYJGUnDjnTeeOLSItkppHcDdRJg/640?wx_fmt=png&from=appmsg "")  
分析得出：选择下拉列表内容，选择的值会赋给 default 并添加到 url 的末尾，再将其传给 option 标签的 value 结点。也就是说我们可以注入一些 JS 代码进去，然后这部分会被包含到 lang 变量中，最终回显到页面上。  
  
构造playload  
```
<script>alert(document.cookie)</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4p7jPPbeZEZZKBdZvjibd5LDfUCuEEo9wHicoAu5IiaBrEIDzktZMQ3ZOw/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4EGicwlhq526WGhfHsice28DBDLic0ASqaZibHbULTxLsPnfkW3PYUjAgeA/640?wx_fmt=png&from=appmsg "")  
  
array_key_exists()函数  
检查某个数组中是否存在指定的键名，如果键名存在返回 true，键名不存在则返回 false。stripos(string,find,start)函数  
查找字符串在另一字符串中第一次出现的位置（不区分大小写），header()函数  
向客户端发送原始的 HTTP 报头。也就是说现在服务器通过一个模式匹配，过滤了<script>标签  
，我们就不能直接注入 JS 代码了。  
  
那我们构造playload，绕过过滤  
```
English</option></select><img src = 1 onerror = alert(document.cookie)>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4rN4D0LLXUJZcialPDju1Cy251uic2ttI6TKbYIHGF0ASr9Rg3v1icWoSA/640?wx_fmt=png&from=appmsg "")  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4O43XRCl8B9ib9okQUD8ku1QxfzSmWuWRIicdf3Xz6fzhbaibAImB0nkvQ/640?wx_fmt=png&from=appmsg "")  
  
服务器设置了白名单，default 参数只接受 French，English，German 以及 Spanish 这几个单词。  
  
那可以在注入的 payload 中加入注释符 “#”  
，注释后边的内容不会发送到服务端，但是会被前端代码所执行。  
```
English #<script>alert(1)</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL47UnvT5jrtxjXluibcruibXkmeKHlU1XJDXCMazL8MfzH8AYYnKI8uSRA/640?wx_fmt=png&from=appmsg "")  
# XSS(Reflected)  
## Low  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4xPtrTl0EZHbNCqZVImqDTbjXYXCjacTXkWy0OBwkX4sXbfoLQmp18g/640?wx_fmt=png&from=appmsg "")  
  
没有任何验证机制，直接构造playload  
```
<script>alert('xss')</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4KUibhx1eicUmYab9nN2q6X1gicqh5XDBGfNGXaQ1O9k8nhiblic25nS2RtQ/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4OOicLc5LTWlPHOpz9ic8WUuebQjibLtaIulhOtc9ILjKJpIptToAQHrwA/640?wx_fmt=png&from=appmsg "")  
我们可以看到，源码对输入内容进行过滤，将<script>标签  
过滤了  
  
那我们使用大小写混淆，构造playload  
```
<sCript>alert('1')</sCript>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL42uhomnVreRSQaxYpN5sUUxch4qowic4aKByvp7naR4S9ZS087SfUibrQ/640?wx_fmt=png&from=appmsg "")  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL48jc8tOYEJ10DFfsQhOID8DcjoJccFiaCCHGrCryaYQOGlZpJib7tYnrQ/640?wx_fmt=png&from=appmsg "")  
  
使用正则表达式过滤了<script>  
标签，但可以通过其他标签如<img>  
的事件属性来执行XSS攻击。  
```
<img src=x onerror=alert(1)>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Lib5ibTeNNDfBwkFUb3SWhhXbZ4OokBhZdfVfibZMQOafQKiaEVUd5hodg/640?wx_fmt=png&from=appmsg "")  
# XSS（Stored）  
## Low  
  
在将请求的输入包含在输出文本中之前，Low level 将不检查输入的任何的请求。  
```
<script>alert('xss')</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4BV7XbrEoR5nCncvCBSXpE8VWF4CibM4VibRRMHQiaH1IDTwFfmgEt79sA/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4yVuu34e2riacA3NS1sP66PGuQ3gfZXk7TWsHOOVnUgJraYsxkWPrBhA/640?wx_fmt=png&from=appmsg "")  
  
addslashes()函数  
在每个双引号前添加反斜杠，返回在预定义字符之前添加反斜杠的字符串。strip_tags()函数  
用于剥去字符串中的 HTML、XML 以及 PHP 的标签，htmlspecialchars()函数  
用于把预定义的字符 "<" 和 ">" 转换为 HTML 实体。  
  
可以看到 Message 参数对所有的 XSS 都进行了过滤，但是 name 参数只是过滤了 <script>  
标签而已，我们可以对 name 参数进行注入。  
  
playload  
```
<SCRIPT>alert(1)</SCRIPT>
```  
  
因为name参数限制了输入字数，我们需要使用开发者工具修改maxlength属性  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4EgcjtwmPicBeBFoBD5fLGicXHmVmDAOrModLibkeOfTRDNtNPswrQB3oA/640?wx_fmt=png&from=appmsg "")  
  
接着输入playload，点击提交![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4lK71yia5VZCia2sFR04QZGKLAdgaLpaCghk1G9BtXibic4scHLMnrG5K3Q/640?wx_fmt=png&from=appmsg "")  
  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4VZniafttdkwdQDibwOsrlIwbZrdjY0w1RO98DxHSWEPib5GvfsJ7StkCg/640?wx_fmt=png&from=appmsg "")  
  
使用正则表达式过滤了<script>  
标签，但可以通过其他标签如<img>  
的事件属性来执行XSS攻击。  
```
<img src=x onerror=alert('xss')>
```  
  
注意，还是在name参数处输入playload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL48851NTQOFQzuPLRm5rMPGk2pDhzaMkUkPQzVFCwCRmU26CfpKmYAkA/640?wx_fmt=png&from=appmsg "")  
# CSP Bypass  
## Low  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4hSGRia00Ribzmzng7rSRUibePqQm3uX4Kkoghx5sriczYYeWG9w1PAJMwQ/640?wx_fmt=png&from=appmsg "")  
  
源码对 HTTP 头定义了 CSP 标签，从而定义了可以接受外部 JavaScript 资源的白名单，通过抓包也可以知道是哪些网站  
  
我们先使用白名单中的js脚本进行实验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL49TlYAgRxBkgIAYLcKpPnMibZE24aYOmJs18bUSmlPeesBV9Y5o2WLeA/640?wx_fmt=png&from=appmsg "")  
  
点击提交，实现xss攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4A7u3ibqrbKIicjiafia5WJkQkTA6Q69LUNKkyMfQFyPXrsEKgHa0EianDzA/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4sQx6Hibrqrdia5ibichh8J2empGrlHDEicN1MZh06UlBf8wLetMyhiarU5SA/640?wx_fmt=png&from=appmsg "")  
  
HTTP 头信息中的 script-src 的合法来源发生了变化。script-src 还可以设置一些特殊值，unsafe-inline 允许执行页面内嵌的<script>标签  
和事件  
监听函数，nonce值  
会在每次 HTTP 回应给出一个授权 token。  
  
playload  
```
<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4PM8D06kVs5x5W3wfwMl5eUkXxxL6o31tNeyerwkL4kawreZCMn7G5A/640?wx_fmt=png&from=appmsg "")  
## High  
  
分析源码![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4YjafMBSj6mYsZIV8unAQFa7WAziavCW0DCMc1UxehYMTvxQmVemBViaQ/640?wx_fmt=png&from=appmsg "")  
  
  
我们可以发现，在点击网页的按钮使 js 生成一个<script>标签  
，src 指向source/jsonp.php?callback=solveNum  
。我们猜测callback 存在注入点  
  
点击提交，使用burpsuite抓包，然后修改callback参数 为jsonp.php?callback=alert('xss')  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL46b4xH0mejksrszom3sjmTbBzbmPPNyq8KDD3SgtAzzqXt1D6z1jOgw/640?wx_fmt=png&from=appmsg "")  
  
  
放行数据包，完成xss攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL45Wwd3D5blOlJbEre0iaibkwkSk9KGGibDQV5iaoa7yFQTXSwQ6Jyh6ibliag/640?wx_fmt=png&from=appmsg "")  
# Javascript attack  
## Low  
  
页面提示只需提交单词“success”即可攻击成功，但这并不是那么容易。因为提交后会回显： token 无效  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4fOkMl9qp5xSErL2aiaTldjB52zjtvbiaUWJDAnqoM1vMPyxPCptHvGFQ/640?wx_fmt=png&from=appmsg "")  
  
输入success  
，使用burpsuite抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL44ADVlveeRNHMh9NyiaT8yFRzmbicfNr8b9eYiakNsnswZdYgvKFKTRoTg/640?wx_fmt=png&from=appmsg "")  
请求网页时同时提交了 token 和 phrase 参数，其中 phrase 参数是我们提交的内容。而 token 参数无论我们提交什么，都是不会变的，也就是说 token 和我们注入的参数并不会匹配。  
  
源码分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4TkMqz8w51icuNIQxQRqf6dIs0Xkv80pqw98G8CPeIu5YySyhddniaoag/640?wx_fmt=png&from=appmsg "")  
  
那我们根据代码审计，token 的生成是基于 phrase 参数的，而现在该参数已经被我们覆盖了。因此现在我们重新拉取一下 token，在 Web 控制台运行generate_token()函数  
或md5(rot13("success"))  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4iajFiaBlY4Mb8A9AQxibys0MpnJlAV9VaSEa2k6rBPOV3wV610Dia0WCKQ/640?wx_fmt=png&from=appmsg "")  
  
在控制台上得到token值，把数据包的token值参数替换掉，然后将放行。![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4gkwUdRhP2NDndA6TmzHDRBzfrHMpGdcGClDiaaf4nWRTOhgprarv4rQ/640?wx_fmt=png&from=appmsg "")  
  
## Medium  
  
分析代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4sD4rsluFnEUgTVpQaM1CMyZDRRY9t0yCBG1AsfXocWhzIZp9LLRUdg/640?wx_fmt=png&from=appmsg "")  
  
生成 token 的函数被放在单独的js文件中，生成的方式是将 "XX" + phrase 变量的值 + "XX"字符串反转作为 token。  
  
输入“success”点击提交，使用burpsuite抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4nvchB1OdHuqoDdmv1IAiaengGAPlVOl2odFyqQWAYIF8OvmianEKgEbw/640?wx_fmt=png&from=appmsg "")  
  
将token=XXemgnghC  
改为XXsseccusXX  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL41BZS2AfkepEfYDYO0bLV6adT8WcWBp45JrNQ82EMliaSYwT4TtQuKew/640?wx_fmt=png&from=appmsg "")  
  
修改后放行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4anm5iczSLWicJWEFzV6hzuy6K7QceYdvFSF4ruAJE7LoyKWmD6pRt8XA/640?wx_fmt=png&from=appmsg "")  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Uw0VrfEeOOWbcAZKuRfMZPXqib2C4HetF6VibE4kqD5Jicr2GF5wpmNzg/640?wx_fmt=png&from=appmsg "")  
  
源码是一团乱码，这是典型的 JS 混淆，使用还原工具得到源码后得到关键代码部分如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4BjNrmjUJ1l04iaoF5YuzvlBBUUwgQJLbBSgR33ek5nJwe15iareL1GxA/640?wx_fmt=png&from=appmsg "")  
由于执行 token_part_2("XX") 有 300 毫秒延时，所以 token_part_1("ABCD", 44) 会被先执行，而 token_part_3() 则是和提交按钮的 click 事件一起执行  
  
所以执行步骤 1、将输入框的值改为success  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4IBdRjjVKkFXckhUjy9D5CI3FTK5VTF50XPUGc6Kmx9d4U29UwL21LQ/640?wx_fmt=png&from=appmsg "")  
  
2、在前端控制台依次执行  
```
  （1）token_part_1("ABCD", 44);   （2）token_part_2("XX");
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4QTDQ1iaW08NI5VjhIA9e00JqUrgLLBicXRgP8Pac9ic8pRXR7EXuOsQ0A/640?wx_fmt=png&from=appmsg "")  
  
3、提交  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4LJYf5BLu3YTZFNJzHnknKeAeKy2qfeyuAytqicCVt9DHs3ahPCqbbdw/640?wx_fmt=png&from=appmsg "")  
# Authorisation Bypass  
## Low  
  
先切换账号/密码：gordonb / abc123  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL46v3JJoLttd2Qob6zwtf7qkOMCM98tr8Wsf5TYZuI8NpzPy5rtAjkSA/640?wx_fmt=png&from=appmsg "")  
  
切换用户后，观察导航栏，缺少了Authorisation Bypass  
关卡  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4d7fNst1mZz7SCa7A7aLQeIk9hec5zqTjlhgUFEBxQU28LLRh3sRYXQ/640?wx_fmt=png&from=appmsg "")  
  
在URL输入：/vulnerabilities/authbypass/  
，回显账户密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL40GiayCYFjY2ribUjIwhiaIFjibbHYhV6XIdD4O57IXF9FU6QnWicV4YP9KQ/640?wx_fmt=png&from=appmsg "")  
  
打开开发者工具的网络模块，我们可以看到用户数据是在get_user_data.php  
内  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL40kO99cfBNWEJPn4PvNlIO9iaPwSwvGuKMK17iaZESQIh337znXJtlZgA/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
我们访问刚刚的路径：/vulnerabilities/authbypass/  
，用户数据没有回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4G94QlOEErKpAN7FShQDl7WmwoH2ybmWUNVeMsQzZTxMEAhicdTNyH6g/640?wx_fmt=png&from=appmsg "")  
  
那尝试添加上上有关找到的文件  
```
/vulnerabilities/authbypass/get_user_data.php
```  
  
页面回显用户数据![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4K4ibTxtVnTIP2ye7BfSa29hicd2VHmclbYHZvhXzVyiblrrHnCLkPEfCA/640?wx_fmt=png&from=appmsg "")  
  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4lvbueWBSah4QZ2uzhEguk3zyoXLTxibtD3n3qHESdFa0RFGo5Yf5ByQ/640?wx_fmt=png&from=appmsg "")  
存在漏洞的网址为：/vulnerabilities/authbypass/change_user_details.php  
  
在url输入该网址，页面提现需要POST请求![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4S60K4E3MVc3a2ic20slNQq8ZC1MB3LO8ez29AJ2zqnfMtWHwZibz5ygg/640?wx_fmt=png&from=appmsg "")  
  
  
使用burpsuite抓包，修改POST请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4cicd2grxWNte1C2U00M9SmQn36eFjwibicsZADvENBKYicOVBgUaqM82hw/640?wx_fmt=png&from=appmsg "")  
# Open HTTP Redirect  
## Low  
  
页面有两个链接，随便点击一个链接![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4sp2OlxZwRug5IFNHpibc0qCt8HVhXlz1X5szjY0qJlhmPibqtUoJdQgg/640?wx_fmt=png&from=appmsg "")  
发现url栏有传参点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4mnwMEPts6n5n6zf9jzpB7u8fAe8b8ibDKbFHTn4EWwibufAJXevn3x3A/640?wx_fmt=png&from=appmsg "")  
  
打开开发者工具，找到该链接的标签  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4daoPUnliakIemnIJPuOicalDl499hXpRH9jEy8d1micxUic60MRpCm1Ytg/640?wx_fmt=png&from=appmsg "")  
  
将source/low.php?redirect=info.php?id=1  
修改为source/low.php?redirect=https://www.baidu.com  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4VmTATRjmfAnvYVDGqSpOBgWOOuNAUf1ia0UYElZTUiat9hehdrZqT9EQ/640?wx_fmt=png&from=appmsg "")  
  
点击链接，成功重定向百度  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Cuh4ickydnfGTLNar36Xzo1Zq8jPvBvicj0Vlc1STgbk7FB6o77pJesw/640?wx_fmt=png&from=appmsg "")  
## Medium  
  
与low级别的方法没什么区别，查看源码可以发现不同的地方在于禁用了http://  
、https://  
字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4ico1g6cwFiazZAtibcKBUficvMZ96wkvwbyZc3wSIOOTC6wdMpotQHHZGw/640?wx_fmt=png&from=appmsg "")  
  
构造url绕过  
```
source/low.php?redirect=//www.baidu.com
```  
  
如果没有明确指定协议，直接以 // 开头，则表示使用和当前页面相同的协议，便可以绕过了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4Gt58Vegic5yQu3xJ65ztHU8pzTvIPOgaVFA8DUFCKGPYsicsJbGOz2YQ/640?wx_fmt=png&from=appmsg "")  
  
成功跳转![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL45Dud3vyhiaTNOuEgRDRCia3o3tEZjWjic2Y4xPtwEb9sSkRYibgLFlU0AA/640?wx_fmt=png&from=appmsg "")  
  
## High  
  
分析源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4gKuNqzYejQSq9RPZZ08ZOtXoY0uRcAy2JGSXub3D7eM86L8C4tdwXA/640?wx_fmt=png&from=appmsg "")  
  
查看源码可以发现与上面两个级别不同的是检查是否有info.php字段，如果没有，则不能进行重定向。  
  
根据这个情况，开始构造代码绕过：  
```
source/low.php?redirect=http://www.baidu.com?id=info.php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR3icQ5LXHOeBdk2Y8pnoSL4cF0iapgG9ygf6RK46EMjparREHusyO1adM7veJpk5vvYZqgibehXbORw/640?wx_fmt=png&from=appmsg "")  
  
点击链接，实现跳转  
  
