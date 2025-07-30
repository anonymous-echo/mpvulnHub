#  XML 基础知识 && XXE 漏洞原理解析及实验   
 编码安全研究   2024-08-05 17:07  
  
# XML 介绍  
> XXE全称XML外部实体注入，所以在介绍XXE漏洞之前，先来说一说什么是XML以及为什么使用XML进而再介绍一下XML的结构。  
  
  
XML全称 可拓展标记语言，与HTML相互配合后：  
- HMTL用来显示数据  
  
HTML的焦点在于数据的外观（如何显示数据）  
  
- XML用来  
传输和存储数据  
  
XML的焦点在于数据的内容（如何存储传输数据）  
  
总结来说：  
HTML提供了一个模板，XML动态的改变模板中对应数据位置中的数据。  
### 为什么要将数据从 HTML 中分离  
  
若要在HTML文档中显示动态的数据，每当数据需要改变的时候需要大量的时间编辑HTML。  
  
通过XML将数据存储在独立的XML文件中，每次需要更新数据时只需通过发出XMLHttpRequest到服务端请求相应的数据（Ajax）即可。  
  
而HTML/CSS只需专注于显示与布局即可，底层的数据从XML文件中获取即可，这样修改底层的数据不会对HTML的结构发生任何改变。  
### XML 的其他优点  
- XML不仅可以用于简化HTML的数据传输于存储中，所有支持XML格式的应用都可以从XML文件中读取文件来使用。  
  
- 而且XML提供了一种数据的格式标准，所有支持该标准的应用之间都可以用该格式在本地或网络中传输数据。  
  
- XML可自定义标签，  
XML是没有预定义标签的。  
  
# XML DTD  
  
既然前面说了XML是没有预定义标签的，也就是说无论想定义什么名字的标签都可以，这个标签有什么属性都可以，看似很自由，但在开发中显然是不合适的，而且在数据的传输过程中如果双方的XML结构不同也会出现问题，所以需要一个东西  
来约束XML的格式，也就是DTD（文档类型定义）  
  
所以通过DTD有如下优势：  
- 每一个XML文件均可携带一个有关其自身格式的描述，从而规范XML的结构  
  
- 一个通信过程中，可一致地使用规定的DTD来交换数据  
  
- 应用程序也可使用规定的DTD来验证从外部接收到的或自身的数据  
  
### 如何定义 DTD  
  
一般有两种方式：  
- 内部DOCTYPE声明  
  
- 外部文档声明（！！理解XXE的关键！！）  
  
DTD（文档类型定义）被包装在DOCTYPE声明中 （无论外部还是内部）。  
### 内部 DOCTYPE 声明  
  
利用DOCTYPE声明内部DTD的格式为：  
  
<!DOCTYPE root-element [element-declarations]>  
- root-element文档类型（根元素）  
  
- [element-declarations]其余的元素都包含在[ ]中  
  
```
<!--xml声明--><?xml version="1.0" encoding="utf-8" ?><!--文档类型定义--><!DOCTYPE note [        <!ELEMENT note (to,from,heading,body)>        <!ELEMENT to (#PCDATA)>        <!ELEMENT from (#PCDATA)>        <!ELEMENT heading (#PCDATA)>        <!ELEMENT body (#PCDATA)>        ]><!--文档元素--><note>    <to>XXE</to>    <from>LEARING</from>    <heading>hello</heading>    <body>My_friend</body></note>
```  
- <!DOCTYPE note [规定该文档是 note 类型的文档 （根元素为<note>）  
  
对应<note> </note>  
  
- <!ELEMENT note (to,from,heading,body)>定义note中有四个元素，分别为：  
  
- <to> </to>  
  
- <from> </from>  
  
- <heading> </heading>  
  
- <body> </body>  
  
- <!ELEMENT to (#PCDATA)>定义to元素为#PCDATA类型  
  
- 其他的类似  
  
#PCDATA表示名字里面可以放任意文本 - 这不是我们关注的重点。  
### 外部文档声明（ important ）  
  
若DTD位于XML源文件的外部，则可以通过如下语法将其封装声明在DOCTYPE中  
  
<!DOCTYPE root-element SYSTEM "filename">记得该语法，XXE中会用到。  
  
我们将这个外部的DTD文件命名为note.dtd：  
```
<!ELEMENT note (to,from,heading,body)><!ELEMENT to (#PCDATA)><!ELEMENT from (#PCDATA)><!ELEMENT heading (#PCDATA)><!ELEMENT body (#PCDATA)>
```  
  
此时若是想在XML文件中声明该DTD约束，应声明为：  
```
<!--xml声明--><?xml version="1.0" encoding="utf-8" ?><!-- 外部引入 dtd 文件 --><!DOCTYPE note SYSTEM "note.dtd"><!--文档元素--><note>    <to>XXE</to>    <from>LEARING</from>    <heading>hello</heading>    <body>My_friend</body></note>
```  
  
此时便会引入上述note.dtdDTD约束文件，  
  
而这个引入的文件，就是该漏洞的关键之一。  
### DTD - 实体  
  
实体是用于定义XML文档中特殊字符的快捷方式，就类似于一个变量或一个宏（宏可能更好理解）。  
### 内部实体  
  
在DTD中声明实体，则称为内部实体  
  
<!ENTITY entity-name "entity-value">  
- entity_name是实体的名称，后跟双引号或单引号中的值  
  
- entity_value保存实体名称的值  
  
同样是上面的例子，还可以定义成这样：  
```
<!--xml声明--><?xml version="1.0" encoding="utf-8" ?><!--文档类型定义--><!DOCTYPE note [        <!ELEMENT note (#PCDATA)>        <!ELEMENT to "XXE">        <!ELEMENT from "LEARING">        <!ELEMENT heading "hello">        <!ELEMENT body "my_friend">        ]><!-- 一个实体由三部分构成: 一个和号 (&), 一个实体名称, 以及一个分号 (;) --><note>    &to;     &from;     &heading;     &body;</note>
```  
  
在上面的示例中，各个实体名称tofromheadingbody由它们在声明中的值替换。通过向实体名称添加前缀&来取消引用实体值。  
### 外部实体  
  
如果在DTD之外声明实体，则称为外部实体。  
  
<!ENTITY name SYSTEM "URI/URL">  
- name实体的名称  
  
- SYSTEM关键字  
  
- URI/URL是双引号或单引号中包含的外部源的地址  
  
<!ENTITY writer SYSTEM "<http://www.shtwo.com/note.dtd>">  
  
使用的方式与上述例子相同，只不过当前是从外部引入，可以是一个URL链接中的文件，也可以是本地的文件（这也就造成了安全的风险）。  
  
可以使用   
系统标识符或   
公共标识符来引用外部实体：  
- 系统标识符  
  
系统标识符可以指定包含DTD声明的外部文件的位置：它包含关键字SYSTEM和指向文档位置的URI引用  
  
<!DOCTYPE name SYSTEM "note.dtd" [...]>是不是很熟悉  
  
- 公共标识符  
  
<!DOCTYPE name PUBLIC "-//Beginning XML//DTD Address Example//EN">  
  
# XXE - XML 外部实体注入  
### 利用 XXE 外部实体获取文件 - 有回显  
  
通过刚才的介绍，可以明显看出若允许外部文档的声明，那么若请求放的 XML 数据可以被我们控制，就可以在其中加入一个用于包含目标机器本地文件的一个外部文档声明，并回显回来。  
  
但注意，对于  
有回显的XXE要满足这样几个条件：  
1. 必须存在使用XML传输数据的情况，且传输的数据我们可以控制；  
  
1. 通过外部文档声明的外部实体要放在一个可以回显到当前页面中的位置，这样被恶意读取的数据才返回显示给我们。  
  
看了这些可能有点不太理解，下面以Vulnhub打靶过程中，一个环节存在的XXE漏洞为例：  
### Vulnhub - 打靶示例  
  
当前访问到一个注册的页面，让输入个人信息并进行注册，所以我们打开Burp提交数据进行抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuS9Ow1ZCZW6cxFtXB2G51B4jwJTz7mcRU54cUpQEun3vySgzDkoPRMaw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在抓到的 POST 请求包中，可以明显看出当前我们注册填写的信息就是通过 XML 形式提交的，所以满足了上面说的第一个条件：  
必须存在使用XML传输数据的情况，且传输的数据我们可以控制。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSw6SkCJw8yn1F8hTccveAKlvP5spkMPSGJ46LNIDlzZkicHJj4Ifp5UQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
且根据不断地尝试，发现无论email处填写什么，都会有is not available的提示，但仔细看，当提交的email不同时，返回的错误提示信息中的邮箱也会变化，  
也就是说明我们在<email> </email>中提交的数据会被原封不动的拼接到Sorry, xxxxx is not available!!语句中xxxxx的部分，并返回来，这也就满足了上述说的第二个条件：通过外部文档声明的外部实体要放在一个可以回显到当前页面中的位置，这样才能被看到。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuS4iaEYiaju2nuTY1K0kia7XgXhJPiahZlcmkpibO9sEsC1ibO2hnibkOWrsIvA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSVCgWciaypWfXdoNS6Pq4TaljzPdNpFue21gbVrBLicK4CBd2Y6lE715Q/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
所以此时就可以尝试XXE了：  
  
插入一个外部文档引用的声明，通过SYSTEM读取一个外部的位于Linux主机上的文件，并将引入的文档赋予deu这个实体（这个名字随便起）  
  
<!DOCTYPE foo [<!ENTITY deu SYSTEM 'file:////etc/passwd'>]>  
  
并且要在<email> </email>中引用该外部实体deu  
```
<!DOCTYPE foo [<!ENTITY deu SYSTEM 'file:////etc/passwd'>]><email>&deu;</email>
```  
  
这就完成了一个XML外部实体注入 -XXE  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuS0hodVrpYkeTib8tFicVahylmVxLcltB9dCd5ArFyr1Sac3P2EbD5ttNg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
什么？还不太理解，那再与XSS对比来说一下XXE的特征  
### XXE 与 XSS 的异同  
- XSS判断的条件一般是：通过浏览器（表单/变量）提交一个数据到服务器端，服务器端没有做任何变化过滤，就直接将我们输入的数据原封不动的返回到页面中。  
  
XSS的攻击目标大多数是浏览器端  
  
- XXE判断的条件一般是：和XSS有些类似，也是通过浏览器（表单/变量）提交一个数据到服务器端，服务器端没有做任何变化过滤，就直接将我们要引用的服务器端的资源原封不动的返回到页面中。  
  
XXE攻击的对象是服务器端  
  
### portswigger - XXE 靶场 - 1  
  
再以 Burp 官网提供的第一个XXE的题为例：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSsRkLm3GNZIv8v8Gd4s6G7J7gs6eBzM00kiagPF8CTeOwm9WwcqkWJXg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
网址：https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files  
  
流程一致，我们要找到可能存在数据交互的位置，这样才有存在 XXE 的可能，所以一上来先点 Home 试了以下，看看有没有登录的界面，发现并没有，于是随便点开一个商品View details  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSC3GpgHsM79A8scqyXqmjIanaHYw3dCuuk99H1Lic4x8STHNjOAqF1mg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在其中看到了一个Check stock好像是一个提交数据的位置，于是打开Burp进行抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSseEB94AJCg1Lw5Zz0xS6YyJOuicBZKHEMIgR7yiatzBfZQUE4oN4xlfQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
果然是XML数据的格式，这次也懒得在判断在哪个位置可以回显，直接扔进Repeater在每一个XML的标签中都放上我们声明的外部实体，果然会显出了/etc/passwd  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSAMCyfShsicsrcia2kT4mp9d3x2pzkmz22PqVVZhPtmsvlEdAhznHupLw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 利用 XXE 外部实体获取文件 - 无回显  
  
直接用实验说明  
### 通过 DNSlog 回显数据  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuS2fFfH2wHxU2SphGNIbRv6wTfnGEn6XLkxVRXhNqRbflZvhkW449ceQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以看到本事的要求是确定   
目标服务器是否存在 无回显的XXE  
  
而确认的方式就是通过DNSlog看是否有DNS或HTTP请求到来，但处于安全性原因不允许使用自己搭建的或外部的DNSlog服务器，要使用Burp中自带的由官方架设于默认公共服务器上的DNSlog服务器。  
  
其在Burp的位置是：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSMreNIv0rYZpfH1kib5jxjFqhbTuFFia7QDsXaE39lMXdX6aqggCUpPHQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
进入后点击Copy to clipboard生成一个子域名，接下来无论是通过DNS查询该子域名 还是通过HTTP范围该域名都会在下面的Poll Collaborator interactions中显示请求。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSia7TMQJQFVuWYfiagQrtCicNRI4tv2wxBibl2nF7ARpTibhLcnFaIIkJnPA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
不过首先还是按常规的方式来测试一下XXE  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuS70xBodJ4pvBlugDsicoCOpdaAdLT2kKl1hw3P9OEYYMvkTAbqyZclGA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
按照之前的套路，这次并没有返回/etc/passwd的内容，只是返回了 Invalid product ID的提示，所以此时还不能判断存在XXE漏洞（不能判断我们写的外部文档声明起作用了）。  
  
为了进一步，确认到底是不存在XXE还是只是没有回显，此时将对我们自己定义的外部文档声明中的实体引用改为一个错误的变量名。  
```
<storeID>
&de;
</sroreID>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSwr4Z7pQoiaJoribOIkN4ibEoV4iae22M0QjU6WU3ZMhZIvNQEIRZ8CialLA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
此时出现了有关XML解析错误的报错，说明若是XML解析失败是会单独报错的，所以大概率可以确认之前的语句已经被成功执行了，只不过没有回显。  
  
由于没有回显，为了进一步确认到底是否存在   
无回显的XXE此时将外部文档声明中所引入的外部文件指向各个生成的那个域名。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSxH7sDVYXR8YgqNRWnyPWyBnhEQ2GnSmCl0NXQEOHOVIRTicdAWvX4Zw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
之后果然在本地看到了目标对 刚刚传入域名的DNS请求与HTTP请求。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuS8cBW62r1RS9d3bBtmicbA9UqMPp5Cica8TXHy6PYNwEZRnHGlRESkGRg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 利用 XXE 执行 SSRF 攻击  
  
在刚刚基础中，介绍外部实体时，举了一个这样的例子：  
  
<!ENTITY writer SYSTEM "<http://www.shtwo.com/note.dtd>">  
  
不难发现，这后面明显包含的是一个URL，所以若将这部分换为一个内网的IP貌似也没问题喔，所以就有可能造成SSRF  
  
及时我们不知道内网的IP，若存在SSRF也可以通过 在XXE中附加可能的内网IP对内网的资源进行一个探测。  
### Portswigger - XXE 靶场 - 2  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSB8icsXlRHj4sPJia0HricagqA7qtaX4JxO7klgSpoNaSVlQbDOicIwqzUw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
网址：https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf  
  
该靶场只能说非常的贴心啊 ... 连存在敏感信息的IP都给我们了。  
  
那就直接开始吧，首先还是要找存在XML信息交互的位置，该题遇上一道的位置相同，所以就略过了，直接写入外部文档声明  
  
<!DOCTYPE foo [<!ENTITY deu SYSTEM "<http://169.254.169.254>">]>  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSjqrdyLUV99tK0Jp7OkOQgD6DBEgCricmmLtwvBtKj8x0Tw0OZ3ictPKA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
得到了一个目录，再继续向下遍历：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuScLic4cTr4EtlPdbBDSyLPAcZPy5ehUIfnOqvXlCCgC2w23tGwwrIjPA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
最终成功获得到敏感信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccysDOsujjxReQKcraLYbfuSqxPt3hOkLV06WFwzw3Fy3OGGcTn4pAdMWUPONaHhicsgyPI7POEHAHQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
由于最难的一步找到要攻击目标这一步被直接告诉了，所以很简单就找到了敏感的信息。  
# 防御方式  
- 禁用外部实体（大多数都采用该方法）  
  
PHP中  
```
libxml_disable_entity_loader(true);

```  
  
- 黑名单过滤（不安全）  
  
# 参考文章/深入学习  
  
Lab: Exploiting XXE to perform SSRF attacks | Web Security Academy  
  
https://github.com/shungli923/WowBigBug/blob/main/  
  
一篇文章带你深入理解漏洞之 XXE 漏洞 - 先知社区  
  
ZZslBl0g  
  
XXE漏洞详解--基础篇 - FreeBuf网络安全行业门户  
  
从一道题目学习XXE漏洞  
### 有趣的 Youtuber  
  
Seven Seas Security  
### XXE 相关实验环境  
  
https://pentesterlab.com/exercises/play_xxe/course  
  
**侵权请私聊公众号删文**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QO6oDpE0HEnGMibdEBOicags5vPicwyeszAiczWiab7e9BhiaNXaT1WIzorBQpRQLE3o8rHySkyNKkLiceRN7uBtzlJ3A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**学习更多技术，关注我：**  
  
  
觉得文章不错给点个‘再看’吧  
  
