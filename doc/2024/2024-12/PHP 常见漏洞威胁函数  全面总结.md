#  PHP 常见漏洞威胁函数 | 全面总结   
繁星01  安全君呀   2024-12-14 00:10  
  
点击上方蓝色文字关注↑↑↑↑↑  
  
将  
安全君呀  
设为"星标  
⭐  
️"  
  
第一时间收到文章更新  
  
**声明: 安全君呀 公众号文章中的技术只做研究之用,禁止用来从事非法用途,如有使用文章中的技术从事非法活动,一切后果由使用者自负,与本公众号无关。**  
  
文章声明：本篇文章内容部分选取网络，如有侵权，请告知删除。  
  
根据 cobra 规则，总结了一些 PHP 常见漏洞威胁函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhY5EicRZ9wZQcCacAmL0rAvXE5UpVbKNp4bSjhRVKiaUSFJZLwBqvurdQ/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0Buh687P64GAMN3QBshygeLxQd6LTS6IpCMOMhG80Rbn0IRZZk2yqP9ibQQ/640?from=appmsg "")  
  
其它工具的规则也可以进行查看。比如我们去查看一下 Badcode 里面的一些检查规则，发现也类似。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0Buhe2UKwYenoYcSjCiaocH3urqJLRSQnWdnqt7kP4Ql5KcDEpibJwiapAKicA/640?from=appmsg "")  
  
  
所以先学习代码审计，你可以先学习一下 PHP 常见威胁函数有哪些，然后再查看这些函数是如何调用的，最后整体进行漏洞挖掘。工具进行测试，也可以手工加工具进行测试。最后结果漏洞发现，不管采用哪种方式，你都可以达到一个上升。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/YohfLjnf0vfAgug0bSTzdWr8svyzDCGbW1licJs6oRKPEYNWPk2A1mT8EibialdIqp8iblW8ictIpzgRfTwuNPN8JFA/640?from=appmsg "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**注入敏感函数**  
##   
```
```  
  
（1）案例 1  
  
为了讲解这些常用函数，临时写了一个 HRvul 小靶场进行漏洞练习。参考了部分安全靶场。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhlLG5hias7JX7fWdibKUH0VzWruuWqLwAia8bkGjUzncLsFVJ2cZ6WADVw/640?from=appmsg "")  
  
首先看注入源码部分:  
```
```  
  
对 query_string 传过来字符进行检查 inject_checking 函数，我们再看一下这个函数有哪些操作：  
```
```  
  
对常见函数都进行检查，我们看看能不能进行绕过，可以直接对常见函数进行编码既可以绕过。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhcP0TQ84gab4prC6r6h2mXB2J3Ocicj71A40gmM0gfMnhuHtN4ibTfvUA/640?from=appmsg "")  
  
（2）案例 2  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC6CankDUFDurKHNPv6c9ko5AqkwHqWpfosEJZolyMm7jQJgETLL5c3liagnTI6wSibQyRKJs5uBBgFw/640?wx_fmt=png "")  
  
这里我们用到了 mysql_query 这个函数。由于$id 参数在传参过程中没有进行修饰，直接传给了 MySQL。造成了注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC6CankDUFDurKHNPv6c9ko501vNgyKf1ImmVAia8gkDje5L6Q8CyuBwNuB2ic5r5ql7ZgBROPgD37Aw/640?wx_fmt=png "")  
  
  
（3）案例 3  
  
Simple Down 简单下载系统 v5.4  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhmIjcuJg4GJg8TdH8JWw2MBK6MFWGC7Md6Vx7secKNbCibBSbHciatdsg/640?from=appmsg "")  
  
  
从源码状态来看，应该没过滤直接 mysql_query 或者过滤不严格。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**宽字节注入**  
##   
```
```  
  
宽字符是指两个字节宽度的编码技术，如 UNICODE、GBK、BIG5 等。当 MYSQL 数据库数据在处理和存储过程中，涉及到的字符集相关信息包括：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC6CankDUFDurKHNPv6c9ko5AqkwHqWpfosEJZolyMm7jQJgETLL5c3liagnTI6wSibQyRKJs5uBBgFw/640?wx_fmt=png "")  
  
宽字节对转义字符的影响发生在 character_set_client=gbk 的情况，也就是说，如果客户端发送的数据字符集是 gbk，则可能会吃掉转义字符\，从而导致转义消毒失败。 例子 3 就是一个存在宽字符注入漏洞的 PHP 程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC6CankDUFDurKHNPv6c9ko501vNgyKf1ImmVAia8gkDje5L6Q8CyuBwNuB2ic5r5ql7ZgBROPgD37Aw/640?wx_fmt=png "")  
  
```
```  
  
产生漏洞代码我们已经利用黄色底纹已经标出来，主要数据库编码采用了 gbk编码，导致了宽字节注入。  
  
POC 如下http://127.0.0.1/hongri/hongrisec.php?name=a%df' or 1=1; +%23 其原理是 mysql_query("SETNAMES 'gbk'",$conn)语句将编码字符集修改为 gbk，此时，%df'对应的编码就是%df%5c’，即汉字“運’”，这样单引号之前的转义符号“\”就被吃调了，从而转义失败。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
  
一个汉字就把单引号吃掉了，导致过滤失败，注入我们还可以继续进行。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**二次编码注入**  
##   
```
```  
  
seay 代码审计书中也描述过二次编码注入，主要是利用工具采用正则进行编码寻找，然后寻找漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
  
代码分析：  
```
```  
  
主要是 urldecode 这个函数导致问题。Addslashes 函数主要是对单引号、双引号加反斜线进行注释。而 urlencode 这个函数又进行编码了，导致漏洞产生。比如我们进行编码，%2527，在这里%25 编码的结果是%，如果程序使用 urldecode函数，会直接和 27 数字连接上，形成单引号导致绕过 addslashes 函数，形成注入。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhedJuniazLG6HtrLiaraL5yPnnhlVOKKmdnMibEQcUgoZbyQ7K35fcUpXQ/640?from=appmsg "")  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**MySQL 二次注入讲解**  
##   
  
在浏览文章的时候，发现一个图片比较好，就给大家放过来更容易理解二次注入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhtkYK1iaByYCQgBhQvTibHK4jtx2x49agdiawpUjJv0XwzM5Xr7icvAKo2A/640?from=appmsg "")  
  
来段代码讲解一下，比较典型代表了二次注入。  
  
Hrconfig.php   
```
```  
  
Hrreg.php  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhGrfiajRoicE4V1PC0xKuqicnUPMoYhrq3atVVF1VMJ1aJoElETOGz7pSQ/640?from=appmsg "")  
  
二次注入的利用就是把第一次存储到数据库里面的值在此调用然后进行二次利用。  
  
Search.php  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhmzcMXTK0LcVYZmKsfVm1Ef5oD6ibic1fFnS8T4ibh6CMM8fc32ITEQ9Mg/640?from=appmsg "")  
  
代码已经为大家分析完毕。现在直接进行操作。首先在输入表里面输入字段。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhMyg3xV9KU2gw7yeJXBYric3z3hZfZyxicNT7siaDoibUxDgXUuy2oruTXA/640?from=appmsg "")  
  
我们已经在输入把单引号已经输入进去，我们查看一下数据库。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhibdWz0iaib3gCIDibumMcYytF2NbrXLyQ9dzDwbzxmGGfFicdibicDp1K9NHw/640?from=appmsg "")  
  
然后调用邮箱，发现直接触发单引号导致报错。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhbticYqoKt9jTAwdc6e4lcrRLj0hdLeM9PysLZa0xx0MFVGlVnFlp43Q/640?from=appmsg "")  
  
然后我们重新注册一个语句。利用 MySQL 语句进行注册  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhbticYqoKt9jTAwdc6e4lcrRLj0hdLeM9PysLZa0xx0MFVGlVnFlp43Q/640?from=appmsg "")  
  
插入数据库语句。然后在利用查找语句进行查找邮箱语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhXkcuiaKPPGGdErMKe3VbxX7zHjQAwe0HWHCqDLC1Am9nj9tl5gn33icg/640?from=appmsg "")  
  
发现已经查找成功。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**文件包含**  
##   
```
```  
  
本地包含漏洞  
常见漏洞代码：  
```
```  
  
案例 2  
```
```  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**文件上传**  
##   
```
```  
  
直接看代码讲解：  
```
```  
  
主要是对图片类型进行判断，如果不是图片类型就返回错误。上传内容也比较多。后续看我们完整版本报告。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**任意文件删除**  
##   
```
```  
  
代码注入 :  
```
```  
  
展示界面：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0Buhd0kCD04zFCZvQVRRwVUNB8RCbbsZ1mVY7K6VwKnD4h49GZdfJEcyKA/640?from=appmsg "")  
  
然后直接进行代码讲解:  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhGrEnVp6BJyiaIYwehZqibCnJHsHBEbVxecj417l3SictBZolib13ibk2GOg/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhjGZGXQtczq0PnjFFia1IZnW4RlQX6yaPvtQ3yPo1c36VicDSticB4Lib5A/640?from=appmsg "")  
  
直接当成代码执行。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**命令执行**  
##   
  
system、exec、shell_exec、passthru 、pctnl_exec、popen、proc_exec、  
命令讲解  
```
```  
  
直接当成命令执行。Hongri 的值如果可以控制，我们就可以执行我们想执行的命令。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhLoMDJAjb9AYaoGOsAZ6DFTfsiaLl6LUjibd2RosIzeiaUT41km37OJHWw/640?from=appmsg "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**变量覆盖**  
##   
```
```  
  
函数演示  
实例演示 wooyun：frcms (wooyun 2014-073244)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Fuj40DV8ibvBp5tkPWM0BuhpYl9YlByOLX2X40jUIFlExmN1wtfcTicc0J4DROETZLOkNxoWNCUNNQ/640?from=appmsg "")  
  
他会把你从 GET、POST、COOKIE 中的变量注册为全局变量，因此我们直接通过GET 参数提交 $insLockfile 变量即可绕过。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**反序列化**  
##   
```
```  
  
代码讲解：  
当在 php 中创建了一个对象后，可以通过 serialize()把这个对象转变成一个字符串，保存对象的值方便之后的传递与使用。测试代码如下:  
```
```  
  
然后我们查看一下反序列化之后的值 O:9:"hongrisec":1:{s:4:"test";s:3:"123";} 这里的 O 代表存储的是对象（object）,假如你给 serialize()传入的是一个数组，那它会变成字母 a。  
  
9 表示对象的名称有 9 个字符。"hongrisec"表示对象的名称。1 表示有一个值。  
  
{s:4:"test";s:3:"123";}中，s 表示字符串，4 表示该字符串的长度，"test"为字符串的名称，之后的类似。  
  
unserialize() 与 serialize() 对应的，unserialize()可以从已存储的表示中创建 PHP 的值，单就本次所关心的环境而言，可以从序列化后的结果中恢复对象（object）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
```
```  
  
反序列之后，就还原成 serialize 之后的。反序列化漏洞就在序列化的时候插入我们需要插入代码。造成漏洞利用化，但是利用漏洞有一定的限制。具体漏洞讲解请参考完整报告。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NibguMrCKs8oFZhrzBgnhHDIpsiaotZA0ic4Q8VzTUYeXgMFTvloeuF5NW8HjWQBtH6wAylVD00WTdVU74iacomPqQ/640?from=appmsg "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhianWLCvZjmk9oXloibQhdg3V9Rwc1aOljYKR4H4ZYd73oTVibwBdn8UoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CfibHa8M3LXELQegMaIK42D9H3TsurtlhJgKvAzf6T8B9icoiax2BdUDkhAQZmgwpM1iaql1icTyqwPdL6IlsvgibOxw/640?from=appmsg "")  
  
**随机数**  
##   
```
```  
  
将在后续中更详细介绍。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMiaHuehQkkYhiabmtiao6oL9rW7GT6gu1SWLdHnKyQH7515gjNjFbluXrBcRBcVDUlkicjXXp4GXVKsJtl4GGOsoQ/640?from=appmsg "")  
  
**Tips**  
  
**欢迎大家在下面点赞评论加关注，让我们一起在网安之路越走越远！！！**  
  
**END**  
  
