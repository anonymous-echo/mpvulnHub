#  无参数读文件和RCE的利用研究   
NEURON  SAINTSEC   2025-01-31 10:02  
  
点击上方  
蓝字关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnScVcsRouHVwHZPpajicxUOMdEQsTIgA14Mib2XfRN7F5OEv0SyLmTYEiczH8qyPajofTKKAnOeFmCwQ/640?wx_fmt=png "")  
  
  
  
  
最近研究了一个以前的题目，涉及到无参数RCE  
  
所以写了一篇文章来记录  
  
首先来看原理  
```
```  
  
根据代码，可以发现，这里例如  
a(b(c()));  
可以使用，但是  
a('b')  
含有参数不能使用  
  
正常情况下，  
print_r(scandir('.'));  
可以用来查看当前目录所有文件名  
  
但是要怎么构造参数里这个点呢  
  
这里就需要使用到  
**localeconv()**  
函数  
  
localeconv()返回一包含本地数字及货币格式信息的数组。而数组第一项就是"."  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnScVcsRouHVwHZPpajicxUOMXib4JXEbpUIvMpgibRIkUkurwwib86o3v8Ff7QTLicQG7aAz5bBSjyh1fg/640?wx_fmt=png "")  
  
这里还有一个知识点，就是从数组中取得数据，可以用到如下函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnScVcsRouHVwHZPpajicxUOMdGT3tnSRSsNamk3iaAadno8jmDaZDjKXMVvjb5CbXXIGxkFXmY6v3kg/640?wx_fmt=png "")  
  
这样我们就可以获取数组的第一项  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnScVcsRouHVwHZPpajicxUOMJCPQnhUc19hMv3xj7CAGdURoGBA75Ivae415OPLTtmG6wwtOm9jlUg/640?wx_fmt=png "")  
  
这样就成功打印了当前目录  
  
那么我们可以利用getallheaders()来达成RCE，但是该函数只能在  
Apache  
环境下使用  
```
```  
  
这样我们在headers中输入命令内容，使用getallheaders来获取就达成了简单的RCE  
  
利用的方法还有很多。。。。  
  
为了更好的理解，我们来看一个以前的赛题  
  
题目代码如下  
```
```  
  
访问  
?action=go  
```
```  
  
通过获取headers的方式，可以设置ua来传入字符串，成功执行命令。  
```
```  
  
由于disable_classes和disable_functions的设置，导致后面open_baseidr完全没办法绕过，但我们可以用glob协议读取目录  
```
```  
  
这里涉及到一个知识点，对于不同的请求来说，  
open_basedir  
都是不同的，那么服务端就需要获取请求的地址，然后做解析，这部分的配置一般是由apache来做的，但如果请求的host中不包含这个sha1的字符串，那么就可以让后端无法获取到这个字符串，就会将  
open_basedir  
设置为  
/var/www/sandbox  
，就可以读取这个目录下的文件了。  
```
```  
  
  
