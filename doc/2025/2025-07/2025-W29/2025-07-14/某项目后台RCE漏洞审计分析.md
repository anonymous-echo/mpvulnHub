> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMjM5NDM3NQ==&mid=2247486601&idx=1&sn=c46a906e9e767159a1953d41fbf8e368

#  某项目后台RCE漏洞审计分析  
原创 学员投稿  进击安全   2025-07-14 01:39  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、前言  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9yibEERvicSazBNiaFS01txn0YtmsL8lBnEKicsicTNubicyQPtu7JG3YdVvw/640?wx_fmt=png&from=appmsg "")  
  
此次为学员投稿案例，我们来看一下。  
#### 二、鉴权分析  
  
    入口分析就不分析了，本身非框架的源码，我们来看对应的鉴权分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9cz0uq7ecfzLwPaZeL6rQJDASYYIsfo8miclOQjnX1SRSD6pJ8043Qow/640?wx_fmt=png&from=appmsg "")  
  
可以看到路由为admin目录下的admin_cl.php文件，并且参数mudi为login，查看一波，但是把进去文件之后发现先一个问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR96UIibVvmLjQdxmavcW1UtnGiaLxFNRtgqH3c09yvOVUVYVIElbKPEq2g/640?wx_fmt=png&from=appmsg "")  
  
其中参数我去哪里找去，mudi在上面并没有定义，可不可控我们知道了肯定是可控的，但是就是无法确定这么传递进来的，所以这里我们要跟进check.php文件了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9sqI0PUFaWkohPiaFJ7VSUad57bHj3A67KQeicl9wEnHLmDKRZwO115yg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9HjmoK76ZiavQPXNxic1c4d4fFdiaeFUVnpicu1NX2ibRic61Tyiat0HOL0ibnA/640?wx_fmt=png&from=appmsg "")  
  
这里就是确定一下你是否存在这几个参数，看其他的吧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR91Ud4tDAuxk50HBrrPIwhSPFmfSFpcE9iblnPPyz5b5UVn3h26lgv1eg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9fFtAvNmGXxiaOtoHxcvE8k9JoLaz6T9RiaGS34eAp0z9wXvFRov8X5tQ/640?wx_fmt=png&from=appmsg "")  
  
去除两边空字符等，传递给了Get方法，继续往下走。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR93C195L0tuDyN2o1eZvkibrJeM0ctHy7fo4icnzibo3wurZUpWTz3SQF8A/640?wx_fmt=png&from=appmsg "")  
  
然后传递到了可控$_GET当中并且判断是否存在值（封装这么多层有diao用）  
  
mudio分析完了，开始分析登陆点  
  
三、登陆点分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9YcwdryUW27eNRhNjr7wJcD9RzWFAXs44SWgtmXJNSG5TljSZiaLp0Xw/640?wx_fmt=png&from=appmsg "")  
  
很明显当mudi等于login的时候调用login方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9EK7sIdVPZ40xFvK0gIaV1Ldico5aJeTibvAloendgibmnrJIhBvWmJAfQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到接受的参数有pwdKey、pwdMode、username、userpwd以及verCode验证码。  
  
这里可以看到讲参数username传递到了PostRegExpStr方法，我们跟入，并且第二个参数为sql  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9CSxyw0E1zqjciaDJqHkxZRnNyla01FMBAibqxxVAwX3z8u6uqXYUpNRw/640?wx_fmt=png&from=appmsg "")  
  
可以看到给str可控之后传递到了regExp当中，跟入方法查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR92uiaoFiajQevGDrvlLmibHDicvxnUgPgoy3C0PubxmsMBNl9F3KRoic6MQA/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们现在fnum为sql我们并且实例化了Filter方法我们跟入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9Il6ULX6OFX4ghPfTeBGFEvMEA74cqYJJlWdic75ZHOqUoCQTUmBSR8w/640?wx_fmt=png&from=appmsg "")  
  
在这里面讲字符串全部进行了过滤，但是无所谓了，也没想着登录框能出现注入，我们继续往下看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR94Bsya74sVibcrbwnmbuqv4AQkZYy89RFEZQho7bofxrNGIvicKAvqDpg/640?wx_fmt=png&from=appmsg "")  
  
其中99行进行传递进去了我们的username值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9zbHEVARV9ibs0sC6XFWxgibWicg5gkFR5L2NGcIwvZOx9lOpHnvvY91zA/640?wx_fmt=png&from=appmsg "")  
  
然后根据我们传递进去的username得到对应密码进行与用户的密码进行判断，并且其中的dePwdData为对密码加密的一个方式，加密之后在进行md5加密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9WLkx5u7W9xaxPWZUgP2FAZm9T9OJ5FOML3uMiaQjyricGwq6ZaHwJib6w/640?wx_fmt=png&from=appmsg "")  
  
登录成功之后进行一系列的添加session  
  
这里就不继续往下分析了，我们看对应的后台鉴权点。  
##### 四、后台鉴权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9Yan3I70XMZm4drQ6MibTMZVicM4kNAF9EMtmxVU5z4E6Rap1w3qZA83Q/640?wx_fmt=png&from=appmsg "")  
  
在后台功能点当中可以非常明显的看到Open还给了注释为用户监测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9OPdeEQiaXShVGSACDoYXhkoZvPeCg9frauBdxzia0vNAc9nFcYBlYLGg/640?wx_fmt=png&from=appmsg "")  
  
分析的不错也是进行查询数据库里面的信息然后在拿出来进行比对，绕过的话比较难，我们来看看对应的漏洞把。  
  
五、漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9M3S93ibpj6buDcicBmibRnzTsYl9O9np8wia71YDxib5ySHfiaIvZLUfmEug/640?wx_fmt=png&from=appmsg "")  
  
在这个界面可以进行慢查询  
  
没有开启⽇志的话就开启⽇志  

```
set global slow_query_log=1;
```

  
设置⼀下⽇志路径  

```
set global slow_query_log_file='D:\\phpstudy_pro\\WWW\IDCcms\\
```

  
查看⼀下状态，成功写⼊  

```
show variables like '%slow_query_log%';
```

  
（其实就是Mysql拿shell的那一套）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhX0lTaJgCQibFnnxyZp6lnR9iaPw3tz0BEpXtpSIbVdZmSyvnoL1qBKL1JyZ2GsZkDibhiaPN46HBuq9w/640?wx_fmt=png&from=appmsg "")  
  
成功写入文件进行RCE。  
  
六、完结  
  
代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
