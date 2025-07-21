> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxNzkyOTgxMw==&mid=2247494434&idx=1&sn=f85a9125e3a2b4c7eb1bf4c737ee71d2

#  契约锁pdfverifier RCE攻防绕过史  
 哈拉少安全小队   2025-07-21 12:01  
  
# 前言  
  
之前比较懒一直没安装契约锁进行审计最近正好爆出挺多这个产品的漏洞，于是抽空分析一下近期的漏洞为后续挖掘打基础。这篇文章主要写
```
pdfverifier
```

  
接口的漏洞以及这个地方补丁被多次绕过的分析。  
# pdfverifier漏洞分析利用  
  
下面分析使用的版本为Linux下的
```
4.3.4
```

  
版本，契约锁启动后会开启三个端口分别对应下面三个服务  
- 电子签约签署平台：9180  
  
- 电子签约管理控制台：9181  
  
- 电子签约开放平台：9182  
  
官方建议只对外开放
```
9180
```

  
端口
```
pdfverifier
```

  
接口的漏洞便是在这个端口，对应的jar包为
```
privapp.jar
```

  
。将这个jar包拿出来分析发现无法解压![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yCHUdyhtmwia7hChJ2vpJKCQhv0zFouyhFAo310jXtlZ8IckzGkcdJSg/640?wx_fmt=png&from=appmsg "")  
使用
```
010Editor
```

  
打开![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yghfuk0IBRZHsT5ib8FN4ph81nwpjV9f7tiaIwRbd7y1CAJU8GBJWmKTQ/640?wx_fmt=png&from=appmsg "")  
发现前面一大段为
```
bash
```

  
脚本直接将前面的字符删除即可成功解压。解压以后发现
```
BOOT-INF\lib\
```

  
下只有少数的
```
jar
```

  
包，简单查看目录结构确定其他依赖应该在
```
/opt/qiyuesuo/libs
```

  
目录下于是直接将
```
/opt/qiyuesuo/libs
```

  
全部复制到
```
BOOT-INF\lib\
```

  
然后
```
idea
```

  
打开即可。这里有个需要注意的问题当我们没把
```
spring
```

  
的依赖放入
```
lib
```

  
时
```
idea
```

  
的两下
```
shift
```

  
查看接口是没有用的，必须存在
```
spring
```

  
的依赖他才会扫描得到接口。根据classes目录结构很快可以注意到
```
com.qiyuesuo.config.PrivappConfigurer
```

  
定义了过滤器和白名单接口。![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ysKvhOE1VG1ia53fXAMXyEEgFbqDvmKCZcAic2WibxVbPoiaxcwgq8W3lHQ/640?wx_fmt=png&from=appmsg "")  

```
pdfverifier
```

  
接口正好在里面直接两下
```
shift
```

  
定位到接口的实现方法![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ypibw2H57XhrQN7AuvlJDQu3qTXibEeKhfYHQ55aibBFx2HG4t7ibviaXtyA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yfCwA5lxJXtLC3TXhTp4MjKqRUeaLcSMvml5ibOshkriaXvVGs6GZic7eA/640?wx_fmt=png&from=appmsg "")  
获取扩展名以后传入
```
com.qiyuesuo.api.PdfVerifierController#doVerify
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yFuF9B1I0Dc4IRUQFMswWvld5GcPB35w43lJWwn5Qa3mdTT2jReU8CQ/640?wx_fmt=png&from=appmsg "")  
当扩展名为
```
ofd
```

  
时进入
```
net.qiyuesuo.common.ofd.verify.GjzwOfdVerifyHandler#verify
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ygGpQGCQfSBF9sLEDf1JsrJBGK5tez4BDBibTVtKxicpuRlM4KZW1Ddhg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yXlndUXdqXic8DG4OcPbjXZicpZ3ynSHediaJ4JsT9Sl5QAT6NlXLr1cUA/640?wx_fmt=png&from=appmsg "")  
最后对文件进行了解压操作![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ybtnEUYKFqwZ1AfWZJKiagyjUTfuB34HEX5vveJ1vgTibZO3NFlcR08fQ/640?wx_fmt=png&from=appmsg "")  
这里没有判断目录穿越的情况，所以可以解压文件目录穿越写入任意文件到任意目录。但是这个服务是
```
springboot
```

  
不能通过写
```
webshell
```

  
来
```
RCE
```

  
，可以想到的几种比较通用的办法如写模版文件、往
```
JDK
```

  
的某些的地方写文件然后初始化类、写计划任务。写模板文件的话好像没有配置了视图模板解析，往
```
JDK
```

  
的某些的地方写文件可能不太通用，写计划任务只针对Linux且没有权限因为他这里是用
```
qiyuesuo
```

  
账号起的服务。如果以前下载过qys的补丁的话就会想到他的补丁是热加载的。![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yXkTlN54PvD72Hch9cRv8c0s71N43XR68D3sYrAArHfyD9dYicUgkMiaQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ysiaia5e2XJM0YpEe84ZldibMMzp9zXwZrzhwhcKsUtNq1NI5iaIxpceWGQ/640?wx_fmt=png&from=appmsg "")  
所以我们可以通过覆盖
```
/opt/qiyuesuo/security/private-security-patch.jar
```

  
文件进行代码执行，虽然知道了可以通过覆盖这个文件来RCE但是我们还需要知道怎么构造这个jar包才会执行到我们的恶意代码。根据补丁安装说明可以知道主要逻辑应该在
```
private-security-loader-1.0.0.jar
```

  
点开这个jar第一个类就是
```
com.qiyuesuo.security.patch.loader.SecurityLibManager
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yeY3kA3peQyu2UK5TYaqk8BfqqK4ibxicdZZiaW80Qb6v9B923fRrXHaSg/640?wx_fmt=png&from=appmsg "")  
这里很明显就是触发热加载的地方，检测到
```
hash
```

  
值发生变化就会进行
```
reload
```

  
以及
```
registerQVDLogic
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yxhrAtVibg751ZcdOXia1FQk4aNDFuiaZTyL9dKpo0JyrsAWxMiaRicrxU8w/640?wx_fmt=png&from=appmsg "")  
这里加载jar包![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yr53IsYIYy1k1RdYLA9d5w3NsUMUa7KLVzybxySZVnXlBiakJUUXGUWg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yiayT1GCeH18bicoRicahicwnQhVoMYfOjUPNNvp0VL3G6R9Cia5dRJagaUQ/640?wx_fmt=png&from=appmsg "")  
加载class![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yllXpdFbsLxUK8ic7iaKRPpEPyvSLib34WXibYzsyHYUVibsjcldYSEEmelA/640?wx_fmt=png&from=appmsg "")  
当全类名前缀为
```
com.qiyuesuo.security.patch.filter.logic
```

  
时会实例化这个类此时可以执行到类的静态代码块，所以我们只需要往正常的
```
private-security-patch.jar
```

  
里加入
```
com.qiyuesuo.security.patch.filter.logic.xxx
```

  
 然后在静态代码块里执行恶意代码即可。于是我使用
```
jmg
```

  
生成了一个这样的内存马注入器类名为
```
com.qiyuesuo.security.patch.filter.logic.ofdrce
```

  
进行漏洞利用发现没有成功，经过调试发现我本地的
```
private-security-loader-1.0.0.jar
```

  
可能和我上传的
```
private-security-patch.jar
```

  
版本不对应![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ynFCaI8Vu6ZQaIGzwibay2icPlzfFedcIwHK9QWDHuR98Ke5AbhRe206A/640?wx_fmt=png&from=appmsg "")  
实例化
```
com.qiyuesuo.security.patch.filter.logic
```

  
包里某个类调用
```
com.qiyuesuo.security.patch.common.util.SecurityResourceOperator
```

  
类里的方法时因为其还没有实例化导致空指针异常退出，解决办法是将恶意类命名为
```
com.qiyuesuo.security.patch.filter.logic.AAAA
```

  
这样的话安装字母排序最开始实例化的就是我们的恶意类。 生成恶意类![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yXGfO7tYAevGgJic9jslW2JzMJBusk69GKmXCoeV97U8OZLIeI2Cib4Aw/640?wx_fmt=png&from=appmsg "")  
将恶意类加入正常的
```
private-security-patch.jar
```

  
中(注意有的压缩软件直接拉文件进jar包会导致错误)![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yJm6G3LzhcXXlKVuT2n1N0bfXSg7PL6C0Vib83HfoF4bfDhyU7RoibvJQ/640?wx_fmt=png&from=appmsg "")  
制作恶意压缩文件
```
LINUX
```

  
也可使用
```
/proc/self/cwd/security/
```

  
目录更加靠谱，
```
windows
```

  
可尝试
```
/qiyuesuo/security/
```

  
目录![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yRpReWuDnTpfwfLrmMIw2SVxyVoKHFnic80hU1pZUPCdpNuibqA1lVoTg/640?wx_fmt=png&from=appmsg "")  
构造数据包上传![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yzSVkMrGoBtVNobzQAZmvVsGHvic6pBrIWKQozy5s1GgS5YwnIh6ic2TQ/640?wx_fmt=png&from=appmsg "")  
等待几秒钟成功实例化我们的恶意类![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ybib0Uja4hHA9libJtHeveB7c01WribDhlGEXFxNHFIibWPG6wysI1rEicPg/640?wx_fmt=png&from=appmsg "")  
成功打入内存马![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yFJhIMGP2icsPr2GpJngVe9IRO2ddqv6SOMEDozd55O3nfubUnguMekQ/640?wx_fmt=png&from=appmsg "")  
  
# 1.3.2补丁绕过  
  
这个漏洞最初由
```
1.3.2
```

  
版本补丁修复,补丁关键代码如下![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67y00fnSRrrL9PBSEKtnnNAkYckU69eyCV1Dy5Mog6KLNFaqibZic5zXqmw/640?wx_fmt=png&from=appmsg "")  
先获取URL然后判断是否等于
```
PDFVERIFIER_URL_LIST
```

  
里的某个值
```
ENABLE
```

  
默认为
```
true
```

  
且请求方法为
```
POST
```

  
则使用
```
PdfverifierPreventWrapper
```

  
包装
```
request
```

  
我们这里按照补丁绕过顺序来分析所以直接对比1.3.2和1.3.3补丁即可发现绕过点![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yCqvGUP7ztmibWjLApOyaMWAfYnoiatkSsmTgic1PG4SEKTiaibzcsB5pl2Q/640?wx_fmt=png&from=appmsg "")  
绕过点位于包装类的
```
getParts
```

  
方法，当spring解析上传格式时会调用
```
getParts
```

  
方法此时会调用到
```
com.qiyuesuo.security.patch.filter.wrapper.PdfverifierPreventWrapper#getParts
```

  
而这个方法里面获取文件名和
```
spring
```

  
获取文件名存在差异。
```
spring
```

  
支持将整个文件名URL编码
```
org.springframework.web.multipart.support.StandardMultipartHttpServletRequest#parseRequest
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yjfDNCBlZwkd8SdyCTJLTN3eMFFl4JAqJPCrkedZSqpiaXsKickwquH7w/640?wx_fmt=png&from=appmsg "")  
这个地方会对整个
```
filename
```

  
进行
```
URL
```

  
解码![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yzcSkJiavPkdia0TaACVFf9cMIQBgKPx7M7MKVrPjWTReqSrw0LiaoUuRA/640?wx_fmt=png&from=appmsg "")  
而
```
1.3.2
```

  
版本补丁使用的
```
org.apache.catalina.core.ApplicationPart#getSubmittedFileName
```

  
不支持将整个文件名
```
URL
```

  
解码![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ykFm1DEN8syS1QjfQEYIC4bria3Pia0cLjwfqoX3OwTe7htNmMIPwibq7A/640?wx_fmt=png&from=appmsg "")  
从而在
```
filename.toLowerCase().endsWith(REGEX)
```

  
时判断失败所以可以直接使用
```
URL
```

  
编码的文件名绕过补丁 直接上传ofd被拦截![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yyPdkctGCJSGH0ibrvsS1v2K5B1gByZDmibrficra5vzGDqQUGGJ7WleSw/640?wx_fmt=png&from=appmsg "")  
使用
```
URL
```

  
编码绕过补丁![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yH8ACCCjybeHypVuqTSuydMbOabAiaicwKIDRodmrOhVf8o2B2adTmQug/640?wx_fmt=png&from=appmsg "")  
其实这个地方也修复了
```
MIME
```

  
编码加
```
URL
```

  
编码双重编码的绕过  
# 1.3.3-1.3.5补丁绕过  
  
我下载了1.3.3之后的所以补丁，1.3.4-1.3.5补丁和
```
pdfverifier
```

  
相关的改动感觉不是在修复绕过或者说是其他接口的
```
zip slip
```

  
漏洞修复。所以这里我们直接对比1.3.5和1.3.6补丁![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67y08kDFqCAn4sLadNR2h9buVMJU5HXCOZkq33N8jHwcCOVJgfIvD4lOw/640?wx_fmt=png&from=appmsg "")  
增加了一个
```
removeEndSlash
```

  
方法用于移除末尾的斜杠，其实这个绕过我感觉比上面的绕过更容易想到。我们先看他是如何获取
```
uri
```

  
的![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yL9L8bJ68pucWjI6Do0s12jfAbbVPlZ41E5NdyYOqJxOm8BOyOTHMDg/640?wx_fmt=png&from=appmsg "")  
通过
```
getRequestURI
```

  
获取![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yFZ1jaT8UibG9iapQyCuVykOAicjia8SR0gicH4DHN1oM1UESwJicX1BKWGFg/640?wx_fmt=png&from=appmsg "")  
将双斜杆替换为单斜杠![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yHOzszEGTAC0R68aaC8YC49WARTmz1eO7QXGY5dkuCuzGx4JDblKEdQ/640?wx_fmt=png&from=appmsg "")  
这里使用的等于来判断![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yxdJeNiaHBHNVFBe5Bxsz6jGc5ZkER0lnjsMQtq5GAh945jCeHibRLszg/640?wx_fmt=png&from=appmsg "")  
虽然用了
```
getRequestURI
```

  
获取
```
uri
```

  
但是不能使用下面这类绕过  
- /api/;/pdfverifier  
  
- /api/./pdfverifier  
  
- ///api/pdfverifier  
  
因为他前面有个补丁
```
com.qiyuesuo.security.patch.filter.logic.DangerUrlPreventLogic#doQvdLogic
```

  
是专门判断这类
```
uri
```

  
的，这里就需要使用
```
spring
```

  
的一个特性在路由后面添加斜杠一样可以访问到，所以使用以下
```
POC
```

  
成功绕过补丁![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yrKpJqwxeOZDvspzMRMzm7hQz5gJzDI1ZFOsBSCKGorbNVzU8gl5USA/640?wx_fmt=png&from=appmsg "")  
  
# 1.3.6补丁绕过  
  
直接对比1.3.6和1.3.7补丁![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yiaI6Hbs3WBYEJibgRrYXJF1ZMEF25o3Eu2ReYzLtTzbRDFibhSbgYLeGw/640?wx_fmt=png&from=appmsg "")  
这里修改了
```
removeDuplicateSlash
```

  
方法移除双斜杆改为了移除所有且将
```
/+
```

  
都替换为
```
/
```

  
，所以这里的绕过应该是三斜杠绕过，不过按道理三斜杠会被
```
com.qiyuesuo.security.patch.filter.logic.DangerUrlPreventLogic#doQvdLogic
```

  
检测到，为什么可以绕过呢，因为正好末尾的
```
///
```

  
先经过一次
```
removeDuplicateSlash
```

  
变为
```
//
```

  
再经过一次
```
removeEndSlash
```

  
变为了
```
/
```

  
正好可以过
```
com.qiyuesuo.security.patch.filter.logic.DangerUrlPreventLogic#doQvdLogic
```

  
检测，所以绕过
```
POC
```

  
如下![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67y3BCaicXAzrZWYMMmTPZ0U699vGJY57ia7ZjIJsiaFf8YTonQGO8J7MaDQ/640?wx_fmt=png&from=appmsg "")  
  
# 1.3.7补丁绕过  
  
直接对比1.3.7和1.3.8补丁![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yibu4CWPLOwPt0NNWE03JGNwx2bMxFmmo5RKa8gmaxCOWypby3IdPrQw/640?wx_fmt=png&from=appmsg "")  
这里改动比较大的地方在
```
hasPathTraversal
```

  
方法里，但是乍一看看不出什么问题。 这里移除了
```
(entry = zis.getNextEntry()) == null
```

  
的判断，改为了使用和后面
```
pdfverifier
```

  
接口解压相同的代码，于是猜测有一种办法可以导致
```
zis.getNextEntry()== null
```

  
而后面的解压代码依然可以解压。跟入
```
getNextEntry
```

  
发现会对文件头做判断如果不是zip文件头则返回NULL![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67yPk2RzOqZSjic9DfVg84SM2X6BTzbwtbgSVDOqGRgxrJqwuOwAlkczZA/640?wx_fmt=png&from=appmsg "")  
而后面解压代码没有使用
```
getNextEntry
```

  
于是直接在压缩文件头部添加
```
\r\n
```

  
发现此时
```
zis.getNextEntry()== null
```

  
而解压代码依然可以解压这个压缩文件，所以这个补丁的
```
bypass
```

  
即为在压缩文件头部添加
```
\r\n
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHXuhibIf5DibcExLvvOUZc67ysC9p5cOFqFtEWjhtP5xFknIv3YBID5ricFPc1DsJ3l0VlUpX6ic6xYHQ/640?wx_fmt=png&from=appmsg "")  
我这里测试绕过成功但是内存马没打上后面看了下又是之前的原因实例化
```
com.qiyuesuo.security.patch.config.logic.SecurityPropertiesConfigLogic
```

  
的时候报错了而这个类的顺序是在我们之前内存马顺序之前所以还是建议内存马使用
```
com.qiyuesuo.security.patch.config.logic.AAAAA
```

  
最为靠谱，替换内存马类名后成功注入内存马。  
# 总结  
  
这个漏洞本身其实比较简单，覆盖补丁热加载来RCE值得学习，后续的多次补丁绕过也挺有意思。所以说挖洞的话还是需要多分析历史漏洞说不定就绕过了挖个新的RCE。  
  
  
本文仅供安全研究和学习使用，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用本人负责，公众号及文章作者不为此承担任何责任。  
  
