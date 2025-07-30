#  codeql 之 SSRF 漏洞自动化 寻找   
真爱和自由  安全洞察知识图谱   2025-02-07 00:30  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1详细介绍  
  
```
作者：Arcueid（先知社区）
原文：https://xz.aliyun.com/news/16467
```  
  
## 环境搭建  
  
下载项目  
https://github.com/l4yn3/micro_service_seclab  
  
然后放入 IDEA 即可，之后运行  
  
这里主要研究 SSRF  
SSRF 的漏洞代码  
```
```  
  
但是这个不太明显  
我修改了一下这样更好观察  
```
```  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIXG1icT7JZXJlcfnQ6pUA6ZsiapfoDk4xk2Iic74UvnJiana9IXqFHK7ESw/640?wx_fmt=jpeg "")  
  
成功  
## 漏洞分析  
  
我们首先需要看明白造成 SSRF 漏洞的类型  
  
**HttpURLConnection 发起请求**  
```
```  
  
HttpURLConnection 是 Java 标准库中的一个类，用于通过 URL 发起 HTTP 请求。这里直接将用户提供的 URL 用来创建连接，并发送 GET 请求  
  
而且 URL 我们可以控制，造成了 ssrf  
  
**Apache HttpClient**  
```
```  
  
这里使用了 Apache HttpClient（通过 fluent API）发起 HTTP 请求。用户提供的 URL 被用来发起 GET 请求，并返回响应。  
  
**OkHttp**  
```
```  
  
OkHttp 是一个比 HttpURLConnection 和 HttpClient 更现代的 HTTP 客户端，它的设计更注重性能和易用性。  
  
**DefaultHttpClient**  
```
```  
  
这段代码使用的是 Apache HttpClient 中的 DefaultHttpClient 类，HttpGet 请求方式用于发起 HTTP 请求。DefaultHttpClient 是 HttpClient 的一个实现，它提供了更丰富的功能和配置选项。  
  
**openStream**  
```
```  
  
URL.openStream() 方法打开用户提供的 URL 并读取数据。openStream() 方法本质上是执行了一次 HTTP 请求，获取响应的字节流。  
## codeql 分析  
  
首先就是 sink 点的匹配  
  
官方的规则库相当的复杂，包含的类型远远比我们这五种多  
  
其中定义在 RequestForgeryConfig 类  
  
我们看注释  
```
```  
  
描述请求伪造风险的污点跟踪配置。  
  
我们的 SSRF 类型就属于 request-forgery 风险  
### source 点分析  
#### RemoteFlowSource  
```
```  
  
首先是 RemoteFlowSource  
  
我们跟进  
```
```  
  
很明显看注释远程用户输入的数据流源  
  
我们看到实现类，这里很多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIWxK1kg7icsHRHIgShyhG1GyD5EooWdA2V05E3L1cwbCtkuHHAvJxyPQ/640?wx_fmt=jpeg "")  
  
这里就拿  
```
```  
  
SpringServletInputParameterSource 来举个例子  
  
首先我们需要知道什么是 SpringRequestMappingParameter 参数  
  
这个就不跟了，因为也不是重点，就是  
```
```  
  
参数的调用方法是 spring 中请求映射的方法即可，这个大家跟了就会明白  
  
isTaintedInput 呢看注释就可以明白  
```
```  
  
isTaintedInput() 是一个用于判断输入是否为污点的谓词  
  
然后我们可以查查看  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIkcGcIrvdBUXqKlDLHMwhAF9gXRSF6TWp80m2MqyXf1v0u4lqCpiahgg/640?wx_fmt=jpeg "")  
  
  
随便点几个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIsHYYpszTzlq3anW4RBhccQibMsGwj0RzbeHll8e4PwPVwctgREBZEvQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIvSiceO3aymloXJA0ehZkqp5Jav771zv0pB73zK9MaD74j8QuFW04ialg/640?wx_fmt=jpeg "")  
  
大家看这个截图应该能明白到底匹配了些什么 source，其实就是 spring 中用户可控的输入  
#### 排除的 source  
```
```  
  
跟过去  
```
```  
  
就是排除某些远程请求：然后，排除所有通过 HttpURLConnection.getInputStream 方法发起的远程请求。这是因为 getInputStream 方法通常用于安全地获取远程资源，例如通过 HTTPS 请求访问外部 URL，不把这些认为是可疑的  
### Sink 点  
```
```  
  
跟进 RequestForgerySink 类  
```
```  
  
他的实现类是 DefaultRequestForgerySink 类，而匹配的是 request-forgery 类型  
  
sinkNode 就是标记特定的数据流的，而 request-forgery 表示被标记的类型  
  
而我们怎么知道哪些是 request-forgery 类型呢？  
  
codeql 有一堆配置好了的类型  
  
我们可以全局搜索 request-forgery  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmILgDNxic2Eia1ojm8mv9NjdpIgoa5rVNyKBoZSpb38PAbgAU8fh8tImWg/640?wx_fmt=jpeg "")  
  
可以看出来大概是以所在的包名来分的  
  
比如 okhttp 这种很小众的  
```
```  
  
我们找找这个包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIic3KaQfHlpiaBfUeajQeClmx1AJPiaVCiaprCJjIDWzuyWQG913xkvCjJw/640?wx_fmt=jpeg "")  
  
可以看到是有的  
### isAdditionalTaintStep  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIxFvqwHJEBbHjwxDNPhPWN1ZZNNzrw8IsicxI2vWsLY4y7dWsJnbQaew/640?wx_fmt=png&from=appmsg "")  
  
这个很好理解，就是可能污点不能从 a 到 b 去追踪，但是实际的情况 a 到 b 就是一个传播过程，这时候我们就需要自己去跟踪污点了  
```
```  
  
跟进 RequestForgeryAdditionalTaintStep  
```
```  
  
一共是两个具体的实现类  
#### DefaultRequestForgeryAdditionalTaintStep  
```
```  
  
其中 **UriCreation**  
 代表的是  
```
```  
  
比如  
```
```  
  
**UrlConstructorCall**  
代表的是  
```
```  
  
也就是匹配构造函数的，不过匹配的是  
```
```  
  
一个是 URI，一个是 URL  
  
而 propagatesTaint 方法就是我们逻辑的主要实现  
  
比如 UriCreation  
  
如果其主机部分（host） 被赋值为 pred.asExpr()（即当前污点源），并且 succ.asExpr()（即潜在的污点目标）是这个 UriCreation 对象时，污点就会从 pred 传播到 succ。  
  
比如下面的代码  
```
```  
  
我们的规则就是  
  
当 userInput 被用作创建 URI 或 URL 时，污点就会从 userInput 传播到 uri 和 url 对象上。  
  
如果没有那么我们的传播就是  
  
**userInput-->URI.create(userInput)**  
这一步它会跟丢，找不到了  
#### TypePropertiesRequestForgeryAdditionalTaintStep  
```
```  
  
注释给的很清楚了  
  
就是如下的这种也需要污点传播  
```
```  
  
通过这种方式，我们可以确保污点传播被追踪到 Properties 对象  
### isSanitizer  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmI7cUbMibut3QDfy0HCjD2LqF1Vx3H2b1nBfwsNynt3I2rFdjSrtzPLeQ/640?wx_fmt=png&from=appmsg "")  
  
emmm，理解为清理的意思吧，就是有些点不是我们的点，可能控制的部分并不能造成漏洞  
```
```  
  
跟进 RequestForgerySanitizer  
有许多的实现类  
#### HostnameSantizer  
```
```  
  
比如  
http://example.com/page?name=value  
 中的 ?name=value 是查询部分，我们只能控制后面的，这种就不算一个点  
#### RelativeUrlSanitizer  
```
```  
  
就是需要满足我们传入的是绝对的路径，这个 codeql 的代码还是很复杂的  
  
比如这端代码  
```
```  
  
call.getMethod().hasQualifiedName("java.net", "URI", "isAbsolute")  
：这部分会匹配 URI 类中的 isAbsolute() 方法。  
  
然后  
  
e = call.getQualifier()  
：call.getQualifier() 返回的是 uri 对象，即调用 isAbsolute() 方法的那个对象。因此，e 需要与 uri 对象匹配。  
  
branch = false：这意味着我们正在查找方法调用的“否”分支，也就是 uri.isAbsolute() 返回 false 的情况。  
  
确保我们可控的是绝对的 uri  
  
当然还有一些......大家自己看看  
## codeql 实践  
  
我们运行最后的代码  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmI0dbqVeLfgYrAY3vEhYo08icicoJkOgaYYn8RF7wpVur3oFjxBiaXTTBKA/640?wx_fmt=jpeg "")  
  
  
没有二和三  
只有三个从 sink 到 source 的点，但是我们是有五个的，这个的话就需要慢慢检测了  
  
首先其实 sink 点是没有问题的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIQmGSXCeiagfxoPYv5nfNia2j1VGeSzNwibSSsy4CvsibicKcJLJfPVolA2g/640?wx_fmt=jpeg "")  
  
问题出现在污点传播的过程中  
可以看到  
https://forum.butian.net/share/2117位师傅  
  
问题出现是在正常情况下程序不会觉得 String.valueOf 方法返回的仍然是污点。  
  
这里我们就需要自己去修改了  
  
这里我们需要按照上面分析的同理去操作  
  
还是回到这个代码  
RequestForgery.qll  
我们只需要续写一下 DefaultRequestForgeryAdditionalTaintStep  
  
首先需要匹配到 valueOf 的代码，然后提取里面的参数  
```
```  
  
调用者是 String  
  
首先我们去匹配这个类型  
```
```  
  
然后只需要使用如下的代码  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmIuzVFMYjK5kn2DSj3wtlWEFb7iaqlHedCIbicpXV8E8swRxaWLsRfrJhw/640?wx_fmt=jpeg "")  
  
成功的匹配到  
  
然后续写  
```
```  
  
然后我们再去查询  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicLdiaG401iamD2WcNy9xwXmI5xMaribhCXtXj4smS9icP2m1oaojGIE8viaiaicKFTzYdxNfkonYBbVrHAQ/640?wx_fmt=jpeg "")  
  
可以看到是已经成功了  
  
参考  
https://forum.butian.net/share/2117  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh91uZfvlPtyiaOKyFDs4mnQXibTpv0BTpkKYEYOPMY0moWEkV5libR3rLKXSOCwY3PK9uhw24rtT08CA/640?wx_fmt=jpeg&from=appmsg "")  
  
