#  SSRF 漏洞自动化 寻找   
真爱和自由  迪哥讲事   2025-01-12 13:40  
  
## 环境搭建  
  
下载项目https://github.com/l4yn3/micro_service_seclab  
  
然后放入 IDEA 即可，之后运行  
  
这里主要研究 SSRFSSRF 的漏洞代码  
```
```  
  
但是这个不太明显我修改了一下这样更好观察  
```
```  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguCKsC4ghiaSr01Qub9G6x8trpInT9JFA2sORshd5NticV0oULxtPic7X7Q/640?wx_fmt=png&from=appmsg "")  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5Lgu7SHb0zHE1icIfFbBiaoibuSaXKGtvWHMOobFnKmJ5lOibl2MzLLbbqdFnw/640?wx_fmt=png&from=appmsg "")  
  
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
  
然后我们可以查查看![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguOZ628IpDKVGZiaKYtGj0gUjo8RpBnbEppuGiaW6Oqqmz0g7icXzExIic7Q/640?wx_fmt=png&from=appmsg "")  
  
  
随便点几个  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguXfQiaIOSicOnMKWqklQS4HicicocJK4JdkL2BicH9vllSHfjhGgWLhLtSGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguXl11lyDTkFYicuOls7k4IibbLzPyMD2ST49ClHUefgN7cR7icFPIx4mNA/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguLohcVQTDMDqRfwyHAR3ib7miaaTZzAPzUiau05qIY59LwKFM9t8ibZpydw/640?wx_fmt=png&from=appmsg "")  
可以看出来大概是以所在的包名来分的  
  
比如 okhttp 这种很小众的  
```
```  
  
我们找找这个包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguQHGE7Gp4ZKibBYXo67iaUsaKibQTaKWQmRanoj3IyB5Uuic57yHMur2GiaA/640?wx_fmt=png&from=appmsg "")  
可以看到是有的  
### isAdditionalTaintStep  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguXROibfLvyIS65aBkw2kujuicCAr7VukyhbNZic0YcQk7ibQPQ0k7yWveqw/640?wx_fmt=png&from=appmsg "")  
  
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
  
其中 **UriCreation** 代表的是  
```
```  
  
比如  
```
```  
  
**UrlConstructorCall**代表的是  
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
  
**userInput-->URI.create(userInput)**这一步它会跟丢，找不到了  
#### TypePropertiesRequestForgeryAdditionalTaintStep  
```
```  
  
注释给的很清楚了  
  
就是如下的这种也需要污点传播  
```
```  
  
通过这种方式，我们可以确保污点传播被追踪到 Properties 对象  
### isSanitizer  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguiaoDibFhfkePEwFpPnbhQgLRicRnS0YUT14e4ib1KuOgYhFj1jWIJW3Pgw/640?wx_fmt=png&from=appmsg "")  
emmm，理解为清理的意思吧，就是有些点不是我们的点，可能控制的部分并不能造成漏洞  
```
```  
  
跟进 RequestForgerySanitizer有许多的实现类  
#### HostnameSantizer  
```
```  
  
比如http://example.com/page?name=value 中的 ?name=value 是查询部分，我们只能控制后面的，这种就不算一个点  
#### RelativeUrlSanitizer  
```
```  
  
就是需要满足我们传入的是绝对的路径，这个 codeql 的代码还是很复杂的  
  
比如这端代码  
```
```  
  
call.getMethod().hasQualifiedName("java.net", "URI", "isAbsolute")：这部分会匹配 URI 类中的 isAbsolute() 方法。  
  
然后  
  
e = call.getQualifier()：call.getQualifier() 返回的是 uri 对象，即调用 isAbsolute() 方法的那个对象。因此，e 需要与 uri 对象匹配。  
  
branch = false：这意味着我们正在查找方法调用的“否”分支，也就是 uri.isAbsolute() 返回 false 的情况。  
  
确保我们可控的是绝对的 uri  
  
当然还有一些......大家自己看看  
## codeql 实践  
  
我们运行最后的代码![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguD8SrDQrH4DPvuiaibr1akoXibibdic8cAiaJiaZOnfGSaWnCsglsLqueBubWg/640?wx_fmt=png&from=appmsg "")  
  
  
没有二和三只有三个从 sink 到 source 的点，但是我们是有五个的，这个的话就需要慢慢检测了  
  
首先其实 sink 点是没有问题的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguvOjEUOjLkaPrcibgiamLv49icjWC8FbkF7QyJno9OqjrWTutH72EMibNXQ/640?wx_fmt=png&from=appmsg "")  
问题出现在污点传播的过程中可以看到https://forum.butian.net/share/2117位师傅  
  
问题出现是在正常情况下程序不会觉得 String.valueOf 方法返回的仍然是污点。  
  
这里我们就需要自己去修改了  
  
这里我们需要按照上面分析的同理去操作  
  
还是回到这个代码RequestForgery.qll我们只需要续写一下 DefaultRequestForgeryAdditionalTaintStep  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguEGrYicY1NIEicNchh7aiaXYRjeMSU2RzAQwiaTrjW4rk7u4qnWcGTShxibw/640?wx_fmt=png&from=appmsg "")  
成功的匹配到  
  
然后续写  
```
```  
  
然后我们再去查询  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6JGkozDWzXR46Koxav5LguGAo3wxoP521nG1ChgtWKW5ziclmjr9u9DXpicIAky8r6NKJkmicMv1jYw/640?wx_fmt=png&from=appmsg "")  
  
可以看到是已经成功了  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
## 往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
参考https://forum.butian.net/share/2117  
  
原文: https://xz.aliyun.com/t/17030  
  
