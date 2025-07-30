#  Java代码审计 | Alibaba Sentinel SSRF漏洞代码审计   
小瑟斯  闪石星曜CyberSecurity   2025-05-25 08:38  
  
内部学员投稿。  
  
首发于：https://xz.aliyun.com/news/18017  
  
学代码审计就找闪石星曜CyberSecurity。  
  
详情可点击下方链接了解。  
  
[《JavaWeb代码审计企业级项目实战》课程2.0升级版，新增10节实战课！依旧低至499，加量不加价！招生！](https://mp.weixin.qq.com/s?__biz=Mzg3MDU1MjgwNA==&mid=2247487386&idx=2&sn=fc36f768e8715e1b0c291519e7dad584&scene=21#wechat_redirect)  
  
  
我公开了一份面向零基础小白的 JavaWeb代码审计入门文档。  
  
欢迎一起来学习，感觉不错别忘了分享给身边的好哥们。  
```
https://www.yuque.com/power7089/ekvyga
```  
  
  
![图片预览](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYd7RkUzZAljDJnVFE5yq3HU9J1lmyCRibNzNeToCkkkrR0ITStW4rJNQ/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
# 一、Sentinel介绍  
  
  
引用自官方介绍  
  
随着微服务的流行，服务和服务之间的稳定性变得越来越重要，Sentinel 是面向分布式、多语言异构化服务架构的流量治理组件，主要以流量为切入点，从流量路由、流量控制、流量整形、熔断降级、系统自适应过载保护、热点流量防护等多个维度来帮助开发者保障微服务的稳定性。  
  
# 二、漏洞分析  
  
  
Sentinel组件曾经有发现过SSRF漏洞（CVE-2021-44139），关于此漏洞，已有很多师傅进行过分析复现，本文在此不赘述，本文着重于分析的SSRF漏洞是另外一处，获取集群状态功能相关的SSRF漏洞。  
  
# 三、Sentinel版本  
  
  
我这里分析的版本是v1.8.8，在2024-05获取时处于最新Releases版。  
  
![Snipaste_2025-05-17_02-27-31.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYHkjhjNMOfhlibVOj5Es94rgT3qEzmJ7Aldl7pOjKMxcqyNa5GQF2wVA/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![Snipaste_2025-05-17_02-33-56.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYN3g5vONkTfKq7hajsPunwCZZuhkLjQicalfPEg1VSvLRL6iaTbMIcunw/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
# 四、漏洞代码  
  
  
(1)漏洞点主要位于com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterConfigController.java  
的第119行---146行，该区域代码功能主要是获取集群或者目标机器状态功能相关，让我们来分析下代码  
  
![Snipaste_2025-05-17_02-38-45.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYcNoYWK1AFa1WCgYsfhCbZ2Xjgc9NsqIvUQoP5kdVwQoZMQWjl6DnoQ/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(2)通过第120行判断出首先它接收三个参数：app（应用名称）、ip（IP地址）和port（端口号），然后在第123行---130行，判断三个参数是否为空，为空则抛出对应的异常，然后第132行和133行，调用 checkIfSupported  
 方法检查当前版本是否支持该 app、ip 和 port 的组合。如果不支持，则调用 unsupportedVersion  
 方法返回不支持的响应。  
  
![Snipaste_2025-05-17_02-52-47.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYSgYlfRibQ70yOHTSSdUdQ516eN2M3vOnsksiaOOSqWochnWDgSg1RMbQ/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(3)接下来第136行---144行，使用 clusterConfigService.getClusterUniversalState  
 方法异步获取集群状态，之后使用 thenApply  
 将结果转换为成功的结果对象，然后使用 ge  
t 方法阻塞等待结果，期间如果发生 ExecutionException  
，记录错误日志并返回错误响应，如果发生其他异常，记录错误日志并返回失败的结果，错误码为 -1，错误信息为异常消息。  
  
![Snipaste_2025-05-17_02-55-50.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nY2AQRtTCv4XE36RjNbaBJZUyJTZg0oAt7miayyjmiarVs5WDBumuJhGYA/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(4)跟进clusterConfigService.getClusterUniversalState  
方法，来到com/alibaba/csp/sentinel/dashboard/service/ClusterConfigService.java  
，第148行---166行，定义了一个名为 getClusterUniversalState  
 的方法，该方法返回一个 CompletableFuture<ClusterUniversalStateVO>  
 对象。这个方法的主要目的是从 Sentinel API 客户端获取集群的通用状态信息，并根据这些信息进一步获取客户端和服务器的相关信息。  
  
![Snipaste_2025-05-17_03-09-49.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYdLgMu2cDOK6JQFdsFAT2oRqLuDkVQ32asfaNELOsdnibjzX4F3y4HJA/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(5)第149行sentinelApiClient.fetchClusterMode(ip, port)  
则是调用 sentinelApiClient  
 的 fetchClusterMode  
 方法，获取集群模式信息，这个方法返回一个 CompletableFuture  
 对象，之后的第150行.thenApply(e -> new ClusterUniversalStateVO().setStateInfo(e))  
则是当 fetchClusterMode  
 方法完成时，将结果 e  
 传递给 thenApply  
 方法，thenApply  
 方法创建一个新的 ClusterUniversalStateVO  
 对象，并设置其 stateInfo  
 属性为 e  
。  
  
![Snipaste_2025-05-17_03-18-10.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYYQVQ5FEVPqHLyUVjz0EZIlqOKYXNWhq9pt9X2odFuL4nSHTQj6xwQA/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(6)跟进sentinelApiClient.fetchClusterMode  
 方法，来到com/alibaba/csp/sentinel/dashboard/client/SentinelApiClient.java  
，第626行---637行，这段主要功能是通过给定的 IP 地址和端口号来获取集群模式，并将其解析为 ClusterStateSimpleEntity  
 对象，然后使用 executeCommand  
 方法发送请求到指定的 IP 和端口，路径为 FETCH_CLUSTER_MODE_PATH  
。  
  
![Snipaste_2025-05-17_03-27-24.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYv0zg7KebrUJr3topzmFj934NwibPkdlnOwdp0YFiaPX0GLjxQLhlmZUg/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(7)跟进第631行的executeCommand  
执行方法，看看执行了什么，来到第253行，没有发现相关的SSRF代码，再继续跟进第254行的executeCommand  
执行方法，跳转到了266行，也没有发现相关的SSRF代码，再继续跟进第267行的executeCommand  
执行方法，来到了第280行。  
  
![Snipaste_2025-05-17_03-34-45.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYljl4j3KKQswg87xHdyflRO7U3xuaicYnZHia1Mnsg3FoaxnibXu84DcwQ/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![Snipaste_2025-05-17_03-39-33.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nY0R67gqzhORmpX19yX2zQF2ib2xhzZ4TD2cfru4E7JGCRJboyPz1hoiag/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(8)第280行---第315行，前面传入的各个参数，都集中在这里进行进一步校验和检查处理，进行参数检查与合法性验证，之后构建基础的URL字符串，包括协议（http://）、IP地址、端口号以及API路径，最后构造HTTP请求（GET或POST），然后异步执行该请求。  
  
![Snipaste_2025-05-17_03-45-43.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYTRMaW6AYMXuojK1uibogDV9f3C6rwZrDg0d5F6Bu3FibYbIQoulUGy6w/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
(9)第310行最后使用HttpGet方法发起http请求时，没有对IP地址合法性进行完整校验，进而导致了SSRF漏洞的产生。  
  
![Snipaste_2025-05-17_04-02-49.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYuEJAKaWWnZ0CowlYOHtGXlIoQHL247XbLNfdOj3ROyXaylPCKvbX9w/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
# 五、漏洞复现  
  
  
通过前面的ClusterConfigController.java  
代码，我们得知了漏洞接口是/state_single  
，然后第57行定义了起始路径/cluster  
，然后再传入3个参数，分别是app、ip、port，最后得出的漏洞地址是【http://localhost:8080/cluster/state_single  
】，该接口需要登录后才能访问。  
  
构造访问的漏洞地址：  
  
【http://localhost:8080/cluster/state_single?app=SSRF-TEST&ip=127.0.0.1&port=80  
】  
  
![Snipaste_2025-05-17_04-16-59.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYiakoMybWxhWibosmMK7oFrAw2dQ1YjXr7tF0usHc61bFN813KDISCGZg/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![Snipaste_2025-05-17_04-17-21.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nYuWHHjYtJyDMLw0ajk75kOEZaclBAQ30wW8xnesAUs7oupMSzTcqNIQ/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![Snipaste_2025-05-17_04-17-39.jpg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc3ULOzAmayLYg54rugCj3nY4uZv7ZggtO4L1bnT33FWnyv7KJFmFyehEUkhnYo09hjVVSf0WNr2YA/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
# 六、总结  
  
  
本文主要分析了Sentinel组件获取集群状态功能点建立http连接时，没有对IP地址合法性进行完整校验，进而导致SSRF漏洞，总体来说并不难，新人第一次投稿分析此类文章，如有描述错误，还请各位师傅多多指教。  
  
参考链接：  
```
https://github.com/alibaba/Sentinel/issues/2451

https://sentinelguard.io/zh-cn/docs/introduction.html

https://www.cnblogs.com/charonlight/p/17552045.html
```  
  
  
  
  
