#  IAST技术专栏 | IAST下基于请求调用链的漏洞验证方案及其问题   
原创 火线安全  火线安全平台   2023-08-09 18:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MibgS41eXiaJicpvhicJbH6N1oX5rT3ILLAibibLJzja72U6NbWSLUBp9Uxx7wonr46dceS6tPY4BPEJNRDnFhLw3b7w/640?wx_fmt=gif "")  
  
  
**IAST 工作原理**  
  
首先这里的 IAST 指的是被动插桩模式的 IAST，流量式的 IAST 本质上还是 DAST。  
  
  
IAST 的工作原理即在正常的功能测试过程中，或触发普通的测试流量时，采集请求中的污点传播链路及其相关信息，然后基于污点关联算法进行漏洞检测。  
  
  
这个过程与 DAST 有一个比较大的区别：请求的相关参数并不是专门针对特定的漏洞类型构造出来的，对应的请求响应信息也是正常信息，所以对漏洞的准确性或可利用性进行验证时存在一定的困难。  
  
  
举一个例子来详细说明一下，比如一个请求是 https://example.org/?id=1，其中 id参数可以触发一个 SQL 注入的漏洞，在这里 IAST 可以直接通过请求及方法调用链的采集就完成漏洞的检测。  
  
  
对不熟悉代码或者看不到具体代码的安全人员来说，仅以此信息无法判断该漏洞是否真实可利用；而对不熟悉安全知识的开发人员来说，同样也很难确定漏洞的可利用性。  
  
  
那么如何验证该漏洞呢，了解安全的人员应该比较熟悉，就是根据该请求构造一些漏洞利用的Payload，手动或自动重新发送请求（DAST）然后根据其响应内容或时间等判断漏洞是否真实可利用。  
  
  
本文就基于以上问题来探讨 IAST 产品内的漏洞验证方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MibgS41eXiaJ9VKy1H5BB2kKech0Va5gWOUmmz4L7MwXBhw8Wn9ssgib7QnzA3cuLBvxhUxTuH97CO85NKVJ3nOXQ/640?wx_fmt=png "")  
  
  
**基于上报请求**  
  
**信息重放并验证漏洞**  
  
这里完整的执行步骤如下：  
1. Agent 采集插桩应用的请求信息  
  
1. 根据采集到的请求及方法调用链，基于污点关联算法检测到漏洞  
  
1. 基于该漏洞对应的请求信息构造出一批 Payload 准备重放请求  
  
这里构造 Payload 的过程实际上是与 DAST 扫描时构造的 Payload 类似  
  
1. 开始在 Agent 端或服务端重放请求  
  
1. Agent 采集到重放请求及其方法调用链并上报  
  
1. 服务端根据收到的重放调用链基于污点关联检测到同一个类型的漏洞  
  
1. 原漏洞验证成功，如果上一步未检测到同类型漏洞则验证失败  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MibgS41eXiaJ9VKy1H5BB2kKech0Va5gWOUmmz4L7MwXBhw8Wn9ssgib7QnzA3cuLBvxhUxTuH97CO85NKVJ3nOXQ/640?wx_fmt=png "")  
  
  
存在的问题  
  
基于上文所述执行步骤可以发现该过程存在如下问题：  
  
  
**1、与 DAST 检测方式的不同带来的逻辑差异**  
  
DAST 是基于重放请求的响应信息或时间等来检测，IAST 这里重放还是基于调用链污点串联的方式来做检测的，那么实际上重放请求的检测和原请求的检测没有本质上的区别，在部分场景下比如两个请求命中了不同的代码分支逻辑时有可能判断出一部分误报的漏洞，但也有其他场景可能还是没办法保证漏洞的可利用性。  
  
另外因为检测方式的不同，一部分基于响应时间盲注的场景，基于 IAST 调用链检测也无法做到 DAST 的准确率。  
  
  
**2、性能影响**  
  
因为 IAST 插桩会采集特别多的方法数据，这种方式不可避免的会对应用的资源占用和响应时间造成比较大的影响，而重放请求想要达到比较好的效果就必须要构造较多数量的请求，那么这个时候 IAST Agent 对应用造成的影响就是不可忽略的了，如果在某一时刻出现了较多漏洞同时开启了重放验证漏洞时，很有可能导致应用本身的不可用，而漏洞的产生时间又是不可控的，所以没有很好的办法进行避免，如果控制重放请求的频次又可能导致漏洞验证任务的积压。  
  
  
**3、脏数据**  
  
既然是重放请求，那么就不可避免地带来脏数据，对功能测试肯定会带来一定的影响。  
  
  
**4、漏洞类型的覆盖**  
  
不是所有的漏洞类型都可以方便使用构造 Payload 方式进行验证的，那么就存在一个问题，漏洞验证覆盖的范围还是有限的。  
  
  
**5、重放目标不稳定**  
  
这里又分为 Agent 端重放和服务端重放。  
  
  
对于 Agent 端重放来讲，它必须依赖服务端给它下发请求，那么就会存在几个场景：  
  
  
一种是精确匹配原请求所在的 Agent 进行下发，这种情况下如果用户是一个 CI 流程，那么是有可能在重放请求下发时原应用（带着 Agent）已经下线了，那么就没有重放目标；  
  
  
另外一种是基于原请求 Agent 所属项目下找存活 Agent，这种情况两个 Agent 的对应代码可能有区别从而导致业务逻辑不同，不过这个遇到的机率应该较小。  
  
  
对于服务端重放来讲，首先如果原请求的 hostname 是 localhost 或其他内网 IP 时，服务端会无法请求得到，另外如果域名配置了负载均衡可能会把请求转发到另外一个没有插桩 Agent 的服务上，除非负载均衡后面的所有节点都插桩了 Agent。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MibgS41eXiaJ9VKy1H5BB2kKech0Va5gWOUmmz4L7MwXBhw8Wn9ssgib7QnzA3cuLBvxhUxTuH97CO85NKVJ3nOXQ/640?wx_fmt=png "")  
  
  
  
**思考**  
  
针对以上方案的设计及其问题的探索可以发现，使用 IAST 本身的检测逻辑对漏洞进行验证还是存在比较多的问题的，在实际场景中比较难以做到 DAST 的准确率，同时其覆盖的漏洞场景可能会比 DAST 更少，目前来看这种验证方式很难达到一个比较好的效果。  
  
  
如果不基于调用链污点关联方式进行验证，那实际上就只有使用 DAST 的方式去验证响应信息了。既然如此，那么为什么不用独立的 DAST 产品来做这个事情呢？  
  
  
之后还会继续探讨基于 DAST 联动来验证 IAST 的漏洞的方案及其存在的问题，敬请期待后续文章。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MibgS41eXiaJ9VKy1H5BB2kKech0Va5gWOUmmz4L7MwXBhw8Wn9ssgib7QnzA3cuLBvxhUxTuH97CO85NKVJ3nOXQ/640?wx_fmt=png "")  
  
  
  
**往期推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzU4MjEwNzMzMg==&mid=2247493507&idx=1&sn=9672a244d0b0c25beefd64c60b41c316&chksm=fdbfce28cac8473eaa47fac73ad4610208dee6dea29738a0f5079390b99964cfb1fb48ca7f9b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzU4MjEwNzMzMg==&mid=2247493507&idx=2&sn=90aeaac3b751343ac143017fb1dfb594&chksm=fdbfce28cac8473e0f3f8d5e34ce805283d040625a6544d9e44a2cfaf556b7bdeaed4ba47c29&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzU4MjEwNzMzMg==&mid=2247493351&idx=1&sn=12a79a771a8453af041dc16f99c208da&chksm=fdbfcf4ccac8465afdb0eab7042f6d287c5d811bb73e7bdfe5ca1ca67f5fae2ec7d751455d3c&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MibgS41eXiaJ9u3wsg2K18WIbp4cCuVpwnDNpWKqCNTFc8S7VhBiaWMCMmMLn4c4eagsM7AvwMHJxMMgdbHUHPdCg/640?wx_fmt=png "")  
  
  
