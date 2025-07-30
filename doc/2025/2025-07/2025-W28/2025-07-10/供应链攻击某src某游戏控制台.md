> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0ODMwNjQzMA==&mid=2247485883&idx=1&sn=bdecfd78df40c0a4d2de65840e06f57b

#  供应链攻击某src某游戏控制台  
 XK Team   2025-07-10 08:04  
  
1.前言  
  
很久没发实战类文章了，以下内容源自于去年我在某src的报告，仅对文字和图片中的关键信息做了脱敏和打码，其余内容基本没做什么修改。在挖掘某src游戏业务的时候，我大量使用了供应链攻击手法，并进入了很多后台，后续有机会或许还能分享。  
  
  
2.从一个限制IP的游戏控制台开局  
  
在搜集某src游戏业务资产时，找到这么一个域名：  

```
v1-prod-gmxxx-abcd.xxx.com
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqumeGPeFgHq90YSWLus2Ou8tlG488uW4cz0TpOxvr5HxCWicnCpLibd4A/640?wx_fmt=png&from=appmsg "")  
  
非常经典的用短横线来划分域名，注意到域名中的两个要素，一个是gm，也即Game Master，游戏管理员的控制台。另一个要素是游戏名字缩写abcd（某个曾经比较火的二游，必须脱敏）。结合来看就是这个游戏的控制台，但是这里做了个IP白名单，无法访问。  
  
有IP限制，当然要试试各种伪造IP的请求头，这里用最经典的XFF头发现可以伪造，但是伪造127.0.0.1依然无法成功访问到后台，FUZZ了一下1.1.1.1、8.8.8.8之类的常见测试IP，发现均无法访问后台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqkKwZ1ibT17QdxkicI3fJG8shAT8CvZSG4L9cjxW2VtPeKRlzgwbicMpvA/640?wx_fmt=png&from=appmsg "")  
  
下面我们的目标就是先找一个能访问这个控制台的IP，有一种方法就是加载所有CN地区的IP然后去硬爆，但是这样过于粗暴了，万一被对面发现直接应急了，那后续都没法测了。于是我打起了这家游戏的供应商的注意。  
  
感觉这个游戏名abcd很耳熟，查看这个游戏的wiki和资料站，我们可以得知这个游戏曾经叫abcd，后续改名为xycd。（题外话，其实后者才是这个游戏更为人熟知的名字）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kq01BL19sb81U6mXpvvE3KUb25Zq95bmXj3GU2GMqt4gzIWqLlZKZjwA/640?wx_fmt=png&from=appmsg "")  
  
那么xycd是哪家公司开发的呢？从资料站中也很容易得知，xycd由xxxx旗下的xyz工作室开发。对xxxx公司进行组织结构分析：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqNtWIEzFYSyLJdS49ymmQ5SuUxPAtfHUxIiaxqsibwEWO8maiaBYGibmRjg/640?wx_fmt=png&from=appmsg "")  
  
发现该公司旗下有一个叫做xyz传播有限公司的子公司，名字和工作社同名，看来有很大嫌疑，继续搜集这个公司的信息，成功找到他们的域名xyz.com：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqCJMSRu2rkyHfK81p4hTRPYLH07RDXJTKjFs5jib4r2VaTwvkA9fRwGw/640?wx_fmt=png&from=appmsg "")  
  
找找这个域名下面的资产，发现了熟悉的gm-prod-xycd.xyz.com，熟悉的短横线划分域名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqbSacmrISpiafCc7ibbHSXGqSJu80HoTMLWOYex9RqGibM9ALUSiaib1OC5A/640?wx_fmt=png&from=appmsg "")  
  
事实上，这个域名确实是攻击链中最核心的一环。  
  
  
3.供应链攻击  
  
访问https://gm-prod-xycd.xyz.com，只能看到403，于是尝试FUZZ目录。很容易能找到一个/api/目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqC3UdN09vDbC9O0bpN1bZFSFqw2EKbyu2AibKAvqlKiaQdRUSdfDicBdtQ/640?wx_fmt=png&from=appmsg "")  
  
这里有一个关键信息，就是这个接口文档里保存了一个登录后的token，其实这种现象还比较常见，有些开发为了方便调试接口，可能会在接口文档里固定一些凭据，具有比较高的权限，这种情况在swagger-ui里比较少见，但是在knife4j等其它接口文档里还是有机会遇到的，平时可以多注意。记住这个token，后续还要用到。  
  
其实在这一步，已经可以影响游戏了，这里面有很多目标邮件服务和用户相关的功能，并且基本都可以调用的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqdj4PMrgERs7WtOibVmqicADEE5or9woBvIjr35uVebicahkULm7zOzKvg/640?wx_fmt=png&from=appmsg "")  
  
而在众多接口中，我测试到一个比较关键的接口：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqcSUMOvjC7ITZ6kFk9icFFkFZDQBlOnaVxRZNSIH7A3oJiaxib430wSc0A/640?wx_fmt=png&from=appmsg "")  
  
这个接口记录了各种操作日志，其中涉及大量敏感信息，例如该供应商OA系统的appid和appkey：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqU600IJ535et0M3PRDHcCuxiaS4Nv9rAb2RYC2ibsicG9r24X3eibccKKMg/640?wx_fmt=png&from=appmsg "")  
  
客服系统的appid和appkey：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kq1YKgJ2TeCSX3lmkJ9gWnaicqw1DPgne9rTa9Xwlb6Y3JM4iaFg9icNzgQ/640?wx_fmt=png&from=appmsg "")  
  
其微信公众号、小程序的配置信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqaqawBiaue4UMb1icAbcXK5QCkEhdaqLkhKF7kdovfcEC6F7wPp49ibXZw/640?wx_fmt=png&from=appmsg "")  
  
此外，还有一个非常严重的阿里云存储桶AK/SK泄露  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqayMibOysqIvhIMuUl7q44AmXbyECSGfBxyJZtC3CM9mrZqF5RsS8hnQ/640?wx_fmt=png&from=appmsg "")  
  
该AK/SK可以接管供应商的137个存储桶，几乎涉及供应商所有游戏项目，很多小有名气的二游都在里面了，我们要攻击的目标游戏的存储桶其实也在这里面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqpXyicaicuLbwxzxC4rt0yaCsxGYX3ic1FgqNxia7zxuqFTPzPcKvjILa8g/640?wx_fmt=png&from=appmsg "")  
  
到这里，还只是寻常的供应链攻击，和我们要攻击的目标控制台并没有联系，这份报告交上去估计也是被降级或者忽略，我们还是没有找到关键要素——白名单IP。  
  
  
4.寻找白名单IP之旅  
  
又仔细翻了一下操作日志，在操作日志里找到了一个唯一一个IP地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqOJz9iczWhl3C9DvxqGGIUSjFvOj2TlEREGCmU42cxicUEz2LEcSpHAew/640?wx_fmt=png&from=appmsg "")  
  
http://4x.xxx.xxx.xx1:xx01 这会是我们需要的IP吗？很遗憾，并不是，但看起来这个地址有点重要，而且开放了高端口，那么肯定得扫扫它的全端口了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqS07Ad5A71r9CtE9GgSgPYkhzpNeFoje3YzoBMFp0DbeK3G6kiaEWmBw/640?wx_fmt=png&from=appmsg "")  
  
可以看到，开放的端口还是很多的，但是大多数都是404，对这些服务依次进行目录FUZZ，基本都存在接口文档泄露，即/api/  
  
这里就不一一展示这些接口文档的内容了，打码略麻烦，可以看看它们的功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqHQx3zmUJytOFe5hwfNHItia5Sp9bkG6Dx0vibial2icbScas1fEnL6JiaqA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqj66X5TFtibcRLpIOu93ZBRTvqMngvDe9ZGUbDgyr7PPOw4txkl2lEVg/640?wx_fmt=png&from=appmsg "")  
  
几乎可以控制游戏的方方面面，这些接口基本都是可以调用的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqkDHS7bH7YV1X2gpx2T3HtGgLfaoeuuQnxuiaonk2CQ8hEQquibHNsujg/640?wx_fmt=png&from=appmsg "")  
  
其中有一个接口是获取玩家信息的，接口文档里硬编码了一个uid，发现这个是游戏最初的测试账号，并且这里拿到了一个登录IP，这边先留着备用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqiaib7sy4913tAqfEbKr0Lf1cRYMEfrcKibSWXUjs8u9fgFQjEIhAYd7aQ/640?wx_fmt=png&from=appmsg "")  
  
继续查看几个不同的接口文档，在http://4x.xxx.xxx.xx1:xx11/api/的操作日志中，看到了一个让人眼前一亮的接口：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqDQSoL2gfWb2ZkJ5otbWgyzcZgU4xXdMSib25eCAaoUhC3xzenYLorRA/640?wx_fmt=png&from=appmsg "")  
  
Ip白名单查询？但是把这个接口拼接到已知的几个资产都无法访问，猜测这又是另一套接口文档规则。于是搜集xxxx公司的所有外部域名和IP，进行全端口扫描，整理出所有外部资产，并进行/ipwhite/query的拼接测试，看看哪个资产存在这个接口：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqtEQm3GiaUqiby5CugyQN0xBIKNVGKhYb2WhBiaRrY1lWzdmHLIBaXWcEg/640?wx_fmt=png&from=appmsg "")  
  
最终，成功找到一个存在该接口的资产，暴露其内部IP信息。  
  
  
5.回马枪  
  
上面我们搜集到了一些IP，其中某一个IP就是目标控制台的白名单：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kq1ian9lE22St2UVs5hgrhV7hDKHk1hQUC97bF0ibTx0PrIZFAibhDrRQxQ/640?wx_fmt=png&from=appmsg "")  
  
这里需要统一登录，虽然可以切成常规的账号密码登录，并且我之前从日志和接口里拿到了很多供应商内部员工和测试账号的用户名，但是依然无法成功登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqdSkf9Y0n552ejG41TNJnPPDSwSS0WhnnBiaYibCDl6m6g4Q9zttmrm4g/640?wx_fmt=png&from=appmsg "")  
  
那么接下来就是喜闻乐见的JS提取接口进行测试了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kq2qoweUmUuWWbb0siaGlzd8Hr4SiaodRCmmicT4c9oiar9TQYQsSpSlMCpg/640?wx_fmt=png&from=appmsg "")  
  
由于这套系统大概也是供应商提供给目标的，猜测这个系统的接口和我们以前找到的接口文档里的接口有千丝万缕的联系，从图中也能看出来，这些接口的命名规则基本都是一样的。找到的接口不算太多，测试了一轮，发现全部做了鉴权。  
  
这时候应该怎么办呢？重新看到登录数据包，发现请求需要携带Token:这个请求头  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kq4icJH5icwerYt4QqDBJlKdzSZ6pnuRXjchIncAX5cibkY2CLA7Y7hf7jg/640?wx_fmt=png&from=appmsg "")  
  
看到这个请求头，还记得我们之前搜集到的测试Token吗？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqm9LZvml0OoaHtq4U1Y0wm9l6uRWhib6INBfVL3KUbmCcfBO1v7ldJIA/640?wx_fmt=png&from=appmsg "")  
  
于是，固定  

```
Token: 8xxxxxxxxxxxxxxxxxxxxxxxxxxxxc
```

  
 以及   

```
X-Forwarded-For: 1xx.xxx.xxx.xx4 
```

  
同时提取接口文档里的接口以及从目标后台JS文件中提取出的接口，将其拼接至v1-prod-gmxxx-abcd.xxx.com，尝试测试目标的接口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqfUQHz3w27xblurMVu1yoZvnNMTnaLU7aaIiaGVViaVMHiasYUdiaI3ECmw/640?wx_fmt=png&from=appmsg "")  
  
这意味着我们除了可以影响官服的xycd游戏，还可以影响另一边这个服务器（你懂的  
  
与此同时，目标也存在一个类似的日志接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqmibdQiaf0Bv6HrRPaqLfVHukZAUXErQPbsYNH9ia3epnBMUYNNZxjC3bQ/640?wx_fmt=png&from=appmsg "")  
  
其中也存在大量敏感信息，并且又被我找到一对不一样的AK/SK  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqAStVG7l3GOcoic5KX84seMxJvyjOgViaFuxd55XACdSQJoQKRibcTrqoA/640?wx_fmt=png&from=appmsg "")  
  
接管另一边的服务器的存储桶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgbicCeRIC2ZMFHQv8r3Vo8kqiaFgfTNa0Aibaiaq1txNt4fArxX0yCxkH70CZgk7043zEqib9UKvbkB1lw/640?wx_fmt=png&from=appmsg "")  
  
综上，在上述攻击流程中，攻击者不仅可以调用官服、某服GM的大量接口，影响游戏安全。同时可以获取大量敏感信息，尤其是AK/SK，直接影响某服游戏的运营安全以及xxxx大量项目的安全  
  
  
6.结语  
  
这次攻击流程全程其实没用什么特殊的姿势，关键点就在于在测试过程中留意各种信息，并且在关键的时刻利用/复用这些信息。我其实是当成解谜游戏来玩的，两者确实有极多相似之处，寻找白名单IP就是这个游戏的主线任务，在完成这个主线的过程中，还要注意各种看似无关的信息的搜集，比如接口的结构和命名规则、硬编码的token等各种信息。等剧情推进到关键节点的时候，你所搜集的所有信息拼凑在一起就能完成任务。  
  
  
