#  KCon 2022议题分享：自动化API漏洞挖掘   
 星阑科技   2022-09-02 11:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGTbxYHk8BcQ45ZxuDGg5apRmWyiaC3uOIuHxNpD1wDpSefKLCxsYr05A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**演讲者介绍**  
  
  
**周阳**  
  
星阑科技安全研发工程师。具有丰富的漏洞研究及红队武器化经验，历经主机漏洞扫描、应用漏洞扫描、开源软件供应链安全跟踪以及漏洞情报管理平台等多款产品建设，曾参与发现多个linux系统安全漏洞并收到工信部及其他部委致谢。目前专注于API安全研究以及自动化应用漏洞扫描方向。  
  
**吕竭**  
  
星阑科技安全服务工程师。曾就职于某大型央企，在攻防演练、甲方安全建设方面具有丰富经验。目前专注于API漏洞挖掘方向，上报数十个SRC API高危/严重漏洞，获得国内多个SRC月榜前十，字节SRC年榜第二。  
  
**议题内容**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGYCMmsiakRQFfq1GLm8XOcdpicefIUaeXrmLAOuRFUEiag0nU0NPiaBWnsg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
本次分享可以分为三个部分，首先我带大家来了解一下为什么目前API的安全问题逐渐成为整个行业内讨论的热⻔ 话题，其次是分析API都有哪些攻击面，从攻击面入手来了解API所面临的安全⻛险;最后，我们将分享API Fuzz方案以及一些实战案例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGMj3zokaibiaU3MlmqM3cibf44U4ic1z6J9w3bCWTgWZSeOjmY4UOu34VCw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
首先，让我们来看看API攻击崛起的原因。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGRdSmaprtDZSkfnPhZ78Yh3fliaRNWmlicp5BF5LJT4xWht5wWUufApng/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
我们目前正处于一个万物互联互通的时代，无论是从IaaS到SaaS，还是从PC到手机再到各种IoT设备， 它们都接入了互联网中进行数字交换，那么API这种数据交换方式也逐渐成为软件连接“万物” 的核心载体。API本质上是一种跨语言、跨架构的数据传输约定，API连接了不同层次、不同编程语言、不同厂商 所研发的软件，让数据可以跨应用软件进行自由流动。同时随着云计算、大规模分布式应用、移动互联网以及IoT 基础设施的蓬勃发展。企业为了提升交付产品的能力，敏捷开发与DevOps也就应运而生。至此，软件系统研发流 程从类似流水线作业的方式演化为组件并行开发生产，然后再集成的形式。与此同时，后端应用组件的解耦以及SOA架构的普及，使得API逐步成为连接各应用组件的事实标准。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGA5MgcJrVbChVbSUTmIlr3ZKhBnzpymOEwKib8wj12TGYQ2MAo4t4qyA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在API高速发展的背景下，API的经济与生态也逐渐成型，左图是Gartner总结的API相关技术的成熟度曲线，我们 可以看到这里面提到的技术已经有很多落地案例，包括API网关、API管理平台与API交易市场。右图是postman提出的API基础设施生态，包括API解决方案厂商、APM厂商，研发效能厂商、云厂商、安全厂商以及新一代API网关 厂商等等。在数字时代下，无论是互联网的商业创新还是传统企业的数字化转型，它们都推动了API经济的发展。尤其是对传统行业而言，API就是其价值链全面数字化的关键所在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGLQicYC0nsBpVibfb0dF4dwSpnNA4tq7vnicZZMU3QzIGghicKTxIibHelSw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
接下来，让我们把目光投向API的安全问题，这也是目前大家最关心的问题之一。根据API解决方案厂商Postman 统计，2021年度全球API数量增⻓为39%，API访问量增⻓为56%，当下正处于我国数字化转型的浪潮之中，可以 看到我们国内的API增⻓速度甚至接近80%。随着API高速发展的同时，我们看到API的安全问题也逐渐被暴露出 来，API安全已经成为企业关注的焦点。例如:2020年7月，美国开放银行泄露了700万用户的数据，其中包括用 户的姓名，电话，家庭住址，出生年月等关键信息;2021年4月，Facebook在线业务API泄露的5亿多用户数据在 暗网公开售卖，这些信息也包括用户的姓名，电话，家庭住址等关键信息；同样，像领英，一些大型电商平台等 等不同的行业，不同的领域的企业都产生过由API安全漏洞所引发的数据泄露事件，严重损害了相关企业和用户权益。**在此之前，数据泄露事件一般都是由于数据库被拖库或数据库暴露公网导致的。而随着API的快速增⻓，近年来我们看到由API导致的数据泄露事件也越来越多了。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGZjwo1D7iaIT9bEo2TNeY0DCH572A1xEpZoSBOSqKnbxmoeQBmR4IV2w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
下面简单了解一下API都有哪些攻击面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGbraB8C6vdVdUjiaVYnKKQVSJ4NTbywb0mrMpFLOqJp8ae88Ys6IraNA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
首先，我们先来看一下API协议的类型，目前的IT基础设施中各个层次都充满了API的交互，那么我们本次分享内容主要讨论应用层的API通信协议，按照使用量来看，目前使用最多的是RESTful API，然后是 webhooks、graphql等这些常⻅的API，也有像gRPC，MQTT这样偏底层的API协议，这些API协议的异构性本身携带着一些安全问题，我们后面讨论API Fuzz的时候也会涉及到协议解码问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGwOLJvY8Zwqqf6pSc9OhLlTlgMU7ELrkZKyuJG57soBZG6q6xiaowckg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
接下来我们来看看API的攻击面到底有哪些，这是OWASP给出的API安全所面临的十大⻛险。根据我们实战经验总结出右边这几种关键问题。首先是越权，权限问题是API失陷或者数据泄露的最常⻅原因，包含垂直越权、水平越权和未授权访问，比如通过未授权访问的API拿到用户数据。之后是敏感数据暴露，比如在API设计不当时，下游业务 方只需要两个字段，但却从上游的API接口中获取到了10个字段，其中多余的字段可能会导致不必要的数据泄露。  
  
接着是代码漏洞，由于API后端是代码逻辑实现的，因此API同样会面临应用安全领域的代码漏洞，例如SQL注入，命 令执行等，这些大多数情况都是由于业务开发者的疏忽所导致的。同样像API网关、API管理平台这类API基础设施 自身的一些安全漏洞，会导致托管在其上的API受到影响。此外还存在一些不安全的业务配置以及业务⻛控领域的问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IG5kFqtptibUc2RRTtlVHDjrQJkuXmz7p68flfqn72r7b1qvWHLX9VeoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这些问题里面，最严重的是API越权问题，举个例子。这是2021年12月爆发的SonarQube未授权下载源码 事件。导致源码泄露的原因是，在默认配置的情况下，SonarQube缺少对API接口的访问权限控制，攻击者可利用 该漏洞在未授权的情况下，通过访问API/settings/values接口从而获取到 SMTP、SVN、GitLab 等凭据，从而进一步获取代码仓库中的源代码，造成项目源代码泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGCXa3Cs4sWezmaacngtPeOeMj8icm4PoGHXPSEEgJNWP1jH1OUVAQ5YQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
同样的，针对新的API基础设施，它们也面临着自身系统的API安全问题，这是前段时间披露出来的一个国外主流 API平台存在的未授权文件上传漏洞，允许未经身份验证的攻击者通过上传恶意JSP文件从而达到RCE。这就是通过 攻陷API平台本身从而威胁到其承载的API，同样的，其他API基础设施也出现过类似问题。比如Apache的APISIX， 它之前bacth-requests插件存在权限绕过漏洞、Dashboard存在越权漏洞。本质上还是权限问题，可⻅权限对于 API来讲确实是一个不可忽视的安全⻛险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGGQIPMqrgEkbIPkTDXIa9r7YOvVytiblBGusYcWGgOqzHnomK8BA9lXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么我们反过来思考，导致API问题频发的原因到底是什么?从API的生产者⻆度，也就是站在企业的⻆度来看有三点:一是大规模分布式系统及复杂应用架构带来API数量迅猛增⻓，在业务增⻓的同时，我们是否针对API建立起完整的安全管理规范。二是基于API-First理念构建的研发流程，极短的迭代周期导致API变动跟踪困难。三是传统安全测试和防护工具对API⻛险收敛的失效，需要面对多种API协议之间的差异、以及频繁变化的API、自定义的 路径等等都为API安全测试带来困难。从攻击者的视⻆来看，也可以分为三点：首先，API攻击路径更短，API可以直达数据而不必像传统入侵那样需要通过内网，进行好几层侵入，最终才能拖取数据，API压缩了攻击链路；同时，在API生态迅猛 发展的背后，安全性是滞后的，这里有大量的API基础设施的漏洞仍未被发掘；此外是云原生应用尤其是容器化、 微服务大规模落地之后，API成为了不同系统模块间主要的通信方式，因此在攻击者视⻆来讲，攻击API是一件投入产出比很高的事情。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGbj5BdCoicER0iaOT0P9al6UrvvLM6jDLM4HdlZpFz52k8Yk0xRRQVib8g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
下面为大家介绍API Fuzz方案及实战案例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGNjo5mK747hxNshmiaQ3j17fLxaJlfiallRHHYElxOAQJu41ib9WP8kXFg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
首先我们先从以下几点了解一下传统web Fuzz方法的弊端。  
  
**第一点就是API的路径是自定义的，无法被漏扫发现。**  
一般我们在对一个目标进行测试的时候可能会先用扫描器进行扫描，看看这个站点是否存在什么已知漏洞，或者使用路径爆破工具去爆破一下看看是否存在什么敏感目录，文件或者接口，但是这种基于爬虫的web扫描和基于字典的爆破工具能获取到的API路径是不全的。我们只能通过请求返回的状态码来判断这个API是否存在。  
  
**第二点是API参数结构复杂，不能直接插入payload。**  
传统的web Fuzz是基于get/post协议解析form表单，而API是存在多种协议格式， 多层嵌套的参数结构，还有参数内编码等复杂场景的，所以以传统的方式去做还不够满足使用者的需求。  
  
**第三点是传统的Web Fuzz工具生成的payload针对API场景很多是无效的。**  
很多比如XSS问题，其实API攻击场景是很少关注的，这样web Fuzz工具在测试过程中会生成大量的无效请求，导致测试时的效率会比较低下，反而API的权限问题等真正需要关注的问题没法有效发现。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGiaSticwkiaWPd3cx4qxYHxq69XqicYAUClPN9icwtw22NZkTan8QuQuicntQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
我们针对以上提到的这些问题提出了一套新的自动化API Fuzz思路。我们先简单的对这个思路进行一个概述。  
  
首先从自动化漏洞测试的角度来看，**第一步就是如何发现API资产。**在发现API路径方面我们有两种方式，第一种是通过解析swagger文档第二种是进行API通信流量分析，这两种方式都可以得到确切的API路径，参数结构，参数类型等信息，可以更全面的发现和了解目标站点存在的API，方便后续的测试工作。  
  
然后是**针对payload有效性的问题**，我们通过对请求序列进行分析，获取API请求的顺序，并根据返回值确认API参数值的大概范围，可以生成更精准的Fuzz向量，确保payload能够正常传递到API后端。  
  
最后，**在API传参复杂性的问题上，**我们通过使用树结构参数解析以及递归解码的方式，对API进行值的变异，结构的变异，参数污染等等来提高漏洞发现的效率及准确性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGQVjGRDkmyJU7c0mGTwZuIJemIS3ypYiaeYZQ1EeMy9icoscoDHRKL9Gg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
从获取API资产角度，首先是Swagger文档的解析。Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化RESTful⻛格的API 接口。我们可以从Swagger文档中获取API服务的很多重要的信息，例如basePath就是API的路径，host域名，以及请求报文 中包含的参数等信息，其中就有这个API有哪些参数，名字是什么，参数值的类型，请求的格式等等。并且他还会提供一些范例来进行一个请求的测试。使用起来非常的方便。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGSlktR7UzfAKfPqSYfN8NuUZoWGZBj7cbxXzfE5789cqjb6ibq3ucLrg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在swagger文档中可以根据API的请求顺序得到更精确的参数值信息。例如左上这个截图是一个商店的功能，我们 通过对/store/order这个API发起post请求创建订单，然后从响应结果中获取到订单编号也就是orderId的值，通过 参照获取到的orderId参数值的格式，生成Fuzz向量，例如这是一个8位的数字格式，我们可以对后四位数字取随 机数。再对这个接口发起get请求测试其是否存在像越权查看别人订单的漏洞。相同的，其他的参数也可以依次的 使用此流程进行测试。  
  
swagger文档的存在非常便于业务的开发和测试，但是一旦泄露也是非常的危险。在实际的漏洞挖掘过程中，也经 常可以遇到swagger文档的泄露，其中还存在很多危害较高的API未授权漏洞。例如通过调试的功能去修改admin 用户的密码，或者通过切换用户的接口直接获取admin用户的token等等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGeCu4eAoicE1SIicn3bLLMmFqjojGqWh4DtradfAjtSnAicn7xLQttYQWQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
获取API参数结构的第二种方法，就是通过代理获取请求数据包，并根据不同的API⻛格对参数结构进行还原。由于代理流量中存在大量的重复访问和一些静态文件流量所以在做还原之前还需要进行一步筛选工作。  
  
流量还原就是将API路径作为根节点，其参数作为叶子节点的树型结构逻辑，并通过统计的方式判断URL path里哪些路径是定值，哪些是可变参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGwMsUs3v7frKayBPELjtWBVnfafWhvXdfQPZuZzPHybaxy20WBINzag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
通过这个例子可以辅助我们理解参数解析的树状结构，最左边的图是一个json格式的API参数，通过对参数进行分 组然后展示为右边这个树状结构图。root作为API的根节点，下面分支为各级参数的支节点和叶子节点，这样看上 去非常的直观，然后我们在这个基础上再进行后续的对结构的变异和对节点的变异。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGibnPicJX9t2eYz4QeyftFx0cEfGTV9Giaiac5fprh0LGViaricVwT32Pcexw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
以树结构为基础的API Fuzz，可以按照以下四点实施对节点的变异。第一点按照数据类型注入payload，举个例子，isVip节点是布尔类型的参数，原始值是false，那么我们可以将其替换为true之后观察其响应包的变化，例如用户是否从普通用户变成了高权限用户。第二点是注入通用型payload，类似在图中name节点上在原值后面拼接SQL注入的payload，对每个参数都依次进行检测再观察响应的变化。第三点是畸形数据替换，他可以在第二点的基础上加入一些控制字符，注释符，运算符等用来绕过一些安全设备。最后一点是类型转换，例如下面这个 count参数，他的类型是number数字类型，我们可以将他改为string类型，来观察响应包的变化，有可能发现一些报错信息或者50x相应，接下来可以手工进行测试。  
  
在节点变异之后是对树结构的变异。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGzP1gxXrfIZKUZ5dtwIcicafvafybEIbVnJXXzDTPiabmHtg0eElm0dlw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
同样的，对树结构的变异有三个方式。首先是可以替换object类型结构，替换单个节点或一整个子树，这样相当于传统漏扫里的session替换，因为API的session身份持久化很多靠的是token而不是cookie。第二点是插入节点，就是在原有的结构基础上增加新的叶子节点，这样可以进行一些隐藏参数的探测，或者通过携带一些场景的认证后的权限字段绕过鉴权等。最后，可以进行节点的删除，这个在后面的实战案例中会提到，他或许可以绕过某些验证措施。  
  
通过这些方式改变原有的参数结构有时候会获得意想不到的效果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGspPzoCEIwjY3t77LHvpOmqdWNvOvx3u0icwX9HZ6CiakickMY0uclXkQA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后再介绍一下关于参数编码问题与递归解码器。实际环境中的请求体格式非常复杂，可能是表单类型字符串， json字符串，xml字符串等，这里面还可能传递路由，或者请求的字段存在不同的编码方式，参数中存在嵌套/循 环编码模式，直接进行Fuzz无法起到预期的污染效果。  
  
例如下面的这个例子，name等于一个base64编码的字符串，直接在后面拼接sql注入的payload是不能成功的，因为多了一层base64的编码，因此需要在对他进行解码后拼接payload再按照原来的方式进行编码，才能真实把payload传递到后端。这里为了做到自动化，还需要去识别各节点的编码模式和层数，遍历和组合所有节点，解码注入payload，然后按照识别的模式重新组装数据后再进行编码，最后发包测试。  
  
简单的总结一下：API Fuzz就是通过给API提供非预期的输入然后监控输出中的异常来发现漏洞，并且在这个过程中不断的调整和完善Fuzz向量来提高效率和命中率的这样一个方案。下面我们来讲一些漏洞Fuzz的实际案例来帮助我们理解一下之前讲到的思路。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGoKAMZPUSDGUO4I9EfLspribYKgyhB46j1VcCe0ib8ibwAfXAHD44vxG0w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
案例一，Fuzz出特定参数值实现零元购。这是在购买某项服务的时候，通过抓包可以看到这个post请求中包含4个 参数。其中resourceID这个参数是采用的base64编码，在购买⻚面上可以看到这里是可以对用户所属的组进行选 择，所购买的服务的项目和价格也会随着变化，其他三个参数的选择不会影响订单的金额，那么就对resourceID这个参数进行Fuzz，并且在对Fuzz出的值进行base64编码，最后成功发现default这个可以免费购买服务。这个值在⻚面的选项中是看不到的，属于隐藏值，可能是在业务的迭代过程中被遗忘的，但是属于一旦被利用可以直接对公司造成经济损失的漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGWR2kxw4xkIzWZykQHwg45Opjaw5oOeBnryC6sewWuw3zs7coWgQgZQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
案例二，改变参数结构实现交易密码的绕过。这也是在购买的情况下，这个是某个基金交易平台。在购买基金的 时候抓包，可以看到他存在tradepassword参数，也就是我们需要输入交易密码才可以完成交易。正常情况下我们需要输入一个正确的交易密码，输入错误密码会得到提示并且返回到输入密码的界面。但是当我们Fuzz工具尝试将这个参数删掉时发现请求能正常执行，并且放行后交易完成了。可以理解为这个业务的逻辑漏洞是当请求里没有交易密码这个参数了，他就不会去进行验证了，绕过了一道安全措施，也就是说对参数结构的变异生效了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGBUyRJpib8kTrwJvEefcyRUl9tyibXlaIyndxDAfTcTcc1U68Jxle8JFA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
第三个案例，参数解析插入payload实现rce。这是一个Maven仓库管理器，某些版本存在一处任意EL表达式注入漏洞。但是当我们在进行Fuzz的时候，是假定不知道这个漏洞的触发点，我们可以在请求的任意参数后面拼接这个payload，当我们发现返回的数据中执行了这个表达式，那么就代表此处存在漏洞。那么在这里我们可以看到，是因为我们的Fuzz系统能够做到json内部细粒度的参数结构解析，才能精准的注入到这个位置，针对API的场景如果还在用HTTP post K-V的方式进行参数污染，是很难找到漏洞的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGD923RBZl6frfkhoNzrSZlnL3TgsZDFQ1fp9ImyoMMwibgEIiaTyUAVTA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
第四个也是最后一个案例，这里我们看到，API同样也受到传统漏洞SQL注入的影响，原始的HTTP GET/POST API仍然有产出漏洞的空间，在我们的Fuzz工具中也针对这种基础情况做了覆盖。这里是一个存在SQL注入的API。在web⻚面上通过点击个人资料的查询，即可看到自己的姓名，联系方式，职位，部⻔，上级是谁，还有公司邮箱等等的信息。根据userid和foldername来筛选数据。这时将filter里的条件注入即可列出所有员工的信息，造成一个比较严重的信息泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MdP6902R0oKOSeFFTibia6IGEpYnpictgoTPBcowfxW8UZwImlI8ibMEic6hn0I5bZ1bdMXsUSgcouCAg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那么今天为大家分享的内容就已经结束，感谢大家的观看并欢迎反馈。  
  
**更多技术干货，欢迎关注“星阑PortalLab”公众号**  
  
  
  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492888&idx=1&sn=219ad26c37836f5cdefc5f41dea620c0&chksm=c0074884f770c192f60f651f3e0c6a0f293b38a59d9499a89cd1b9c2e2d8cbc4dd4620783ed1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492771&idx=1&sn=5bc86cbf62a83db69b1b1919ad86273b&chksm=c007493ff770c0290f199daef6b03bd09f9f85e35c5179c3ca8fe062623ecc27522b45850f0a&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492691&idx=1&sn=7f4fdf863953280d024c2ae7144badff&chksm=c00749cff770c0d98d9848f5415e2c7b395add84d39e4ab51172549c024d36cfc80af23ad43e&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492617&idx=1&sn=103b4a185c02f1435ddcc1778bd038e6&chksm=c0074995f770c08374efe7cda4e53a8991a867e2b1b73fe05f0f4a32335756a56c77483ee75f&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
