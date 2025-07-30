#  JAVA常用组件未授权漏洞解析   
Notadmin  Hacking黑白红   2024-01-24 20:03  
  
**文章目录**  
```
前言
Druid未授权漏洞
  修复建议
SwaggerUI未授权漏洞
Spring boot Actuator未授权漏洞
  漏洞发现
Spring Eureka未授权访问漏洞
  漏洞利用方式
  漏洞危害
  修复方式
总结
```  
  
## 前言  
  
在java项目中，经常会使用一些监控类的组件来监控系统的状态，如果对这些组件没有做好权限控制，公网可以任意访问的话，就会泄露敏感信息，进一步造成更严重的危害。今天就来看一下，都有哪些组件。  
  
关于java安全的系列已经出了10篇，大家感兴趣可以去看一下，后续会继续出关于java安全方面的内容，如java内存马，Weblogic系列，spring框架系统漏洞等。  
> java安全基础-java反射  
> java安全基础-类加载机制  
> java安全基础-spring框架  
> java下exec命令执行问题  
> JNDI注入详解  
> JNDI注入高版本绕过方式  
> SPEL注入详解  
> java反序列化漏洞详解  
> java安全之fastjson反序列化详解  
> java安全 | Thymeleaf模板注入漏洞  
  
  
由于本人水平有限，文章中可能会出现一些错误，欢迎各位大佬指正，感激不尽。如果有什么好的想法也欢迎交流~~  
  
java项目中可能造成未授权的组件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbuDYgVE8czQbib0fEiakpx5JsJotuIwNYZ2NImI2ibmAj3I98ibWw96UibwA/640?wx_fmt=jpeg&from=appmsg "")  
## Druid未授权漏洞  
  
Druid是阿里巴巴数据库出品的，为监控而生的数据库连接池，并且Druid提供的监控功能，监控SQL的执行时间、监控Web URI的请求、Session监控，首先Druid是不存在什么漏洞的。但当开发者配置不当时就可能造成未授权访问。  
  
检测与利用：  
  
直接在网站的url中后加上：  
  
/druid/index.html  
  
如果可以无需登录，即可登录到Druid监控界面，则说明该网站存在Druid未授权访问漏洞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbicJ6048TrJnjTjyyMAlMerqNH7sLRk9MLMvKYgu2jwuJHbxt7uM5mBA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbIOFJW7ZaqguBH1Zs1o7EIjbCzMhNeuGnmsWhiaHcYhHxFWlA4wg4tWw/640?wx_fmt=jpeg&from=appmsg "")  
  
从这里可以看到，Druid数据监控界面，里面存在数据源，sql监控，sql防火墙，web应用，url监控，session监控，spring监控等信息，可以详细监控该网站的情况，获取敏感信息，在web监控中，可以获取整个网站的目录，在session监控中，可以获取网站用户的session，从而伪造用户session进行登录！  
### 修复建议  
  
方法1： 设置StatViewServlet(监控页面)为 false  
  
方法2： 给druid的web页面设置账户密码，增加访问druid的权限。  
```
```  
## SwaggerUI未授权漏洞  
  
Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务。总体目标是使客户端和文件系统作为服务器以同样的速度来更新。相关的方法，参数和模型紧密集成到服务器端的代码，允许API来始终保持同步。Swagger-UI会根据开发人员在代码中的设置来自动生成API说明文档，若存在相关的配置缺陷，攻击者可以未授权翻查Swagger接口文档，得到系统功能API接口的详细参数，再构造参数发包，通过回显获取系统大量的敏感信息。  
  
Swagger 未授权访问地址存在以下默认路径：  
```
```  
  
可以添加上述默认路径到dirsearch等目录扫描工具的字典中，再对目标网站进行扫描测试。  
  
如下图显示的页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbr7iaUl5gF7Pd9R3WCPmrbyr8CQtZfictMqayKbU6knTYViaxueeogiaagA/640?wx_fmt=jpeg&from=appmsg "")  
  
漏洞修复  
1. 配置Swagger开启页面访问限制。  
  
1. 排查接口是否存在敏感信息泄露（例如：账号密码、SecretKey、OSS配置等），若有则进行相应整改。  
  
## Spring boot Actuator未授权漏洞  
  
Actuator 是 Spring Boot 提供的服务监控和管理中间件。当 Spring Boot 应用程序运行时，它会自动将多个端点注册到路由进程中。而由于对这些端点的错误配置，就有可能导致一些系统信息泄露、XXE、甚至是 RCE 等安全问题。  
  
端点描述  
<table><colgroup><col/><col/></colgroup><tbody style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;display: table;width: 680px;table-layout: fixed;"><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 36px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">路径</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">描述</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/autoconfig</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">提供了一份自动配置报告，记录哪些自动配置条件通过了，哪些没通过</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/beans</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">描述应用程序上下文里全部的Bean，以及它们的关系</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 36px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/env</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">获取全部环境属性</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 36px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/configprops</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">描述配置属性(包含默认值)如何注入Bean</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 36px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/dump</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="36"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">获取线程活动的快照</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/health</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">报告应用程序的健康指标，这些值由HealthIndicator的实现类提供</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/info</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">获取应用程序的定制信息，这些信息由info打头的属性提供</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/mappings</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">描述全部的URI路径，以及它们和控制器(包含Actuator端点)的映射关系</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/metrics</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">报告各种应用程序度量信息，比如内存用量和HTTP请求计数</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/shutdown</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">关闭应用程序，要求endpoints.shutdown.enabled设置为true</p></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;height: 62px;"><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">/trace</p></td><td style="padding-right: 5px;padding-left: 5px;border-color: rgb(204, 204, 204);font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: preserve;" width="320" height="62"><p style="margin-bottom: 10px;border-width: 0px;border-style: initial;border-color: initial;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: 26px;font-optical-sizing: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;word-break: break-word;white-space-collapse: collapse;">提供基本的HTTP请求跟踪信息(时间戳、HTTP头等)</p></td></tr></tbody></table>### 漏洞发现  
  
一般分为两步  
  
1. 识别当前 web 应用使用的框架为 springboot 框架；  
  
2. 枚举执行器端点路径；  
  
1. 识别当前 web 应用使用的框架为 springboot 框架。主要有两个方法判断：  
  
①通过 web 应用程序网页标签的图标（favicon.ico）；如果 web 应用开发者没有修改 springboot web 应用的默认图标，那么进入应用首页后可以看到如下默认的绿色小图标：  
  
该绿色小图标是 spring 框架下的一个默认图标，尽管不能百分百就此图标确认当前 web 应用使用的是 springboot 框架，但是基本上也能百分之八十确认该 web 应用是使用 springboot 框架开发的了（毕竟 springboot 框架确实是太流行了）。  
  
②通过 springboot 框架默认报错页面；如果 web 应用开发者没有修改 springboot web 应用的默认 4xx、5xx 报错页面，那么当 web 应用程序出现 4xx、5xx 错误时，会报错如下（此处仅以 404 报错页面为例）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbjavDSUrXOMVZOn0CG55pQncCVGjnrFLhcQo8KOUwIU7uNKriao23VRg/640?wx_fmt=jpeg&from=appmsg "")  
  
当出现如上报错页面，就能确定当前 web 应用是使用了 springboot 框架的。  
  
那么综合以上两个途径来判断当前 web 应用是否是 springboot 框架，就是通过访问不同的目录，看是否有小绿叶图标，然后就是想办法在不同目录下触发应用程序的 4xx 或 5xx 错误，看是否有 Whitelabel Error Page 报错。  
  
2. 枚举执行器端点路径。这个其实很简单，在确认当前 web 站点是 springboot 框架后，枚举当前站点的所有一级、二级甚至三级目录，然后写脚本对每个目录进行探测，查看目录下是否存在 actuator 执行端点路径即可。也可以将这些路径放到目录扫描工具去扫描。  
  
尽管这些监控信息的泄露已经足够高危了，但是还有一些提高漏洞危害性的利用方式。  
  
①认证字段的获取以证明可影响其他用户；这个主要通过访问/trace 路径获取用户认证字段信息，比如如下站点存在 actuator 配置不当漏洞，在其 trace 路径下，除了记录有基本的 HTTP 请求信息（时间戳、HTTP 头等），还有用户 token、cookie 字段：  
  
trace 路径下用户认证字段泄露：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbbaicWDRhJD301Mia5VJqlWbOnfJicTVPTWk11yZbYBFQQGtT3uLI5Rn9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
②数据库账户密码泄露；由于 actuator 会监控站点 mysql、mangodb 之类的数据库服务，所以通过监控信息有时可以拿下 mysql、mangodb 数据库；这个主要通过/env 路径获取这些服务的配置信息，比如如下站点存在 actuator 配置不当漏洞，通过其/env 路径，可获得 mysql、mangodb 的用户名及密码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbp52EkNEzYibzAh7iavsgPdygtqEud93anhCVVYPQwETg7IzTicXg0kOgg/640?wx_fmt=jpeg&from=appmsg "")  
  
③git 项目地址泄露；这个一般是在/health 路径，访问其 health 路径可探测到站点 git 项目地址  
  
④后台用户账号密码泄露；这个一般是在/heapdump 路径下，访问/heapdump 路径，返回 GZip 压缩 hprof 堆转储文件。在 Android studio 打开，会泄露站点内存信息，很多时候会包含后台用户的账号密码，通过泄露的账号密码，可以进入后台进行一波测试。  
## Spring Eureka未授权访问漏洞  
  
Spring Eureka是一个服务注册和发现的组件，他提供了一个web页面用于展示注册的服务信息。如果没有做好权限控制，可能会导致未授权访问漏洞。  
### 漏洞利用方式  
  
直接访问路径/eureka/，看是否可以访问  
  
或者添加消息头X-Forwarded-For:127.0.0.1看是否可以绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBb6p96K59AOhP7c3Hh3QQ89TYHKSChhgRjXC0zgYOjZmWuNROpT79Nicg/640?wx_fmt=jpeg&from=appmsg "")  
### 漏洞危害  
  
1.泄露敏感信息：如果公网可以访问，会把注册信息泄露  
  
2.与其它漏洞进行利用：如spring boot actuator+eureka+xstream可以导致RCE漏洞。该漏洞可以看下面的链接：https://blog.csdn.net/qq_18980147/article/details/128041932  
  
web页面如何访问  
```
```  
  
如上面的配置，web页面的访问链接就是http://localhost:8881/eureka/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSEliaGLlvdJJVVV78krdRBbVicg9xhIhqQ95ZjrQroXHBdMkUzO5vppD1InQ6Ndy8eic3m2BrXlKXPg/640?wx_fmt=jpeg&from=appmsg "")  
### 修复方式  
  
1. 启用Spring Security进行身份验证，在Eureka Server的配置文件中添加如下配置，启用Spring Security进行身份验证，需要在Eureka Server中配置用户名和密码。  
```
```  
  
2. 配置Eureka Server的防火墙，可以配置防火墙，只允许指定IP地址或者网段访问管理界面。在Eureka Server的配置文件中添加如下配置：  
```
```  
  
3. 对于生产环境中的Eureka Server，建议使用VPN等安全通道进行访问，避免直接暴露在公网上。  
## 总结  
  
上面介绍了java项目中一些常见组件的未授权漏洞，这些往往是由于配置的问题导致的，在测试的时候一定要注意这些组件的权限问题。  
  
本文作者：Notadmin，   
转载请注明来自FreeBuf.COM  
  
  
  
【Hacking黑白红】，一线渗透攻防实战交流公众号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONQbd1LqAKpAlwVM9pRXpJ8iapW6J2BmBkPWnGk0hia1t6DkVC8Jrl7pvmO5aAf7Kl5HEp7pDaFGffdw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSgp1TKd5oeaGb76g5eMFibnANHNp30ic7NtpVnU12TNkBynw2ju7RDHbYtVZibm5rjDh7VKbAEyO8ZQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
      
  
**长按-识别-关注**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONTgEGpyZx7OiaI1JkST23pJPIIgiaejD1CAyicricZQeBtf4rYlib4NmVKjiah6icBHjWwOu54zq6Wvib0HIg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
**Hacking黑白红**  
  
一个专注信息安全技术的学习平台  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBDEU5hJAFfap4mBBAnI4BIic2GAuYgDwUzqwIb9wicGiaCyopAyJEKapgA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBRJ4tRlk9QKMxMAMticVia5ia8bcewCtM3W67zSrFPyjHuSKmeESESE1Ig/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBnTO2pb7hEqNd7bAykePEibP0Xw7mJTJ7JnFkHuQR9vHE7tNJyHIibodA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBhibuWXia5pNqBfUReATI6GO6sYibzMvj8ibQM6rOo2ULshCrbaM0mJYEqw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点在看  
  
