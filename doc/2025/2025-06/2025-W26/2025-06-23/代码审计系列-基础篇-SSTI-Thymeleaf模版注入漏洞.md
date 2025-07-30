> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3MDU1MjgwNA==&mid=2247487469&idx=1&sn=969aa08661d0f26aeb3b4f8d5321b200

#  代码审计系列-基础篇-SSTI-Thymeleaf模版注入漏洞  
 闪石星曜CyberSecurity   2025-06-23 08:49  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er9m1ZBsCDwBKMTNZny1xUesHEdZfVl5W0S5N9tkUgfaKhXSWqJCQAcA/640?wx_fmt=gif&from=appmsg "")  
  
本篇为代码审计系列SSTI服务器端模板注入漏洞理论篇-Thymeleaf第九篇，看完本篇你将掌握关于Thymeleaf模版注入漏洞的代码视角原理剖析、基础挖掘漏洞核心能力，看完如有技术错误欢迎评论区指正。  
- Thymeleaf概念  
  
- 业务视角Thymeleaf流程  
  
- 漏洞视角Thymeleaf漏洞原理及防范(  
Thymeleaf  
3.0.11版本)  
  
- Rouyi实战审计案例(  
Thymeleaf  
3.0.12版本)  
  
  
  
**Thymeleaf模版注入漏洞**  
  
一  
  
Thymeleaf  
  
        Thymeleaf 的模板引擎通过将模板与数据模型结合，实现了动态内容的渲染，适用于各种 Web 开发场景。  
  
1.1Thymeleaf引擎  
  
        引擎是 Thymeleaf 的核心组件，负责解析模板、处理动态表达式，并将模板与数据模型结合生成最终的输出内容。  
  
1.2Thymeleaf模版  
  
        模板是 Thymeleaf 中用于定义页面结构和内容的文件，通常是 HTML 文件。模板中包含了静态内容和动态占位符（Thymeleaf 表达式），这些占位符会在渲染时被替换为实际的数据。如下图所示：${user.name}和${user.email}是 Thymeleaf 表达式，会在渲染时被替换为实际的数据。  
  
二  
  
业务视角Thymeleaf场景流程  
  
Thymeleaf数据流转流程  
  
- 用户请求阶段  
:用户通过浏览器向服务器发送 HTTP 请求（如 GET、POST 请求）  
  
- 数据绑定Model  
:控制器将数据绑定到Model对象中，Model是 Spring MVC 提供的一个接口，用于在控制器和视图之间传递数据  
  
- Thymeleaf视图解析器  
:Spring MVC 根据控制器返回的  
视图名称  
（如"greeting"）调用 Thymeleaf的视图解析器（ThymeleafViewResolver）来解析模板。  
  
- Thymeleaf 引擎处理模板:  
Thymeleaf 引擎根据模板名称找到对应的  
模板文件  
（如greeting.html），并将数据渲染到模板中。  
  
- TemplateEngine：Thymeleaf 的核心类，负责模板的解析和渲染。  
  
- Context：Thymeleaf 的上下文对象，用于存储模板中使用的变量。  
  
- TemplateResolver：负责定位模板文件（如从类路径、文件系统等）。  
  
- 模板渲染  
:Thymeleaf 根据模板文件和数据生成最终的 HTML 内容。  
  
  
  
  
2.1Thymeleaf使用流程  
  
- 定义模板:开发者编写 Thymeleaf 模板文件（通常是 HTML 文件），定义页面结构和动态占位符。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErR9DZO0kfCYmDf8n3YIl4mY8UjnWjABQoQGH4d33LwLmADu4RWicov1w/640?wx_fmt=png&from=appmsg "")  
  
- 准备数据模型:在后端代码中，准备需要渲染的数据模型。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErK4wGk0rrjju2Tj39VTJIWytQvurx5mibKVKZP9ahIGcwOrIib9M4BU8w/640?wx_fmt=png&from=appmsg "")  
  
- 渲染模板:Thymeleaf 的TemplateEngine将模板与数据模型结合，生成最终的 HTML 内容。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErCXPn7cW66x9Kk80mLdrHafG8ibBsR2ribJibwFK13p2O9paKRCXTCJJ0g/640?wx_fmt=png&from=appmsg "")  
  
- 返回渲染结果:将渲染后的 HTML 内容返回给客户端（如浏览器）。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErtD2wIlk8VDDFqS6Za5NdYicic2KFTWIoNiblPGYpUJG6kibJx4GibNZcdiaw/640?wx_fmt=png&from=appmsg "")  
  
  
三  
  
 漏洞视角Thymeleaf模版原理及防范  
  
Thymeleaf模版注入漏洞属于SSTI类漏洞，触发漏洞根因是在用户输入参数后模板渲染前Thymeleaf引擎使用Spel解析阶段造成Payload被执行，且不同版本的Thymeleaf模版会有不同的漏洞触发场景。  
  
3.1漏洞场景研究  
  
示例漏洞场景项目https://github.com/veracode-research/spring-view-manipulation/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er9S3Z1vP417MR1A0U0lv925XopIic0zcUFAJqEXAZnXp2r4FAO1z91Zw/640?wx_fmt=png&from=appmsg "")  
  
Thymeleaf模版版本为3.0.11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErnUuXwiaJvH9icXnaYrk9u1yWau5nNTsaSPh01FMyyPKOiapY2uk6icraew/640?wx_fmt=png&from=appmsg "")  
  
3.1.1表达式拼接注入  
  
直接拼接注入表达式经测试不可行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Erjy0ekE3Tt17YBzYKzYUKp9vJpqdibib53RULiclWd5v4O6piaiaJFnvMHtQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9EreRayGiayTFJandO7wnmW5sYBYBrWDoC3pRMH8EujQHsGYOuZgnC5Hlw/640?wx_fmt=png&from=appmsg "")  
  
输入表达式无法进行拼接模版注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Eribj2afCPxptAiba2fC7IyEicvYVcslO6T73icNqD6jhkQva0LNnHeRmIyg/640?wx_fmt=png&from=appmsg "")  
  
测试模版是否能解析SPEL表达式：  
  
StandardDialect：Thymeleaf 使用`StandardDialect`来处理标准表达式（如`${...}`）。可以通过检查`StandardDialect`是否被注册来确定表达式解析是否启用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErVicbw6GE3NKiatmoXEvLZst7JzZSen5yiaYiaDTDV5ZMhsxJow32QH5dtg/640?wx_fmt=png&from=appmsg "")  
  
发现开启了表达式的解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Eribgnacicoojiczc3IWKhVSr8OguVcia3phpYfpU53OzHUvicYYaojRXMrqw/640?wx_fmt=png&from=appmsg "")  
  
模版修改为Payload形式直接访问测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er16kg1p3x5v63JJicibbo0rS6bv2ibibsuEJCHlxqXr7lmCmhIH0nibdGicrA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErQdnTPuZjzGDkTg2o3wrAVFH91yiciaXvEZhrJVOvicsP2PicBounSmjnSA/640?wx_fmt=png&from=appmsg "")  
  
访问show接口发现也能直接解析Spel表达式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErpAvO1hush8wxWrkHibav48UP5U1jcce0FTCOZUOWQYUQkHWD9AEhheQ/640?wx_fmt=png&from=appmsg "")  
  
那么只有一种可能：Spel中getValue()处理完模版中固定的Spel表达式再渲染的Html，而不是解析传入的Spel表达式到SPELVariableExpressionEvaluator.java中的getValue()方法进行下断发现传入的是模版中写死的$message表达式并非  
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("calc").getInputStream()).next()}__::.x::  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErMuWNkzxh3mG3h1XAWmavWiaicuBKlADWA8LvNaByeoHFMAQicm9GpWrNg/640?wx_fmt=png&from=appmsg "")  
  
Spel表达式流程发现：ThymeleafView.java中吧templateName是核心内容，主要是传参可控制模版名字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErW1O642J40Dq81xEmbVHibRiaAoBdWhRfds7Uf3qqbuZiaqdBavquEluLQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9EricIVXBcE77xXB1qxAFhicicd8iaCaaONiaTxnZyqS5AaTJNZSVibiakRnBXmA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErGjwpDGyYlibsTY4HvWYj0LT1V7ldSry2KMhdPaQEwoMgWxeDLG6alBA/640?wx_fmt=png&from=appmsg "")  
  
将${message}作为input传进去，后续将作为直接解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErpSYQibZibnjo4wozzQce9FyaOEd8lhlDpHUAbOqLpD1GKicwWLSOWbq4A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er9BRXKdoYgXCMnMkT5YO0OD6v6vPMD1WSjOKKLjy4icXnNN8Q0EicYibEA/640?wx_fmt=png&from=appmsg "")  
  
  
3.1.2return模版路径表达式解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErWib88SchI6WDNXxXuabhxuQd7tWicXldEffumqxDPyVPJxibdQBlH4jhA/640?wx_fmt=png&from=appmsg "")  
  
3.1.3分段表达式注入return模版路径表达式解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErZk4b27Uk9ZrKdA8cvdnnOcWVniaMUUT4ClThnsbZ8ZGepHOrEqElDPg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErvAskBOGMVkOLFMxf4RxUeq3WOpBdffxicibFrjXpkN6IHmcgAZsJuamg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er1K2wfsficODWdrhaqFtyytM2gb2icJdR4Sl8Hdjx0WJk20CltEGIpNqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErZhceN2EkCmia4YDiavVejgvGYrgSict0LkF9KLMNaCoYYwxrCWHdDT3tA/640?wx_fmt=png&from=appmsg "")  
  
3.1.4Url表达式注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErEl0IUKZTsyEWI9k57JjvHhXfbbmBTMSgRNKTRj6rZhM9L01kuc9BdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Erice2EWBvHDk5PbAcLmlxIvMGeQgrN6iaHadKMDnwK3bQ5cpOuzNTBbibQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Erpcrnbeya5092NeEVgIuibXBPbQdcFR1rCqSp7QHPLHLXibg74VMiclokg/640?wx_fmt=png&from=appmsg "")  
  
四  
  
实战审计案例  
  
此篇RouYi-v4.7.1为分析Thymeleaf漏洞进行白盒方式审计模版注入漏洞。部署后从系统功能视角到源代码定位及抓包调试进行讲解。  
  
白盒审计思路  
  
- 关键词定位Control层  
  
- 查看是否存在注入点  
  
- return or url模版路径可拼接进行给视图传参数  
  
4.1RouYi-v4.7.1漏洞项目部署  
  
Gitee项目地址：https://gitee.com/y_project/RuoYi/compare/v4.7.1...v4.7.2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErRqdQQELf6o0UpG7hR5a1kicibEcsgDM495cvQgYbgltHicNsMSDS2qCLg/640?wx_fmt=png&from=appmsg "")  
  
直接打开Pom.xml引入依赖即可，查看thymeleaf版本2.1.0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Ermvuk1NCjp45cD8E3EzibWN6H85pt5DKR4wY7MkGORiciceXxyZGsLAz8w/640?wx_fmt=png&from=appmsg "")  
  
启动项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9EraIibiaibjP92zMibEBbMB7e2hKrbrxlHjFeChdXlRZWwGjx690muKJlv2w/640?wx_fmt=png&from=appmsg "")  
  
导入2个数据库文件，并修改数据库账号密码，成功启动项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Erfvaw09FZ8OC3bZs8XKACFgKoM7RlkouAX0lwerAjwOoGMBD0ScldbQ/640?wx_fmt=png&from=appmsg "")  
  
4.2白盒源代码漏洞分析  
  
定位SpringBoot中Thymeleaf模版配置项及前端模版位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErpWQnWlpJqup6xjwnVVlvj7ROQ0bf1ULVyFwYq9atZpxq6m2lkAszIw/640?wx_fmt=png&from=appmsg "")  
  
关键词定位：在Thymeleaf漏洞中的业务代码，会在控制器（Controller）和视图（View）之间传递数据。它们的主要作用是将数据从控制器传递到 Thymeleaf 模板，以便在模板中渲染这些数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErfOFgciaBdRLUoKuYE85XYyxg3A7W8DytaEO7cMMico9P1B9EcxGlSC2g/640?wx_fmt=png&from=appmsg "")  
  
使用关键词定位Control层，看样子用的ModelMap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er6nV9E3eTr1IpDs3nF3t8Md9T9dhUYzasOiag5swQk2TznPRYX45kwpw/640?wx_fmt=png&from=appmsg "")  
  
DemoOperateController.java中修改用户方法返回视图模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErS9ZZ6YAPwgFDqLsVkhAZtUJc7dIZV0P2FpYBZB2K6BMZl4TajPicGGw/640?wx_fmt=png&from=appmsg "")  
  
第二处也不可控  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErwSCukGyx4qtZBPT2UgTJw6MDYB5hou0zRpFpg6P5TDNicPqTyhqymZQ/640?wx_fmt=png&from=appmsg "")  
  
查找到CacheController.java发现惊喜，return路径可直接传参数控制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErsmRXRrTG76IvSh5NPrVqldYDU0MgCTicur3cIBcfN9vcP2SeZ57opuQ/640?wx_fmt=png&from=appmsg "")  
  
Rouyi的模版版本为3.0.12,需要定位此版本Payload才可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Erkm1icuKSuiaCdbGYttT6We84La0wpB1jLt4k4oQucoJLJ4GFFictn1kQw/640?wx_fmt=png&from=appmsg "")  
  
根据描述信息3.0.12防护信息需要进行  
Url编码并且进行空格处理才可绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErUtBOibqpaZMhvuXA3icMpXdqmLibQyxOJuRHzzqncCRmib5g3uHhaKffBw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er5NmxamyYmmzZsxMcI9hXeuKicwKbFflujtl7uhvqF6Oicia9ZxvnpmtDg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9EruA98dj55dcw3lyVBcXJ28iaSMBhlmkFGW3EzG1ibNJFqDn5RibG0ophUg/640?wx_fmt=png&from=appmsg "")  
  
源码跟踪3.0.12绕过方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9Er2DwJ3kVWK9ZvV1hmlZkqZDLF3ibEKF9ZXrPBoBfNyqHLNBpoXWt8Jgg/640?wx_fmt=png&from=appmsg "")  
  
发现使用SpringSecurity框架中的一个工具类：SpringStandardExpressionUtils.java用于检测 SpEL具体逻辑如下：  
  
1.倒序扫描表达式字符串，逐字符匹配"new"关键字(使用倒序方式匹配 "wen")。检查匹配到的 "new" 是否为独立关键字，而非标识符的一部分。  
  
2.同时检测类似 T(SomeClass) 的静态方法调用形式。  
  
如果发现上述两种情况之一，则返回 true，表示存在受限操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8xNC9yLibCeoWMhsICVjB9ErJ2Jte3GprZPYe7hs7JrsVw1uvPVcX1iaYojeibSAuQnUmxuEwJGnru4Q/640?wx_fmt=png&from=appmsg "")  
  
所以此时需要先查看SpringEL表达式是否从语法方面绕过：支持"T (SomeClass)"这样的语法，因此我们只要在T与恶意Class之间加个空格  
  
END  
  
  
  
