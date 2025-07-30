#  拿到了 SpringBoot 开发的系统，该如何代码审计分析漏洞？分享下我的一二三步的思路。   
原创 润霖@闪石星曜  闪石星曜CyberSecurity   2025-02-12 10:19  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/FFcgFn6WVc2ribkEhzXXbiaAE31xwNoCLjKDDibq9HkTiab5BllP8wbSSabd7CIoJSLfHQHjq6ZBf0CoVJaEdKgibNA/640?wx_fmt=gif&from=appmsg "")  
  
嗨，大家好，这里是闪石星曜CyberSecurity。  
  
众所周知，Java 语言生态在中大型企业中的使用率居高不下，可谓是如日中天，经久不衰。  
  
使用 SpringBoot 架构来开发的 JavaWeb 系统，更是数不胜数，也因此我们渗透测试中一部分的挑战，可以说是来对抗 Java 代码。  
  
如果我们拿到了基于 SpringBoot 开发的系统，想要进行代码审计，分析漏洞，第一步该怎么做，我来给大家讲讲。  
  
欢迎大家点个关注，带让大家轻松学习代码审计，掌握代码审计技能！  
  
下面，我先讲一些基础知识。  
  
如果大家想系统入门学习 Java代码审计，欢迎报名我的课程，五十多节课，平均一小时，20+企业级实战项目，低至499，详细可点击下方链接查看。  
  
[《Java代码审计零基础入门到项目实战》2025年第一期招生即将结束，低至499，五十多节课，多重福利来袭！](https://mp.weixin.qq.com/s?__biz=Mzg3MDU1MjgwNA==&mid=2247487190&idx=1&sn=704ae787b03a1066720f28cecdc33545&scene=21#wechat_redirect)  
  
# 【壹】基础知识  
## 1. 什么是 Spring Boot  
  
Spring Boot 是基于 Spring 框架的扩展，旨在简化 Spring  应用的初始搭建和开发。它通过自动配置和约定优于配置的原则，减少了开发者的配置负担，使得开发者能够快速构建独立的、生产级别的 Spring  应用。Spring Boot 内置了嵌入式服务器（如 Tomcat），并提供了丰富的 Starter  依赖，使得集成各种技术栈（如数据库、消息队列、安全框架等）更加便捷。  
  
其实对于我们代码审计来说，挖掘此类架构系统的漏洞，也变的非常方便了。  
## 2. 第一个 Spring Boot 项目  
  
创建一个 Spring Boot 非常简单，只需打开 IDEA，选择新建项目，然后在选择 Spring Initializer，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIxw7Icwib4hicLADkNSSQ7rSiaJtADblJqjExOsOu4Zl2MR7Y7iakyLbOBg/640?wx_fmt=jpeg&from=appmsg "")  
  
需要注意的我也标注了红线，但值得注意的是服务器 URL。  
  
我们要设置为   
start.aliyun.com   
脚手架地址。  
  
因为官方地址抛弃了 Java8，可能有些地方会影响到我们。  
  
然后，点击下一步即可，下面在依赖项中可以选择一些我们所需的依赖，比如   
Web-Spring Web  
，这样我们就创建一个 JavaWeb 系统了，可以拥有处理 Web 的相关代码了。如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIaarUQGDXmkAygIGYhuCGkHgpVIQ2G1MHSIOffKLJjiaTamgnbMTA0Dg/640?wx_fmt=jpeg&from=appmsg "")  
  
然后，点击创建即可。  
  
我们可以看到成功创建了一个基于 Spring Boot 架构的 JavaWeb 系统，在这个项目中，阿里云还提供了一些基础的案例代码。  
  
也就是所谓的 Controller 层，亦或叫做路由映射，都是一个意思。是某个功能接口的具体代码，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HISIsJXdeSgu8aygRaAv7jB9NA9XedgzibNiaLnQic6RDQVrttOHx5koqiag/640?wx_fmt=jpeg&from=appmsg "")  
  
最后，找到 Demo2Application 中的绿色按钮，点击启动项目即可。这样，我们就可以在浏览器中通过案例中的 URL 地址就可访问调用这些接口了。  
  
当然了，每个项目名称不同，所以这个启动类的代码名称也有所不同，一般都是项目名称+Application。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIHOPQz8jWpW0Yria4dB0KaGChDk6Sua9aET2KpkrDicCvHlm8VO2DewLw/640?wx_fmt=jpeg&from=appmsg "")  
  
这样，我们就成功创建了一个 Spring Boot 架构的 JavaWeb 系统。  
  
项目中的一些基础案例代码，大家可以摸索下。  
## 3. Manve 管理项目  
  
刚才，我们选择了 Maven 作为项目管理。那什么是 Maven 呢？  
  
Maven‌ 是一个项目管理工具，主要用于构建和管理基于Java的项目。它通过一个叫做 POM的文件来管理项目的构建、报告和文档。  
  
Maven不仅简化了构建过程，还提供了依赖管理和项目信息管理的功能，是一个跨平台的自动化构建工具‌。  
  
对于我们来说，，他主要功能在 Pom.xml 文件中引入了第三方依赖，做统一的管理。  
  
比如引入 Fastjson2  的某个版本我们可以在 Maven 依赖库中找到对应的依赖项，然后可以将具体的格式粘贴进 Pom.xml 文件中。如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIPOyMPibTwRTukfN5O2p4ibtibjGd8kDYicn9BMGCMvHFxGLdqPPp0scBkw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIgjXkKRXChkp3EzUBluYMK96BBBsUNqaJuHL8hE4iaU3VW2PBGiaicr8Ww/640?wx_fmt=jpeg&from=appmsg "")  
  
最后，由于我们引入了新的依赖，所以需要点击右上方加载 Maven更改按钮，让他从仓库中把该依赖加载进来。  
  
【注意注意注意】由于 Maven 中央仓库在国外，会经常因为网络原因没有成功把一些依赖加载进来，也就会导致项目无法成功启动，一般百分之九十的原因都是如此。大家一定要注意配置好国内源。  
  
我的建议是，在官网自行下载一个 Maven，不用 IDEA 自带的，然后放在一个固定文件下，自己修改下国内源（搜索引擎搜下即可）。  
  
最后，在  
设置-构建执行部署-构建工具-Maven  
中键入该文件的地址，就像我下图所示标记的样子。  
  
这样做的还有个好处是，对于相同的依赖，就不会重复下载了，相当于自己搭建了个本地仓库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HI4ZvZianPCjwOSrHLgvenNsvj2kFnmVSSicRmYUFhFjc5WrmSUtG4LuPw/640?wx_fmt=jpeg&from=appmsg "")  
  
对于 Pom.xml 文件还有个重要的一点，就是我们能通过该文件快速了解该项目引入了哪些依赖，以及该依赖是否存在漏洞版本，如果有的话，可以代码审计漏洞点了。比如引入了 Fastjson 1.2.6 版本等等。  
## 4. 基础架构  
  
其实，对于基于 Spring Boot 开发的 JavaWeb 系统，其项目结构都大致如此。  
  
开发人员也有自己约定俗成的一套架构模式，也就是所谓的应用分层/分层思想。  
  
具体内容大家可以打开这个地址看看：  
```
https://developer.aliyun.com/article/1589859（阿里巴巴 Java 开发手册）
```  
  
简单来说，就是项目中会有不同的文件夹，也就对应着不同的作用。  
  
我们常见的有 Controller/Domain/Action 等名称的文件，就是所谓的路由层。以及 Service/ServiceImpl 文件，在 ServiceImpl 实现了一些功能所需的复杂代码，当然我们也可以写在路由层。以及 Dao，Mapper 文件，这部分是有数据库相关的代码。比如，整合了 Mybatis 框架，会在 Mpaper 中定义，拼接 SQL 语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIMBRZdyxOXfDbM5pLn5feZOCI4icibvhRF4uqFws3pb8laOHRRyRanQ8w/640?wx_fmt=jpeg&from=appmsg "")  
  
通过这几个大致的分层，我们能够大概理解一个项目从浏览器访问该接口传入该参数的大致流程了。  
  
也就是先会经过路由层，然后在到 Service 层，ServiceImple 层，在最后到 Dao，Mapper 去进行数据库处理。  
  
通过理解目录分层，我们最起码可以在抓包到某个功能点的 URL 后，可以通过找到对应的路由映射开始分析代码了。  
  
当然了，随着学习的深入，也会遇见较为复杂的系统，但本质不变，大家多多练习就能慢慢理解了。  
## 5. 目录结构  
  
下面，给大家讲讲一些常见目录，以及具体作用。  
### 5.1. Java 目录  
  
该目录下一般都是存储的关键代码。  
```
annotation：放置项目自定义注解
controller/: 存放控制器，接收从前端传来的参数，对访问控制进行转发、各类基本参数校验或者不复用的业务简单处理等。
dao/: 数据访问层，与数据库进行交互，负责数据库操作，在Mybaits框架中存放自定义的Mapper接口
entity/: 存放实体类
interceptor/: 拦截器
service/: 存放服务类，负责业务模块逻辑处理。
Service层中有两种类，一是
Service，用来声明接口；二是
ServiceImpl，作为实现类实现接口中的方法。
utils/: 存放工具类，比如文件上传，一般会统一写个文件上传工具类，系统内其他地方需要该功能时，可以直接调用。
dto/: 存放数据传输对象（Data Transfer Object），如请求参数和返回结果
vo/: 视图对象（View Object）用于封装客户端请求的数据，防止部分数据泄漏，保证数据安全
constant/: 存放常量
filter/: 存放过滤器
```  
### 5.2. Resouces 目录  
  
该目录一般都是存储的静态资源，比如模板文件，Html，JavaScript，CSS 等。  
```
mapper/: 存放Mybaits的mapper.xml文件
static/: 静态资源文件目录（Javascript、CSS、图片等），在这个目录中的所有文件可以被直接访问
templates/: 存放模版文件
application.properties或
application.yml: Spring Boot默认配置文件
```  
## 6. 常见注解  
  
下面是一些常见的注解，及其意思。  
#### 6.1. @RequestMapping 注解  
  
@RequestMapping  
 是 Spring MVC 中最常用的注解之一，用于将 HTTP 请求映射到指定的处理方法上。  
  
他有两个级别，首先是类级别，也就是在类上做了 @RequestMapping 注解。  
  
次之，是方法级别，也就是在方法上做了 @RequestMapping 注解。  
  
那么他们的完整路径是类上边设置的路径加上方法上面设置的路径。  
  
在该注解下，还有几个属性。  
- value  
：指定 URL 映射路径。  
  
- method  
：指定请求类型，如 GET、POST 等。  
  
- params  
：指定请求中必须包含某些参数。  
  
- headers  
：指定请求中必须包含某些请求头。  
  
####   
#### 6.2. @Controller 注解  
  
@Controller  
 是一个类级注解，标识该类是一个控制器类，用于处理 Web 请求。表明该类是一个控制器，使用  @RequestMapping 注解设置路径，也就是表明接收处理该接口的参数。  
#### 6.3. @ResponseBody 注解  
  
@ResponseBody  
 是一个方法级注解，他表示该方法返回的内容将直接写入 HTTP 响应体中，而不是被解释为视图名称，这点要注意。  
  
通常用于 RESTful API 开发，他返回的数据通常是 JSON 或 XML 格式。  
#### 6.4. @RequestParam 注解  
  
@RequestParam  
 是用于处理请求参数的注解，它用于方法参数上，能够将请求中的某个参数值绑定到方法的参数当中去。它常用于从查询字符串、表单提交的参数中提取数据。  
  
有这么几个常用的属性，不是强制的哈。  
  
value  
：指定请求参数的名字。如果请求参数的名字和方法参数的名字一致，可以省略   
value  
 属性。  
  
required  
：指定参数是否为必需的，默认值为   
true  
。如果请求中没有该参数，Spring 会抛出异常。  
  
defaultValue  
：为请求参数指定默认值，如果请求中没有该参数，会使用默认值。  
  
有一点，我们需要注意的是，要清楚的知道参数的数据类型。  
  
比如，之前发现了一个 SQL 注入漏洞点，试了半天怎么都没有跑出来漏洞来。最后仔细一看，数据类型是 int，在 Java 中是强数据类型，所以也就导致这个 SQL 注入漏洞可能没办法利用。当然了，凡事不绝对还要具体看项目情况。  
  
# 【贰】审计思路  
  
基础知识我们学完了，下面我给大家提供一些基础的代码审计思路。  
  
至少拿过来项目，知道该如何入手，第一二三步干什么。  
## 1、找项目开发文档  
  
如果是开源项目，或者是工作中提供的项目，亦或是闭源项目。  
  
我们都可以去找到项目的开发文档，去大致的看一遍。这样我们就会对这个项目有了最基础的认识。  
  
比如说，知道使用了哪些技术，有哪些功能点等内容。  
  
所以，看下项目开发文档，会对整个系统有个较为清晰的认识。  
## 2、正向追踪找路由入口  
  
上面基础知识学完，我们知道，一般 Controller/Domain/Action 等名称文件都是存放的路由映射的代码。  
  
如果大家想要入手 JavaWeb 代码审计的话，可以先从正向追踪路由入口开始，一步步追踪分析代码。  
  
我们可以部署启动项目后，抓取某个功能点的数据包，然后通过全局搜索的方式，找到对应的路由具体代码。亦或者直接去看该类文件夹下的代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIORBQgBxj8tx3fXL2xWZXOdn3easdn9N5saNMF6MzUHQSPocSXm3mJg/640?wx_fmt=jpeg&from=appmsg "")  
  
我们可以看到，  
common/download  
接口，注释说明了是一个下载功能，其中代码就是下载的步骤。  
  
这样，我们就可以代码审计是否存在任意文件下载漏洞了，经管我们看不懂代码，但我们完全可以解除各种 GPT 来辅助我们理解代码。  
  
我们可以想下任意文件下载漏洞的本质在于没有过滤  
../  
，导致了穿越目录读取一些敏感文件。  
  
所以，在这个点上可以分析下是否校验了路径中是否存在  
../  
，  
..  
 诸如此类。  
  
这就是一个基础的正向审计思路，多看看代码，慢慢就明白了。  
  
各类 GPT 的出现，大家也要抓住一点，就是利用他们来帮我们学习更多深入地知识，代码看不懂直接问就行了，需要磨练反而是思路！   
## 3、逆向追踪找漏洞函数  
  
上面讲了通过看路由层，直接从正向分析代码。  
  
其实，如果我们知道了一些漏洞函数，也可以通过逆向追踪的方式来分析漏洞。  
  
在这里，所谓的逆向追踪，就是找到了漏洞点后，我们需要向上逐步追踪，直到发现该漏洞点是有对应的路由接口的，并且期间没有做一些防护过滤代码，那么基本就能确定这个点，是存在漏洞的。  
  
往往我们逆向追踪会发现，经管项目中存在漏洞点，但没有对应的路由接口，仅是在内部代码中传递，调用，那么我们不能直接控制的话，也就导致没有办法利用这个漏洞了。  
  
比如，一些常见的漏洞函数，大家可以看 su18 师傅整理的这份文档。  
```
```  
  
比如，我们可以通过关键字全局搜索有多少出使用了 File 类操作文件的地方，然后可以进一步分析是否存在漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HISy4H0kJxyyaXpZ01boVpkZtHUnm3TdSiaxCNXVBXpffVQTPiase2mGsQ/640?wx_fmt=jpeg&from=appmsg "")  
## 4、看 Mapper 找注入漏洞  
  
该方式更多是用于项目集成了 Mybaits 框架。对于 Mybaits 框架来说，会将定义的 SQL 语句放在 xxxMapper.xml 文件中。  
  
当然了，有的也会放在 Mapper 层中使用注解的方式来定义 SQL 语句。  
  
不论哪种，我们都可以使用全局搜索的方式，来看看 Mybatis 中定义的 SQL 语句是否有使用   
${}   
花括号的方式拼接的。如果有的话，那极有可能存在 SQL 注入漏洞。  
  
然后，一般就是按照逆向追踪的方式，来找到对应的接口，进而进行渗透测试验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIofTicfjibt4wKz60vmSJaoocf1UUlibLHVS4pufvdF0626WulpzOT0XzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
所以这个点会有漏洞嘛？大家可以试试。  
## 5、看 pom.xml 找组件版本漏洞  
  
前面，我们讲了 Pom.xml 文件中定义了所需的组件，以及组件版本漏洞。  
  
那么很明显，我们能够知道该项目重要用了哪些组件以及版本存在漏洞的话，就可以进一步去找组件存在的漏洞点了。  
  
比如，这个项目引入了 Fastjson 1.2.60 版本，该版本是存在漏洞的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HIbTMzsJO2Xrd0DoaBEJicaupZ4ywHv7OVFOQcfP82opXNLw7eyib4sfuQ/640?wx_fmt=jpeg&from=appmsg "")  
  
那么，我们就可以进一步全局搜索查找 Fastjson 的漏洞点了，比如这几个函数，  
parseObject  
，  
parse  
等。如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FFcgFn6WVc2riaMcVTHn0cvCpeiab4H0HI56sviaALC1MgyVVYTQzDau5uoRfKibtLG5NGV1Rm1ts6hEkKzsWOLyTQ/640?wx_fmt=jpeg&from=appmsg "")  
  
当然，我们还需要进一步逆向追踪分析，该参数我们是否可控。并且，如果想进一步利用一些链子的话，还得看项目中是否有相关组件，能够调用。  
  
大家可以自行练习下，这个点存在漏洞嘛？  
  
好啦，这就是拿到 Spring Boot 开发的 JavaWeb 系统该如何进行代码审计了，希望能够对你有所帮助。  
  
不要忘了点个关注，点个赞哦~  
  
（文章中所演示的项目，可后台回复关键字【  
20250212  
】获得）  
  
如果学习有问题，可添加我的好友 Power_7089，帮您答疑解惑。  
  
  
  
