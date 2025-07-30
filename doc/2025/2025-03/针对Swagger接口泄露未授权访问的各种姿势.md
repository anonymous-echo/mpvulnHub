#  针对Swagger接口泄露未授权访问的各种姿势   
原创 神农Sec  神农Sec   2025-03-01 01:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
加内部圈子，文末有彩蛋  
（知识星球  
优惠卷）。  
#   
  
  
**0x1 前言**  
  
  
  
这篇文章的话主要是给师傅们分享下Swagger接口泄露包括未授权访问然后导致信息泄露相关的一些常见姿势。然后先从Swagger漏洞的相关简介，再到相关使用的插件包括工具等的使用，然后再从实战中的案例进行解析和讲解。           
  
              
             
           
  
**0x2 漏洞描述**  
  
  
### 一、swagger接口泄露  
  
某公司平台系统存在敏感信息泄露漏洞，由于对  
swagger-ui  
未做好访问控制措施，导致攻击者可以通过swagger页面获取网站  
API  
信息，进而导致攻击者构造  
payload  
对系统API进行攻击。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLprDmR9zxVkg0fxWVxGMqKI3nA1FncB3hC3VmJhK7VD20FncKmzuwYw/640?wx_fmt=png "")  
  
                  
### 二、浅谈  
### Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务。总体目标是使客户端和文件系统作为服务器以同样的速度来更新。      
  
  
相关的方法，参数和模型紧密集成到服务器端的代码，允许API来始终保持同步。  
Swagger-UI  
会根据开发人员在代码中的设置来自动生成  
API说明文档  
，若存在相关的配置缺陷，攻击者可以  
未授权  
翻查  
Swagger接口文档  
，得到系统功能  
API接口的详细参数  
，再构造参数发包，通过回显获取系统大量的敏感信息。  
    
  
             
### 三、swagger未授权访问地址存在以下默认路径  
### 下面的路径就是常见的Swagger 未授权访问泄露路径，师傅们可以通过bp抓包，然后再通过bp对该接口路径进行爆破，但是我一般是先使用曾哥的一款spring-boot扫描工具去做一个自动化扫描，但是有部分网站可能对那个工具会拒绝请求，所以还是可以尝试使用bp爆破  
  
/api            
  
/api-docs            
  
/api-docs/swagger.json            
  
/api.html            
  
/api/api-docs            
  
/api/apidocs            
  
/api/doc            
  
/api/swagger            
  
/api/swagger-ui            
  
/api/swagger-ui.html            
  
/api/swagger-ui.html/            
  
/api/swagger-ui.json            
  
/api/swagger.json            
  
/api/swagger/            
  
/api/swagger/ui            
  
/api/swagger/ui/            
  
/api/swaggerui            
  
/api/swaggerui/            
  
/api/v1/            
  
/api/v1/api-docs            
  
/api/v1/apidocs            
  
/api/v1/swagger            
  
/api/v1/swagger-ui            
  
/api/v1/swagger-ui.html            
  
/api/v1/swagger-ui.json            
  
/api/v1/swagger.json            
  
/api/v1/swagger/            
  
/api/v2            
  
/api/v2/api-docs            
  
/api/v2/apidocs            
  
/api/v2/swagger            
  
/api/v2/swagger-ui            
  
/api/v2/swagger-ui.html            
  
/api/v2/swagger-ui.json            
  
/api/v2/swagger.json            
  
/api/v2/swagger/            
  
/api/v3            
  
/apidocs            
  
/apidocs/swagger.json            
  
/doc.html            
  
/docs/            
  
/druid/index.html            
  
/graphql            
  
/libs/swaggerui            
  
/libs/swaggerui/            
  
/spring-security-oauth-resource/swagger-ui.html            
  
/spring-security-rest/api/swagger-ui.html            
  
/sw/swagger-ui.html            
  
/swagger            
  
/swagger-resources            
  
/swagger-resources/configuration/security            
  
/swagger-resources/configuration/security/            
  
/swagger-resources/configuration/ui            
  
/swagger-resources/configuration/ui/            
  
/swagger-ui            
  
/swagger-ui.html            
  
/swagger-ui.html#/api-memory-controller            
  
/swagger-ui.html/            
  
/swagger-ui.json            
  
/swagger-ui/swagger.json            
  
/swagger.json            
  
/swagger.yml            
  
/swagger/            
  
/swagger/index.html            
  
/swagger/static/index.html            
  
/swagger/swagger-ui.html            
  
/swagger/ui/            
  
/Swagger/ui/index            
  
/swagger/ui/index            
  
/swagger/v1/swagger.json            
  
/swagger/v2/swagger.json            
  
/template/swagger-ui.html            
  
/user/swagger-ui.html            
  
/user/swagger-ui.html/            
  
/v1.x/swagger-ui.html            
  
/v1/api-docs            
  
/v1/swagger.json            
  
/v2/api-docs            
  
/v3/api-docs  
  
      
            
  
   
   
           
  
**0x3 工具篇**  
  
  
  
上面我也给师傅们介绍了使用工具对Swagger 接口泄露进行一个扫描，下面给师傅们介绍下使用曾哥的spring-boot漏洞扫描工具进行一个接口泄露的扫描。  
  
https://github.com/AabyssZG/SpringBoot-Scan书签：  
  
python SpringBoot  
-  
Scan  
.  
py   
-  
u url  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLjZ7DJtn4F8dN85eRnvZKk8K0UAEvYXiaD47Yqpqeq34NUdtDk4YhgVg/640?wx_fmt=png "")  
  
             
  
Swagger 也是spring二次开发的产品，所以一般找Swagger 接口信息泄露的漏洞可以去找spring-boot经典报错的页面，下面就是经典的spring-boot报错页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLAx0MmCztu0qJ48Hdh9LN4RrftxK3AdibJCGIUOavnfIGMKQS1Kia4cAw/640?wx_fmt=png "")  
  
             
  
             
  
对于这样的大批量的测试的话，可以使用FOFA检索语句，就对上面的一个关键字进行检索  
  
FOFA语句：  
  
body="Whitelabel Error Page"  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLlwmQnSbT5zsLVmTic4cLM91WTGibF09icap06gMuJicecswMMia8HS91XMg/640?wx_fmt=png "")  
  
  
可以看到里面的icon数量非常多，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhL4DPdLa2Ay9icMfHFaX3d4lnnuZamhD2ZAhO9rp4ZTYHHym8KnqBD1lg/640?wx_fmt=png "")  
  
             
  
**0x4 Swagger漏洞通杀**  
  
  
### 一、加密的Swagger  
  
首先一般大家分享Swagger泄露接口敏感信息，一般都是在Swagger-UI这个插件里面分析  
  
我这里以Google商店的插件为例，然后火狐和eg浏览器的话也差不多都是这个绿色的小图标  
  
https://chromewebstore.google.com/detail/liacakmdhalagfjlfdofigfoiocghoej?hl=zh书签：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLemSFxQ10b5qGXXKN2dbNiamu8NO6SKo6OfI1ek5xF1uWsWwpxWOQjdQ/640?wx_fmt=png "")  
  
             
  
             
  
然后可以看下我下面通过FOFA找到的一个Swagger接口泄露的一个站点，然后利用这个插件去打开  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhL15FlE6frFmP6eiaKJ9I9eSbjZqjiamLrtTqptibmDBNc3POKPNAprtaBQ/640?wx_fmt=png "")  
  
  
但是这个插件可以看到  
Authorize  
关键字，这个你可以点击下，这个标识就是表示这个泄露的 接口需要我们输入加密的信息，要是按照正常的直接访问这个泄露的api接口，然后看敏感信息就不可行了，下面我来带大家使用一个Swagger脚本工具来给师傅们演示下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLUQpciaibz27Bia87bPicYEsibUnszaUIdMyicgw7fCFgthiaZlqNaQX04u8Cg/640?wx_fmt=png "")  
  
  
首先我们先访问下这个泄露的swagger/v1/swagger.json文件目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLNfCmBqggSyicI6hBF5fYeGZNw1NazicOQq70hh48hSxkD4rmzqzXkyPA/640?wx_fmt=png "")  
  
  
然后可以在json文件看到里面有非常多的api接口泄露，但是太多了很多都是没有权限访问的，要是挨个拼接不太现实，那么下面我就给师傅们介绍下面下面的这款swagger工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLU2OMxPbiaGqG2I2Jqvn4BOvjPKibXRpuR59KP6nNTapDDdaxu0by83tQ/640?wx_fmt=png "")  
  
### 二、Swagger-hack工具  
### 简介：自动化爬取并自动测试所有swagger接口  
  
https://github.com/jayus0821/swagger-hack书签：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLIjyH242pQHodTDFxp67mRrhB7WNfKyFlJhWxR7kibK2DHcaUwFgakdQ/640?wx_fmt=png "")  
  
             
  
直接使用这个工具进行扫描，扫描完成后目录下会有一个swagger.csv文档，我们可以在里面找信息泄露的接口  
  
python3 swagger  
-  
hack2  
.  
0  
.  
py   
-  
u ip地址  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLTb4NwXVZlPEG1GKyvw64PjR0MPDsGPzHWsic8AK59ymjRciaEmxyjPYg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLhXrbdpianPsdUc5TbbyOgc5adBKkLkBXibUNBB0DMkRwAY9QmWIib079g/640?wx_fmt=png "")  
  
             
  
然后可以在里面找泄露的接口信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLUFwv2eU3pA5EuR1ewAKLZblHuUAJJpEdja3jiceicpwezWFu8ib4W2oDg/640?wx_fmt=png "")  
  
             
  
/actuator目录接口下面有非常多的接口信息泄露，什么env、log日志信息、heapdump信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLXg8AH69bJLHhCYAG2D2Q7dia3w1bmNgUg9yjOZyymicRuH35icZeqlKMg/640?wx_fmt=png "")  
  
  
  
**0x5 Spring-Boot接口信息泄露**  
  
  
###   
  
从上面分析的Swagger接口泄露来看，师傅们是不是可以看到在分析Swagger的时候常常碰到Spring-Boot的经典报错页面，然后再通过接口进行拼接，发现也存在很多的api接口敏感信息泄露。  
  
所以下面我再给师傅们分享下下面常见的Spring-Boot泄露的接口以及利用接口找到敏感信息扩大rank值 的方法  
  
/actuator            
  
查看有哪些 Actuator端点是开放的。           
  
              
  
/actuator/auditevent            
  
auditevents端点提供有关应用程序审计事件的信息。           
  
              
  
/actuator/beans            
  
beans端点提供有关应用程序 bean 的信息。           
  
              
  
/actuator/conditions            
  
conditions端点提供有关配置和自动配置类条件评估的信息。           
  
              
  
/actuator/configprops            
  
configprops端点提供有关应用程序@ConfigurationPropertiesbean的信息。           
  
              
  
/actuator/env             
  
查看全部环境属性，可以看到 SpringBoot 载入哪些 properties，以及 properties 的值（会自动用*替换 key、password、secret 等关键字的 properties 的值）。           
  
              
  
/actuator/flyway            
  
flyway端点提供有关 Flyway 执行的数据库迁移的信息。           
  
              
  
/actuator/health             
  
端点提供有关应用程序运行状况的health详细信息。           
  
              
  
/actuator/heapdump            
  
heapdump端点提供来自应用程序 JVM 的堆转储。(通过分析查看/env端点被*号替换到数据的具体值。)            
  
              
  
/actuator/httptrace            
  
httptrace端点提供有关 HTTP 请求-响应交换的信息。（包括用户HTTP请求的Cookie数据，会造成Cookie泄露等）。           
  
              
  
/actuator/info          info端点提供有关应用程序的一般信息。  
            
  
             
  
/actuator接口下面经常会有信息泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhL4LPkFOShfJ3cBB1pq2McQaPJkWoOQ54mrdd6iaaFzg9CnA9BniaQrsNw/640?wx_fmt=png "")  
  
  
/actuator/info泄露版本信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLN7GVU7nbj4Qf34EWic7kNZbEcOuFRibKbZbnR4YB21RPfHWWTtu4sl2w/640?wx_fmt=png "")  
  
  
/actuator/env目录账号密码泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLxM2ic4cIQcfJEWACg21dyRk2hibeLtvgnic6DicAeKS8OicNKK1x6GAhphg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLHO7wJsdibWBuMa8Q3saQXPsjs2Bapj87LoU3cLsx7gxf5dgW5g4eOKA/640?wx_fmt=png "")  
  
             
  
访问/actuator/loggers获取服务器的日志级别  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhLCyXBrTTCy7CRO0dV9asy9GsjwA3Xkg2MemO6icrvjKfVicKibzQacDJtQ/640?wx_fmt=png "")  
  
  
访问/heapdump或者/actuator/heapdump  
  
Heap Dump也叫堆转储文件，是一个Java进程在某个时间点上的内存快照  
    
  
其中可能会含有敏感数据，如数据库的密码明文等  
  
直接访问路径会返回一个GZip压缩的JVM堆dump，其中是jvm heap信息。下载的heapdump文件大小通常在 50M—500M 之间，有时候也可能会大于 2G  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU3kWic8KA2TXYm9AFM8rzhL0ufbpxux9x5JZhGLAUeWX3BI12s1v8CmzbSibibtyiaTnic5jKW0KLvGsg/640?wx_fmt=png "")  
  
             
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x6 内部圈子详情介绍**  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
神农安全团队创建的知识星球一直从未涨价，永久价格40  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPc1EozoB3Ot6GeEWkmvp7qAb2T5kW3pRnaDNgXbdxVPAH9xTNWcTEK9STgibiasOdg3guEibtPa1kQ/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满350人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
****  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyM1H14EvZYIgHzRfpmhyIQuP2zhzRAmuRANnna1jSIzhwgI5MusUrkA/640?wx_fmt=png&from=appmsg "")  
  
****  
    
```
```  
  
  
