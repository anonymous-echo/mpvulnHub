#  渗透测试 | 实战swagger框架漏洞   
原创 神农Sec  神农Sec   2025-04-24 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 加密的Swagger**  
  
首先一般大家分享Swagger泄露接口敏感信息，一般都是在Swagger-UI这个插件里面分析  
  
我这里以Google商店的插件为例，然后火狐和eg浏览器的话也差不多都是这个绿色的小图标  
  
https://chromewebstore.google.com/detail/liacakmdhalagfjlfdofigfoiocghoej?hl=zh  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKtsbpAYaehdibM6Qyeketo1iaCbJu8sySGka4tFEL5l5iapS6EWXawkU6A/640?wx_fmt=png&from=appmsg "")  
  
然后可以看下我下面通过FOFA找到的一个Swagger接口泄露的一个站点，然后利用这个插件去打开  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKJ3dyBib2zYBOzsGy2AKFpfCJsJlnZGOO58n3zQbukBCRG6TiaaSn5kGA/640?wx_fmt=png&from=appmsg "")  
  
但是这个插件可以看到  
Authorize  
关键字，这个你可以点击下，这个标识就是表示这个泄露的 接口需要我们输入加密的信息，要是按照正常的直接访问这个泄露的api接口，然后看敏感信息就不可行了，下面我来带大家使用一个Swagger脚本工具来给师傅们演示下  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKGResACy77kl0Lt7WdqA91EicsSDjiciaabGPOlWzv8KqoRnXsuG7dZx9g/640?wx_fmt=png&from=appmsg "")  
  
首先我们先访问下这个泄露的swagger/v1/swagger.json文件目录  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK7hFBIMh88FkYMKU0Hs5l7DV1uyboUGk3xIjAnrCyDobwqjgecw4ITw/640?wx_fmt=png&from=appmsg "")  
  
然后可以在json文件看到里面有非常多的api接口泄露，但是太多了很多都是没有权限访问的，要是挨个拼接不太现实，那么下面我就给师傅们介绍下面下面的这款swagger工具  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKYzPQytiaboGnYZ4ticohnzcgntWNcSzJl1p0QogiaAcVDFNeb1DmM8nqQ/640?wx_fmt=png&from=appmsg "")  
### 0x2 swagger-hack工具  
  
简介：自动化爬取并自动测试所有swagger接口  
  
https://github.com/jayus0821/swagger-hack  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK4rqRiaa5SsgoUzbuqQ3HHt1WKQNv39icLAibichNaPqLfiaD67y85805bqQ/640?wx_fmt=png&from=appmsg "")  
  
直接使用这个工具进行扫描，扫描完成后目录下会有一个swagger.csv文档，我们可以在里面找信息泄露的接口  
```
```  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK9bgibuqBWkHicqDfhV4D21d4df59nYw2s8ibDw7fL9ibqkmibq6RuoxPwfA/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKPSaAvoKwBv9ANyRIpNich8jiaFr6XkuN7k46hsksetI0nmdq1icKMoy4Q/640?wx_fmt=png&from=appmsg "")  
  
然后可以在里面找泄露的接口信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKzthYQKjR9WhnAzkxHaEEZb1krqX6b90wfxIfydCTVLD2xDtPZsKy5Q/640?wx_fmt=png&from=appmsg "")  
  
/actuator目录接口下面有非常多的接口信息泄露，什么env、log日志信息、heapdump信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKRIBJqAUh1lfjnOU48KE7Nos3TCT9nYXh7vp7nYabNlJdDLEWe2u0pg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 Spring-Boot接口信息泄露**  
  
  
从上面分析的Swagger接口泄露来看，师傅们是不是可以看到在分析Swagger的时候常常碰到Spring-Boot的经典报错页面，然后再通过接口进行拼接，发现也存在很多的api接口敏感信息泄露。  
  
所以下面我再给师傅们分享下下面常见的Spring-Boot泄露的接口以及利用接口找到敏感信息扩大rank值 的方法  
```
```  
  
  
/actuator接口下面经常会有信息泄露  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKHRwCibKaWqtfqcW5uiasaW9p8w9icVZA03IbsTia9h1SkLOkSDpubgnkow/640?wx_fmt=png&from=appmsg "")  
  
  
/actuator/info泄露版本信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK0QcW42lAafmx1Y6oGSPudIIJia4RwjnRnNRLcRYTbxZs3sc6oQKpX3w/640?wx_fmt=png&from=appmsg "")  
  
  
/actuator/env目录账号密码泄露  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK0ewstvnRibwnOFHfBwhNIRJlINV1lGtxJYHpCW8cDalO66xAibFM0Ykw/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK9Ixvs907N9mwCbNeic82lW3DoseIpK0VSrgcmkib1YiabicibicT9y3W3hCA/640?wx_fmt=png&from=appmsg "")  
  
  
访问/actuator/loggers获取服务器的日志级别  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK0yzzaVN73abOiaVw3oUmG2tAK1ANQLNicMWTCgzTDrnNAf8CWYzedp0w/640?wx_fmt=png&from=appmsg "")  
  
****  
**访问/heapdump或者/actuator/heapdump**  
  
Heap Dump也叫堆转储文件，是一个Java进程在某个时间点上的内存快照  
  
其中可能会含有敏感数据，如数据库的密码明文等  
  
直接访问路径会返回一个GZip压缩的JVM堆dump，其中是jvm heap信息。下载的heapdump文件大小通常在 50M—500M 之间，有时候也可能会大于 2G  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKMQu5HvWcSKewqolkmcTLVND6zlKk90wP4h4qYJPUN1elghRksmtRhw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 Swagger 未授权访问地址存在以下默认路径**  
  
下面的路径就是常见的Swagger 未授权访问泄露路径，师傅们可以通过bp抓包，然后再通过bp对该接口路径进行爆破，但是我一般是先使用曾哥的一款spring-boot扫描工具去做一个自动化扫描，但是有部分网站可能对那个工具会拒绝请求，所以还是可以尝试使用bp爆破  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 内部圈子详情介绍**  
  
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
  
星球现价 ￥40元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于400人 40元/年  
  
星球人数少于600人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWeuMPBRkPema0jlwibpxWEDJSWyZvtpib5n7NJiaM1lqSeSYeiaKmFrRj7wfHjEWkgTH2zZHiaxKsG2MQ/640?wx_fmt=png&from=appmsg "")  
  
  
欢迎加入星球一起交流，券后价仅40元！！！ 即将满600人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYZYx1WKX3mtsCeiblhQKkonJr1BXj5mlefZE8U2ibUnyibG9ZvbibNMC8Rg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
  
  
  
