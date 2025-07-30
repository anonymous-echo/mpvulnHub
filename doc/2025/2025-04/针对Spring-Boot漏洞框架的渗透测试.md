#  针对Spring-Boot漏洞框架的渗透测试   
原创 神农Sec  神农Sec   2025-04-29 01:03  
  
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
**0x1 Spring-Boot漏洞框架信息收集**  
### 一、通过icon图标进行识别  
  
可以直接利用icon图标，可以直接找一个这样的网站，然后利用FOFA检索  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKDmCibZ31aniceQKC6xIBkib27CM8VwQbezxOiceGYpibFNhaYNDlFGpfywQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以搜索到八十万条左右的资产数据，说明Spring Boot框架是应用广泛哈哈~  
  
（其中还有很多服务更改了默认的ico图标，所以这个语法找不到）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKaU3tRibKxwBv6RpBsX5JLybLoeVMLdiaMIzmbyRnKVnk22CMUT71PK0g/640?wx_fmt=png&from=appmsg "")  
###   
### 二、通过网页内容进行识别  
  
通过网页内容那就是要判断这个网页的特征了，师傅们可以看下这个经典的Spring-Boot报错页面  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKoRibW45rf6l98J07SPibO1DYbBF3uDQoK7g3lWuzPqctOW7nwms9Ff5A/640?wx_fmt=png&from=appmsg "")  
  
  
我们可以通过网页内容进行识别，因为在Spring-Boot报错页面中都存  
**Whitelabel Error Page**  
 关键字，所以就可以直接检索这个  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKMiasicWuKv35qIjdic0T8I1THNdWOWib1YBKt1yUaX44qTiaxwvcBJkUalQ/640?wx_fmt=png&from=appmsg "")  
  
  
FOFA语句：  
```
```  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKzFvXFUA0VSw7v6MYnzPWCGbiaV7XX05icv6yZSSPk8oqsygP8w2UWF5g/640?wx_fmt=png&from=appmsg "")  
  
可以看到里面的icon数量非常多，  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK4Innq7f9bqOFkvPcv32SpCOKz5tWCvqicy8eI0BYic0rPa4CSPTtHFyg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 渗透测试**  
### spring-boot接口敏感信息泄露  
  
首先我们对于Spring-Boot漏洞，我们可以使用Spring-Boot-Scan漏洞扫描工具  
  
https://github.com/AabyssZG/SpringBoot-Scan  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKduC7Iw6AqdsAFzhHFlKleBkl3ib1SiaHtNvFYialJLhTaHIz4qia7umdJA/640?wx_fmt=png&from=appmsg "")  
  
  
工具使用语法：  
```
```  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKEfE4UFZhTgdLSXMCQYvoQjljkriaXRHdOgY78oQLWoH2jrgL3wB7U7Q/640?wx_fmt=png&from=appmsg "")  
  
  
后来就可以直接在urlout.txt文件里面找到扫描存在的接口，后面我们就可以直接丢到浏览器去访问下，看看有什么敏感信息泄露  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK5jN7ibWicGzbRVIBqtqLicMiaYgqp0hDZ8BBZKRxIhfDo0MkWAs18sHppA/640?wx_fmt=png&from=appmsg "")  
  
要是使用这个spring-boot漏洞扫描工具扫描，然后禁止扫描，或者没有扫到，那么师傅们就可以尝试下手工去拼接接口目录  
```
```  
  
  
/actuator接口下面经常会有信息泄露  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKHRwCibKaWqtfqcW5uiasaW9p8w9icVZA03IbsTia9h1SkLOkSDpubgnkow/640?wx_fmt=png&from=appmsg "")  
  
  
/actuator/info泄露版本信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKm0TmgsShFlzd5LJe13h8R0vyLv7Ek9Mzeibg7WoM7ricjYc3ibQibl7aDg/640?wx_fmt=png&from=appmsg "")  
  
  
/actuator/env目录账号密码泄露  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK0ewstvnRibwnOFHfBwhNIRJlINV1lGtxJYHpCW8cDalO66xAibFM0Ykw/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK9Ixvs907N9mwCbNeic82lW3DoseIpK0VSrgcmkib1YiabicibicT9y3W3hCA/640?wx_fmt=png&from=appmsg "")  
  
  
访问/actuator/loggers获取服务器的日志级别  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK83x6WRPu3fpHuNf2G2s7f4YFa9sZC5bIruibkNAXjN3LDua10JPPNkw/640?wx_fmt=png&from=appmsg "")  
  
****  
**访问/heapdump或者/actuator/heapdump**  
  
Heap Dump也叫堆转储文件，是一个Java进程在某个时间点上的内存快照  
  
其中可能会含有敏感数据，如数据库的密码明文等  
  
直接访问路径会返回一个GZip压缩的JVM堆dump，其中是jvm heap信息。下载的heapdump文件大小通常在 50M—500M 之间，有时候也可能会大于 2G  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKlg9CIeHvSSialsibtibib89V4fCCY6MRDSt6icWuaHpr8FQNP1ux8GMoicfg/640?wx_fmt=png&from=appmsg "")  
  
  
可以使用heapdump_tool工具进行查看  
  
https://github.com/wyzxxz/heapdump_tool  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKiaQvzLhbtupRgC6yCoGWJDibQfczZ0o2DBVX8pS6s7aaYZnoxhr9jIdQ/640?wx_fmt=png&from=appmsg "")  
  
  
命令如下，然后对其中的数据进行内容检索，寻找敏感信息  
```
```  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKsCXhTQAbviaySaV2f9kM51wCfhrNywQR81SMENibhCC6Rt3oSpibtt3LA/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKdTPBYq9NMh2ojFlK4yGbkXIibtZSIZoITZvWY3yjjogYXLysgR2Am9g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 内部圈子详情介绍**  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVdr1LG2hibEwnyTTwkbfiamGAFG7vo1UjRY04jHtSPOOXOOyb4dC0M7icXxPBvTVm3JicRZ5ncECp63A/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
