#  针对Nacos漏洞猎杀的各种骚姿势   
原创 神农Sec  神农Sec   2025-04-23 01:03  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠券）。  
#   
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 相关漏洞资产收集**  
  
像比如师傅们不知道怎么找**nacos相关漏洞**  
的话，其实师傅们就可以直接使用空间检索引擎进行检索，比如常用的就是使用这个**icon**  
图标去找相关漏洞，因为很多nacos框架网站并不一定进行了魔改，所以可以使用icon图标进行资产收集，是最简单的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK3T3T9QViaJiaD3nUu9eiak4GvmcgSlPROlcapr50iboI2rEXwck8whtM4w/640?wx_fmt=png&from=appmsg "")  
  
  
然后就可以使用空间引擎，下面我使用鹰图给师傅们演示下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKyEZxKT238JCHllnUicc1kicI3xx19bQpAMpjvWk5HWicdndR4qsNcMTicw/640?wx_fmt=png&from=appmsg "")  
  
  
还有一种方法就是使用FOFA空间语法进行检索相关资产信息  
```
FOFA语句:app="nacos" && port="8848"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKJrib76ibqzHPksRfgoOZ76HCCicEmfrnaOPtMxhzmicQgSNUf5GOswE5jQ/640?wx_fmt=png&from=appmsg "")  
  
  
下面可以看到icon图标，除了开始我们上面的一种，下面还有好几个，  
  
然后看下面的独立IP数量，有上万个，数量很多，那么我们就可以使用自动化扫描工具了，就比如使用我们上面的NacosExploitGUI自动化工具进行批量漏洞匹配  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK5mBydBp7s3Yddch4KibibrMRo1nFQdwlgic4rcqgDpd98G7fpTqFMvb5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKstFZOmaCdkubXNvVe1XKCLZbtp8Oz47gNbC5v9JR4n063UF8fDBvRQ/640?wx_fmt=png&from=appmsg "")  
  
然后确定完漏洞以后，就可以直接进行挨个测试了，比如弱口令进去的，那么就可以进行然后再后台进行一个漏洞测试，扩大危害。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 User-Agent权限绕过（CVE-2021-29441）**  
  
  
**漏洞描述:**  
该漏洞发生在nacos在进行认证授权操作时，会判断请求的user-agent是否为”Nacos-Server”，如果是的话则不进行任何认证。开发者原意是用来处理一些服务端对服务端的请求。但是由于配置的过于简单，并且将协商好的user-agent设置为Nacos-Server，直接硬编码在了代码里，导致了漏洞的出现。  
  
**漏洞影响版本:**  
Nacos <= 2.0.0-ALPHA.1  
  
直接访问下面的目录，可以未授权查看到账号密码  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK6h38WWPbFMcdEmyGniaYFRf8wdjrcZCwPc69crr0ibhN2RwTc1PuZbJQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看下里面的账号密码，很多情况下账号密码都是这个暴露出来的username  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKp1guhM87RCS4xLibGqeuyAziaDzdebXxaSgXTR3mSyc3LQsoJJHNfMOQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKnRoBQy76ad0U6XCny9ZrpYs4aUv6PRZrZuwXRmmItrBaqsibGUfykOA/640?wx_fmt=png&from=appmsg "")  
  
  
添加用户，访问下面的接口  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKAmo7Y0G4Lh0QQ20muJF82OcT0THZ7nvbgicccWEp4j9iaic5NGL8mObFQ/640?wx_fmt=png&from=appmsg "")  
  
```


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKuDnerY5icdk0h80qR1chEkUV22NliaE0RnbdYrOIThb3wB6l2KproyMQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后还可以使用我前面介绍的工具哈，直接就可以进行创建用户和删除用户的操作，十分简单便捷，适用于大批量IP渗透测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKDmpRB9H2Hicgq4iaRG9mCwU0ppLkc5GnMlZOJtVibRQTpvSHIshFm21GQ/640?wx_fmt=png&from=appmsg "")  
### 0x3 默认弱口令漏洞  
  
nacos框架的默认弱口令直接使用工具刚才检索出来了，直接常用的nacos：nacos登录成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKtaIgI6o03JbmEl91hHpn7Mv9PWU0sicGgxicPnnvBYcagjySNvoRLx2A/640?wx_fmt=png&from=appmsg "")  
### 0x4 阿里云主机泄露Access Key  
  
然后你可以直接在配置列表中的详情里面查看网站的配置信息，然后去挨个找，因为里面都是云安全的一些环境的配置，里面经常会泄露一些云安全的信息key值等，都是可以进行利用的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKiarlMGPT7L2bxjTCmENBCibINc0VibuYO397ibRkuOI13q6QNHHelticGiaw/640?wx_fmt=png&from=appmsg "")  
  
  
比如说里面找到OSS储存桶相关的，然后访问下，尝试打个OSS存储桶漏洞，感兴趣的师傅们可以根据我的这个思路进行测试下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKXWb5sVJpclUOXQVnNffng9sbKoggt7UdxvIOjNWECB5Wlmg1QMCSUg/640?wx_fmt=png&from=appmsg "")  
  
  
后来我在rokid-ar-security-platform-biz-prod.yml  
配置详情里面找到了这个东西，这个也是OSS储存桶相关的漏洞，下面的url可以访问下，然后要是有回显的话，然后尝试使用下面的access-key和secret-key进行密钥登录  
```
  endpoint: xxxxxxxxxxxxxxx
  access-key: xxxxxxxxxxxxxxxxxxxxxxxx
  secret-key: xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK9GX8y1XASFVz7lmZZeKHLrP1k3iaXV1TWZULeUl8e5uARSicsBms8mjg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这里我直接就登录成功了，且里面都是云空间里面的存储东西，下面可以看到里面的日志信息等  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKQAkdic2wGefO1wZLAuCsqndiaWWOkS6rb2Uo1ibx6p2wkDOko8yHUW1fA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKAqnLDkhZqictEUA2cUia2jtNmpCVGOicciapEqBgNIPSgic01JmqLLvAemQ/640?wx_fmt=png&from=appmsg "")  
  
  
有一些他里面你要是没有找到那个访问的url或者访问不了禁止访问登录连接，那么师傅们可以尝试下下面的这个工具oss-browser  
，就是专门来连接OSS的  
  
https://github.com/aliyun/oss-browser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKyNOAr4nK4ZThNqwfrLZD6x2IsPxL1YFna4wrXXZeGsA8iaKWu1Gu8MQ/640?wx_fmt=png&from=appmsg "")  
  
  
直接输入泄露的access-key值，直接使用OSS连接工具就可以直接连接成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKa3y7YgqSlydav0PDSOSIPSXQibJQT5icY7gYmuvItnMQOC0XvUicIwfew/640?wx_fmt=png&from=appmsg "")  
  
  
包括也会使用阿里云的下面的这个连接工具：**aliyun-accesskey-Tools**  
  
https://github.com/mrknow001/aliyun-accesskey-Tools  
  
  
**参考文章如下：**  
  
https://www.freebuf.com/articles/web/255717.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKWCt99OYuXwbRPqLyChcoKBld57Zhj62icibcc35GYd5b9jgTk9NapWtg/640?wx_fmt=png&from=appmsg "")  
  
  
要是运气好的话们，也就是我们上面的那个直接找到了下面的OSS阿里云主机登录的后台地址，且允许我们直接拿泄露Access Key值进行登录连接，直接可以看到该阿里云服务器云上的所有信息了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKibDZPmXwQUxe3tcYZa9G1qJsBGAmO0EoqjYzssnd7899fCpAACInzAg/640?wx_fmt=png&from=appmsg "")  
### 0x5 token.secret.key默认配置(QVD-2023-6271)  
  
利用刚才的图形化nacos自动化漏洞扫描工具扫出来的一个token.secret.key默认配置(QVD-2023-6271)漏洞，下面就来打下这个洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKUyW8UU1BvT4XSibH9rWia4de3VsjjsgtxNDpc14rslwCiaatxqSTvRrHQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用nacos默认key可进行jwt构造  
  
nacos默认key（token.secret.key值的位置在conf下的application.properties）  
```
```  
  
SecretKey012345678901234567890123456789012345678901234567890123456789  
利用该key构造JWT，可以直接进入后台。 在：  
https://jwt.io/  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK2tgOXiakEUicHak8V8ej1sNFPSPtGzMmWjhD7dCYenlFFxX7zflYvVfg/640?wx_fmt=png&from=appmsg "null")  
  
```
```  
  
我们先直接随便输入一个账号密码，然后看看登录失败的返回包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsK1bapCoHHKmshkzFWo7XIbMcqQFxPd35TeNs7pVWLRzeWibbqaEYVtAg/640?wx_fmt=png&from=appmsg "null")  
  
  
然后把下面的payload复制到数据包中，就可以成功了  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKuPeNDGdZrv3etdp8K1QgP45ibeUWjslvTkmciafLwoMnLpscdUlGwCkA/640?wx_fmt=png&from=appmsg "null")  
  
  
然后再把返回包复制，再利用刚才的网站登录抓包，然后修改返回包，然后放包，就可以直接登录到网站后台了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKwmmnUO6MXAyDfm4UTCNRS5WV5yDgc3UkJnB5VxrfdhdlfXiblda8YTg/640?wx_fmt=png&from=appmsg "null")  
### 0x6 spring-boot漏洞  
  
对于Spring-Boot  
漏洞，我们可以使用Spring-Boot-Scan漏洞扫描工具  
  
https://github.com/AabyssZG/SpringBoot-Scan  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKduC7Iw6AqdsAFzhHFlKleBkl3ib1SiaHtNvFYialJLhTaHIz4qia7umdJA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKl5ibcHOBCPzmCIyzlE6rjb1ibe9aHYwyPUWiccT2LWMN9Y1zpp7iazrAcA/640?wx_fmt=png&from=appmsg "null")  
  
然后进入后台里面有spring-boot相关源代码，都是可以进行分析的，感兴趣的十分可以尝试下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX58VXjXLg4WSNEpFcUIjsKnYtzmzib3qn8IUO3mdhIB8BVdZksSll5qfGOcnj9B1TZT1J055pnfWA/640?wx_fmt=png&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x7 内部圈子详情介绍**  
  
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
  
