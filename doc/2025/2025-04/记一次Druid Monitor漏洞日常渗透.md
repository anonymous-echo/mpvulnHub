#  记一次Druid Monitor漏洞日常渗透   
原创 神农Sec  神农Sec   2025-04-22 01:00  
  
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
**重点知识点**  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**渗透测试**  
  
### fofa检索druid漏洞  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYPhtAmD4eD5gqttBOicxrIYrNPydwCiaRmhKK6CpIwRXvV8yz8eWBBciaQ/640?wx_fmt=png&from=appmsg "")  
  
  
这个登录界面就是Druid登录认证页面，我看着十分熟悉，要是经常打VulnHub靶场的师傅应该在VulnHub靶场里面是老朋友了，第一次搞Druid的cms框架还是VulnHub靶场上的，当时就是直接弱口令admin:123456进去的。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYeFBsCiaIw0KnlzEhiaRG9DjSlzNibiaRora7ng8Bw7ZGqbGnOdsVgLWuUQ/640?wx_fmt=png&from=appmsg "")  
  
  
这次我找到的这个Druid框架网站也不例外，也是直接admin:123456登录进去了  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYUEjqm9K7IyUSXGN8whjLol6eZNDqV1aWer71ibUTVUGvVF1I0tZOz1w/640?wx_fmt=png&from=appmsg "")  
  
  
其实像对于Druid框架熟悉的话别的功能点的信息泄露没什么利用的价值，主要就是开头讲的URI  
**监控、Session监控、Spring监控**  
这三个功能点  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYU2syIkbCia91DgdvecuCIRfS1ZdwYkRm4zDejGZhBupLA1Eh1MvfhOA/640?wx_fmt=png&from=appmsg "")  
  
  
1、首先我们可以点击URL监控进行查看  
  
可以看到下面显示了很多的URL，其中就有网站的版本信息，还有/actuator目录，这个目录熟悉的师傅们就知道这个是spring boot全家桶的一个常见的接口信息泄露的一个目录  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYibjh8GKfJR2QXALuajfZqMasvtHjziaxJxLNbfbehpHOBTwe1jABcKEA/640?wx_fmt=png&from=appmsg "")  
  
  
直接这样请求，这里报错，那么下面我们尝试使用bp抓包，然后更改下请求方式  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYRUBZf6uOZiaFohr0XOaaxoa7H1fTav5Cic0tqricS3yqcGoKCzojYoahA/640?wx_fmt=png&from=appmsg "")  
  
但还是没有什么信息回显出来  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY1AnBjSrcdQFzfpgUFAMQPVIicXyV2mmP0iaLRGeMaCcHVP7z2ws8Vc5g/640?wx_fmt=png&from=appmsg "")  
  
  
/actuator目录，我们可以看到下面暴露出来了好几个接口，感兴趣的师傅们可以尝试下swagger接口泄露，使用swagger插件进行测试下  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY9c2iaRUT1zIovRgRI4vgdH3ADibl7LdPxoQo99182ouZXMBRE9aD3w1Q/640?wx_fmt=png&from=appmsg "")  
  
  
2、我们接下来点击这个session监控的位置，可以看到下面有两个session值，那么我们就可以想一下了，有session值，那么我们不就可以尝试下未授权访问嘛，直接先保存这两个session值，然后再利用   
**/druid/login.html**  
接口进行测试爆破session值，然后看看能不能直接利用session值登录的  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYRIFBhjQQOOUNEHTcHQTflYZ7mgguPNhEia0RcgECkLJiaxlJUNmaHJ9w/640?wx_fmt=png&from=appmsg "")  
  
  
这里直接抓登录页面的数据包，然后利用bp爆破（思路，因为要是session泄露特别多）这里泄露的少，其实也可以手测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYMG06PC91b3c5PhspjtMobXNk5g4vbaAxOsL8hfGXQAUlr35gEVTh4A/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到session值爆破成功了，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYnJW2tHt05YYWfsibeL2A7c03VqYibYKhgszibStGRY8SHXJH6nHmy1Kpw/640?wx_fmt=png&from=appmsg "")  
  
  
然后拿到爆破成功的session值，去下载一个  
**小饼干插件EditThisCookie**  
，使用这个小饼干插件  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY8tLBeWSc2HVicJicaFibdRWibBBdAS09PlB8nRccQlAqQQzQ2Im8hxib3Gg/640?wx_fmt=png&from=appmsg "")  
  
  
在开始的登录页面，需要我们输入账号密码，且没有session key值，那么我们下面直接把刚才爆破成功的session值替换上去，然后再选上下面的勾，然后再刷新，就可以直接免密码登录了  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYV4nFWuFStC82TCluerKicGbAG0oPLiapz5Adyzibn8iaENbemTPJtlKW4g/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY8Kot5hIib7hnhBhfOKjQIsjcgzvYvtPRZW9Vqfwx9p3DpP50vxRRzuQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**内部圈子详情介绍**  
  
  
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
  
  
