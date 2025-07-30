#  若依系统 | SQL注入漏洞+druid框架漏洞   
原创 神农Sec  神农Sec   2025-04-26 01:02  
  
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
**若依系统渗透测试**  
### 漏洞一：SQL注入漏洞  
  
都是POST请求方式  
  
**注入点一：：**  
在/system/role/list接口的params[dataScope]参数  
  
**POC如下：**  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FL90IMcwGkKPOicsZibh8g5qYyar555prjqN3TynWdxUBMicSsO7QOQ8vQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**注入点二：**  
/system/dept/edit    ancestors参数存在SQL漏洞  
  
RuoYi  v4.6版本  
  
**POC 如下：**  
```
```  
  
  
其中最简单的测试方式就是直接把url以及cookie值拿到若依工具去检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FGUgITCXM1ZtwQxpGFJxOu2pz52BPkUcKq6oRTCIVCByFpgXYGduTNQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里需要注意的是这个小饼干插件，新版本的若依系统的cookie值是Admin-Token值且是JWT编码的，右边的是老版本的，就是jsessionid值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5F3AhYCS9ycsA34MWEY3NXYic2UNRRDia8rLyKvU9AkXhOTE2rwzFJbQ3g/640?wx_fmt=png&from=appmsg "")  
###   
### 漏洞二：druid页面渗透  
  
可以看到bp数据包里面有很多的/prod-api接口，其实看若依系统多的师傅们都这到这个接口就是若依框架的常见的一个关键字接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FKCDThGKiaPalKWL1OOmIpyV85uIv6Qicd0KHJAWEVIuDzicfJr1MsbGHw/640?wx_fmt=png&from=appmsg "")  
  
  
**druid常见访问路径：**  
```
```  
  
  
直接访问这个常用的路径，直接爆出来了druid的登录后台的页面，这样我们就是可以尝试使用弱口令登录，或者通过bp抓包然后进行账号密码爆破，账号一般是admin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FUiaElfCZZWCaQyLbcxd1Be1jhrLlbQxrxmXQ3fdPwu5G4z7Wakr17nw/640?wx_fmt=png&from=appmsg "")  
  
  
下面就直接利用弱口令登录成功了，然后后面就可以尝试打下druid的nday漏洞了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FJ5WL3Amt4FdwEW7aJ4Re0e9IlaPaoJwibUS1iabDG9JGNdGmuUKJ05ag/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到在URL监控里面泄露了很多的敏感信息接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FSEWibtY3aO1YwrPNibo5xb7K2YjezToYZPN75lXNTXgCqAnDicIKHRH6w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5Fg9te9T7drPciakg2d6TBQVPXsB6EObzZCU5onW4UdZ7JyP0XpmBZfuQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后还可以使用swagger插件进行信息泄露的利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUC10GsvKBwRWhZg09RpU5FdyKZVRGzbHcfwj8aj7eoFiaHYviayqyyLqRBwcwjTfpkypblxvdTOjcA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVdr1LG2hibEwnyTTwkbfiamGAFG7vo1UjRY04jHtSPOOXOOyb4dC0M7icXxPBvTVm3JicRZ5ncECp63A/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
