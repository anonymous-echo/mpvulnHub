> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492929&idx=1&sn=7efca7e920c15972ade5f16cedbece86

#  【攻防演练】从JS泄露到内网主机失陷  
0x1eeA  神农Sec   2025-07-11 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：0x1eeA  
  
文章来源：https://www.freebuf.com/articles/defense/417182.html  
  
**0x1 JS泄露未授权接口**  
  
  
  
主办方直接给了一张资产表,表上有所有目标的ip和域名  
  
讲真的,这种主办方真的感动死,比那种只给公司名的懂事儿多了,我雷某人很欣慰  
  
锁定xx政府大数据平台,直接把ip扔hunter  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBDMSXfEX6pnBicvjMnXcwgdMXeMgCOQcYYCR6A5EnbLFnexKibWxCcYhw/640?wx_fmt=png&from=appmsg "")  
  
哦哟,只有8条数据,但是能访问到的基本都是登录页面  
  
点开xx大数据管理平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibB8PIUSlaNn1zkURhancAUT58adHTG9lSCjibPzLq7Z6r2xSKeRfxkpVw/640?wx_fmt=png&from=appmsg "")  
  
直接爆破用户名密码,以失败告终  
  
拿出神器Findsomething  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBVZMIl1YuBQoicCtUnyXicWwDb6QoibbhibUMke02iaK3KnkfYuQZ3lLic5mQ/640?wx_fmt=png&from=appmsg "")  
  
光锁定在最上面这个接口: **xxx****/xxx.aspx?id=**  
  
直接访问该接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBK6kQaaYAxYCfy5xl4MTBIicr2V6KDHicWM4oze4aIZ8ajDTRoMCNcZVQ/640?wx_fmt=png&from=appmsg "")  
  
哟呵,看起来有点东西,尝试爆破纯数字id值,但是爆破了整整两个半小时毫无收获  
  
重新查看**Findsomething**  
按ctrl点这个位置,看看泄露这个接口的js文件是啥样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibB5qbHgCYRA0CCupIAZZEmVicM62ZtccO3y2K1x5jq8qAcQ3wknMdMHiaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBIgVff6tpEUVCECYKW35vYc3iaZYBO8ZXbjJU2HqVwNp4kBQVAiaOg2FA/640?wx_fmt=png&from=appmsg "")  
  
咦? 看来Findsomething提取出来的接口并不全,挨个访问接口,最终找到两个接口有东西  
  
涉及公民数据,直接厚码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBicUs95maTK6OgaggCgx4SeCmzAmTasfIQqBQDgYImtmx3UXeJWSw5ZA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBDew63gX7fsoHDkstibgTUtKcxtJGzianr3m0CWN35ywfrQFkVl6aTWEA/640?wx_fmt=png&from=appmsg "")  
  
ok数据分到手了  
  
  
**0x2 未授权接口获取权限**  
  
  
  
先查看下接口有什么功能  
  
这个加号是查看数据更详细的信息,会做一个查询功能,直接抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBHGprkGtz0lG1GGrMdJxuwg1dMtjjIUicgpsN7bXS1iaNziaSBJKKdbdBA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBf1Oe2WCRKzSiaBicnMIjCsVphDu93ewIHVOic2nMkxsggvrrBxfF44HUQ/640?wx_fmt=png&from=appmsg "")  
  
分别加一个单引号,两个单引号看看  
  
一个单引号报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBItfKYu7iaR1N5actMFbYOjcggicOykwvBLWD2F9WgX7k52o61Zr7PqYA/640?wx_fmt=png&from=appmsg "")  
  
两个单引号正常查询  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBVAGiaGR2xUmiaxAwjLQajgRzUAelAP8tkGYLCpYTbHDEQvTWGEyJpVKQ/640?wx_fmt=png&from=appmsg "")  
  
这个地方存在注入,直接丢slqmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBVEkU2mb10JcDfOrPmkX3HxOD1oVx5RJdYSErM15FmD9Wg7tUia8Sz7g/640?wx_fmt=png&from=appmsg "")  
  
非常的丝滑,直接写马连接蚁剑  
  
翻找数据库配置文件  
  
一眼就是他  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBK2MeyXTWCkdtIFTQ7lV01sy6X7I3eosSOs2TKnTvW8vKiaibCH2hibFfQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBHfhkI4q8alicMERydmjibFmoGicicAjWibjJgIeZ24JticAF9qzcd7NDm9bQ/640?wx_fmt=png&from=appmsg "")  
  
直接隧道代理出来,连接数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBRpJ63lthqWHqcJF2xcrqTsd5JCuczbXImkckDD4lKPFy7jsWB2TXNA/640?wx_fmt=png&from=appmsg "")  
  
有些兄弟要疑惑了,都拿下shell了还看数据库干嘛?  
  
数据分,旁站web应用管理权限分都是分啊好兄弟  
  
最终也是成功拿到几十万公民数据和旁站服务的管理权限(同一个数据库,直接读取数据库里管理员的密码)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBbFXK5ibzrE4tEVUtrf7y3LNR9cr0s9ibVAZRJpiaHZSUZBCP7jmnBxJOA/640?wx_fmt=png&from=appmsg "")  
  
可惜是云服务器没内网,最后也是拿下几千分  
  
  
**0x3 总结**  
  
  

```
1.通过JS发现泄露了几个未授权接口地址
2.通过未授权接口获取公民数据,吃到数据分
3.通过未授权接口的功能抓到SQL注入,并通过注入获取服务器权限
4.翻找服务器数据库配置信息,连接数据库
5.数据库中找到旁站管理员密码吃到旁站web应用权限分和公民数据分﻿
```

  
  
**0x4 内部小圈子详情介绍**  
  
  
  
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
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXYSHg6L72Acqz6CcxdTTR72ic6bOSuMibJkYgVvibYfvrIwxESqR5TL8qrZhUQicKTUGeOic4VMibicF6Mw/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXYSHg6L72Acqz6CcxdTTR7Fotibpcs8XRn33xic5cMHaRIVPPBX9pJynCUQ7II1kBnsQCfzwXSToMw/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
