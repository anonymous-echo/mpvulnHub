> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492582&idx=1&sn=72585c466075f048fcdd42667e4209a0

#  【车企SRC渗透】某国产新势力车企SRC挖掘小记  
kid_H4k  神农Sec   2025-07-06 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：kid_H4k  
  
文章来源：https://www.freebuf.com/articles/web/418100.html  
  
  
**某国产新势力车企SRC挖掘小记**  
  
## 前言：  
  
其实没想去挖
```
src
```

  
的，可是好兄弟叫我一起，那就一起挖挖看，反正没啥事儿做，提升提升思路（其实我真的是fw）。那我们就开始吧，首先信息收集还是很重要的。  
## 前期信息收集：  
  
给大家介绍一款工具，我觉得蛮好用的，原始不自己添加其他东西的前提也不错（反正我没添加，都用自带的，目前来说够用）。 密探 :https://github.com/kkbo8005/mitan  
  
ps：这里说个小故事，当时我还不知道这个工具是谁写的，我不认识这个作者，居然在某次线下论坛的时候阴差阳错的见过一次面，其实当时见面的时候我也不知道他是这个密探的作者。是我后面有他vx好友的时候看朋友圈才知道的。其实这以上都不重要，重要的时候我以为这哥们很年轻，没想到是个**“大叔”**  
，他也没想到我**“小学毕业”**  
，互相都惊讶着对方的外表四目相对，爱情的火花…………（付费，付费，超级付费节目 o.O）  
  
![1734589906_6763bdd2a6c9e2c031061.png!small?1734589908656](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHsh0DwH9FK0cMuKIKtYwzrM6m56gP2SJEM1OWdyZ0yKkswkpRMvVcmA/640?wx_fmt=jpeg&from=appmsg "")  
  
扫描
```
1k
```

  
个子域名还是很快的，这几个我都大概试了一下没啥东西，个人觉得还是不要一直收集，有点东西就先试一试，一天时间就那么一点，信息收集方法方式五花八门的，到头来一整天过去了还在停留在信息收集部分，所以我个人建议就是有点东西就先试一试，万一就有洞了呢，这样的话有正向的信息输出就不至于感觉一整天没有东西出有总挫败感，挖洞就不那么快乐和开心啦。人嘛，不至于一天都板着脸搁这儿收集东西吧，总有点添头分泌点多巴胺让自己爽爽。  
  
最后是在鹰图找到个子域名进去，进入后如下图。（ps：文章是后面写的，当时的截图没保存。写文章的时候再去找子域名鹰图里面就剩下两个子域名啦，无语子+人门）  
  
![1734589941_6763bdf53cb052fc1019e.png!small?1734589941635](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHSkIJLJ6InmSqLscPZcLcia8aD5WqpbGNMySgeltAgOFYZzPQ1TnIvtQ/640?wx_fmt=jpeg&from=appmsg "")  
## 思路  
  
**现在思考一下。**  
  
**如果你要打这个站点那么你会怎么测试这个站点？**  
  
**如果你是开发你将会怎么设置防备？**  
  
**现在看到这个界面我能迅速给出答案的测试点是：**  
1. 登陆界面的sql注入  
  
1. 能不能注册账号，如果可以注册账号那么进入后有没有什么功能点  
  
1. 游客登陆进去后能不能出现越权  
  
1. 帮助文档进去后是不是可能出现信息泄漏  
  
1. 忘记密码这个功能点是不是能越权更改其他人的密码  
  
现在大概确定了这五个方向，我相信各位彦祖看到这个登陆界面应该能迅速的想到测试的方法一定比我多。既然想到了那就去做，万一就成了呢，就好比你喜欢的女神你不表白那么成功的几率是0，如果你表白了，你就有成功的几率了。一个是没几率一个是有几率，不管这个几率是多少，我就问你有没有嘛。大胆的尝试就完了（别搞崩了）  
## 测试  
  
先来个sql注入打个样  
  
老规矩抓个包先  
  
![1734589988_6763be240e0dc44878182.png!small?1734589988627](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHl90OfbFlRWzMZ38AVTAz4RKVLl8tr5DiaSk0nmMIMb8wcAciaahFWSPw/640?wx_fmt=jpeg&from=appmsg "")  
  
嘿嘿，不出所料的没有  
  
  
然后我点击了忘记密码  
  
![1734590013_6763be3dbe9829c0c4f66.png!small?1734590014269](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHu2oYdVqbib72Ypqsf7YiaRctYIicXEK9FnP8wOVKWuicHvcJicoFA9VtTlA/640?wx_fmt=jpeg&from=appmsg "")  
  
ok～这个时候我眼睛一亮，我敲，输入账号后就是验证身份，那我能瞎几把乱输吗。万一我输入的是确实有这个账号的然后到验证身份怎么办。管他的先试再说  
  
![1734590045_6763be5da62c7a38f6be4.png!small?1734590046138](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHfsib3LW2jQxjL9VovqU6GQrJm2MdyFYX6m1oPdVIH6WBxaE1GRBDiasQ/640?wx_fmt=jpeg&from=appmsg "")  
  
看来瞎几把输8行。但是捏，作为测试嘛，admin、root这种类似的账号名怎么能不测呢  
  
![1734590083_6763be83809dfdd9bf3e2.png!small?1734590084384](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHwJAEm5EpiaQmibscBibo3ALia9d3OZv4rqf2lNsU6vicmtP0ibGsel7avfQA/640?wx_fmt=jpeg&from=appmsg "")  
  
root也不行，再试一试admin  
  
![1734590113_6763bea12629c434d4d63.png!small?1734590113668](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHtVfa4Fibow3rDZkKk3frce5vA4nqD0H7jJ0KHHkAz5pVUaicSp3OQApg/640?wx_fmt=jpeg&from=appmsg "")  
  
耶～居然成了，这个时候我看了一下burp里面的http 历史  
  
![1734590146_6763bec2bf9c65a94cbb5.png!small?1734590148386](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHSQ8LEukiak0nQroF0OS7a4BILqia0Mmhf9ciccIXQwCvWcHM1M9YBcHeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
刚刚我们输入的
```
admin
```

  
居然拼接在
```
url
```

  
中，那就
```
FUZZ
```

  
一下  
  
（ps：可能有人就要问了，为什么我的
```
http history
```

  
里面为什么是黄色，那就不得不提到三个大字：HaE ，好用、爱用、喜欢用，工具地址：https://github.com/gh0stkey/HaE）  
  
在这里也给大家推荐一个
```
Fuzz
```

  
的字典，同样来自
```
Hae
```

  
工具的作者
```
Key
```

  
佬的，地址：https://github.com/gh0stkey/Web-Fuzzing-Box  
  
确实很齐全：  
  
![1734590305_6763bf619cca5a74bf80b.png!small?1734590306321](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxH4alOibk7HxbDib3kmF1Iia9hxXaTu5S5Zg0Ts240KCm8zOSlN1JLWJtoA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
经过一顿爆破后确实爆出了一些，如下图：  
  
![1734590340_6763bf840e3027ca03045.png!small?1734590341831](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHFNA8E0p5ZYDUhiaMefdpDtdm4MOmOjhGgyxlYctLnjMzBtV6mZA7UibQ/640?wx_fmt=jpeg&from=appmsg "")  
  
难道就这样简单挖一个就结束了？请看VCR，现在我们换一个测试账号。账号名为：bin  
  
![1734590368_6763bfa05836dd0361cb0.png!small?1734590369168](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHdSz7OVzibVSXNCf5zOcUcP6QEADvCiag4bvgxRSCMoDNJTo3vDZiaG5EA/640?wx_fmt=jpeg&from=appmsg "")  
  
这里有个获取验证码，一眼丁针，邮箱轰炸  
  
抓包重放  
  
![1734590409_6763bfc9c9b9d75aec4d7.png!small?1734590411052](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHsibauUibvqd6oUDXc7icw0V75IsYnibmYEew5U73Oib6N46NyAMJaGhFJJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1734590438_6763bfe6782cb462722cc.png!small?1734590440349](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHsQMicGeVqiaLSeqFicO3Mnqg5WHKLMLAZyC1gSwt1apeu06ZW4d02oPqw/640?wx_fmt=jpeg&from=appmsg "")  
  
还别说真行  
  
请注意刚刚请求的
```
url
```

  
中  

```
/api/rest/base/verifyCode/forgetPwd/xxxx?verifyId=bin&verifyType=EMAIL
```

  

```
verifyID
```

  
这个参数跟着的就是我前面输入的账号。那么我更换其他账号行不行。最后的测试结果是可以的，前提是这个账号是已经存在的。图我就不放了，太长了。  
## 结语  
  
漏洞难度不大，这里仅仅是说一下简单的思路过程，对于老手来说这种漏洞出得很快。挖掘src过程中信息收集固然重要，思路也一样重要，每一个都得去测，验证每一个想法。祝大家都嘎嘎出洞。  
  
  
**内部小圈子详情介绍**  
  
  
  
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
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU0bsia0ju14OCUfVMSnyJJX4SAHwM2uxfzyQ99oMpk5ib5iavqd6nQicUWV26KKYYvm9e9AkIXKBYFBg/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWVED9b2pQcIicYSpecBvsgjoKVqQwoTMrP4ib6NKzia8NLsUo6Z1ykmp2rpHPyNNgKeoKWpzOrgZQ0Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
