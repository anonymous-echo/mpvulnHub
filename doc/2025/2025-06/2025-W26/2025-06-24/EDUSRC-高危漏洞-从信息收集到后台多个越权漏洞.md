> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492076&idx=1&sn=c161a60e6baa6ab0e5c752b83c22a82c

#  EDUSRC-高危漏洞-从信息收集到后台多个越权漏洞  
原创 花师傅  神农Sec   2025-06-24 04:26  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
  
**从信息收集到后台多个越权漏洞**  
  
  
## 0x1 前言  
  
哈咯，师傅们！好久没有在平台更新文章了，最近想着把之前EDUSRC的修复的一个高危漏洞给师傅们分享下，然后这里也不希望师傅们进行一些非法测试，有时间可以去多试试挖，然后最近这两年比较火的小程序漏洞建议师傅们看看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXVibn6GLacmLGDDxvBpUaw8kRs3mJ1YiaN9ibebfEEU0mhmZ0B3U3gPV4Q/640?wx_fmt=png&from=appmsg "")  
  
这个漏洞主要是前期的一个账号密码收集，因为有了账号密码能够进入后台，后台的很多功能点我们才可以进行测试，特别是后台的越权漏洞。然后关于账号密码的收集，具体可以看我之前在社区平台写的 一些文章（大佬勿喷）。  
  
## 0x2 信息收集  
### 一、猜测注册接口  
  
这里说的信息收集，我下面会结合之前在社区平台分享的文章一起来说，因为之前的写的蛮详细了，就不再多说了。关于进行EDUSRC的测试，很多师傅问我要是没有账号密码怎么办，web前台登陆不进去是不是就寄寄了呢？  
  
  
我想说的不是，其实你账号密码是可以通过信息收集去拿到的，但是要是没有拿到其实问题也不是很大，因为学校的系统很多，站点不止这一个，有些系统，都是可以注册，但是有些系统可能说注册接口被隐藏了，举个例子，前段时间大火的若依系统，其实是有注册接口的，但是很多都会被开发给隐藏了，这个时候可以进行接口拼接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX4t4h8TtNseDpKdU3gSCLLljfCGPaSTDJ4meX5A3l1JCLIkFk98lIQQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过在 url 中直接添加/register 或者在 js 中进行寻找”register“ 成功进入到注册地点。  

```
/register
/register.php
/register.jsp
/register.html
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXhv180kX2bl2NBalXibiavNA8ptIsCqiazcmYnLUaMLMbos58VYNNYg0BA/640?wx_fmt=png&from=appmsg "")  
  
  
还有就是很多人会遗忘的js代码，建议师傅们没有思路了可以看看这里，有些开发也会把账号密码写在js里面，方便自己查看，然后这里也建议师傅们可以去学习下JS代码审计、加解密之类的，各种断点、调试操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXnJ2b53pXrjbWLo5OBh8nQibZMphwzNcbP3BECIWArN1PCIO4oXSuVqw/640?wx_fmt=png&from=appmsg "")  
###   
### 二、各种信息收集打法  
  
这篇文章主要是就是分享通过奖学金名单泄露学号，然后去看那个系统登陆页面，有没有那种账号密码提示，有些默认账号是学号，密码都是一样的初始化，比如：学号@abc等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXzSe8vhtf3hW5NyFFBKFofMCG9kvjJaBJTUIFrUrAFic47uXW6zAEEzA/640?wx_fmt=png&from=appmsg "")  
  
  
师傅们可以看到，像国家奖学金的公告都是之间公开的信息，像师傅们平常不知道怎么进行检索学号时，不妨可以使用这个非常简单，且很好用的方法进行一个学号检索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXuO5vSG1sWtibNBn4XP16X3F0QWD3xSYYHBoxDQ2vqWZA60NdAcicJ6kg/640?wx_fmt=png&from=appmsg "")  
  
  
通过一些Google语法或者一些操作，可以找到网上泄露的敏感信心，比如：xh、sfz、xm、sjh等  
  
这里给师傅们附上一些好用的Google语法  

```
1.site:域名 intext:管理|后 台|登陆|用户名|密码|验证码|系统|帐号|manage|admin|login|system

2.site:域名 inurl:login|admin|manage|manager|admin_login|login_admin|system

3.site:域名 intext:&#34;手册&#34;

4.site:域名 intext:&#34;忘记密码&#34;

5.site:域名 intext:&#34;工号&#34;

6.site:域名 intext:&#34;优秀员工&#34;

7.site:域名 intext:&#34;身份证号码&#34;

8.site:域名 intext:&#34;手机号&#34;
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXoGcG8PKz04t9jP4ianbJ5AN5lDctWbl9Kz2Iiara9Aiajs9Dibwribtqibcw/640?wx_fmt=png&from=appmsg "")  
  
  
很多种挖掘EDUSRC时的一些信息收集方法，建议小白师傅可以多看看。  
  
当然你也可以加入班群，表白墙等容易泄露信息的地方。（如果你语雀玩的好，你可以通过语雀去查找重要信息）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXzmc9R0fKtARj4IvsZpNck3YxOEgoLxU704E2OpZticOickNhmOPdGCZA/640?wx_fmt=png&from=appmsg "")  
  
  
包括使用抖音平台，可以去检索某某大学录取通知书之类的信息，很容易可以找到该学校的一些用户信息，比如常见的学号和身份证号，都是可以收集的，然后对于某些大学的门户网站，是不是可以进行渗透一波了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX9F8FqgWSkTsn2XRrQJPfr2z7Ks7QbKT1eCNcedoYG8eAMvtY38fvPQ/640?wx_fmt=png&from=appmsg "")  
## 0x3 渗透测试思路  
### 一、弱口令泄露敏感信息漏洞  
  
这里我就是先按照上面的思路进行收集，找找泄露的账号密码、学号、身份证信息等，然后通过猜测密码进行弱口令登陆，找到系统登陆后台，可以多尝试几个系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXsvbwiadiaPaxBDiaicghYicCG1AE94flHIiaF7A8uj1uKIkkibp0M3CTSrFbQ/640?wx_fmt=png&from=appmsg "")  
  
且这次我是收集到一个学校管理员老师的账号，进行登陆的，账号是教职工号，密码是123456  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXaBe3CvmyNuEJ2EPrzJnD1YdWwazfcOc9jpuicDcrgyj9fA0ic9UjyOmA/640?wx_fmt=png&from=appmsg "")  
  
这个老师的账号权限比较高，可以看到，可以进行一些修改和删除的操作，且学校老师的账号密码都可以重置，这样的弱口令如果要是在众测或者企业src中，都有好几千的赏金，所以有时候别瞧不起弱口令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXnPWwgibpsaBbSjcOo2hL4RK3wiaNCOAcFr565Ql5oXmcV44qpqiatJ9TQ/640?wx_fmt=png&from=appmsg "")  
### 二、越权漏洞  
  
这里直接创建两个老师的账号（都是普通老师账号，看不到别的老师的信息），然后和我这个账号一起测试下越权，也就是企业src常用的A、B账号测试越权漏洞的手法了  
  
这里我直接先测试的是重置密码的接口，尝试看看有没有越权操作，登陆A老师账号，点击重置，再抓包，保存这个接口和后面的参数值  

```
/personnelManagement/TeacherManagement/xxxx
```

  
然后再登陆B账号，进行上面的操作，再把后面的参数修改成A账号的，然后返回包的数据包显示修改成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXrjqwvpbibE7kRLq2FtElnzVoTnzETuKcXJfZHJQibxurWoxK6icJeTT9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXR2C7Zc9qSIDW1dynsN3Bib4cR6SzE0ZokXHqOJIDYiadXzicCjrsia4x8A/640?wx_fmt=png&from=appmsg "")  
  
尝试使用修改后的密码去登陆A账号，显示登陆成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX0EciawnmCU1z6KQpCLAGiaOFdT3FnYenEXNZOYSBSurtS72bUkGeY02Q/640?wx_fmt=png&from=appmsg "")  
  
到这里这个越权就给大家分享完了，其实这个系统后台有好几个功能点是存在越权漏洞的，但是操作思路都差不多，也就不全写上去了，就拿最严重的修改密码的越权给师傅们演示下即可。  
  
## 0x4 总结  
  
到这里这篇文章就给师傅们分享完了，其实后面的操作不难，主要是前期的一个信息收集，特别是对于后台登陆系统，能够找到账号密码进去测试，特别是敏感信息和敏感操作多的（众测和企业src这样的弱口令赏金蛮多），然后建议新手师傅们要是web搞不来，可以去测试下小程序，然后有突破再转web端测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXRocjD06cajB3AWeMFJ0HoPa3Ekoicd3wfJibgJOLXgSwz9pUVlnqp0wA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoMttntYglBBjtL5tbEeyjQxaibiablKM26xoGibI1Rc1QgOrQbDvia1suXA/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX7AicI3tqibhLhQcrwZ2PH9XygJXxdlKwt3lqOqYlCJUE8IBHw43Ox2zQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
