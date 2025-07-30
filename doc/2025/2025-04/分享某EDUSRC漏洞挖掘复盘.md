#  分享某EDUSRC漏洞挖掘复盘   
原创 神农Sec  神农Sec   2025-04-21 01:02  
  
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
**0x1 信息收集**  
  
首先我们先确定下目标资产，某某大学站点。  
  
然后再利用信息收集的手法去收集一下该学校的一些站点信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYB5IscVBGNWFrx8tkekNSO9QcIM352hVjZh4GKzZa52R27sFvO6Yv7w/640?wx_fmt=png&from=appmsg "")  
  
确定目标之后就是对于该学校的信息收集，主要收集：xh、sfz、gh、电话号码等信息，因为信息收集是渗透的核心，如果信息收集几分钟，那么你挖洞就是几个星期或者几个月都不会出货，如果信息收集够多，那么挖洞就会很快出货。  
#### 浅谈  
  
对于高校，一般可以利用谷歌语法：filetype:xls  site:xxx.edu  xh  gh  sfz这些去收集我们所需要的东西，也可以去当地的教育局官网查看有没有敏感信息泄露，比如贫困生补助，奖学金补助等等文件很容易泄露重要信息的，再者就是在学校官网查看看有没有信息泄露，一般有公示文件，这些文件也特别容易泄露信息。  
  
此次突破就是该学校的官网泄露，造成此次的渗透事件，  
所以高校在发文时一定要做好脱敏处理我们可以看到该学校的站点xxxx.edu.cn/xxx/info/xx.html页面  
(可以看出是主站泄露了同学的sfz，然后我们再利用该信息，反查xh，这样就可以利用sfz和学号的弱口令进入webvpn，然后开始挖掘漏洞）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYbicicDQmSZ3stv4RJ35JdGDkAv42wn79uAPic8nViak0ibVt8oAnoEyt0Uw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 渗透测试**  
  
信息收集搞好后，就可以开始渗透之旅了，利用收集好的账号和sfz对官网一站式服务大厅进行爆破（高校网络安全意识差，肯定存在弱口令的），找到门户服务网站此时一定要注意门户网站的帮助说明这些，因为这里会告诉你默认密码的情况：  
  
这里我主动去找找这个学校的门户网站，包括其实师傅们还可以去检索统一身份认证、学生登录后台、教师登录后台等关键字，然后去测一测（根据我们开始收集到的信息）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYKbbQZZAbmptDto5ibPqUqdb2akmZIqQ6ibVdyGI1ZYnaawtTEVPUYsXQ/640?wx_fmt=png&from=appmsg "")  
  
这里咱们二话不多说，直接访问这个门户站点，然后去里面找到了下面的这个统一身份认证登录平台  
  
不知道师傅们这里是否有点惊喜，看到下面的使用说明，是不是会有一点想点一点测试一下，看看里面的使用说明会泄露什么信息呢？  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYHUEvgRqXRJNWbFNIDaua9vLSCRNdEoKurDYCMISyQLx1zb1BuJtwrg/640?wx_fmt=png&from=appmsg "")  
  
当我们点开帮助说明的时候，几乎就可以露出笑容了，很清楚的写出来了初始密码；  
  
而且还很清楚的告诉你比如身份证号是多少，然后初始密码是多少的，像这样的特别是在新生八九月分开学的时候，你去测试一般的大学站点，很多都会给你一个pdf文档，然后告诉你怎么进行登录学生管理后台。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYiaZCX2vJ8jmvbicye2K8skVlx1bXOIgkiaPthHdwhawzMWCguEicFtEWQQ/640?wx_fmt=png&from=appmsg "")  
  
这里给师傅们看看之前我找的一个企业公司的系统使用手册，然后也是通过信息收集找到了相关的账号密码信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYicBLdSia4lc7WJyq7Os5I0nuqU84rLicXAperHuAbQLJhR35COr7Ft8IQ/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYTXeVUETHDu3sJEzkl4Y1oArkLSt1GtWbdeEETvQk4x2KDVdj8KJdGA/640?wx_fmt=png&from=appmsg "")  
####   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 横向渗透**  
  
我们信息收集的也很顺利，其中很多账号都是默认口令，于是开始对系统进行挨个测试，然后扩大危害，提高我们提交的rank值，可以在edu打包提交一波  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYuxocfhWOiad9Pvpciad0H7K5VlgAObjcU8HHycUVJm1ibd5h6HpicE0z6w/640?wx_fmt=png&from=appmsg "")  
  
然后开始对每一个系统都开始进行测试，当然，进去后我最喜欢的系统一般是人事系统，学生管理系统等等，这个师傅们应该知道吧，主要是这方面的安全系数相对底。  
  
所以我第一个打的就是人事系统了，可以继续猜测，这个学校没有任何安全意识，于是这个人事系统也可以猜测大多数为弱口令，加上刚才收集的老师和学生账号开始测试：直接抓包爆破，果然在我猜测之中，该系统全体师生都是弱口令：admin666/admin888之类的  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYs8FjjiaO1W36ZJTsNGkFBdX3DPaYWic6TffkEPzQg9YWiawTdmTuLOk5w/640?wx_fmt=png&from=appmsg "")  
####   
#### 0x4 任意用户密码重置  
  
此系统还有一个有趣的地方就是任意密码重置，可以直接将管理员密码重置  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYwmDuibE0ugs7FC9mBjPuML0rujaG4twaYNqEiaIWibWJCiaV0vzu3ibPaxw/640?wx_fmt=png&from=appmsg "")  
  
这里的操作也很简单，师傅们可以直接看到左边的操作下面的重置密码的功能点，然后直接使用bp抓包，然后尝试重置admin超级管理员账户即可  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYDjhic4AvvmaDiaI60ZWKVBicHiaMZB0gz3WpLOliccbhnFvtxbGxv3xQLfg/640?wx_fmt=png&from=appmsg "")  
  
后面就可以尝试登录admin超级管理员的账户权限，高权限的账户看到的全校敏感的信息是不是更加多了呢。这里我就不给师傅们演示了，点到即可，不给这个学校的站点做破坏（害怕被搞，哈哈哈）  
#### 0x5 大量敏感信息泄露  
  
当进入这个系统后，就可以宣判这个学校结束了（当然这时候才是开始）全校师生的个人的信息全部都泄露了出来，这些泄露的敏感信息都可以汇总下，然后看看有多少条，一般edusrc收的敏感信息泄露，收公民三要素：姓名、手机号、身份证信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYXETZrmgCfpt0jesonFYib7zM7xEzIsYjGqMDopsMuy33E9icQ2Cwm1yA/640?wx_fmt=png&from=appmsg "")  
  
泄露多的都可以单独提交edu，泄露的信息少的话，可以和前面的几个漏洞一起提交，然后打包在一起，扩大rank值。  
  
此系统因为弱口令泄露了很多信息，其余逻辑都测试和一些不重要的xss我就不写了，然后进行学工系统的测试。  
  
然后这里我点击别的功能点去看学生的功能点的时候，看到了这个学生请假功能，点击该学校的教务系统，然后可以看到该系统的请假页面中，有一个附件上传的功能点。  
  
这里像在学校的管理后台，应该很少有对这些上次的文件进行一个白名单过滤，很多学校都是前端验证，我之前也是碰到过完全没有任何过滤的上传功能点，然后直接上传jsp/php木马，然后拿到一次getshell的。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYiaBWmyShibpia5DT6p4kGhiash7elqSMqkVwjHtp9oXM7vgLOiaLgSayZBA/640?wx_fmt=png&from=appmsg "")  
  
这里我上传的php没有被拦截，直接打了一波phpinfo上去，懂的师傅都知道，这里都是学校的管理后台，也不去上传什么木马了，到时候直接提交phpinfo页面上去，证明下这个文件上传的功能点存在getshell即可。  
  
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
  
  
  
