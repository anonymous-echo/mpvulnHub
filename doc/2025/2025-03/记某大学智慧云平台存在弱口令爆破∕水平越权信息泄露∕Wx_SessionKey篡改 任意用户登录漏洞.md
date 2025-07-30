#  记某大学智慧云平台存在弱口令爆破/水平越权信息泄露/Wx_SessionKey篡改 任意用户登录漏洞   
 sec0nd安全   2025-03-04 22:33  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
本篇文章是记录最近给一所大学做渗透测试时该学校存在的漏洞（目前已经修复）。我是先找该学校的微信小程序的资产，因为各位佬们也知道，微信小程序相对于web应用服务端来讲维护较少，所有漏洞存在多，好挖点。  
  
嘿嘿嘿，下面就来讲讲我是怎么从这个小程序端渗透到web应用端。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 知识点讲解**  
  
#### 微信小程序的session_key有什么用？  
  
官方文档说是用session_key来生成登录态，让前端每次请求的时候加上登录态来请求接口。  
**session_key 功能说明：**  
1. 微信客户端通过wx.getUserInfo()获取用户的信息  
  
1. 后台有时候也需要获取微信客户端的用户信息，因此，就需要利用session_key这个秘钥来从微信平台中获取  
  
1. 后台如果想要获取用户的信息，就一定要知道session_key，如果session_key 过期，就需要客户端完成一次登录的流程  
  
**图文参考：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB08PoymmnaP2GHHVBljXjWXFJavNb14eqLch6hDGjSxFciaaBJmHTQItQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 渗透测试**  
  
  
我是有目的性的针对这个大学的小程序进行渗透测试的，所以直接在微信小程序检索该大学，然后挨个进行测试，发现该学校有智慧云平台（这个我还是蛮感兴趣的，因为之前我挖到蛮多的这类平台的漏洞）瞬间就比较兴奋。  
#### 一、弱口令爆破  
  
直接进入该小程序，然后通过bp抓包，一般的思路就是拿到小程序的数据包，然后进行访问下该host，尝试下是否存在弱口令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0wiaGToF8IAU9q7QT0fxke844yueJakShDvWpEWic7I7ic7KhjBAhTerWw/640?wx_fmt=png&from=appmsg "")  
  
一访问该host，然后跳转网站也没，中间是这个动态，一看就是若依系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0PktAIhNwCpRcv0OWUE4ZsF7DTY9y7eSBIPATBv1Zoich1LdbbmpOusA/640?wx_fmt=png&from=appmsg "")  
  
看到若依，那么就得优先尝试下弱口令了  
```
```  
  
但是这个web端是需要使用手机号和密码进行登录的，所以平常使用的那两个弱口令也就没用了，但是经常碰若依系统的就知道，进入后台以后，里面一般会经常留有一个测试账号和测试手机号，可以给师傅们看看若依系统的后台用户管理界面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB01FibmZWTd9vCGcsIVD0ZAoNeu0M394vavbjAuPklEjXXib09e7hxVLsg/640?wx_fmt=png&from=appmsg "")  
  
可以看到该测试账号使用的手机号，都是很弱的也就是容易爆破的手机号。  
  
下面我们回到小程序端，然后可以看到这里存在用户登录的地方，且比webduan爆破更加方便，没用验证码什么东西。  
  
然后抓包，通过bp的爆破功能模块进行尝试爆破他的用户名，密码我们这里直接使用123456，因为这种学校网站存在这样的123456的弱口令很正常，目前要做的就是爆破用户名也就是手机号了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB07AN6mzycclYtLm0ujVIoZTkH06eibe4qBdCA70BcaU72aaMl6sBjQbQ/640?wx_fmt=png&from=appmsg "")  
  
下面是我自己准备的常用的测试手机号，然后导入bp中进行爆破。  
  
比如师傅们也是可以收集一些常用的测试手机号，有需要的可以私信我，可以给大家发一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0COXka9K5Gq1iconjc9icEibANWUddpcKskD0pEzusR8rZ4LibYxIZkoo7A/640?wx_fmt=png&from=appmsg "")  
  
可以看到00000000000:123456爆破成功了，且成功登录进了web页面端  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0ye6uhajv05bo9SjjHRbfXbZUFQiaa5Q7CZtmeg3YeK2IK2MLfcjkDGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0lGHkr0w8YmmXss7FZmfDaCXRrId6rXFQkaPOlrNh74DIbZEMWqhVXQ/640?wx_fmt=png&from=appmsg "")  
#### 二、越权漏洞  
  
在这里进行测试，发现**getteachers参数**  
，这个应该可有查到很多老师的信息的（这里就是查询的性王的老师信息）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0HnxDyD8gjyw3Q2U1bOHFd7RHHQF2SDl2YB925L7Gia8icw5AItZAxhHg/640?wx_fmt=png&from=appmsg "")  
  
  
这里也可以尝试删除下这个参数，就可以获取所有老师的信息了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0G3WlyciagNRzLjePsQialm7M5Cv49cEoAYqky2ayEeicOZj6Yg7oSe1Vw/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到我们开始爆破出来的测试账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0cH6gPSnI0ibDYF38hBZyiavp4FQyQCF7YlHSIYgGwuusWew8Vk1huibKA/640?wx_fmt=png&from=appmsg "")  
  
我们开始知道了账号就是手机号，那么我们目前获取到了那多的手机号，我们就可以尝试获取有权限的账户了  
  
尝试发现这个性王的老师，应该是学校管理员账号，可以看到全年级的考勤信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0c9XWGia61X7Riczic8ibqMLlTb3Fmot0r4aAG8ZCL5iawDKQ4ibyhsAetm4Q/640?wx_fmt=png&from=appmsg "")  
#### 三、Wx_SessionKey篡改 任意用户登录  
##### Wx_SessionKey_crypt工具下载链接：  
  
https://github.com/mrknow001/BurpAppletPentester  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0fHibFhSWEpaP6Qtc4JDCTlV6WqWa69ZJeQgXNJJ9nGVgJa8HxanTRDw/640?wx_fmt=png&from=appmsg "")  
  
  
收集该数据包中的SessionKey、iv以及加密字段三个部分，然后再利用Wx_SessionKey_crypt这个工具，我们就可以通过篡改手机号，从而可以任意用户登录危害漏洞。  
  
可以利用这个Wx_SessionKey_crypt工具，进行解密，可以看到确实是我自己的手机号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0UMuTOHrJcQrSlUPTzorzMPbMR6ntKOLljDYqoer1M4Bvm5SFsReVNw/640?wx_fmt=png&from=appmsg "")  
  
我这里前面进行信息收集到了好多个老师的手机号，一个17开头的朱老师的手机号开始尝试123456弱口令没有成功登录后台，  
  
那么现在尝试把Wx_SessionKey_crypt里面我的手机号改成17开头朱老师的手机号，然后再利用上面的工具进行加密，再替换上面bp里面的数据包，就可以成功登录了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0VOOtuDjYiabgjtibCTEBwxdokQjibqEvkobJkAOcAzY5Hbtv6yLL6evBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUuFEWX7AxlYefibGBKAPkB0y8yFf4Hefmk9iaYmZR3hree2ZguHbt0SrIk2nDQXibL2ICQcZhBxUkmA/640?wx_fmt=png&from=appmsg "")  
  
到目前为止，任意用户登录也就复现完毕了！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 总结**  
  
  
这次的渗透测试来讲还是很有收获的，特别是第三个Wx_SessionKey篡改 任意用户登录，大家可以去小程序尝试下，大家首先得找到SessionKey、iv以及加密字段三个部分，然后才可以利用这个工具进行篡改，然后任意用户登录。然后其次就是大家如果第一次挖漏洞还是渗透测试什么的，一定不要小瞧弱口令，因为只有登录进去了，里面后台的很多功能点你才有机会进行测试。  
  
最后希望这篇文章对漏洞挖掘和渗透测试师傅们有帮助！！！  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX30mOXFhyTaRBZcK1doDYSUgvLHstZSKdZzB4GeepEHrja02M95tqVXE0NMBuiciaVdxfEoiaHNAWUw/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满400人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
****  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyM1H14EvZYIgHzRfpmhyIQuP2zhzRAmuRANnna1jSIzhwgI5MusUrkA/640?wx_fmt=png&from=appmsg "")  
  
****  
    
```
```  
  
