#  【src】SRC漏洞挖掘｜优惠券叠加思路分享   
F1sh0rk  神农Sec   2025-05-25 01:02  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：  
F1sh0rk  
  
文章来源：  
https://www.freebuf.com/articles/vuls/410979.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
在漏洞挖掘中，相信许多人都遇到过优惠券， 优惠券想必所有人都知道是什么意思，简单聊一下，就是商家为了使商品更加促销推出的类如“满25-13”等等，在下单商品到达特定金额时可以获得一定的优惠力度，简单来说就是用了优惠券可以比直接买便宜很多。优惠券在很多购物平台都非常常见，红包也是属于优惠券的一种，那当我们对SRC的资产进行挖掘的时候，碰到优惠券如何进行挖掘呢？我先简单的说一下常见的利用优惠券的几种挖掘思路。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 挖掘思路**  
### 1.并发-优惠券  
  
        在很多购物小程序或很多购物平台中，可以领取类似图下的优惠券，这里我就随便找了几张截图，思路就是当我们是新用户的时候，通常都有很多新用户才能领取的大额优惠券，比如“10-8”之类的，都是只能领取一次，后面就无法找到领取的链接了或者是无法领取了，这时候我们就可以想如果我们能大量获取这些大额的优惠券，那岂不是就突破了商家限制的只能领取一张的限制吗？这时候我们就可以抓包抓取领取优惠券这个数据包，将他进行并发，成功的话将可以无限领取优惠券，达到高危！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWVAWLpb42WO7jCUdA6xeyrEojunvbIY0vdmnhtEtMz2uBmZUoxkSyCP9vtRdsuoYlHeQgkUYJRIA/640?wx_fmt=png&from=appmsg "")  
  
### 2.领取隐藏优惠券  
  
  尝试无法并发领取优惠券的时候，却发现数据包中有对应优惠券的参数，通常逻辑是你点击领取优惠券或者输入优惠券的优惠券号就给你兑换对应号码的优惠券，不同的数字号码对应的优惠券额度也不同，但是有时候出于某种原因，商家在节假日活动会上架一些大额的优惠券，只能前几个人领取，兑换按钮就灰色了无法领取了，但是如果我们遇到非常简单的比如四位数字的优惠券id我们就可以尝试进行爆破，有时候会有意外收获！！可能会领取到商家隐藏的优惠券（可能是等下次活动又重新上架的优惠券），通常会有大额的优惠券！！就已经有了一定的危害级别，想提高危害级别，比如再创多几个账户等等，后面的就不多说啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWVAWLpb42WO7jCUdA6xeyrO9WY9WkrKibTAxQxruEraALnWnBUJlJ6vHyjQnpa0uCQ4lf52ZtN5Yw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWVAWLpb42WO7jCUdA6xeyryUbJFAmOt41oDZekXRd1hia8RibZIibIfwPU0tgFY3E3uMfJfeCbcibsEg/640?wx_fmt=png&from=appmsg "")  
  
### 3.越权使用优惠券  
  
  如果经常使用优惠券的兄弟们会发现，每次优惠券的特定id号都是不一样的，就算是同一个额度或类型的优惠券，每个账户领取的优惠券在数据包中id都是不一样的，这时候我们可以想到：我们自己账户1没有优惠券，但我们还是想用优惠券，这时候我们就可以尝试找一个有优惠券的账号2，进行抓包，然后获取到优惠券的id号，在账户1中进行购买的时候，发现在数据包中优惠券的参数是类似："couponCode":"null"或者在购买的数据包里的json数据没有优惠券的参数，我们可以自己尝试加优惠券的参数然后将值替换成我们抓到账号2的优惠券id号，最后成功在支付页面金额达到优惠！并且可能会发现账号2的优惠券并没有被使用掉，可能是开发只是简单的处理对最后金额=单价-优惠券，这样子危害性就非常大！那么我们还可以有另一个想法，如果优惠券的id号有规律，那我们岂不是可以爆破比如最后四位，我们只要查看返回包的金额是否变化即可知道是否有优惠券，只不过这样子的话工作量会非常大不知道是否会有大额优惠。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWVAWLpb42WO7jCUdA6xeyrGb7MVyxXtib7GVOAKK8fpNKickVaBkf0euQCSVxV7fxDEibImtW2ibkBcg/640?wx_fmt=png&from=appmsg "")  
  
补充:因为有可能无法获取到优惠券的id号，所以很多时候都是拿两个账号来进行测试，但是也不是说所有情况都无法获取到，可以在领取优惠券的页面查看数据包，查js等等都是有可能的，或者在社交平台别人看发的订单截图中寻找都是有可能的，方法有许多思维不能被限制住！！  
  
### 4.优惠券叠加  
  
  这个类型就非常特别，当我们点外卖的时候，可以发现有商家红包和通用红包，并且是可以达到叠加的作用，在其他的平台也有不同类型的优惠券，比如找到两个不同类型的优惠券对应的参数，我们就可以尝试将大额优惠券尝试叠加使用两次，达到更大的优惠！！这是因为开发没有将优惠券进行划分，很多开发为了偷懒都会用最省事的处理方式，但是不一定复杂的处理就没有漏洞，有时候往往越复杂步骤越多就越难保证其中的其中一步不会出现逻辑上的错误，往往一步错步步错。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 总结**  
  
  本次的分享是我最近挖掘中总是遇到优惠券，这篇文章我只是对优惠券的利用思路进行了简单的介绍，并没有结合支付漏洞来讲，我想写的是单纯优惠券的测试思路，最主要的是只是一时兴起写的哈哈，希望读者们可以学到自己想要的东西，思路不是唯一，漏洞挖掘的时候要多多思考发散思维，往往别人想不到你却能想到的时候就已经超越了大部分的人，漏洞就会随你而来，希望这篇文章可以起到一个抛砖引玉的作用！加油各位师傅们！本人也是一个小菜鸟，轻点喷。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 内部圈子详情介绍**  
  
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
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQrFWcBesgFeibmAaLTXbl25YKcjTuT0F7X8qBLgI7JaOjU1DxsgxfyicbBDibicKwvIhjia1Jm33NQaA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUz6lqTKv8vQ4xvhXgcCeRvRDlGwaA5B6ibFjVQKQJuhgMN3DQFKodJEfTbFTJQibCGJUv9jpiaEL3dg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
