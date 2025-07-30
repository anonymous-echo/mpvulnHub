#  JS漏洞挖掘｜分享使用FindSomething联动的挖掘思路   
原创 神农Sec  神农Sec   2025-05-10 01:01  
  
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
**0x1 前言**  
  
  
哈喽，师傅们！  
  
这次又来给师傅们分享我的文章心得了呦，这次是给师傅们分享下js未授权漏洞挖掘的一个小技巧的汇总，然后也是会给师傅们分享几个案例，带师傅们更加深刻的理解和看的懂这个js未授权，然后再带师傅们去挖这个漏洞，从怎么挖去带师傅们掌握这个js未授权。  
  
然后特别是给一些不会挖漏洞，然后针对于FindSomething插件工具的使用来做一个分享，让师傅们对呀FindSomething插件的使用更加娴熟，能够更好的利用这个插件，然后让师傅们挖出属于自己的第一个js未授权漏洞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65qVkyDBbRHlwAxoGPhfDdqgsNcW6nz0rC2krianq0C5Cj04Zpia7pVwFA/640?wx_fmt=other&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 js未授权简介**  
  
## 一、什么是未授权？  
  
首先理解什么是未授权漏洞  
  
 未授权字面上理解是未获得授权，对于正常的业务来说，有些功能点需要经过登录之后才能进行，那么如果我们通过一些绕过，无需登录也可以完成此类操作，那么便是未授权访问漏洞了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65jdNCe31uibialzs8bk6VBHMmk4hicmJ2wkmubichLb3iagQFl0DbA8b7yfQ/640?wx_fmt=png&from=appmsg "")  
###   
###   
### 二、常见的未授权访问漏洞  
  
**常见的未授权漏洞一般分为两种：**  
1. 组件类的，如js未授权、redis未授权、mongodb未授权等，也是比较常见的。对于此类漏洞，可以理解为不需要登录即可执行里面的功能，所以存在未授权漏洞。  
  
1. WEB层面的，如某某CMS未授权文件上传、未授权创建账号、findsomething接口拼接未授权访问敏感信息泄露等。因为可以绕过登录限制进行操作，所以存在未授权访问漏洞。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65oSot8PnHxPLRLECps9sj1JdQrOKRdQGpmcB23maD5EcGEnYK8yoIKw/640?wx_fmt=png&from=appmsg "")  
###   
### 三、浅谈  
  
未授权访问的挖掘不是针对所有网站，这只是一种思路，通过信息收集来实现登录绕过，从而达到未授权。正常来说可以通过抓包修改返回值也可以达到绕过，前提是不知道网站代码的判断情况下，可以尝试猜解返回值。如果网站后端认证做好了，是不会有该漏洞的。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 浅谈 js未授权挖掘技巧**  
  
###   
### 一、常规js未授权挖掘  
  
这里就要和师傅们分享下我之前在没有认真研究js未授权的时候，喜欢的一个针对js的一个测试手法。我相信很多师傅应该都是和我一样的思路，就是大家知道且都非常喜欢使用的一个插件findsomething。就是常见的使用findsomething小熊猫头插件打开，然后把里面的泄露的路径进行拼接使用，然后直接拿bp进行POST/GET方法都进行跑一遍，然后再看看有没有什么js路径拼接，然后导致的敏感信息泄露。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65E7zgzCGUoS7wXLVslFQkO0YHAUUZddh2kDibpkeOkyvbJIXbXpuZR9Q/640?wx_fmt=png&from=appmsg "")  
  
  
然后把插件泄露的js路径保存到一个txt文件夹里面  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65T0UHKuEqcW1UEgDyQa3TBtFfBkLUxW4AVdMRcRfhq7eR5Kx8zGb7Fg/640?wx_fmt=png&from=appmsg "")  
  
  
然后简单的进行GET/POST跑下  
  
然后跑完以后会发现，怎么还是没跑出什么东西来，然后就这样觉得这个js路径很安全，没有漏洞，直接下了  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65OfwPiagjDcBf3jzGVqqib7XjiaUIJjO0953Pa9sgFr4G1j4tfiaFxeyhQQ/640?wx_fmt=png&from=appmsg "")  
  
  
**Google插件FindSomething下载链接：**  
https://chromewebstore.google.com/detail/findsomething/kfhniponecokdefffkpagipffdefeldb  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65Nnfic9oqWLG44KdCr7eJNUFo2icLJsZt5Oenwia9fGYunvicrTqhm3t6KQ/640?wx_fmt=png&from=appmsg "")  
  
###   
### 二、使用findsomething插件工具的目的  
  
为了寻找  
隐藏的接口  
  
JS中存在一些网址或接口信息，特别是隐藏的一些信息，也就是UI中没有的，这些隐藏的 接口很有可能存在各种常见的漏洞，例如越权，未授权等。  
  
如果我们通过JS中的信息构造出完整的隐藏接口和传参，就有可能发现极其隐蔽的漏洞  
  
  
### 三、js未授权挖掘小技巧分享  
  
师傅们来看下下面的这个接口，是不是可以看到存在一个id参数，那么你要是直接把这个复制下来，然后去使用bp跑，是不是再怎么跑都跑不出什么信息泄露  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC651sic9CLLyEefXyygxjzTWuQ9UUFeicqlhHK1b0icZOWJSwrcyERIKueBQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后还有就是下面的这个js接口，findsomething显示出来的接口，一个?id=xxx的一个参数，像碰到这样的，我们是不是得提前进行一个数据的处理，然后再放到bp去跑接口，才会最大可能性让你找到一些敏感信息泄露的接口，这样就是有些师傅挖不到js未授权的漏洞，但是有些师傅却可以的原因之一了  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65RhuMGFGw4puZ6PGibibjDAS0NsBFCQYiaLmFYUmQJE8ajm4icicD79GJPgg/640?wx_fmt=png&from=appmsg "")  
  
  
还有下面的这种情况，就是跑js路径的时候，需要我们注意前面是否有前缀  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65jJCUehPQo1Hw5xsbZKicQ8FpwibPPf24el17VdbMUzRvdgEOChslTQww/640?wx_fmt=png&from=appmsg "")  
  
  
  
像上面的存在一个#的路径，建议是师傅们单独把这些js路径给拿出来，进行一个手动拼接尝试看看未授权，或者说要爆破，那也得把这个/#/这个给带上，然后再进行一个爆破，下面简单来拿百度的给师傅们看看这个案例  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65gNibMu7dsParvQwWCXTdhdicAfz0ApE8zGclK5SfBiaw1cnGk9rQ1ayfg/640?wx_fmt=png&from=appmsg "")  
  
  
下面可以把findsomething的url复制到一个txt文本里面，然后进行替换如下：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC654QdgLnmNe7PibEPTBAmEAa971cIpBc15ezSVxRE1NQpLUiaO6f8TiaUJg/640?wx_fmt=png&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65oYQElWZuuxlgNKamtuYBFbPbq70fkbwoqkyRPiara3K9PcQQjKLicOVQ/640?wx_fmt=png&from=appmsg "")  
  
###   
### 四、查询接口的未授权访问测试奇招  
  
就是我们平常在测试漏洞的时候，有时候不传参，或者在参数置空，发包的时候，对方服务器返回的请求是500的时候，那么有时候使用下面的参数进行一个传参，把这个给加上去，那么有时候会有一个不一样的效果，有时候就能返回一些高权限才可以看的内容  
```
{
"pageNum":"1",
"pageSize":"100"
}
{
"pageNo"1",
"pageSize":100,
}
```  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65JLDtCoppSbNA6lp4AI5aLmjRfA5olHaQgLT7tMR4KibelaGlibloLCkw/640?wx_fmt=png&from=appmsg "")  
  
### 五、HAE匹配规则  
  
下面是我给师傅们整理的HAE正则匹配，直接使用bp中的hae插件，把下面的规则直接导入到bp插件hae中，或者编辑Rules.yml文件  
```
type:"POST"|type:"GET"|post("|get("|ashx?|ashx|ur1:|ur1:"|ur1:|path:|path:|path:|action?|data|params
```  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVPsSrNDyAho2XibNfGCuC65B5tRhHQ6gQCl27Pu9GI4y36wVP1FRciayPmBMLTc5icDOECiaJHWUOWibg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 总结**  
  
针对js未授权漏洞的一个分享呢就到这里文章就结束了，希望这篇文章对师傅们有帮助。  
  
师傅们在挖掘企业src或者edu过程中，这个js未授权和使用FindSomething插件使用去挖掘漏洞来讲，特别是针对小白师傅们是非常友好的，也是蛮建议师傅们看完我的文章然后去进行一个js未授权的一个漏洞挖掘，这样可以让师傅们更加掌握这个技能，也是希望师傅们偶尔挖挖漏洞，然后赚点赏金什么的。  
  
****  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXzIXhsuibSCxH9DL0qbmoy9fgFDcSWC6Yyg3eJsoE70q5jJ1OiaSQYcFsw/640?wx_fmt=jpeg&from=appmsg "")  
  
****```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
