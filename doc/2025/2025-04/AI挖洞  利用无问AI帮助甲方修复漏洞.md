#  AI挖洞 | 利用无问AI帮助甲方修复漏洞   
原创 神农Sec  神农Sec   2025-04-16 06:55  
  
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
**利用无问AI帮助甲方修复漏洞**  
  
  
今天在渗透的时候，发现了一个低危漏洞，就是通过插件进行修改IP，比如我这边都改成：127.0.0.1（修改IP的一个插件，新手师傅们可以直接利用浏览器加载：X-Forwarded-For Header插件）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHuF5szHfgVCCFiczWgBVjibghOmPSVQ12iaG914EhUwgWWcJaSic5LyLWmw/640?wx_fmt=png&from=appmsg "")  
  
  
我在这个系统网站上做渗透测试的时候，操作日志就会有显示是这个IP操作的。如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHfqrKbAFrQwd3VPlqAhrIk7lBtdWJ3kVJFwKdBjs0fsRcMsEeej8O2w/640?wx_fmt=png&from=appmsg "")  
  
  
  
但我实在想不起来这个漏洞叫什么名字了（原来挖到过，好久没用了）。  
这里直接上Google浏览器进行访问浏览下，是跟IP伪造相关漏洞有关系。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHvTibyoF6WpXx8WGbqFcwt3Qb60ATRnIQWUO6xHld3zCs5MTuHfW0aXg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
查出来了，是IP地址欺骗漏洞，然后我就发给甲方爸爸了，结果甲方看到后，直接来了一句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHVCG7UjwibqAcWrCwmibjeV8MrohFhsvDS4oFqPTQw6onRRdXPfGkwQqA/640?wx_fmt=png&from=appmsg "")  
  
  
这把我给问住了，因为我也忘记了  
  
这时，我便想起了无问AI，我们看看他能给我们什么答复  
  
  
这里没有使用注册的师傅们直接可以使用我的邀请码注册，且可以签到积分，免费使用AI大模型操作。  
```
邀请码如下：
https://www.wwlib.cn/index.php/login/icode/afc2c7c7cfafe7c9
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHq0LvaibrWtlkBBmEZicHPfqEXNnJHZrQmfy0YLu6h3WhN65PWjdpv5Qg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
无问AI地址：http://chat.wwlib.cn/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHHePhd71KCWHKFQSiaN5fhKLCW3usziaWJB8PWOCOdw6P7T65cX20ttSg/640?wx_fmt=png&from=appmsg "")  
  
  
同样的提问，没想到无问AI给我的答复非常全面。不仅包括利用过程，  
还有漏洞原理，危害，  
和修复方法，甚至代码都给我了，真让我大吃一惊  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlH2k8hLbmPDcChjKAmBVicjvcCevFv8ByTksN6MiaNPAb0L7ia53fzibQqkw/640?wx_fmt=png&from=appmsg "")  
  
接着，我整理完后发给了甲方，这个漏洞也成功修复，我不禁感叹无问AI真的太方便了，真的欢迎大家进行注册使用，听说每个月月初还会送额度，赶快扫码进群领额度吧。  
```
邀请码如下：
https://www.wwlib.cn/index.php/login/icode/afc2c7c7cfafe7c9
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWV0QqiaoZIuIV2gJsf01ArlHL7hjQLpW4JCrtfoYjAtPG8YUWNZDXErkyoshq84yDQJ1eB34BM7Fog/640?wx_fmt=png&from=appmsg "")  
  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXeC6fCPlKvnACtNdmjsibia9WE3nXHz8akgVUIs9bKpIm2AicIC9xk4QEibiaPv2cK5M9rS4yTcyunXqw/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
