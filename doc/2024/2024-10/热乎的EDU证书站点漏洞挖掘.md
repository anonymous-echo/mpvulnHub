#  热乎的EDU证书站点漏洞挖掘   
原创 zkaq - Tobisec  掌控安全EDU   2024-10-19 12:04  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  Tobisec 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 0x1 前言  
  
今天也就是15号，出了某电力大学的漏洞证书（一大群人都在疯狂挖掘漏洞中，我也不例外），这不得去挖一波漏洞（早起的鸟儿有虫吃）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiaicfAboF11Gy7IctqIJQ2BBBibCKUFiaQCJYtohJ5FBSlCS5jS9mATthHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiaTyE6OX3U1p6Y84rryHwxj6qDS93U8SbIIicc9BSwCtlNvMpdWQeP1dg/640?wx_fmt=png&from=appmsg "")  
## 0x2 漏洞挖掘  
  
这里这个系统需要我们登录验证，所以需要使用身份证、学号、手机号进行校验。  
  
所以我们下面就是需要去找信息。  
  
身份证信息是先通过网上奖学金获得，然后获取到的姓名、学号最后通过抖音和小红书还有QQ，进行查找，最后得到的身份证、手机号信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiap6opiboWlcE5aoMUiayVShByFKrB2QNiccOLxstia0yTsb6VvtcibqCLaFg/640?wx_fmt=png&from=appmsg "")  
  
这里使用默认的六位数身份证初始密码登录不进去，直接点击忘记密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiaTBcc4DRCa8f93l3o90ED7m3ZooI4CxDTEP4vMNMUS2POkk5ZO1D1Mw/640?wx_fmt=png&from=appmsg "")  
  
然后下面输入对应的信息，要是输入正确，那么就会出现下面的短信验证界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiaZJ4XM2DPARbLWsKL98hcL6NemicFkI5chiaAOorERp3hVUD59MTh2NUw/640?wx_fmt=png&from=appmsg "")  
  
点击下一步，出现这个说明我们的信息试正确的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiacI2iaibrfqiaOYvmWkmOF5KbvibSiaUfWaje0MGhxXwkeFKQBribf1h5alrw/640?wx_fmt=png&from=appmsg "")  
  
后面就是一个逻辑字符绕过了（这个站点刚挖的，不写太详细了，怕没修复），然后数据包修改返回包如下  
```
{
  "data": {},
  "success": true,
  "code": 0,
  "message": "success"
}
```  
  
后面然后我们就可以成功修改这个学生的账号密码了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiayqPLJAZmD5vSzMnov2jSg5hJ35LLfhTpe4wib72tPt2UFQDbddnEWyQ/640?wx_fmt=png&from=appmsg "")  
## 0x3 总结  
  
这个新出的证书站点的漏洞挖掘就到这里，希望师傅们也可以挖到属于自己的一个edu证书站点漏洞。希望这篇文章对师傅们有帮助！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrVlUhiaFicz74FSdysUlialRiasrvQCq87HWfq3oGkFYx1lRxt8qq5rtSQPLcsOKBN5bkjt5OBqKib6cw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
  
