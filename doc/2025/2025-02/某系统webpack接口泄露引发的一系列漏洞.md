#  某系统webpack接口泄露引发的一系列漏洞   
原创 zkaq - 腾风起  掌控安全EDU   2025-02-08 04:03  
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 - 腾风起 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 信息搜集  
  
这里找到从小穿一条裤子长大的兄弟，要挟他交出来他的统一账号，否则把小时候的照片挂网上，开始某大学的资产搜集，直接hunter搜索此大学域名![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PL2DzWBMSII8mD93VMHPyhG99ribCLpsFH6ozIMAJ9DmqYicicvqfE0v8w/640?wx_fmt=png&from=appmsg "")  
看有价值的站点，ok找到下面的站点  
## 未授权+敏感信息泄露+越权+任意用户密码重置  
#### 1.越权访问  
  
站点是webpack打包 app.js 还有路由的js没有登录就有大量js接口还有path路径泄露![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PiaLS4YvmmdqcTcm1sk76Th3bpp6QGqJpknCqCEq7hxqVNmzmpoxKsAw/640?wx_fmt=png&from=appmsg "")  
以普通用户身份登录，所有的还活着的接口都能访问，很多管理员才能访问接口也能访问，并且进行增删改查等操作，这里提供几个页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9Pt8JFss7BzalCsW956b5ib4dafibsWFkCYdjib4LkWOrBosOUppFtCCQVw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PeqbEFDom8kdhFlo5zricicGO0GIsCUH8bnKuoibbvWictpHPqZIYZHRpxg/640?wx_fmt=png&from=appmsg "")  
#### 2.大量敏感信息  
  
根据上面翻js，找到下面这个页面，接口回显所有用过这个系统的同学和老师的信息，包括身份id，电话，照片，邮箱，学号工号等等，数据量巨大，后面任意用户密码重置会继续利用这些信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PtFBMXADwghrGLAAc7og1icrZQ9t9jo29UC21fYSIKGGOibSyaWibbfyAQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PWKPCFWfFEDic1ma3ZJvoUa13mDzAkibTmka4wOKWFJs9AEiat5XUJGs1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9Pc81iaf7jOOhribt9u5QicGq7LolIuLtfiazlXlKKwg23IdqBb8vuwR8EnQ/640?wx_fmt=png&from=appmsg "")  
#### 越权  
  
有些页面做了鉴权，没有访问权限，但是通过前面的未授权获得的信息 我们知道各类用户的id和usertype  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PQEkv0NQ0xQQz6DFtT7norgEibwOf6qIRicq9Osj8QpfAic34SSUhO2ic2A/640?wx_fmt=png&from=appmsg "")  
比如有一个教师列表接口普通学生无法访问，但是在返回包中，把学生的id和usertype修改为管理员对应的参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PhC95SCZdDtmxriaYV6BHict8BS7uZPSQP7evN3q9tqHcwEsFezEiciabhA/640?wx_fmt=png&from=appmsg "")  
成功访问，拿到所有老师的敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PJIAriaj3SmSBDYxZx8W8SgYdvPyNShLT9WsJcsibXmA3txtXmnx1pRVw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9P54fDApibHP8mtNibp0iadNeQed6JPUvJWqjCtATQCWbMYdzSmLHpX9aHA/640?wx_fmt=png&from=appmsg "")  
#### 任意用户密码重置  
  
在修改密码界面抓取提交的报文，修改成我们前面拿到的各种信息，对应起来id，userNum，cardNum可以实现所有用户的密码修改和信息修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PJFl1jOeCsCV6BOs3DxJGxGvO3JRssiahAj0x54xiaOoPyEdX8n0g51EQ/640?wx_fmt=png&from=appmsg "")  
  
对应不起来会报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PhsJKbs1xHnpFz3YFR2kGodByH8p8icrfeJ59xVgsc7CSJVibIOyEicHXw/640?wx_fmt=png&from=appmsg "")  
重置其他用户密码并且登录成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcos1uwfwXdXqsMzfaAB8G9PcyqGVaJsU8ibIB09mic1wbASkZaaYlejcM19OdznD1hKtyruudFa4PGQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
