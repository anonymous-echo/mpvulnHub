#  edu小程序挖掘严重支付逻辑漏洞   
 扫地僧的茶饭日常   2024-12-11 01:30  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -   洛川 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
声明：本文所有漏洞已提交修复了  
## 一、敏感信息泄露  
  
来到某学校电费充值公众号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlOOICuV4hAABjj0Ecur83v4Tib5zc3RQoHWibR3dibIibo8LwfXY5KcN1FQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
打开购电小程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlC3AU2XDUtwcLsA1aliaicdZiay6rBrVxQNlSyI702Q8hZgME81YqGPibaQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里需要输入姓名和学号，直接搜索引擎搜索即可得到，这就不用多说了，但是这里的手机号可以任意输入，只要用户没有绑定手机号  
  
这里我们输入自己的手机号抓包直接进去  
  
在进入的过程中发现一个很有意思的包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlKOnKnCjptoMObvEu6HCZqkzNZ7xibr6FicsiaWgvB84TsEUj3jjUVia7Ew/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
前端js中竟然泄露了debug模式的密码，当时试了一下确实登录进了debug模式，但是忘截图了，这妥妥一枚中危敏感信息泄露了  
  
继续挖掘  
## 二、垂直越权  
  
登录过程中发现这个数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlVtSOryHdicnuTyWwcWq55fWzcGsBrjicq3ia1bING0FRhAp3kMXneQk7A/640?wx_fmt=png&from=appmsg "null")  
img  
  
通过roleid和type来鉴权，一开始的roleid为4，type为学生端，我们直接修改为6到教师端  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZl0qTrayhsUbmeyETA8T1N1StuqiaARP1dribhm9icpVibica6xXaRbFTn3FA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
成功返回教师端的功能，我们直接修改后续返回包即可登录教师端，但是这里之后点击的每一个包都需要修改数据包，有点麻烦  
## 三、多个敏感信息泄露  
  
从下图数据包中可以看到通过getPersonInfo功能点的accountNo参数可以获取学生的敏感数据包括代表个人身份的PersonUUID和UserId和手机号，WxopenId和账号密码等敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlZUSp18grO2evO0qibMkckvI2HYsDiaaanfoTj266cgqY1F0LUyfaV10Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
既然这样直接遍历accountNo参数就可以获取全校学生的敏感数据了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlMtNEYfZcV6ZjPbRvW3Eiaa00We44PbeLQndCWiaZ85smSIGgMic1pVyfw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
又找到个查询一卡通信息的接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlRwIa0EPkn0QCicHUlZEoialjWWIEROYSic0J8LIEvjB0SgrDhkgLFGblg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
同样可以遍历获取全校学生一卡通账号和余额信息，虽然危害不大，但也是一枚越权导致的敏感信息泄露  
  
继续测试，发现一接口，需要配合第一个数据包获取的PersonUUID使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZllnbCAicZnaPIQ1fGwCqTB4sojibPxFy40UGMesuibNrezfNUOiaP4Tm28A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
虽然我获取的用户没有填这些信息，但是这个功能点的泄露可以看出危害多大，具详细的敏感信息，只要配合第一个遍历获取到的PersonUUID和accountNo配合遍历即可获取全校学生信息，一枚高危到手  
  
最后上正文  
## 严重支付逻辑漏洞  
  
登录进来后点击电费充值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlb9FIecicVwSAqBQRYrHlzn2UaibImpuORCnYczuLdn9Xn52mnKhAlbJQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlozOvXxOf7yzibJ8giaoZVecq4IsHtw9VQuL7ynFa0LJdfqWrfZIebtrQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
选好需要充值的宿舍之后电脑开始抓包，点击充值抓到如下数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlrSKahYy1aWiajicY0NeJJVmo9HKdp6nPmmib9IFIegkiaW8hzThGPR8AcQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
发现这个包为校验包，用来校验订单金额，改了这个包后续就做不了事了，直接放掉得到下一个包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlszoPTcqLs7Kf7mMjJLibUQfv0ySTTm6dM4TlEbKmqOD3TliauX78fEjw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这个包就是调用微信支付api进行订单支付的数据包了，直接修改totalfee参数即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZl0ZFC6yU4Ss4PA4N0NtMv76OnVxAB3UVj1K70b7JqHfST7F4mMDycqA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里还存在一个知识点，就是调用支付只能手机上支付，电脑无法进行支付，所以我们需要抓取手机上的包才能进行后续操作  
  
这里教大家一个简单的方法，让你的好朋友给你开个热点，然后你电脑连上他的热点，查看获取到的ip，然后在burp里添加获取的ip进行代理，端口随意  
  
然后在手机上也连上热点，然后给手机添加代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlxm7lpLXYQATLTzeoaiaJC8slmWOFo7Ll0dGzKYwia2Vib8iaiaCcJ6cvF3A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
填写刚刚添加的ip和端口保存即可抓取手机数据包了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlYRlc61ib1mia72axVFTkiay3hicZGn7p6sQlTEDID7ibXiaw1V9f6dlw0Iicg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
最后也是一分钱支付，到账一开始充值的五块钱，也就是说可以一分钱到账任意数额的电费  
  
漏洞危害大，利用难度低，直接给了个严重，还收到了学校的感谢信  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcrPdhibnbWwmbvEnOTdDcxZlaYVZ6U1YZK10F9MIp1ibxiaYZ5XJ3ZPl0hibTt2I1XuVOpyeib7mR2thicw/640?wx_fmt=jpeg&from=appmsg "null")  
  
img  
```
```  
  
