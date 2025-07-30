> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2ODYxMzY3OQ==&mid=2247519515&idx=1&sn=f30efcb700f7338573925ec983993cec

#  SRC漏洞挖掘之“嫂子开门，我是我哥”  
 Z2O安全攻防   2025-07-02 15:23  
  
**No.0**  
  
**前言**  
  
  
在一次日常的漏洞挖掘过程中，在一个微信小程序中本来毫无头绪的时候，在巧合之下点开了另外一个小程序，结果两个小程序竟存在联系，经过不断测试，挖出水平越权漏洞。  
  
成功达成成就“嫂子开门，我是我哥”  
  
**No.1**  
  
**正文**  
  
  
开局就是这样一个小程序（我们称之为小程序A）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnal0BJB5cZpOwgTVs5rygHISAt0yicu0FDibicr7icuibX19Lz5SDyfhfbdw/640?wx_fmt=png&from=appmsg "")  
  
  
随便输入一个手机号13111111111之后，会显示如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnu3VxjTBt2VOeF8abyZLcJicYQWv3VxgLAZU5VK3v3QZxtPqpFlrcPQg/640?wx_fmt=png&from=appmsg "")  
  
  
可以知道13111111111这个手机号绑定的用户名、学号以及学校，但是用户名被打码了，抓返回包也是打码数据，这也构不成敏感信息泄露，只能先放在一边。  
  
  
然后我又点开了另一个小程序（小程序B），在小程序B的个人中心处有一个添加学员的功能点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnsz4ictudAHFpNYszph8OFNrx42czOOd2yqsomERpgOOzU9X8AOm4wqg/640?wx_fmt=png&from=appmsg "")  
  
  
有两个方式添加：手机号绑定和学员号绑定  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLns1Xb46oTrHETdbdwWV0qn4rlQkecTInxjLcDZ5m71ddkkkCEcWzt8Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLn5fYHkfsW2owr4rn8dw0wecKxXibbzjh8DxlTetQ242o4pdQzz2vEakQ/640?wx_fmt=png&from=appmsg "")  
  
  
等一下，这个学员号看起来好眼熟啊，会不会是小程序A中的学号呢？试试呗，反正又不会怎么样  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLns2ibjAOvic2JJUg1cgCiaoXVUhUCGvx215UBO7PUTsWv8StSB3qECboXw/640?wx_fmt=png&from=appmsg "")  
  
  
好家伙，这明文信息就这么轻松得到了，事情变得有趣起来了呢。当时我看到了信息名片下面有一个获取验证码，想着会不会有验证码回显导致的任意用户绑定，于是bp抓到如下数据包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnhuZWTQbhXPyNqgAbJQtFgQ3HoMLaEh6IsKPCxYq2vK9FwROWAYSiaTg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLn8c1aelYHGgxX0OPGZmeRQTV8XjBKiae0CHxUGh0qb9rdia6diaBKbXdhQ/640?wx_fmt=png&from=appmsg "")  
  
  
遗憾的是，该发送短信的接口不存在验证码回显，但数据包携带的数据引起了我的注意。“userId”经测试是自己账号的身份id，而“studentId”就是用户名为“家长”的账号的身份id。这样一来我首先想要去测试的就是水平越权漏洞。  
  
  
仍旧在当前小程序的个人中心，来到个人信息修改处  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnb0YpyC0Ay6O4mTVBZTYcAOAFYA8aMmytGicZ9dsaibCvxCgiaYJRbibQrQ/640?wx_fmt=png&from=appmsg "")  
  
  
点击“修改”时bp抓包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnTPX6CIwCIuTA3YKLkC3ErMTZjZNXAr5pEtZfTpKdDKujfJ0iaq6aBtQ/640?wx_fmt=png&from=appmsg "")  
  
  
数据包如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnNEEXWZDgWcM7XbvyqicY9ojegqWRkBAAXZicgCS4dZVc8ibBadFMYpicrA/640?wx_fmt=png&from=appmsg "")  
  
  
哟？！，改成我们之前说到的id试试  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnEiaBVekCBfJTv1W8Wl5wzLLEu0fckfkspD7Dy9chFsuaCNDjVM0Nl2w/640?wx_fmt=png&from=appmsg "")  
  
  
再次去查那个账号时，发现已经被越权修改了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnbCUyNzkicgYIHvYAMe9LxRIAsuGq3qRmOIdpmLLAELstu3JjyAMjXzA/640?wx_fmt=png&from=appmsg "")  
  
  
好的，得吃！直接写报告提交。  
  
建立了一个  
src专项圈子  
，内容包含**src漏洞知识库**  
、**src挖掘技巧**  
、**src视频教程**  
等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```

  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZXTocHUwICeriaREbZRb72OuCxoJ3bkSCes9WxYqHFlUkyZhiaMyu4gpQ8ic6JI4GSmse87g0VT4Hjw/640?wx_fmt=jpeg&from=appmsg "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
