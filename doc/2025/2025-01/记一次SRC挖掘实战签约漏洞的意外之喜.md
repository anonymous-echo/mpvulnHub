#  记一次SRC挖掘实战|签约漏洞的意外之喜   
 Z2O安全攻防   2025-01-23 12:55  
  
在一次日常漏洞挖掘中发现某系统存在一个连续包月的签约服务，那二话不多说直接上一个签约漏洞的测试流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5le6up1jLY2d5A0ibGJUb9nOQ7XyXCDsICqYMpYXEXP92yqeq4nd5Cv9aOysnKlt8jglF5hHfUgvwA/640?wx_fmt=png&from=appmsg "")  
  
框框扫完两次支付宝和微信美美的去看一下结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5le6up1jLY2d5A0ibGJUb9nOLJtDMiaoNlG1KsZ0hbkCuJgphUibMgyWNiaGftUlxd7VA7znwl7dndXUw/640?wx_fmt=png&from=appmsg "")  
  
发现只有一个发货其他都不发货，等了一下还退款了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5le6up1jLY2d5A0ibGJUb9nOUQBrhBRDCz2W98u0JJBmGDr5bZQdfA9qvbUFZp9iaBGicc1hCd6frsfw/640?wx_fmt=png&from=appmsg "")  
  
GG感觉没啥好测试了准备换地方  
  
但是柳暗花明又一村  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5le6up1jLY2d5A0ibGJUb9nORYPbN6VCW0MibvFCia2JTBd0u7TaibWLNwFbujsRM0F3zldpOBmeYuT2g/640?wx_fmt=png&from=appmsg "")  
  
  
突然发现发现会员发货完后，其他待发货的会员的赠品会单独的创建一个新的链接，点击去支付发现支付成功。(神奇逻辑)  
  
然后美美的刷了一波赠品  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/veA9QmcJk5le6up1jLY2d5A0ibGJUb9nOZMeAszH12wta3kEic5MINpzB5M1AfMLQV2SUTHGBPlEM6Ra1nKMywUg/640?wx_fmt=jpeg "")  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuY6DfYOuUzWiaPBBq4L5bV9ZRMpUcFktl9oiazJicibKEVwZoWo5dEaXGHIoa6yOEkfnicbMibJDALxuk1w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
