#  Parameter is null引发的一次五千漏洞赏金记录   
小乳酸  Z2O安全攻防   2025-04-19 12:44  
  
## 0x01 前言  
  
Missing parameter？Parameter is null？一次众测实战教你如何高效的找出缺少的参数。  
## 0x02 漏洞背景  
  
一次众测项目，称其为https://uctenter.target.com。  
## 0x03 漏洞挖掘过程  
  
前期通过信息收集，找到一处目录organization 状态码返回302，跳转到https://uctenter.target.com/organization/#/，熟悉的空白页面。直接翻js，正则匹配目录，拼接到url后面爆破，全部返回401。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pOOKGW9VicEocpROtyRzdFEUkj9pc2j2UbYbv3NFTvKmTVJIehxJAofgewAsuCStBZiaCuzQn32aib432NtYjiaCFA/640?wx_fmt=png "")  
  
  
将其匹配的目录导入到excel，使用/为分割符号进行分列，将其分列后的所有参数保存为字典，导入burp继续爆破。其中一处orgapi目录返回302，跳转到https://uctenter.target.com/orgapi/。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pOOKGW9VicEocpROtyRzdFEUkj9pc2j2U2vXP7tBooWWUVeCzbE5aHXlYMZ7QbxYzBpttC9f2wiaPglxR2fhwadg/640?wx_fmt=png "")  
  
熟悉的spingboot界面，掏出珍藏的springboot字典，/orgapi/..;/v3/api-docs返回大量接口。继续上续操作，匹配接口，拼接在orgapi/..;/后进行爆破，发现多个接口未返回身份认证失败，说明已经成功绕过身份认证，但是未发现敏感信息。  
  
观察接口信息，发现其中一个接口带有selectuser字段，返回报文为parameter is null。使用Arjun进行参数爆破**，**  
  
使用Arjun自带的字典爆破无果，使用正则将https://uctenter.target.com/organization/#/中的js文件所有单词匹配出来构造字典，去重，大概五万多个。为什么推荐使用arjun进行爆破，假如有一万个参数，正常爆破会发送一万条报文，Arjun会将一万个参数分为25个组合，一个组合为400参数，第一次发送25次请求，只要其中25次请求中，里面有一个参数正确，便会返回不同的响应长度，以此类推，继续分割**，**  
直到剩下一个参数。  
  
正常使用burp或者其它软件进行爆破，需要发送五万个请求，使用Arjun可发送不到3000个请求。  
  
发现其中一个参数searchId返回不同的响应长度。通过其id值可遍历此厂商所有人员的用户名密码，身份证号码，手机号。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pOOKGW9VicEocpROtyRzdFEUkj9pc2j2UH1p8IKB1f9mYTMMCrQhlaZ2gaYUrNynedJb7QLEl5eBZUhuia1uH74w/640?wx_fmt=png "")  
  
通过前面获取的code值可获取所有人员的家庭住址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pOOKGW9VicEocpROtyRzdFEUkj9pc2j2ULv0eyffxpqtapHicPaYE7wOvFbYx1rsho3iaOZyAFBKLcR5PzkAm9oeA/640?wx_fmt=png "")  
## 0x04 厂商反馈  
  
获得了最高赏金五千。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pOOKGW9VicEocpROtyRzdFEUkj9pc2j2UXkmicic5SEJ117D6ae4ic1hPAwiaRD2DRdVCg8fEVX2mOnp7oxItccE63w/640?wx_fmt=png "")  
## 0x05 总结  
  
方法很笨但很实用。  
  
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
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaEwb07ryAplac3KXf8QkE5JSlU4iahMxnfDB6daPMUX2Ys9T7PlheOKe8ZgicIpicUxDzNW92w3t56Q/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
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
  
  
  
