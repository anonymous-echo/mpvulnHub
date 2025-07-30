#  CNVD通用型漏洞挖掘-app逻辑缺陷的两个挖掘案例   
 Z2O安全攻防   2025-06-04 14:40  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cAsYQibT8icFSc9Hzia4g4HQMIG2v6psQnXdSs9w7OnWzeNRPEGzNCoHGeB4hyzNwp8c7X1iahsLEaG/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cAsYQibT8icFSAjv9ibeNuqB0yzE8iaJtPI3QFjBnl6Vu0K0mANkAJ0rAzWDtgy8eaUCRdvF34gbZXE/640?wx_fmt=svg&from=appmsg "")  
  
  
> 大家都说web的难挖,又要十个案例才能下发证书,那就挖app吧,不需要案例,因为本身app就是一对多的用户关系,能够影响到别的用户即可  
  
(以下漏洞都已提交了CNVD)  
  
  
  
  
01  
  
# 任意用户密码重置漏洞  
  
  
  
通过日常的爱企业查高级查询导出5000万以上企业,并筛选有app应用的,随机开始挑选软柿子来捏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquwIknfInLTHFQlfZKlXc1qxxTteD37UAVARajN78qO76y808w1mQ1Fg/640?wx_fmt=png&from=appmsg "")  
  
通过百度该公司的app发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquHozxg7e4ZLcqtdic5wyIqnnN2pxUeQ78O5hOLlxmo36ylrWfMHtq93w/640?wx_fmt=png&from=appmsg "")  
  
app还是很多的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquHUqVfeqoRicjib4qDNFwQSyIjvBYvzmb0SYibILNqvnzhiaCNb5icn3U67A/640?wx_fmt=png&from=appmsg "")  
  
这里使用的是夜神模拟器  
  
安装好后,这里任意选择两个用户的其中一个都可以作为漏洞验证  
  
用户1:1881924****  
  
用户2:1598913****  
  
  
选择任意一个手机号,选择忘记密码功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqu2tc6e08DAUS7ObK7T53qia1NBe9U8uibvp4hXQzUgfqQKr1ib6OXWdTGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquQrOa2aqGBMBBLsq0ic78ib1L7uJTybfkicb8tUm8WbzBINiagE1nc6bWbw/640?wx_fmt=jpeg&from=appmsg "")  
  
点击进入下一步  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquYVCSRFk0lsa3AvnibYWkcrhGADcyDLxJNUbsacFiaOkOuw4ibmgrlzgFg/640?wx_fmt=png&from=appmsg "")  
  
这里的验证码随便输入6个1  
  
点击下一步开启抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqu9mknQd5vSQLlBHxFDwdZWC5DUvVmKb3bT7keTSv2mxWkSKPyoWM0qA/640?wx_fmt=png&from=appmsg "")  
  
抓取响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquC4ZMkuQ1rU0Rjf3HQnVta3QbT7TA2IlI7kBETOQxofnIjibhvoR2wIg/640?wx_fmt=png&from=appmsg "")  
  
将这个响应包改为如下:  
  
HTTP/2 200 OK  
  
Date: Mon, 08 Jan 2024 03:49:00 GMT  
  
Content-Type: application/json;charset=utf-8  
  
X-Application-Context: arch-zuul:prod:80  
  
Server: elb  
  
  
{"code":200,"message":"成功","data":null}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqudmrQcDuPuiaRibX79dcsEy0K7PP84P7TXdEdiceFOu1SQKJjXmKYCEIDg/640?wx_fmt=png&from=appmsg "")  
  
这里一共两个请求包,都要将响应包进行替换  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquoJ0d1FYPFNYvxNOBQsULMhpltHicFyDQXRsc6oehv3L2zIPLDib6OXnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqudmrQcDuPuiaRibX79dcsEy0K7PP84P7TXdEdiceFOu1SQKJjXmKYCEIDg/640?wx_fmt=png&from=appmsg "")  
  
成功进入修改密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqun5BTF9x0kBbFicHLneg5HASyHnO6rKibOSZEich1B6huT4APiceVq2ag5w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqupDfr8a8FsVW0bwfR5rKIaa9vzoqKhuwJcBRYv199ibEHgKL2RsBkHWQ/640?wx_fmt=png&from=appmsg "")  
  
证书+1  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cAsYQibT8icFSYmK7Vch7f2NBFbEgoXfBOYic7ydibfQWgwaibED0Z155mqLVpQL5CBYtqnDVPjPr8CF/640?wx_fmt=svg&from=appmsg "")  
  
# 02任意手机号换绑  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cAsYQibT8icFSVC2GcMVTicsejibfic7hPSuyibUeKDXJmcp1CKdqqbdD1LHicLCwC7JBjccWBAqH2RJH9/640?wx_fmt=svg&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqurYBKqDkJr0JoIGhHotExCiarxuEXorqY3ia4TJucx9HuicxAW9wuQibswQ/640?wx_fmt=png&from=appmsg "")  
  
下载好app后,模拟器启动Burp开始干活  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquP9KlFDfibatwXmr8vFibD9VE0ia889V5jicwSLGaS69X8HfHZ16a2WceqQ/640?wx_fmt=jpeg&from=appmsg "")  
  
注册好一个用户并登录后,来到设置处  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquuSO1NEsoRicyzGUaCL7KQTzl4RgGjxWQQfr4CUqqzu7ZyBI08msgBwA/640?wx_fmt=jpeg&from=appmsg "")  
  
点击绑定手机处  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquly4jT29BPm2GBsItuVwuZ5D2ljLe8lib8GV2tQkKqUMZldbiaWjy7tPA/640?wx_fmt=jpeg&from=appmsg "")  
  
现在要进行换绑新的手机,我们随便输入6个1,点击下一步进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqudaX8FN8v3sDuibeFft5ib2jEOCChU9D82AwcoPOIsQfPGONw6hXn3Wgw/640?wx_fmt=png&from=appmsg "")  
  
抓取响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquZricUOicNEUyC1UMN9ib3ibDSic4ib63YSzmvwdYuW8vOwib4epgViaTSOIvBA/640?wx_fmt=png&from=appmsg "")  
  
将其替换为:  
  
{"message":"成功","return_code":"0"}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqu90FLSiaj7nFZgbZ907VWdmTKUF2RNb92fXhMPHPmV2oTjCegicfDXrVQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icquvT6TfutTBmeDoZcJ95v6rWbFib0uyp6DiaQxLjnQezrZliaKnffwiaJzIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
新手机接收验证码后,点击完成即可  
  
刷新下发现从155变成了188的手机号,证明成功任意换绑  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqulXONh1Pb4AFGP4EyadeXvCL6ltPg09SEBhuDw2sDSIovdXu7kaRbdw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqub9xBOyOhI3B9uP6McAQZqaR1ahT02ZIFxbeJsGWUCL1XTCEBYoj98w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYY8q8CZqffeicCspiaq3u0y7lQ2ia1ZLXbhqIbjvnBdsrlTFOJjSXbu8fmmliaLticl6P0iaXjbnxokM0g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8rxbzfE4kRAaiboO1nM99icqu4OMib4icicrMYicCUordORFrTHLEgicDwWECozvY4RFYgkYH46anuiaUggPg/640?wx_fmt=png&from=appmsg "分隔线")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYY8q8CZqffeicCspiaq3u0y7icJl2JSxY9aESQTyhS2t7fic2niaQmYE90k5EfJccbgoic6icGhPHBTI5ibA/640?wx_fmt=png&from=appmsg "")  
  
  
