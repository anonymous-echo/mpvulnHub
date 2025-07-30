> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2ODYxMzY3OQ==&mid=2247519526&idx=1&sn=37208f0ff625ea825f473f210671c887

#  几个常见场景下的xss漏洞案例  
十二  Z2O安全攻防   2025-07-16 13:01  
  
**免责声明**  
  
本文中所涉及的技术、思路仅为学习交流，  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，一旦造成后果请自行承担！  
  
**公告编辑器处xss**  
  
发布作业处，这种有编辑器大概率就存在xss  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM89r44TljzMe4FMW2SzSrkibgiacmT6NHziaFkaI67t80rSAvvkAduSEEw/640?wx_fmt=png&from=appmsg "")  
  
点击提交，拦截数据包，添加payload：  
  
<details+open+ontoggle=confirm(document.cookie)>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMl60hsudz6Z2YS3hlGNmnE5RjU2KUewV8RjDnC1nQ9VbNjKhTcrhalw/640?wx_fmt=png&from=appmsg "")  
  
放包，访问作业处弹出cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMqAeVGcg32YvOuU6tcw8se63yXt4FuIibcd9MDrzxwib19iaE59Nuq58Bw/640?wx_fmt=png&from=appmsg "")  
  
**上传文件名处的xss**  
  
前端功能点如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM6mpQaLNB8C6siaJDm1DFyQZryA7uicWuPsbX3FSpzc8nicwY6HlXj8jHA/640?wx_fmt=png&from=appmsg "")  
  
点击我要办理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMb05dHChVibrBlb7sOaoh1tAxa4ODLg80L9wBAgiaBbzbLibNqah4Jm98g/640?wx_fmt=png&from=appmsg "")  
  
点击上传文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMysNADuPTxI96ibWdXJlLt5lGt0ebKOcZKcAmBWiaeLwD2hHwyO1vvNoA/640?wx_fmt=png&from=appmsg "")  
  
文件名直接修改如下  
  
<details open ontoggle=confirm(document.cookie)>.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM1IhI4OO96S5CYowNm0qaAu2CW5KxRuia18XgUv9No5o40wlnmibT1IlA/640?wx_fmt=png&from=appmsg "")  
  
成功执行js代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM3ZKr6dPwiaCibZVicNwwoZDGJfckcMv5qK2BbgMicEd5PDzaluKjYFWmWQ/640?wx_fmt=png&from=appmsg "")  
  
点击保存草稿，有的网站是在保存的这一步有过滤，去草稿箱确认一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMFFAhogpqzyxnJf6QvEuSk82Nsg3RA8mj1BL3v3j5icFKZd8hQutKrYw/640?wx_fmt=png&from=appmsg "")  
  
确认无过滤，依然可以触发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM3ZKr6dPwiaCibZVicNwwoZDGJfckcMv5qK2BbgMicEd5PDzaluKjYFWmWQ/640?wx_fmt=png&from=appmsg "")  
  
**针对于管理员的xss**  
  
前端功能点如下，点击发起申请  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMUnr8bTvuHrZM7PicHbx8do4XvbicLCuw5d3aBr1oEeSVbIBNfSfevjag/640?wx_fmt=png&from=appmsg "")  
  
这里s标签就是给中间文本划横线  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMqkmISqStPeLqUWjmTKGC9GHDImZluiaGUVlrfmiawbWUygzhbWeR3wlw/640?wx_fmt=jpeg "")  
  
请求包如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM1U2yS6L9njrYITmtnd5icZobO64lBM1SuB8gYj5JWgQmAyoO0TjjcNw/640?wx_fmt=jpeg "")  
  
这里手动再添加下s标签  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMUBmYwpX5lMYQO6Qx11IqFb4rcqBtPQlmbz0AWtzh1oQmAzK8jibTGqw/640?wx_fmt=png&from=appmsg "")  
  
可以看到是成功解析了s标签，如果没解析也不一定就不存在xss，但是只要解析就大概率存在xss了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMRtj46RLshGTft9BFHjHpm3xs1icTN6ZebMG8ejIaVYGWoiaRwPdOoq9Q/640?wx_fmt=png&from=appmsg "")  
  
再重新编辑替换为最常见的paylaod  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMCrCRvYwuQFAmCweqjr0iawIICtqQLWp7ia4xSUHtlMy5KLKCqKsVPFqw/640?wx_fmt=png&from=appmsg "")  
  
没有什么过滤，成功执行js代码弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMU8Qf51Ur7xjvN3u2Nue3Ct0L7icOwT4Pt7Uhk88KmoDq1tdXnnzRNIw/640?wx_fmt=png&from=appmsg "")  
  
**存储桶修改response导致xss**  
  
首先新建一个txt文件  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CgXd9Hbb64nQNeSxwrlYXynxwOUjsWJmCiaiaCGzTvM99AqyiaYzlbdgQiaaaRakxmy66gvsTedJArELJ5oic4Fs6RQ/640?wx_fmt=other&from=appmsg "")  
  
上传文件功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nQNeSxwrlYXynxwOUjsWJm6jSbLIHmiaa8PS4hx8VQjBrojnx6hHC5J1UicJb1UCLyS3uAGGrk94jw/640?wx_fmt=png&from=appmsg "")  
  
可以看到绝对路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMC1hUl45qcZAkhZKwFhaL2aNRI7yg6VOgiasrGUPO37Fk4f8XR1nurRQ/640?wx_fmt=png&from=appmsg "")  
  
存储桶域名修改为绑定的CDN域名，后面添加?response-content-type=text/html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMNgMxgrTwmaUYWNhMCe2usiatFyKlxIqxPX3MicWYn7oj0K6EjYFMqzSA/640?wx_fmt=png&from=appmsg "")  
  
这种就属于低危反射型xss  
  
**并发绕过限制的存储型xss**  
  
地址簿管理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YbB7xAvjV7hAmCMM7lgiczhvGtDdjvaib1dxlA8dIuLjFTdY8ibGssVr0w/640?wx_fmt=png&from=appmsg "")  
  
直接添加下面payload会被过滤  
  
<input2 onmouseout=\"alert(1)\">test</input2>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YdEx3AfOSgVVyDJ1WsHLuEgibc7Bo9o4zOIpIhibNghJlAHtc3jrLEWYw/640?wx_fmt=png&from=appmsg "")  
  
遍历下面数字达到简单的并发效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YZG2icdm9wibGrNooiawbNzFR3OqEw6saAqnt4une1c5eIaickzhyeG2eqg/640?wx_fmt=png&from=appmsg "")  
  
成功绕过拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YiaDtgPX8SjWlHIltKlvshuQ8weUNo5LmtQYzNPJTAz1H84oQ9iaAT4vw/640?wx_fmt=png&from=appmsg "")  
  
这里来说只是self-xss，但是通过下订单选择此地址，再通过并发绕过限制即可盗取目标cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YVdQWPy4ZqThzggIliabHuCOZe6e68JPxvLficcvOphn1C1cD0K7SFOug/640?wx_fmt=png&from=appmsg "")  
  
**某企业论坛的存储xss**  
  
漏洞点在评论区  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1Yxro87ib7tGqPHia2YDeDKCNPnkHR1BUW0mEqvxUkeKC3RBGpiaS8SL25A/640?wx_fmt=png&from=appmsg "")  
  
先测试最常见的a标签  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YA1o46gC3HT3lR4HJV2kbvFdFIvC0fmwTKibTxwxamY0dy0y84NicdRfA/640?wx_fmt=png&from=appmsg "")  
  
发现成功解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1Y7R7LbIn6fR74KCJuXnicAcALibktbOMzEy0aJC5vcKqdriaia82mZswmPg/640?wx_fmt=png&from=appmsg "")  
  
随便打个payload：  
  
<a href=javascript:[1].find(alert)>xss</a>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1Y7r8CXMEIaLU2j7jbpp8SD70ric9QnmxVRLlmpNWIqSPQ51QoqQicCFLA/640?wx_fmt=png&from=appmsg "")  
  
发现有过滤，构造事件属性，测试不太会过滤的事件，复制才会触发：  
  
<a oncopy=alert(1)>t  
  
选中t直接复制即可弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1Yo6l6YgiaR1SSKs0vEgMvAaicWsKVbqY37MLdDxPIiceJpO457yIy1RWmA/640?wx_fmt=png&from=appmsg "")  
  
再测试一下简单交互就触发的事件，payload如下：  
  
<a onmousemove=alert(1)>t  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YEEIbPjClYojpIuGC6RAHWPibRj31F7Gw15knJOeG0uZ8gZZqn7EocXQ/640?wx_fmt=png&from=appmsg "")  
  
晃动鼠标就可以弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YUicAQZbqYVWwE2V4uAXMw5riaFvcZM3QDfH1jwqkPIOyxPWfA3vMem2A/640?wx_fmt=png&from=appmsg "")  
  
再稍微变换一下展示操作  
  
<a onmousemove=top[/al/.source+/ert/.source]('xsss')>test  
  
**银行门户的反射型xss**  
  
点击关于我们功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YTZRmYpOK3WibmoLOCDmEmic9hqkJuzPSbmA2yHsUYia3eDvJib2F5TqQYA/640?wx_fmt=png&from=appmsg "")  
  
url中拼接title参数，发现回显到了前端  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMM54ibibX1LzSVwFzZKdzXOhg5GNbEGicSzY94t1Ng2ILBwTBoPWicf9gHmg/640?wx_fmt=png&from=appmsg "")  
  
随便插个payload被waf拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1Y9DC50TFyzCu9LLpY3Nb3q3fOVRibzHcb9WnQdGnnok4L8XSeMw8AvmQ/640?wx_fmt=png&from=appmsg "")  
  
手动测试a标签，可以解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mQwrXCJVQxLqDkTyes5Z1YgzvV8eDuv7BtwaotUb7ZD5xwUiaxaVtO1SCT9T7cV7GOMFgiaFCibnXMA/640?wx_fmt=png&from=appmsg "")  
  
直接上payload：  
  
<a onmousemove=alert(xss)>test  
  
这里本来以为会拦截，结果没拦直接弹了，省的再绕了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMEbMs9kgS0Qltaoualovoaz5nkZpsuwia3UM8Q2yuvUnQA6EcPofeMdg/640?wx_fmt=png&from=appmsg "")  
  
  
**总结**  
  
如果有可以解析的标签，大概率就能用冷门的事件绕过waf，alert有太多变形，比较好绕过waf，如果输出就对尖括号做了转义，那就只能看运气了  
  
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
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZXTocHUwICeriaREbZRb72OuCxoJ3bkSCes9WxYqHFlUkyZhiaMyu4gpQ8ic6JI4GSmse87g0VT4Hjw/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
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
  
  
  
