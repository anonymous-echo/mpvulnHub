#  利用ce修改器进行漏洞挖掘（内存修改）   
原创 zkaq-lao六  掌控安全EDU   2024-08-24 12:02  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  lao六 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# CE修改器原理  
```
ce修改器可以修改内存数值，因为有些程序会把一些值放在本地，然后改动的时候访问的本地的值，修改之后，客户端服务器再次发生交互的时候，把修改的值发出去，可能会影响到服务器的数据，可以进行修改数值，改变里面的金币，等等。但是实时交互的值，或者服务器本身有数据库校验的值，一般很难做到修改。

```  
### CE修改器下载  
```
可以在吾爱破解上下载，链接：https://www.52pojie.cn/thread-1844927-1-1.html    **解压即用**

```  
# 漏洞复现  
  
第一次，我写的详细一些，可能会对你们有些帮助。1.打开之后点击这个小电脑  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWHWgIrFapMaFguzRzXJ6J8tREicMVlUF2FvibAyEMzSQJdh3Oic6Mcxs9g/640?wx_fmt=png&from=appmsg "")  
然后打开任务管理器搜索打开的小程序找到详情数值，一般打开小程序的时候，会有一个进程内存突然暴涨，就可以确认到。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWsVE04seZNRKjwfKiaPyut7wYngwZSU0EpVjp0jewKJ8gQb8ZFBGhooQ/640?wx_fmt=png&from=appmsg "")  
  
右键，找到转到详情信息会查看到一串值，然后用计算器转换为16进制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumW74XozHaMg7LKxL1ibUIxXgeLQTIBp49G8pibiaVgbJ5JKqFyB4Fibib3qng/640?wx_fmt=png&from=appmsg "")  
  
选择该进程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWH4nyCCR46L0jDNtzZ2vPticXhkhbziblgt4Xvmexf6gJzQLZH5MxsmpA/640?wx_fmt=png&from=appmsg "")  
  
)选择未知初始值，点击首次扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWC6rcu7t7bMYQ5Tma0ZMyJEaIXLMHUXdzLpm10ez4wpXC36LEic9iamhQ/640?wx_fmt=png&from=appmsg "")  
然后购买商品，点击减少的数值，再次扫描，多扫几次，最后出现一个或者几个或者十几个内存地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWFPeBYnutGrMiafpeFedFicDxnxTo5PiaGZbznEHRrFpOZNR9aBSAAdfqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumW3aESx7Hk6degxPuTTiaLpa1iaeMHIgobOgsR3w6iayicahqlC7gkls162w/640?wx_fmt=png&from=appmsg "")  
  
双击，修改，在游戏中在改变一下该值，领取金币或者消费，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWOBFYpU6sicHJLmqJ4LongrjSAsaAGcwDtRkB1byb01br5FScOoZASfg/640?wx_fmt=png&from=appmsg "")  
此时便修改成功，再次消费，确认修改成功，这样的话，这个基本就算是一个漏洞了， 便可以进行提交，看看漏洞平台怎么说。ce修改器还有一些高阶用法，修改汇编代码等等，都有不同的效果，各位可以去哔哩哔哩学习十几分钟，大概看一下就行。这个漏洞比较简单，没有涉及很多，但是一般内存修改，只要会查找值，就行了。  
# 修改之后的使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWreC2YW1NCnZCOU87hHa4NhSl2rbYRyicbLGL0FX2pnriaE8jiaic11JRsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWqY46O1ib1g5yDtWC4ezDT5S7HpVCiaOCiaMoMx6UCUlFIfP9HbmSicqJXw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWOib6LbsB0dIC8aPuKj8TVTeNUbpuCfic5Skw8lmGGyuvRhg3cQDXQiaWg/640?wx_fmt=png&from=appmsg "")  
# 总结  
  
对于这个工具的使用，作用，大家都可以尝试一下，我是觉得也算是一个新的尝试。这个不仅仅限制于一些高阶漏洞，这个可以挖掘一些逻辑漏洞，像一些有SRC的公司，中的一些游戏，都可以尝试挖掘，网页端也可以，这种方式也可以尝试越权，支付绕过sign，签名等等，用处很多，希望对大家有所帮助。  
```
```  
  
  
