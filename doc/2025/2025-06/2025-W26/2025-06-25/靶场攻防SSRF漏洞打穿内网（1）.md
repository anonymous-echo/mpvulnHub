> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484473&idx=1&sn=72dbb861fc8336a1ec596800f5ed6f51

#  靶场攻防|SSRF漏洞打穿内网（1）  
 天黑说嘿话   2025-06-25 02:23  
  
“我愿自己是一只上足了发条的时钟，在昼夜不停的流转中留下自己充实的每一刻。”-《钢铁是怎样炼成的》  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkh3wwjHA4mBy5l1AeXERlGAcU2vlmkicuE9d6BN4u1iciazvUnCdia9lQLw/640?wx_fmt=jpeg&from=appmsg "")  
  
今天沐泽为大家带来ssrf靶场通关系列第一期！  
  
我们使用国光师傅的ssrf靶场，感兴趣的小伙伴可以自己搭建一个试试看呢！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axklw8Pibx7kHkayIWNibicVEXbDRg4Ox9Dpyibz5gvHwxb4C9DFtLUoBG1CA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkerC6GyylOK79ueXSic6CGFY8pIxTz2m2tqoDJdCtE3O8tCBKib03y3HQ/640?wx_fmt=png&from=appmsg "")  
  
  
我们先来看看本次靶场的拓扑图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkHiaq5YGye0pX1CeFBxSKcichVnoGzNmmJticLwP0Azd6YbRd9sZLGjl3w/640?wx_fmt=png&from=appmsg "")  
  
粗心的程序员做了一个迷之操作  
  
172.72.23.21 这个服务器的 Web 80 端口存在 SSRF 漏洞，并且 80 端口映射到了公网的 8080，此时攻击者通过这个 8080 端口可以借助 SSRF 漏洞发起对 172 目标内网的探测和攻击。  
  
  
  
一.判断 SSRF 是否存在  
  
能够对外发起网络请求的地方，就可能存在 SSRF，所以先判断SSRF漏洞是否存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axk5pLLT3Eia2QHt7jguzRAEmGK5QHYYhwejVgMDkFSPsaoVGoQ03q79LA/640?wx_fmt=png&from=appmsg "")  
  
   先尝试获取外网 URL 试试看，测试一下经典的 百度 robots.txt：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkcbiccibbFicuriaoCnEf2R8NcLo867YnyWiaEXJeg2hd1HOB1SL2fwC7l5Q/640?wx_fmt=png&from=appmsg "")  
  
测试成功，网站请求了 Baidu 的 robots.txt 文件了，并将请求页面的内容回显到了网站前端中。那么接下来尝试获取内网 URL 看看会有什么反应  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axk9OVyKStv9RkGLj3SpvrE4EftqibGhaAbaU09Q8tvqRyrczh4xCXUWQQ/640?wx_fmt=png&from=appmsg "")  
  
测试依然成功，网站请求了 127.0.0.1 的 80 端口 ，也就是此可我们浏览的界面，所以我们就看到了图片上的 “套娃” 现象。 通过以上两次请求，已经基本上可以确定这个输入框就是传说中的 SSRF 的漏洞点了，即没有对用户的输入进行过滤，导致可以用来发起任意的内网或者外网的请求。  
  
  
  
二. SSRF 获取本地信息  
  
我们可以尝试配合 file 协议来读取本地的文件信息，首先尝试使用 file 协议来读取 /etc/passwd 文件试试看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axk0CIo4kAibremRAWDLW8DjTVD91XOdO1UddcbpicZibrHICR8RVcTdtvXw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkibtY7mnBJbzOXksibZsoZFe8ZSnWxA9MFLbgofJlfmC8yc5ZEnnoWWlA/640?wx_fmt=png&from=appmsg "")  
  
我们再去尝试一下其他的文件如/etc/group，/etc/hosts  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkvZHEjdiajqWZjTBeLlOKgm78WGRCEFY8TYAkMBNJkZ5ibiaYEJSFAVrhQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axk2DFBvL6QtWEdcicgIkvvGKdH1K1WL7sSRsVFehP1ic0yia8tLf1OWiaibCg/640?wx_fmt=png&from=appmsg "")  
  
我们看到/etc/hosts有一个172.72.23.21的ip地址，这个就是当前服务器的内网地址，那么接下来我们就是开始对内网进行信息收集并开始尝试攻击  
  
  
  
三.SSRF 探测内网端口  
  
SSRF 常配合 DICT 协议探测内网端口开放情况，但不是所有的端口都可以被探测，一般只能探测出一些带 TCP 回显的端口，具体可以探测哪些端口需要大家自己动手去测试一下，BP 下使用迭代器模式爆破，设置好要爆破的 IP 和 端口即可批量探测出端口开放的信息  
  
  
首先在注入点输入  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkuTtIqsX0dSPReLJZDSZmjoGI9Eo4jhjqV5Moich030KqgetIRIYBXpA/640?wx_fmt=png&from=appmsg "")  
  
  
通过BP去抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkibCkIZgubeSuccTPvd2XMqegjIqFBBXGjySXrwK4aFUc6b5c7v3PXIg/640?wx_fmt=png&from=appmsg "")  
  
然后我们选择狙击手模式并在端口（图中22）位置处添加变量  
  
这里我们攻击的是172.72.23.1并在端口处添加变量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkCmEYUJOnAGVr6sTE8PuaF4fKXFRC1iaj3icooEPpruGGph8ELj8VyRNA/640?wx_fmt=png&from=appmsg "")  
  
然后在payload处选择payload类型并添加端口号字典开始攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkaJRO0QslofnOtYWrHwC6kVaedZt8WIez5SkLqLfxbkc708LVsnSYVw/640?wx_fmt=png&from=appmsg "")  
  
通过长度和具体内容来判断该端口是否开启  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkSMTbhKj9luQP0x7XqlGxINhDfsC2zOibgS1ibnpRO5GdBaxj72vKFyTA/640?wx_fmt=png&from=appmsg "")  
  
然后我们更换IP重复上述操作探测其他的端口开放情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axk8yJDsrKJSZRSaB3F07gg1MSq1cE98zGWUWPP7FeQG7XqMJeXzAm31Q/640?wx_fmt=png&from=appmsg "")  
  
以下是整理出来的具体数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkT4kJkeKib8ibmAO4IjBQDjqw2Aqlp0bs48Vr8tVEA7PDYRz7p37arggA/640?wx_fmt=png&from=appmsg "")  
  
okk,那我今日的分享就到了这里结束啦！  
  
ssrf前三关很简单  
  
后续会继续更新  
  
大家敬请期待  
  
希望沐泽有帮助到大家哦  
  
如果可以的话点点赞支持一下呗  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/T4ubpADcLWFyHuiczIFiaI5LElaSgB9axkDrPpjNsKNUhicU8Lm5AogdXaERRyBnSEGmQ1ptkwXbYvs6cHvXN4oCg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
