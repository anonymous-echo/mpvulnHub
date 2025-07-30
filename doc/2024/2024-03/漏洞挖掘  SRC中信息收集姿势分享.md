#  漏洞挖掘 | SRC中信息收集姿势分享   
原创 zkaq-杳若  掌控安全EDU   2024-03-28 12:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
本文由掌控安全学院 - 杳若 投稿  
## 前言  
  
前前后后挖了四个月的EDUSRC，顺利从路人甲升到了网络安全专家，从提交的内容来看大部分还是以中低危为主，主打的就是弱口令和未授权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfStsocse8NmzA7uyb2Jbdb27pl3v8ElIrPlibDzSqaiacscNB7gdyMHF0A/640?wx_fmt=png&from=appmsg "")  
  
在这过程中还是比较浮躁的，因此接下来的时间还是要好好沉淀一下自身的技术，学习如何提升危害到高危。  
  
下面是常用的一些信息收集思路 (不做任何漏洞分享，思路为主)  
## 搜索引擎  
  
如何选择搜索引擎是一个很重要的内容，根据需要的方向，选用引擎的方法大不相同。  
### Google、bing、baidu  
  
Google  
需要翻墙，一般用来收集一些敏感信息，用老生常谈的方法  
  
这样收集特定的域名  
```
site:xxx.cn
```  
  
我通常用来收集特定资产的敏感信息  
  
如 intext:身份证  
 intext:电话  
再指定后缀 xlsx  
 pdf  
 docs  
等  
  
另外的时候会收集一些藏的比较深的路由  
  
指定inurl:xxx  
可能会发现额外的资产  
```
我经常fofa和鹰图收集完资产之后再用谷歌语法收集，会发现额外的资产
```  
  
不过相比起Google  
我更喜欢用Bing  
，因为不用翻墙，适合我在这个懒b  
  
语法的话与Google  
同理，不过Bing  
如果用谷歌语法的话搜集的内容会模糊一些，不是精准搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSwWd3o4V7wBUBibgFdx7DkGpXpzTLL3WyDtia6SSoybyOERkCHkleASIA/640?wx_fmt=png&from=appmsg "")  
```
https://cn.bing.com/
```  
  
最后就是百度，也是搜集信息的一种方式  
```
Ps:搜索引擎一般用来收集信息泄露和隐藏较深的路由
```  
### Fofa、360q、鹰图  
  
这类网络空间搜索引擎主打的就是快速收集资产，缺点就是藏得深的路由找不到  
  
所以和Google  
这类相辅相成，一类主收集信息，一类主收集资产  
  
在这里我示范一种信息收集案例 以若依 为例 (鹰图)  
  
在这里讲解的主要是如何精炼指纹  
### 提炼图标  
```
web.icon=="4eeb8a8eb30b70af511dcc28c11a3216"
```  
  
最常见的一种指纹收集思路是图标收集  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSCj3Dld7sKb5qib7KibH89y6ognQic0xWsbiaCOuXxOILauNOx5eibMH7gtQ/640?wx_fmt=png&from=appmsg "")  
  
但是若依系统存在很多二开，往往还有其他的图标  
  
例如web.icon==”e49fd30ea870c7a820464ca56a113e6e”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSib8LYicS6whUXDh4lWpiaMTBlrt06qMh9VE64Igabnq589yCLrE5cZzjA/640?wx_fmt=png&from=appmsg "")  
```
web.icon=="eeed0dd225e44a5fe7b5f31fea185b61"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSVDpsUvAwAbnmhshQzD1fhNSWhrBcDia9SgrbdBibsibeHv0Wq5U4lB9IA/640?wx_fmt=png&from=appmsg "")  
  
当然不知这几种，只是希望大家能发散思维  
### 提炼标题  
  
最常见，老生常谈的就是  
```
title="若依"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfS2tQpcBDVVoV51D2eJWhVgTQuY1uLXZetXTVzfrQUcblibetib0P5HzbQ/640?wx_fmt=png&from=appmsg "")  
  
其实，这时候可以发现很多图标，两者是相辅相成的，通过收集图标提炼共性标题，通过收集标题找到共性图标  
  
所以还有接下的title  
```
title=ruoyi
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSUriaYfwq69OJz7t5cObMmBeazC86Ns55J8zq78WdyicAaWdYoQibz9Ldg/640?wx_fmt=png&from=appmsg "")  
  
当然还有很多其他的，大家可以自行寻找  
### 提炼Body  
  
其实也与上面的方法相辅相成  
  
部分站点的底部存在了关于ruoyi的相关内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSRY0o7LB7Fn5fqkfScIXN9KPXveic3h75hOA63H5r3qPIiayNnTSIGwNg/640?wx_fmt=png&from=appmsg "")  
  
因此可以搜索  
```
body=ruoyi
```  
  
然后就是加上title和icon一起找共性  
  
此外就需要我们多观察F12  
里的前端源码了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSibzyhhbOmKvtK6fLDyNicmNvceU60ia9aau9A9vo6hrtykYph97nAZ3pw/640?wx_fmt=png&from=appmsg "")  
  
在这里我附上我常用的精炼指纹  
```
body="window.location.href='/html/ie.html'"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSYo1YNFVbBiaf9aDzlDcf5KFWMeBIKgibAgPSe5X3JyPlv5eGxR613DRg/640?wx_fmt=png&from=appmsg "")  
### 提炼特殊路由  
  
不同的站点路由其实是不一样的，在这里的话若依站点最特殊的路由是prod-api  
  
因此我们从路由的角度来体验  
  
一种是找超链接的提炼方式  
```
body=prod-api/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSvopl9kY72iapybnuUpar1xHOC5kn2iaLk9WFYV3icoTF39Dr12cPpwGJQ/640?wx_fmt=png&from=appmsg "")  
  
可以找到站点中带有若依的超链接路由  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSVic1BmXTZIr4NNdViaTmKFlhND8N4RibZaeQsiaeas6zS7YoGx0MXSjpkA/640?wx_fmt=png&from=appmsg "")  
  
打开之后我们就可以发现确实超链接指向的是若依的系统  
  
如果收集的若依系统够多，可以发现存在二开的系统有其他的路由，比如admin-api  
 dev-api  
 等等  
  
另一种方式可能就需要用到搜索引擎去相辅相成的寻找特殊路由  
### 提炼特殊服务  
  
若依系统有时候是存在前后端分离的情况，而它的后端默认界面是这样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSjMz3tYBKCRRkNpP6jg0X5NicST45icyJHZWf4HBVHTeXZ4hwxpwrNXibQ/640?wx_fmt=png&from=appmsg "")  
  
而且就是映射在别的端口，那么我们完全可以利用body搜索相关内容  
```
body=请通过前端地址访问
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpfwDWVraCSX0RxcXhNqfSDf6mqEI6F70S74WcOjUHYZ0ZicUZlXcpCddbNu3PMewY0UuCttqdVibg/640?wx_fmt=png&from=appmsg "")  
  
有的开发后端映射出来的默认内容是会修改的，这时候就需要我们结合上面的内容相辅相成的进行寻找以及收集，提炼共性  
### GIT提炼  
  
很多开源的若依二开可以在github  
找到相关的项目，往往修改较多的就是默认的prod-api  
为主，可以按照上面的内容去提炼，这样可以直接收集各个二开若依系统  
## 总结  
```
当然收集的姿势肯定还是有的，网络安全的未来就靠你们了
```  
  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+靶场账号**哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[Xray挂机刷漏洞](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247504665&idx=1&sn=eb88ca9711e95ee8851eb47959ff8a61&chksm=fa6baa68cd1c237e755037f35c6f74b3c09c92fd2373d9c07f98697ea723797b73009e872014&scene=21#wechat_redirect)  
  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[代码审计 | 这个CNVD证书拿的有点轻松](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247503150&idx=1&sn=189d061e1f7c14812e491b6b7c49b202&chksm=fa6bb45fcd1c3d490cdfa59326801ecb383b1bf9586f51305ad5add9dec163e78af58a9874d2&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
