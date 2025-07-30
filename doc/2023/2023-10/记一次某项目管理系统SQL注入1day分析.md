#  记一次某项目管理系统SQL注入1day分析   
湘安无事  湘安无事   2023-10-10 00:00  
  
**声明：**  
该公众号大部分文章来自作者日常学习笔记，也有少部分文章是经过原作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关  
。  
  
在HW值守期间，监控设备上捕获到了几条比较眼熟的POC，对已经掌握的情报进行了对比之后，应该是已经确认的某道SQL注入的利用POC。应要求需要写溯源报告，涉及到本地分析复现以及EXP相关内容，于是乎就开始了。  
# 0x00 简单梳理  
  
在开始之前简单大概过了一下某项目管理系统的目录和路由模式，这对于理解整个原理个人认为有很大的帮助。下面对主要的几个目录做一个简答的说明。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fTDErrvNIm5XP9OIhh9EYkVp9XyIiaR2icZGhPxa0oiast19xicBbLmUg4Q/640?wx_fmt=png "")  
```
- config下面存放了运行的主配置文件和数据库配置文件。
- framework里面是php框架的核心类文件。
- module下面则是存放了具体的模块。control.php则是各个模块所有页面的入口，相关的方法都在其中。
- www目录则是存放了各种样式表文件，js文件，图片文件，以及禅道的入口程序，index.php是整个程序的入口程序。所有的请求都是通过这个程序进入的。

```  
  
对于路由模式，它总共有两种，分别是PATH_INFO、GET方式，其中GET方式为常见的m=module&f=method形式传递模块和方法名，而PATH_INFO则是通过路径和分隔符的方式传递模块和方法名，路由方式及分隔符定义在config/config.php中。这里所有的采取默认配置也就是PATH_INFO伪静态路由，而实际上两种路由模式是可以同时使用的，具体感兴趣的可以去看看网上的文章讲解。  
# 0x01 漏洞分析  
  
根据所知道的POC利用的请求路径，快速定位到了/module/user/文件夹，看了一下视图文件，主要是前端代码，以及前端参数的传递，对比了一下代码和站点登录界面符合。  
  
直接看目录下的control.php,这里面有我们根据伪静态路由规则可以定位到的方法，在#848行的login方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23flKe8wvm55EmvvHAtcAhTu2GoRME0pFv5zYATFMWiafGVY67uL1EBJibQ/640?wx_fmt=png "")  
可以看到POST或者GET来进行传递参数都是可以的，并不会因为默认配置影响参数的获取  
  
首先会调用checkLocked方法，跟进查看代码，主要是对当前登录的用户是否被锁定做一个简单的判断，具体的判断方法就是计算当前登录时间和锁定时间的时间差是不是仍小于锁定的时间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fHESOEhWIlygRDc6zyDE7a43nUr2ficCKyPJdiaOyUhvRl4rpxOMcXK5g/640?wx_fmt=png "")  
  
接着往下直接看到identify方法,该方法在同路径下的model.php文件中。看遍了整个方法，涉及到数据库查询的地方都采取了预编译的防御措施，并没有找到能注入的地方。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fRe64EMI2eo1zrka6naEEp3W0KDR5GW1XdcickfE8VMOUIA94QowlcXQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fqiaPUIKIYibzGK882Jt0Z37Io6lg1tfb9YPTQQPFOlN2DeJULdWJBiceA/640?wx_fmt=png "")  
  
这个地方卡了挺久，一直没有找到漏洞产生点；漏洞的利用路径并没有错，不知道问题在哪里。后面重新梳理了一下目录，突然想到/www/index.php,作为所有请求的入口，说不定有点什么特殊的地方，果然，在全局搜索和var_dump全局打印下找到了点。  
  
/www/index.php,作为入口，每一个请求都会调用它；来仔细看一下代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fp6oVGowEicBO2c543RTdeQHGaJgubE7AapCE5WnBcGCQLwEeIUicoRyQ/640?wx_fmt=png "")  
  
首先会包含framework文件下的框架的核心类文件  
  
之后就会调用router类中的CreateApp,跟进，定位到/framework/base/router.class.php,根据传入的参数会实例化一个router类对象，,又因为router类继承自baseRouter，所以在实例化router类的时候会调用__construct()魔术方法，也就是父类的构造方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fiaJYMHNaI3H4eCCiblEAzvEaEb6WU0ich5p6ibs8kRv7D5eqN5RypO5bfw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fgSAibuF6IM8t75wu60DXt4EtWC0zafu37nCn3btDE4zto0h6tTlKhew/640?wx_fmt=png "")  
  
看一下该构造方法，在初始化的时候会调用很多本类中定义的方法，像设置目录的分隔符，基础目录等。在经过逐个方法跟进查看之后将视线放在了setVision()方法上面，跟进，一眼就看到了漏洞所在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fVeAk5DU8rhpqYw2l3rpV2RsSic04Nj80AnCpoiclY0CanazvEbf6CmSQ/640?wx_fmt=png "")  
  
可以看到这里手先获取了account参数，只要已经安装过该系统，那么就会进入第一个if判断当中，这里虽然采用了预编译的方法和数据库进行了交互，但是其中的参数却是用了字符串的拼接方式，那么毫无疑问字符串拼接并且没有过滤的情况下，很轻易的就能够进行SQL注入的利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23fj1KIKP4ET4KArvVjCDK2D2Uh1MrfBib7g7NZVDLu0dzjCPAHPx9GOxg/640?wx_fmt=png "")  
所以实际上这个漏洞的利用栈是：  
```
/www/index.php(34)
->/framework/base/router.class.php(433)
->/framework/base/router.class.php(410)
->/framework/base/router.class.php(702)

```  
# 0x02 漏洞利用：  
  
事出匆忙，EXP简陋，后续有时间再好好写一下了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvNxSW6ujhmq3lVRia57y23flw4LSsnic8v0iaO51E5mIoTI29ulcicic4hyZwvMiaKUEJuuLkfgw6LHxPg/640?wx_fmt=png "")  
  
原文链接  
```
https://forum.butian.net/index.php/share/1788
```  
  
**|**  
**知识星球的介绍**  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。添加下面wx加星球可享优惠  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
一些实战报告，截的部分  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62RcLSRwZcEVNtIZkzdBc6oFT9jYPTSicI2dfuibvXY2XkqPEcmFtWPIxw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62RB3woW60WbOxWFuYycTic8ltSWVvXRCHcpLIfl3tnaUI4rArq2YTPhw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62TzMgcj8bnia1VDlFiaE5HHo8DGBibrfGYLJibnlEZ8MaJD1H5bNjUM4WiaA/640?wx_fmt=png "")  
  
  
一些1day的poc,这些也就是信息差，不想找可以让wk帮你们嫖,群主也会经常发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62u6rIc801vEhGFYFsVtzrSKobQpybfzZvtmwOUjLStelMbJ5yg3Ouow/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62oKLUAWOIwkcYbWfmE1JNBma2h9sEsJz7T6SRBOqz72gz9Cy0K7rlyQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62vibbG0Nu1NhibkJcshXVDrklAYuXlTIK7Frkia05hmQZRAXEgpxF0MHOg/640?wx_fmt=png "")  
  
一些共享的资源  
```
1.刀客源码的会员
2.fofa 360高级会员
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
技术交流可加下方wx  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/S2ssjS1jNYsH9Jqc2oFlBRnJHSLLwNsCg8qFbg1wQiaUcIicmO873ShNoVUj3DtGsZZy1iarbDibSLGhBFzFL1eXnQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvS1u1PKCurEmuM61nGSElnNalHCy4YicPa9bZ23vMDPHzQPDxybG50b760tL8KcAYTGjBicGocsdXw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvM6WiaR5ibLImBVXffTWBPcwFRclvucl2KDBy7oCHGic78sP8CjxYf2QtRQNAxgn0BjfaLSH0ruUlCw/640?wx_fmt=jpeg "")  
  
  
