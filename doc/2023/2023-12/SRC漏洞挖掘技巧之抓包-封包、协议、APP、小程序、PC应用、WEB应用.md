#  SRC漏洞挖掘技巧之抓包-封包、协议、APP、小程序、PC应用、WEB应用   
Cheetach  湘安无事   2023-12-10 09:40  
  
## 前言  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td width="557" valign="top" height="62" style="outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><section style="margin-bottom: 15px;outline: 0px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 14px;color: rgb(217, 33, 66);visibility: visible;"><strong style="outline: 0px;visibility: visible;">声明：</strong></span><span style="outline: 0px;color: rgb(106, 115, 125);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;font-size: 15.3px;letter-spacing: 0.544px;text-align: left;text-indent: 2em;visibility: visible;">这里是由零信任安全实验室组建的一个知识平台，平台有批量验证的脚本、工具以及一些漏洞的POC，后续还会分享网络安全资源（漏洞挖掘文章 工具 资讯<span style="outline: 0px;letter-spacing: 0.544px;text-indent: 30.6px;visibility: visible;">）</span>以及SRC漏洞挖掘案例分享等等，资源多多，干货多多！</span><span style="outline: 0px;color: rgb(106, 115, 125);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;font-size: 15.3px;letter-spacing: 0.544px;text-align: left;text-indent: 30.6px;background-color: rgb(233, 237, 239);visibility: visible;"></span></strong></section><section style="outline: 0px;color: rgb(106, 115, 125);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;font-size: 15.3px;letter-spacing: 0.544px;text-align: left;text-indent: 2em;visibility: visible;"><strong style="outline: 0px;visibility: visible;">请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者和本公众号无关。工具<br style="outline: 0px;visibility: visible;"/>来自网络，安全性自测。</strong></section></td></tr></tbody></table>  
  
****## 作者：Cheetach  
  
```
基于网络接口抓包-网络接口
基于程序进程抓包-程序进程
基于数据协议抓包-HTTP/S&TCP&UDP
基于应用对象抓包-APP&小程序&PC_UI
基于系统使用抓包-模拟器&WIN&LINUX
基于应用对象封包-WPE动作数据包重放通讯

工具介绍
Fiddler：
是一个http协议调试代理工具，它能够记录并检查所有你的电脑和互联网之间的http通讯，设置断点，查看所有的“进出”Fiddler的数据（指cookie,html,js,css等文件）。Fiddler 要比其他的网络调试器要更加简单，因为它不仅仅暴露http通讯还提供了一个用户友好的格式。

Charles：
是一个HTTP代理服务器,HTTP监视器,反转代理服务器，当浏览器连接Charles的代理访问互联网时，Charles可以监控浏览器发送和接收的所有数据。它允许一个开发者查看所有连接互联网的HTTP通信，这些包括request, response和HTTP headers （包含cookies与caching信息）。

TCPDump：是可以将网络中传送的数据包完全截获下来提供分析。它支持针对网络层、协议、主机、网络或端口的过滤，并提供and、or、not等逻辑语句来帮助你去掉无用的信息。

BurpSuite：是用于攻击web 应用程序的集成平台，包含了许多工具。Burp Suite为这些工具设计了许多接口，以加快攻击应用程序的过程。所有工具都共享一个请求，并能处理对应的HTTP 消息、持久性、认证、代理、日志、警报。

Wireshark：是一个网络封包分析软件。网络封包分析软件的功能是截取网络封包，并尽可能显示出最为详细的网络封包资料。Wireshark使用WinPCAP作为接口，直接与网卡进行数据报文交换。

科来网络分析系统：是一款由科来软件全自主研发，并拥有全部知识产品的网络分析产品。该系统具有行业领先的专家分析技术，通过捕获并分析网络中传输的底层数据包，对网络故障、网络安全以及网络性能进行全面分析，从而快速排查网络中出现或潜在的故障、安全及性能问题。

WPE&封包分析：是强大的网络封包编辑器，wpe可以截取网络上的信息，修改封包数据，是外挂制作的常用工具。一般在安全测试中可用来调试数据通讯地址。
```  
  
  
**演示案例：**  
  
WEB应用站点操作数据抓包-浏览器审查查看元素网络监听![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmnWmOV5tw67RgIgCCZHshz6P5ltoSkzuQR2uSvKxpXeGSTpbQtibiaeMA/640?wx_fmt=png "")  
  
打开一个  
站  
点  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmDn0PZEpaTDlZAfodJLgMF1HQxrvMaoCsOAibZBMAuov7gNiaiaM3oPvIA/640?wx_fmt=jpeg "")  
  
然后F12，点击Network，然后这里会加载网站所需要的数据包以及数据  
  
  
**APP&小程序&PC抓包HTTP/S数据-Charles&Fiddler&Burpsuite**  
  
APP抓包：安装好手机模拟器，然后导入证书，接着配置代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmvB41o08oMnIuYwsyiaHMLmZYU4FdzKobwGaficQ96zvTU7NBIkGr5qsw/640?wx_fmt=png "")  
  
即可抓到手机的数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmldM4wUYBDxmTIKxgFoMBGC8aicwAeibrGOrhrRhI3oKicv5FIUqVyfHPA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmNNC2ypzGgmXlfJsAxZDPEg9Wagb1giaiaROcBuYun6tia98icXlm8jkv6g/640?wx_fmt=png "")  
  
****  
**小程序抓包**  
  
使用Proxifier全局代理，然后设置代理服务器为bp的服务器![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmgbD4qazSNqmKc4ImCtRiax98qKRKfWOVqmG8ndPLAfqR0wCI5dH2PjQ/640?wx_fmt=png "")  
  
  
登录微信，点击小程序然后就可以抓到包![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmiccDFsNILREgkibMafOf0icDPnaHXVUyTzQ5qX6jw8FZe8KZliccZgicpFw/640?wx_fmt=png "")  
  
  
  
**程序进程&网络接口&其他协议抓包-WireShark&科来网络分析系统**  
  
打开科来网络分析系统，然后选择Ethernet 2接口![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmCB17kO53OOT4ldy6QMHBuObqwlAzSZyOBAicZb6YHzeIiafDwG4G1akg/640?wx_fmt=png "")  
  
  
打开PC应用，然后进行抓包![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmPawB7tvRtcN4YrCYV7wZJmrO2NSncpet6IfMkNFaFTQc6rns9oyKjg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmZHqyeumuWsOftyZDTe98EMQRTsiakpy1x0XdTwJeqtibdqicjiaMvIfNsg/640?wx_fmt=png "")  
  
  
可以看到我们的应用进程所产生的数据包都会被抓取到，并且显示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAm9eDB3PX4Q5d8nVLlvlkHDNicwD8aWgPYd3l9jYLalcvdTWVBcUGZcibA/640?wx_fmt=png "")  
  
点击协议，选择http协议，可以看到数据包  
  
通讯类应用封包分析发送接收-WPE四件套封包&科来网络分析系统  
  
封包技术：更直观的观察到每个操作的数据包  
  
应用场景：有一些app（比如说游戏）里面是不走http协议的，这个时候可以用封包来进行观察数据包，当我们在app里面获取到一个目标服务器的真实ip的时候，我们可以扫描这个ip的端口来进行资产获取  
  
app->ccproxy->wpe监控ccproxy进程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmIMoZrsUL1SnMToqsaYwlXBaIHkuBD5fEbkXVgNEFy1uMeegMyic9nBA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmECMS0iczWYYlO5X50PiccJprs6Ga7x1VfYb89oTGJsHKWGNfqyrpp9Xw/640?wx_fmt=png "")  
  
在代理机器人.apk里面设置好ccproxy的代理，然后开启![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmC3oomqD6e2fVCQibJUiawL7L0EdjxAVic91CKZ2XPtRnLstOH3qYTAwlg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAmmp4uMgVOkjKrfMf7pN7zg28bGW5PQGo1r9VFK0Yr4iap6xhZNFvZliaw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/txT26ZyLdUTdDicHvyq6I30Oq6MvD8mAm73ibBGeOuyrNNSC6AQ04m9z1tdXX4ZXQ6pDRGG9uyIibgiaYyaE4ibrFSA/640?wx_fmt=png "")  
  
  
使用wpe监控ccproxy进程，开启抓包，成功抓取到所有的浏览包。点击停止，就会记录抓包开始到结束的数据包  
```
#环境配置：
1、安卓模拟器安装搭建
逍遥，雷电，夜神等自行百度下载安装
2、工具相关证书安装指南
Charles
https://blog.csdn.net/weixin_45459427/article/details/108393878
Fidder
https://blog.csdn.net/weixin_45043349/article/details/120088449
BurpSuite
https://blog.csdn.net/qq_36658099/article/details/81487491

1、为什么要抓包？-抓包应用的资产信息进行安全测试
2、抓包对象有那些？-小程序,APP,桌面应用,网站应用
3、抓包协议区别工具？-有部分应用不走HTTP/S，需要用到全局协议抓包
4、封包和抓包不同之处？-零散整体的区别，封包能精确到每个操作的数据包
```  
  
进技术交流群可加下方wx  
  
****  
****  
**|**  
**知识星球的介绍**  
  
  
湘安无事星球部分内容预览在线链接  
```
https://docs.qq.com/doc/DUEVsVWhaUk51VUlr
```  
  
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
  
知识星球一次付费，后期都是永久免费续费的！！！  
  
加入知识星球之后，可享受其他永久两大圈子"知识大陆+纷传"  
  
一些共享的资源  
```
1.刀客源码的高级会员
2.FOFA在线查询与下载，key使用、360quake、shodan等
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYsHR6CaxF0VtiaIhM3XMm8EjWtzeq6cdnCdf0TsTF7FR6ukMZr4S9KUYDgKicicS9PIHpermh1CgYg3w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
关注下方公众号，输入"  
xaws"即可领取安全类电子书籍一份  
  
  
  
