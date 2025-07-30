> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU4MjYxNTYwNA==&mid=2247487834&idx=1&sn=ab354dd326ae72b7c8f31e4dc3c183e7

#  新手练习向——基于文件上传漏洞获得网站shell权限  
原创 白  白安全组   2025-07-19 06:18  
  
注：DVWA靶场虚自行搭建，网络搜索即可。  
  
任务一、实战-基于DVWA的 low级别演示文件上传漏洞  
  
首先开启虚拟机打开靶场。登录到靶场设置级别为low  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFBY5uicUaClicMdXfdvDNkjzrFtcCv2rDibsSIZPLaQPTwNXVsCSWKKTkA/640?wx_fmt=png&from=appmsg "")  
  
然后我们这里传送一个文件上去  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFmt9pfibDrFyhPiaZR6ojszIyHoqCTq6wwr1zhocE8Eyjmxgibgqfgb99A/640?wx_fmt=png&from=appmsg "")  
  
将我们的含有一句话的php传上去  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFGzOONM7Cb9uHqcibH8pa9HzcxYRRNj3pHPY9mPDr0HvXicdu5vEib1gmA/640?wx_fmt=png&from=appmsg "")  
  
我们打开蚁剑连接一下上传的webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFicX9DTKpTarogYicyP8rel9l5QtoPibFNpaFwh7x3JeibhZjbeFr8ESCYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFIl2wfMnOyecy5mr6x43q6YbxYyuicuRib8TVrbd70dYDAoVicVOR2yB5A/640?wx_fmt=png&from=appmsg "")  
  
这里显示已经连接上了，可以看到可以读取上面的文件了  
  
任务二、基于 DVWA 的 Medium 级别演示文件上传漏洞  
  
首先我们调制相应的等级  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFIPgwwEYTaAh9QlQ75s6gXO2Uhs1PRxpdOjb9jcWDVDwgpXib8ZIBRxw/640?wx_fmt=png&from=appmsg "")  
  
这里我们需要用到burp来抓包处理了  
  
因为这里是基于前端的一个验证，我们只需要绕过前端的一个验证，所以这里我们先将webshell复制出来，改为png后缀同时上传抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFfUH0fwdQUMb8XhL209f5hDPsBkjckqEySmwcibbQRab2BCMH9BMe3xg/640?wx_fmt=png&from=appmsg "")  
  
然后上传打开burp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFIkQ2w2JnAHMLQBZibWWVibgEc0nL1nGo46rNWB9FKTpkiacQnQTbJWHhg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFSf1l4UpHeCmheOaoFc0W0vbPL13T0ApYakXZI7uvvibDvdF3mpvZT9g/640?wx_fmt=png&from=appmsg "")  
  
截取了数据，修改文件后缀  
  
先发送到重发器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFwnticlqzLLhGWmVfiblpzlPor90sXPO04C4YkWlKa3D0knPbCQoa9ib6Q/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到我们上传成功了，我们利用蚁剑连接看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFMBkvJ2mS6xxd7ACWG39a1QYUNH14NoeM2ibVIqCV0qsq1ATarlm4zjw/640?wx_fmt=png&from=appmsg "")  
  
连接成功  
  
任务三、实战-基于DVWA的High级别演示文件上传漏洞  
  
我们将防御等级调制high  
  
我们先上传一个木马试试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFo2KvHlWUo6obtgqd0xjVBaT5rYhgiaShB3h37ibPNvZY1xxpnllCelgQ/640?wx_fmt=png&from=appmsg "")  
  
这里提示我们只能上传图片格式的文件，我们可以使用图片加一句话的混合，可以利用cmd命令加工  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFDFZDJDJGt8Pxv0DEgdbknicvrhSzhew2mVKuv6yuI3GEUt5viaf9kwZQ/640?wx_fmt=png&from=appmsg "")  
  
我们上传文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFPadGLOdZKfag5twcKsOnWnEesea4x4aSl1qjwLFLx6pW3Uiao1icG8nA/640?wx_fmt=png&from=appmsg "")  
  
上传成功后，我们无法直接修改，我们利用另一个文件包含漏洞，不过我这个靶机的php版本较低，也可以使用%00来完成，这里我使用文件包含漏洞  

```
192.168.0.107/DVWA-master/vulnerabilities/fi/?page=file:///var/www/html/DVWA-master/hackable/uploads/1.jpg
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFSMJmf9BAGHESTzaRBB7crpWB6K9Oh1nE2IicYEsGI0y8KCbqKS8ChAg/640?wx_fmt=png&from=appmsg "")  
  
访问之后可以看到都是乱码，这是图片被解析为了php文件，我这里直接把这个地址加载到蚁剑中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFBzc7rqcLZxQHTiaHVWvT46FmdRDibia2mEo0eUI5ibX6ROysP2L7sHTbZw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFRC4sAZQ5Y5m6nHKPX2ozuYLIMNfNCQ1bicDvLSeF5RxTzwJmTmp4Xeg/640?wx_fmt=png&from=appmsg "")  
  
这样就可以完成了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUaV3gYIsljFsibz5zliaz2jkFUxq0Ym1wkm0U5wrQe2TaR8SyCH9FhGHXAmibmxLFeVpXaY2zjON9TyQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
