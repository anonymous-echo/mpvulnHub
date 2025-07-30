#  Yakit + xray联动探测漏洞   
 sec0nd安全   2025-05-14 12:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
如有侵权烦请告知，我会立即删除并致歉。谢谢  
！  
  
文章有疑问的，可以公众号发消息问我，或者留言。我每天都会看的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
   
  
> 字数 261，阅读大约需 2 分钟  
  
## 前言  
  
虽然Yakit自带很多插件，但作为从Burpsuite转过来的人，还是习惯通过抓包工具 + xray的形式走一遍功能点。我的第一个SRC漏洞就是通过xray找到的，所以对它还是很有感情的。  
  
毕竟，有的时候就是虽然两款工具功能相同，但就是有的能检测出漏洞，有的不能。还有几分运气的成分。  
## 过程  
  
xray开启监听  
```
xray webscan  -listen 127.0.0.1:7777 --html-output test.html
```  
> xray的证书安装就不写了  
  
  
Yakit MITM配置下游代理  
```
http://127.0.0.1:7777
```  
  
![cbad9a18c5621c3f70f107e17f460e2b.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaIt1qicnRJHtaIPZZGXHfWRvR9JQicLIuV6oot9ria7MBxVMDPWrdbf4ZAfe2wU2ictLDR9ia5yQR2rNg/640?from=appmsg "null")  
  
cbad9a18c5621c3f70f107e17f460e2b.png  
## 注意  
  
我用Yakit的时候遇到了一个bug，不知道新版有没有。  
那就是下游代理只能在上图的位置配置。  
  
点击下图的下游代理  
虽然能页面上清空了代理，但其实还是走的7777端口的代理。  
![c6776e2a558ce187944bf2ac15ddd8c7.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaIt1qicnRJHtaIPZZGXHfWRjqcz0OKAmKVFVN9f3vatotL2C1lq6aJsqz8aiawr96dquopKWPLXfVQ/640?from=appmsg "null")  
  
c6776e2a558ce187944bf2ac15ddd8c7.png  
  
提示7777端口找不到  
![6be4f7115b2c9f06930c4b761e203100.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaIt1qicnRJHtaIPZZGXHfWRpRG9o8ddGMwctdE1cIMZD3lPtZ9VYLuStvHgCc4yQO5KD7gswqCGOg/640?from=appmsg "null")  
  
6be4f7115b2c9f06930c4b761e203100.png  
  
同理，如果之前没有配置下游代理，在这个页面配置代理，依然不会走7777端口。  
  
   
  
  
  
