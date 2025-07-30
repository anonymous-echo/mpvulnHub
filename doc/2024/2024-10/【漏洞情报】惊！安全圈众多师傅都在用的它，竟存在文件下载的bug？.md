#  【漏洞情报】惊！安全圈众多师傅都在用的"它"，竟存在文件下载的bug？   
原创 隼目安全  隼目安全   2024-10-18 22:59  
  
## 免责声明  
> ❝  
> 由于传播、利用本公众号"隼目安全"所提供的信息而造成的任何直接或者间接的后果及损失,均由使用者本人负责,公众号"隼目安全"及作者不为此承担任何责任,一旦造成后果请自行承担!如有侵权烦请告知,我们会立即删除并致歉谢谢！  
  
  
"某传"微信小程序疑似出现bug或漏洞，目前尚未得到官方回复  
  
在PC端微信小程序中任意进入一个圈子，对文件进行下载操作  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/9HKdHo8BvC2Tsj0oicft90mto04gCet9vTBORuVx74GHbYK0FqoH8vyb0gm1EJ9dibyF3g17EFCGrw3AmC4CHAdA/640?wx_fmt=jpeg&from=appmsg "")  
  
这里我们进行下载，下载后可以看见，要求我们保存文件时，该文件后缀为".xls"  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/9HKdHo8BvC2Tsj0oicft90mto04gCet9vH2Iia6raRb4aAYc4ribND7SPD3nJgCl2nejWJbEqiaF9cknxawNJn9Yiag/640?wx_fmt=jpeg&from=appmsg "")  
  
将文件保存打开后可以看见文件名与下载保存时一致，但内容却很奇怪  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/9HKdHo8BvC2Tsj0oicft90mto04gCet9vYKgZqQYibhq3sB9AbEAw0wzu7n7fJvOX4Cxn3kA5fJ46ep8CECHaCpw/640?wx_fmt=jpeg&from=appmsg "")  
  
这里我们尝试将后缀改回".pdf"，尝试后发现文件无法打开  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/9HKdHo8BvC2Tsj0oicft90mto04gCet9vibYgjsDM5MHd3x57cOm8qgsoeznxgybsE6D0sUcoZyG6UH62aoEaBWg/640?wx_fmt=jpeg&from=appmsg "")  
  
经测后发现网页版不存在该问题，有极大概率为该平台小程序出现bug  
  
该小程序在线访问pdf文件时可以正常访问，但点击下载后，保存时默认的".xls"令人疑惑，多个文件下载后所访问的表格文件内容基本一致  
  
  
初步猜测是pdf/zip等文件下载时替换成了某个奇奇怪怪的xls文件，为了防止是我们电脑的问题，我们又另外找了几位师傅，情况皆是如此  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2Tsj0oicft90mto04gCet9v9tDN8VKIYupvtMRh8ZCz2a3UtloS9pRHXScxHyvDSOzODMR7UmpkWg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2Tsj0oicft90mto04gCet9vuvR0ibhIEUrwHjF6ciaRwXp7rhBTaVNyW3oibrTsrdjxEgmGPziaDefZEw/640?wx_fmt=png&from=appmsg "")  
  
—— end ——  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/9HKdHo8BvC2Tsj0oicft90mto04gCet9vmWDZIf4cDffVNrWszj5ficSSvZWANKC0PCbvHoy4950syI0s9sIFPYg/640?wx_fmt=gif "")  
  
  
  
题外话  
  
我们搭建了社区论坛，可以在社区中分享相  
  
关资源以及思路，社区已经开放用户发布文  
  
章的权限，论坛部分资源已经在"百度网盘资  
  
源共享"群内分享过，可进群免费获取，详情  
  
见下文，社区论坛URL:  
  
  
https://www.cn-fnst.top/  
 欢迎发文  
  
  
[【重要通知】资源共享与交流社区](https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247486203&idx=1&sn=e43ef53b53aa1db54872169ad1724c98&scene=21#wechat_redirect)  
  
  
  
↑↑↑↑↑  
  
  
点击上方"资源共享与交流社区"查看相关信息  
  
  
往期回顾  
  
  
[【相关分享】ProxyCat：一款完全免费的代理池中间件](https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247486702&idx=1&sn=399e66b25b7cea1272f8ae8926a89345&scene=21#wechat_redirect)  
  
  
  
[【相关分享】低成本作弊神器？使用ESP32将通义千问AI接入学生计算器（更新按钮支持）](https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247486563&idx=1&sn=399892037d3d8a42b91fcd287f618821&scene=21#wechat_redirect)  
  
  
  
[【相关分享】低成本作弊神器？使用ESP32将通义千问AI接入学生计算器](https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247486556&idx=1&sn=b74ee1a9e70edbac276e218797deff95&scene=21#wechat_redirect)  
  
  
  
[绷](https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247486539&idx=1&sn=4118d5f656b12226f7495d468678b963&scene=21#wechat_redirect)  
  
  
  
[小学生进！黑客手把手教你制霸小猿口算天梯榜](https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247486533&idx=1&sn=88971771f6fb8d265ef1aad53f609ff0&scene=21#wechat_redirect)  
  
  
  
  
  
