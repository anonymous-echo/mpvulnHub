#  0day Telegram核弹级漏洞 ？1day Telegram Windows客户端RCE漏洞复现   
hacking  Hacking黑白红   2024-04-13 23:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vU4zibJwEqibfEf5EzGibc5U8f1qHCkCib83C54fUv6J5rmAz1p94eeVOTqUE8ZbOwVk06pvPePDOkO6KO0ZMsE0WQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
本文字数：1947｜预计3分钟读完  
  
  
  
  
Telegram是一款跨平台的即时通讯软件，用户可以相互交换加密与自毁消息，发送照片、影片等所有类型文件。  
  
**你和我聊天，电脑就有可能被控制？最早发现这则消息是在8号晚上Tg某channel上看到这个消息**  
  
  
  
  
  
  
  
文丨  
hacking  
  
  
  
  
1  
  
  
**漏洞描述**  
  
   
  
  
攻击者向用户发送特制的媒体包括图片、视频或其他文件，即可在用户无需交互的情况下进行感染  
。  
  
4月8日晚，有网页发文telegram 0day漏洞  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTzct8DmYfB0To86U14EZf3zJzmKemq8dcohBMOYibtAlQ5yYrXYBJqouf8xTcReSgTfhw2w6wPiawg/640?wx_fmt=png&from=appmsg "")  
  
  
0day telegram Desktop<=4.16.4  
  
  
   
  
  
2  
  
  
**大佬曾哥发布Twitter进行安全情报预警**  
  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTzct8DmYfB0To86U14EZf37btdoo59XIZH4CaTz7QtUoDmEC4D22XghzfrEqs6Niav0YFmnCMtYVQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
3  
  
  
**漏洞防护**  
  
  
禁用自动下载：  
  
1. 打开 Telegram Desktop  
2. 转到设置、高级、自动下载媒体文件  
3. 分别将私聊、群组和频道中的自动下载关闭，包括图片和文件  
4. 全部关闭后保存即可  
  
  
漏洞暂未被官方证实存在，因为出于风险预防，建议对Desktop版本系统进行设置以防止未知的风险。  
  
根据视频来看，漏洞仅在 Telegram 桌面版中存在， Windows 版应该是存在macOS 版是否存在还未知，Telegram for Android/iOS 版不存在类似漏洞暂时不需要进行处理  
  
具体如下  
  
  
（1）打开 Telegram Desktop转到Settings下的Advanced  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTzct8DmYfB0To86U14EZf33W8HZAuBzW7lGxusCRicYTmGaJvoMOtzyMDaW7lNohicM2PupgFwia87Q/640?wx_fmt=png&from=appmsg "")  
  
  
（2）分别将chats、groups、channels中的自动下载关闭，包括Photos和Files，之后点击save即可  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTzct8DmYfB0To86U14EZf3HqA9nZTtKBNL7eZ67g6nHv20GJjRqfkcAgicZEx5iasXMHAg1lGNkRiag/640?wx_fmt=png&from=appmsg "")  
  
****  
  
4  
  
  
**报官方发布Twitter消息表示无法确认是否存在此漏洞**  
  
  
**之后电报官方发布Twitter消息表示无法确认是否存在此漏洞，视频可能是假的**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTzct8DmYfB0To86U14EZf3IeTlEmALnFOa1m2Nj8CGUeJic6bKfLZxvs5yF8EhUk2U3tS43QUznzg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTzct8DmYfB0To86U14EZf3H1KICTnq9xZMnxe91fLJOH3czMS4wRZfUBiaM7kGZFP91qItysO9TRQ/640?wx_fmt=png&from=appmsg "")  
  
  
参考：  
```
https://mp.weixin.qq.com/s/yaXnssyndbIKbRMf0DZcUw
https://mp.weixin.qq.com/s/jg0b1A1MV94q1mkx19WDug
```  
  
  
  
  
  
  
【Hacking黑白红】，一线渗透攻防实战交流公众号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONQbd1LqAKpAlwVM9pRXpJ8iapW6J2BmBkPWnGk0hia1t6DkVC8Jrl7pvmO5aAf7Kl5HEp7pDaFGffdw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONSgp1TKd5oeaGb76g5eMFibnANHNp30ic7NtpVnU12TNkBynw2ju7RDHbYtVZibm5rjDh7VKbAEyO8ZQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
      
  
**长按-识别-关注**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rf8EhNshONTgEGpyZx7OiaI1JkST23pJPIIgiaejD1CAyicricZQeBtf4rYlib4NmVKjiah6icBHjWwOu54zq6Wvib0HIg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1 "")  
  
**Hacking黑白红**  
  
一个专注信息安全技术的学习平台  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBDEU5hJAFfap4mBBAnI4BIic2GAuYgDwUzqwIb9wicGiaCyopAyJEKapgA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBRJ4tRlk9QKMxMAMticVia5ia8bcewCtM3W67zSrFPyjHuSKmeESESE1Ig/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBnTO2pb7hEqNd7bAykePEibP0Xw7mJTJ7JnFkHuQR9vHE7tNJyHIibodA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBhibuWXia5pNqBfUReATI6GO6sYibzMvj8ibQM6rOo2ULshCrbaM0mJYEqw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&retryload=1 "")  
  
点在看  
  
