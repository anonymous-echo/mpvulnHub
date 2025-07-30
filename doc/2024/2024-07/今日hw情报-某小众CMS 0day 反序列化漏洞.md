#  今日hw情报-某小众CMS 0day 反序列化漏洞   
private null  轩公子谈技术   2024-07-24 19:51  
  
此系统为.net开发，即为viewstate反序列化漏洞。  
  
通过爆破获取到默认key，利用yso，构造数据包可以执行任意命令或内存马。  
  
[NET系统漏洞｜view state 学习](http://mp.weixin.qq.com/s?__biz=MzU3MDg2NDI4OA==&mid=2247489655&idx=1&sn=94c5c6cb82abaf400fad32a1ed907dd5&chksm=fce9bfb8cb9e36aea637e8b8e52f4a43d87e06d8937b18a21850fd4703e37f0ef16f627ea86f&scene=21#wechat_redirect)  
  
  
[NET系统｜RC到注入内存马](http://mp.weixin.qq.com/s?__biz=MzU3MDg2NDI4OA==&mid=2247489684&idx=1&sn=6859e3e317a0c3bdef8f86e04db7568f&chksm=fce9bf5bcb9e364d2599ea1009772ba7a81334cf4f29b3918453f6450cf9f1fb602a0175977d&scene=21#wechat_redirect)  
  
  
搜索历史漏洞，仅存在sql漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZ17jQUziaQlzibiaBkgHXY3sdMHAkQN4EoeeianmJKXicWDU9s8crGquudZS2wUbUA21ZftSlTbW5wSJA/640?wx_fmt=png&from=appmsg "")  
  
特殊时期，所以先码死  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZ17jQUziaQlzibiaBkgHXY3sdOFab0LsM9pPNVp9aHw5JtvqW1oytoSPRxBqUqzn8odah6ticDOOU2tA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZ17jQUziaQlzibiaBkgHXY3sdPBtoW9lf9qxR8kQ8MjRwuN4qfHxLwH1iamxUUnTmktuKpo6WnB3uD1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZ17jQUziaQlzibiaBkgHXY3sdDNnwnHpgDo8o8Rw96qL9Ic1FoHRaIkljVjKrEialhzRP24ibv7FyvVeg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZ17jQUziaQlzibiaBkgHXY3sdE11OkZtwI2ibOziccs85FTeX4lK2TgmGNEzKMvV46sg0LczPtItaDvQw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
