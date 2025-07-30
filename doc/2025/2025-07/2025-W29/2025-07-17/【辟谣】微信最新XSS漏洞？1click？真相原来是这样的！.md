> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNjQyODY5MA==&mid=2247487268&idx=1&sn=32c18f49eefc14d6b05cb8af3b337109

#  【辟谣】微信最新XSS漏洞？1click？真相原来是这样的！  
原创 Flowers aq  flower安全   2025-07-16 12:11  
  
前言：  
  
本来前天就写好文章了，但是微信没给过审..  
  
前天早上发现很多安全群都在传一段代码，说是微信最新漏洞，好奇的我也赶紧看了看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIUGktEq4vojEIEVibXp8b7DtMYn4fHKIYyicSzgVuCRSKwO5ZqXI8KqjNw/640?wx_fmt=png&from=appmsg "")  
  
具体功能是，点击自定义文字的标签就会跳转到发送这串代码用户的私聊界面自动给他发送代码中设定好的信息，例如：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/licEEwv67W2Y0cINAWd0kc6KdMJm63VIUWdTp5Lrs6lZ5dVv9PSpro6PD4RweTUKJOO4DaAKDMiaVZgLLZT2ZAlw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
正文：  
  
那我们分析一下这段代码就可以知道：  
  

```
<a href=&#34;weixin://bizmsgmenu?msgmenucontent=test&msgmenuid=960&#34;>Test</a>
```

  
- weixin://bizmsgmenu：微信内置协议，用于触发公众号自定义菜单功能。  
  
- msgmenucontent=test：用户点击公众号菜单后，公众号后台就会收到test这个文本内容。  
  
- msgmenuid=960：数字是自定义的，意义就是使公众号号主及开发者区分不同的菜单按钮，可以理解为一个标记。  
  
- <a>标签的文本 (`test`)：用户聊天窗口可显示的点击文字，一般为蓝色超链接的样式。  
  
  
所以，经过分析后大家就可以得知此自定义代码其实就是微信公众号的一个功能，代码还能写成：  

```
<a href=&#34;weixin://bizmsgmenu?msgmenucontent=选项A&msgmenuid=101&#34;>A</a >
<a href=&#34;weixin://bizmsgmenu?msgmenucontent=选项B&msgmenuid=102&#34;>B</a >
```

  
效果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIUMzHtEJW7Dgo7ggNibicTy8NHEDVZvPItEVteib4Z9Kv9yWZTcvO8RicQGw/640?wx_fmt=png&from=appmsg "")  
  
服务型的公众号就能通过此自定义功能去实现订单查询，机票查询等等功能！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIU8pIDxWVbFXCC5TzwzXbC0Z3SmBTYn78t0JqjBvR31wzvwBCjW1czNA/640?wx_fmt=png&from=appmsg "")  
  
很多公众号文章都把此功能加上了“  
最新漏洞”的字样，实际上此功能也不新，比如下面这个公众号，早在23年就已经发布过相关功能文章：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIU6nMn01RNPpfURAR4zwxx8ke29XTozoIiccecSHDAEKOzI22PePmMStQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIUbwjsPtO0f6z7NIrzOODCzcZ1woacvbEmOyQOZfZaG9HF3JTBh1qb7g/640?wx_fmt=png&from=appmsg "")  
  
总结：  
  
所以综上所述，  
此功能并非微信最新漏洞，其实准确来说此功能也并非漏洞！功能虽不是漏洞但也具备有一定的  
迷惑性，所以大家遇到以下样式的超链接信息一定  
多加防范及辨别，最好的办法是  
直接复制这条链接，到粘贴板看看它的具体内容。  
  
示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIU5y4Ql4iaBcBjpbjOJVgZ7ozPZbp9ESZQXdK06NkIRBQU1w2c9ibKibmrQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIUnKrQ7eNz50fKrts6MpJrH6pFJmibDMBWXicKfkUibnWR6ob8Dicxg6AtKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIU2dBtI3A8uiclaC99r03PV5RRibuSVczIcFUK1JJU6MchEQ5st6uAHiaCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIU2CdbUR9HLvlicfa8AXW6TFSTyXUUshn9FnJIxIcAvvrRbW7XM304Bww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/licEEwv67W2Y0cINAWd0kc6KdMJm63VIUHaFEqmmOd87PB1IRL4icy0bDLaJnibMQbFlq50N2s5yI3tdQREWrpt1Q/640?wx_fmt=png&from=appmsg "")  
  
