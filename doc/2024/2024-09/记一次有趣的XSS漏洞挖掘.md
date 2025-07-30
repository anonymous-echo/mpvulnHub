#  记一次有趣的XSS漏洞挖掘   
 船山信安   2024-09-26 00:00  
  
### 功能点一  
  
首先这里的话是存在一个简单的功能点，就是可以发布自己的一个作品，这里挖掘的时候想法肯定就是插一些xss的payload（因为我们就是挖掘xss嘛），所以的话就插了一些payload进行测试，意料之中，肯定是没有反应的。但是我们肯定是不能放弃的，因为在挖掘的时候很多漏洞可能是组合在一起产生的，所以我们可以多一些脑洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMdskVLkX7eo9z5ibPhIhvbPvwolV4pc878Wiaf5QL3bubBansibrPvibsKQ/640?wx_fmt=png&from=appmsg "")  
  
这个name参数就是我们的作品名称。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMd0zDdcdqls5C3iaNrBNSIU2MvKFtrDPclntibRUjhIDCSqX0LXSib02tQ/640?wx_fmt=png&from=appmsg "")  
  
发出来的效果就是这么一回事。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMwancSRAv8tjGXibRSB9ItiaPxo5icqucOnqwKHibDpeAIicgjC4CUgjEdrw/640?wx_fmt=png&from=appmsg "")  
  
然后呢，这里没有发现漏洞，那么我们继续测试其他的功能点。  
### 功能点二  
  
这个功能点也是很常见的功能，就是评论。评论区一般都是xss的高发区也是重点防护区。当然我们也是可以进行一个简单的payload测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnM6Ncl9BGcEwXqO7MP1aiaQia9av2LuVf6vdxCovZyo0eI15oWRz4qyolw/640?wx_fmt=png&from=appmsg "")  
  
一样的没有任何反应，但是这里的话我在看别人的评论的时候就发现了一个好玩的事情，如果评论的时候，我们评论的内容是该网站的其他作品的链接，那么它会自动转换为该作品的名称，一个a标签（外站的链接不行）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMkkIsj1nDfZ3glZVcbcqc7MhwzJaNUwY92SmE2oDJydJeeFqLP2hfHg/640?wx_fmt=png&from=appmsg "")  
  
那么这里就是有思路了，把这两个功能点结合一下或许就可以变成一个有趣的xss漏洞。把之前我们存在xss payload的作品链接在我们的作品底下进行评论  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMh69JlEeO4loiaribwnAjlMxR5kibTEXqX7nDjYhIlDa6Kib3j4kbsBBqeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMM1OsLuVLXruWcoNGM0TNpOwDtf21dszbsstMiaQ630oItRejdWTWRzg/640?wx_fmt=png&from=appmsg "")  
  
好！符合预期，这里确实存在xss漏洞，那么我们如何把这个危害进行扩大呢，我们都知道xss主要是因为js的问题，而js是可以发起http请求的，那么这里我们就有一个思路了（当时也是看了大佬挖掘b站xss漏洞的启发），我们抓取api，然后自己编写一段请求代码，只要别人访问我们的作品（或者我们在别人作品底下进行评论），都会触发这段js代码从而发起请求。借助一些xss在线平台，编写以下代码，通过fetch发起请求，让其他用户自动关注我的账号。  
```
```  
  
在其他作品底下进行评论  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMpS0jnohZvjCLUqcnQg1EcxV4vomKpnedkbKordPksNTPfrmA3g4t7A/640?wx_fmt=png&from=appmsg "")  
  
抓包可以看到确实是已经发起请求了，那么坐等消息即可（狗头）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMsEQghvbTODQXyT5icGI4J1MicjnhATpJGZYrTgtYa4r3RibgsEbGvuAPA/640?wx_fmt=png&from=appmsg "")  
  
可以的，百万关注不是梦啊，这里其实可以借助xss平台进行更多的操作，比如盗取cookie...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPQRoViaNolFgOxicNQkZxKnMQibjvlqQK6ZOSsLRaQ4mKPx7Tgz6HIW7kWQNgZ6xXQIjFsqqIuzatew/640?wx_fmt=png&from=appmsg "")  
### 总结  
  
在挖掘一些漏洞的时候我们的思路需要发散一些，碰到功能点我们可以去思考开发者开发这个功能是想实现什么东西，多个不同的功能点是不是组合在一些会产生一些特殊的化学反应。  
  
来源：https://xz.aliyun.com/ 感谢【  
xiaoqiuxx  
 】  
  
