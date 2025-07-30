#  漏洞挖掘 | 基于mssql数据库的sql注入   
原创 zkaq-洛川  掌控安全EDU   2025-02-03 04:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  洛川 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
### 前记  
  
今天挖edu随意点开个站，发现存在mssql数据库的sql注入，在此分享下整个挖掘过程  
### 目录  
  
0x1 判断网站数据库类型 0x2 了解mssql数据库的主要三大系统表 0x3 了解mssql的主要函数 0x4 判断注入点及其注入类型 0x5 联合查询之判断列数 0x6 联合查询之获取数据库相关信息 0x7 mssql之时间盲注 0x8 mssql之报错注入 0x9 总结  
### 0x1 判断网站数据库类型  
  
•根据后缀进行判断，mssql数据库一般后缀为aspx，只要是后缀为aspx的站一般都是mssql数据库  
  
•根据报错的信息进行判断，一般报错信息中会有Microsoft等字样，如下图所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUAKOxXYvib7TfC5gzxeYZovo5aQeJcmmdBh9Ydg8WeibYqlvJaOCU02pQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
•根据系统表进行判断，利用mssql数据库包含的主要系统表进行判断，例如and (select count（*）from sysdatabases) >0如果成立，则可判断数据库中包含mssql的主要系统表，但是这个方法不绝对，可能出于安全考虑，数据库管理员会删除主要系统表  
### 0x2 了解mssql数据库的主要三大系统表  
  
•sysdatabases :这张表保存在master数据库中，里边的name字段下存放的是所有数据库的库名。  
  
•sysobjects：这张表保存的是数据库的表的信息。  
  
•syscolumns：这张表存放的是数据库中字段的信息。  
### 0x3 了解mssql的主要函数  
  
•host_name() :返回服务器端主机名称。  
  
•current_user()：返回当前数据库用户。  
  
•db_name():返回当前数据库库名 。  
### 0x4 判断注入点及其注入类型  
  
这里注入点就不用判断了，点进子栏目发现就一个参数，此参数就是注入点了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUwv11NB9pgp7yAZzYZaeU4REkVy8gUib6ZpRW07GmLK8cV9Agk7PPVqA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
直接一个万能’（单引号）然后报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUQfK8rBgH78dkRISUJOJoygCSL7AOyGILPSslkHJNRqtLhjCKdPnxjg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
直接使用55-1判断其数据类型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUDoygjsCVkdlfP48oJ7rofsU4tWIUhOibHf4EfB0CRqLsgvp5uiaFeUpA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
发现页面成功回显，于是可以确定是数字型  
### 0x5 联合查询之判断列数  
  
使用order by判断其列数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUfLQO31jKN2508sjpzmdy3b66lIrw840F0SFibJlHsUWqoHyzP8UrLAg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
可以看到order by 4正常返回  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUMOWnbiaibl8246HdRDXO8RqUtnickfvqYADZ2yj7iaG5Iz0O7pMOv6nARA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
order by 5 报错,可以判断列数为4  
  
然后使用UNION SELECT来判断 按理来说，UNION SELECT 1,2,3,4应该正常回显，但是不知道是配置原因还是什么原因还是报错，但是还是可以从细微上的差别来区分列数是否正确  
  
当列数设为其他时，报错信息如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZU4JwtKtqgTtiasicdhIgVQzIy4bFiaICXTSBpjKG0eDB62rXA7YuFOAHVw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
但是列数设为4时，报错信息有所不同，如下图所示，多了一片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUREJL7XTjthibPJicJILJnYu20PJUAB7nyKgbmXbnPmP7fAiaUtpODkLAQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 0x6 联合查询之获取数据库相关信息  
  
既然UNION SELECT 能正常使用，那我们就可以通过这个直接判断显位输出数据库的相关信息了  
  
前面提到了mssql的三大系统表，这里就是从系统表中查询数据 使用:UNION SELECT 1,2,3,4 from master..sysdatabases  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUvKtuZMVa9aic5qfMictNiaqQQyRWHUXN61RPlkcx1aCcpTiaQn0ST3za2w/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUxTOZa3SEpKLibTFOibcick6J462hSIZyuqiakxnTe7xCTicKhNhDnr6AqKg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
可以看到在显位处于第一列，直接从第一列使用mssql函数db_name()获取数据库信息  
### 0x7 mssql之时间盲注  
  
页面正常返回时间为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZU5Cfsz1WL9Rx78Imj6dZd4fIsIEbmsFmvvCCZscFmiaib2teaHClLMziaw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我们直接使用时间盲注的函数WAITFOR DELAY ‘0:0:5’进行测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUs1rI0HxaHCoNhibGShkMF7qMYHgj5wPsQ1bnSah8zOX9pib3LtRxz7Vw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
可以看到页面延迟返回，说明存在时间盲注（本站还存在堆叠注入，但是在此不做演示）  
### 0x8 mssql之报错注入  
  
mssql数据库的报错注入与其他数据库类似  
  
直接使用and 1=(select db_name())获取当前数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUEQYYscrG7LXictt9iaHWV9NPU7xZkNVkw0XAPibTiaP0X7xykkdXZuhWxA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里我们使用的是and 1=（）进行报错，所以一次只能获取一个值，如果想获取其他值可以使用top函数进行操作，这里不做演示  
  
获取表名：and%201=%20(select%20top%201%20name%20from%20获取的数据库名字..sysobjects%20where%20xtype%20=%200x75)  
  
在mssql中xtype为指定数据类型，0x75对应的数据类型为NVARCHAR  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUWCb8rBW5NbeoMbibKtryOgAlD4aW1meDVea3aLZa7LndNic4m1H3fBSA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
后续不进行测试  
### 0x9 总结  
  
```
sql注入漏洞挖掘主要还是需要了解各类型的数据库怎么操作，数据库的系统表有哪些，对应的函数有哪些，对过滤机制的绕过手法（虽然本次漏洞挖掘没有涉及到绕过），建议有时间还是需要深入学习一下各类数据库，不仅对漏洞挖掘有帮助，反之对以后可能需要涉及到的安全开发也有很大帮助，比如如何过滤危险函数啊，如何清洗用户输入的数据啊等
```  
  
  
最后也是拿下两个中危  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpoic034GNzhXRthTX08zTZUEMiaTplvTtzop6M8dUp6fgCicIiaia7Q3piaia2Nesa58ePh9BLu7UdB8uuQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
```  
  
  
