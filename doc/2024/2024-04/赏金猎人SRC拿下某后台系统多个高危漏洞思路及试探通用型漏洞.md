#  赏金猎人|SRC拿下某后台系统多个高危漏洞思路及试探通用型漏洞   
 迪哥讲事   2024-04-15 20:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**0x01 前言**  
  
   本次漏洞挖掘对象为某公交后台管理系统，经过前期信息打点，成功从js中拿到多个接口，通过接口获取到未授权信息泄露以及SQL注入，包括前端登录页面SQL语句不严谨导致的万能密码登录，某理论来说，应该算SQL注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2g3X6E0GcgtQeBzgic5NHYwLBsa8Ae52GQoWj4c6xkf5YEUpVaJAtJpTg/640?wx_fmt=png&from=appmsg "")  
  
    实缴只有2000个，本想上交到补天通用，奈何系统太冷门，独立IP小于30个，补天没有通过，最后上交到CNVD，**由于涉及私密性，所以部分截图厚码**  
  
*** 文章仅供参考分享思路，一切均为虚拟，请勿非法使用技术进行破坏，否则后果自负**  
  
**0x02 思路复现**  
  
    首先是一个登录页面，未知管理员账号，无法爆破，太费劲，所以先看看js里面有什么，分析一波  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gwFicPjvyzIpKqOicWUSibX1hl0w7kRK4Bjfav8Suo0sQd3xiadiaY0omOYQ/640?wx_fmt=png&from=appmsg "")  
  
    好家伙，合着这把所有js都放前面了，不过这样审计太累，直接提取出js里面的接口放到txt里面，fuzz跑一下提取的接口  
```
/upgrade/xxx 泄露所有设备状态以及设备信息
这个必须登录后才能查看的，所以此处犯了两个错误
1. 登录后的信息及接口包括js不应向外暴露
2. 未对接口做鉴权(未授权)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2g4xy5USY0y1xEkl8YfQ27b7nmzUwJSmCGYMc6uKrKXPEeT1JV871qVA/640?wx_fmt=png&from=appmsg "")  
  
```
/upgrade/xxx?id=number
此处不输入数据默认是下载全部数据导出到excel表
经过测试，发现前端可对查询数据直接控制
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gQaAmrvNPmlicAqIMfh9Ticfv3dkZIgkxWPHLooK9a4eRc6UicNas0HqqA/640?wx_fmt=png&from=appmsg "")  
  
    在我输入1的时候，表示我想导出第一列数据，此处包长为6360  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gCd1t6fv7uPKRasY6Hkzmn0WHBKMFtbttnhH4tCVvQQUTZiaOAO4UPWA/640?wx_fmt=png&from=appmsg "")  
  
    在我输入2的时候表示导出前2列数据，此时包长为6364  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gF63L8ZHALy0zgmNkEhgMS9saJ1hbmSt9yEj6vFZiar87JUaZEUpeMtg/640?wx_fmt=png&from=appmsg "")  
  
    当我输入xxx?id=2-1时，此时导出的居然是1列数据，包长为6360了，这就很明显的用户可以操控拼接进SQL语句  
```
假设原本的 SQL 查询语句为：
SELECT column_name FROM table_name WHERE id = '用户输入的id';
如果用户输入的 id 是 1' OR '1'='1，那么拼接后的 SQL 查询语句会变成：
SELECT column_name FROM table_name WHERE id = '1' OR '1'='1';
这个条件永远为真，导致查询返回所有记录，从而绕过了原本的查询条件，获取了所有列的数据。
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gvlsAATWxhT7eUOQ7jN3HsIicVOU2tDOa1OkwNSVWQ8LVG2sQDhJhrTQ/640?wx_fmt=png&from=appmsg "")  
  
  
    直接sqlmap跑一下，不用想就知道是盲注，而且经过/sys/config泄露出数据库为MSSql，并且泄露出数据库账号密码及地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gteJQm9uHsO4FyLKbgxoDTYhTMxvT2afrUzDrQ0HCH6Lp2I3S99mYtA/640?wx_fmt=png&from=appmsg "")  
```
sqlmap -u "http://xxx.com/upgrade/xx?id=2-1" --dbs
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpN3biawAKjnNzvBHaIqFtgJrZicNxQOKbqbICflHhEwGKibBzUd8fctpuua3EBajGTUdEsx96UpjicGuA/640?wx_fmt=png&from=appmsg "")  
  
    看数据库命名，其中包括IC卡、设备信息、密钥等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpN3biawAKjnNzvBHaIqFtgJrOicofUuDTAaTJq9EJZzsM5NZ7CGGQrRmOmXwmEeAFtUotGY4Ka2mGeg/640?wx_fmt=png&from=appmsg "")  
  
    但是我还是没有登录进去，正在一筹莫展之际，想到，既然有sql注入，万能密码是否可以呢，直接万能密码跑一下，成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gJoBVaNtlOickGBcdib2Tlwlye8jIGr9wEiczxex3NEOMWtMm7Gq1GoSWg/640?wx_fmt=png&from=appmsg "")  
  
   
   管理员用户还真是admin，假设登录失败会提示账号或密码错误，登录成功，则后端会返回一个jwt编码，来赋予后期登录系统后所操作的一个令牌  
```
模拟一下，前端登录页面大概SQL语句如下
SELECT * FROM users WHERE username = '输入的用户名' AND password = '输入的密码';
则使用万能密码admin'--后 如下
SELECT * FROM users WHERE username = 'admin'--' AND password = '';
- -是 SQL 中的注释符号，它会注释掉后面的所有内容。因此，' AND password = '' 这部分被注释掉了
使得查询变成了只检查用户名是否为 admin，而不再需要密码验证
```  
  
    所以它只需要查询用户admin存不存在，如果存在则登录成功，通俗易懂  
  
    登录成功后大概是可以看得到刚才js文件接口中的那些数据的，没做鉴权，比如车辆的状态，比如系统的配置，部门信息，车辆型号，但是我估计数据库中有些库没有对接在这里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2grlLtIBYjZqiayonSbibNDPqaVjf1ErjGJFyyz7k737PtqsNicKGtInAAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2g9DNUMPYsuxNWDVmdSsib7u5diaaonvEPickw7Hc5JPk9kftyySpcO2K0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2g3SJAr3IjoKdibyvAlbcqjnia3o8XScLsXqNlqfIr4Pn9FlLGKnoqyEow/640?wx_fmt=png&from=appmsg "")  
  
    然后就是找到一个上传入口，但是不管上传什么文件都提示解析异常，这里就先不搞了，到此为止了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gibkU1ZEjmOYQ1wkt0aK2hoglHZZ1goRpq0MXUfic6z3pqzuXUGIcPTFg/640?wx_fmt=png&from=appmsg "")  
  
    接着就是提交环节，一个站不能扩大危害，且后台管理，谁没事天天去访问啊，然后大佬告知我可以去查一下特征同源站点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gUfWRcXXPibPoSwmKUbgW5n0jT1T7EDvGItmx1JyQeQxadh3k3sOqJhA/640?wx_fmt=png&from=appmsg "")  
  
    直接fofa语句，然后加上hunter  
```
body="xxxxx"&&title="xxx"
```  
  
    可能系统太冷门，或者企业需要的少，满打满算就二十多个站，最后交上去看一下吧  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gjLCxibo7MoEgxWwy0hABmsEDU7YqIx8iaDXvNhliaprKIGDcll6AEdggQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPia8ibB2bjMYGkwDqNB1Ur2gHkDKf3yfiabzrLwCdw1InNJQzGL1rGCexEZIrnMicdMsbr5JalwnkCEw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 总结**  
  
    虽然，这次挖的并不难，没使用fuzz大量扫描，基本上分析分析，梭，全程不到半小时就出来了，再加上学会了不少东西，也是很满足的  
```
关于以上出现漏洞成因分析及修复方法:
  1. 部分JS文件不应出现在未登录页面
  2. 未对接口做鉴权，这和不登录直接访问接口没区别
  3. 未对用户做的操作做判断，用户可直接拼接sql语句
修复方法:
  1. 将合适的js文件放在合适的位置，在用户非法访问时提示403或报错
  2. 对相关接口做鉴权处理，后端都生成jwt令牌了做个鉴权不难吧
  3. 对前端数据库语句固定，使用参数化查询或者预编译语句来代替直接拼接用户输入的方式
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpN3biawAKjnNzvBHaIqFtgJrpCicmTsibSJpWVHgUwhEKDMueD4enf8YsibU74NE9m4UiaCQzMnVCzotWw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpN3biawAKjnNzvBHaIqFtgJrXGdJb19u2BjUUXTbemUl2NM43gkokaFWxrfHZTZIQqpeibDYINLFe5Q/640?wx_fmt=png&from=appmsg "")  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
