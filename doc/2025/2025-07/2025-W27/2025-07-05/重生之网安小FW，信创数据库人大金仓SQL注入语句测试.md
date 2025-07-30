> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247487536&idx=1&sn=5be5ad79cbddbf7d01d2a8048c749aa5

#  重生之网安小FW，信创数据库人大金仓SQL注入语句测试  
原创 chobits02  C4安全团队   2025-07-05 14:38  
  
## 前言  
  
近几年信创化改造的系统越来越多，更多的系统在数据库的选择上以华为高斯、电科人大金仓这类数据库为主  
  
虽然这些国产数据库都对Mysql有一定的兼容，但是在有些具体函数上面的用法还是有细微区别的，近期乘着信创化改造部署了测试数据库，便来对比Mysql函数语法  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQHxXNZxOYnZDK6mj3pxzPH8IuygUxlXk0PFM3gyChxZq22YicBy2zPrM9OOcfsiaJHPTrf5t9vSO3g/640?wx_fmt=jpeg&from=appmsg "")  
  
这里主要以人大金仓数据库为主来分析下常见SQL语句的差别，数据库官网：  
  
https://www.kingbase.com.cn/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQHxXNZxOYnZDK6mj3pxzPHicwU69kydgOXrOoyYQCj8wgnUfk86WF6IjORJliaKyDgQORSdzTCXDsA/640?wx_fmt=png&from=appmsg "")  
  
数据库有专门的链接工具，名字就叫"数据库开发管理工具"，可以在官网上面下载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQHxXNZxOYnZDK6mj3pxzPH11p2RP0txLcetU5SUMnnk6hNsQ5BfibTARVHbDq3KzW2iamf4vQ0ztEQ/640?wx_fmt=png&from=appmsg "")  
  
这里测试就以延时注入打个头吧  
  
Mysql的延时注入是这样的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZu0AOwfwekw4CJZFrndM2KG45UVicJv00WTRn5nYibTdgW5cicSxMjKrQg/640?wx_fmt=png&from=appmsg "")  
  
而人大金仓（以下简称  
KingbaseES）因为兼容**PostgreSQL，所以延时语句就用pg_sleep函数实现**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZtnJJibApznpmaFsZWiaKLLl3iciapSFQ0vTaicQUmFl0MZicVZaySmTbFMXA/640?wx_fmt=png&from=appmsg "")  
  
**这个实测在加了延时语句之后，正常查询数据会为空，平时KingbaseES查询数据就稍微有些慢了，所以可能延时不明显**  
  
****  
**布尔注入没有多大的区别**  
  
这里就不贴Mysql的语句了，无非是判断长度和ASCII  
  
直接来看  
KingbaseES的语句吧，查询自带的sys_user表第一条用户名的长度  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZ2JZopaNQvXtT0NXdPKRrqoEjKkCxq1Zr8C0lK74B3ojNFLmB9JX0mQ/640?wx_fmt=png&from=appmsg "")  
  
直接返回结果true，反之返回结果为false  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZDDKlaS3yfu27pSBBYaECR8fm7k2OVg2Cd1IJKYJt1fz4OS04HNJmTQ/640?wx_fmt=png&from=appmsg "")  
  
同理再拿ascii判断测试下，结果也是一致的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZzcicKibAgwMeyNv1IYgBzeVXcrn9SNTeWiacJ5HDK6aGzVibIyOsuIABdw/640?wx_fmt=png&from=appmsg "")  
  
**可以说这一块和Mysql的几乎没有区别**  
  
****  
**来到报错注入**  
  
**KingbaseES的报错注入可以使用类型转换报错，用::+类型转换把报错数据带出来**  
  
**因为数据库对数据类型特别敏感，用如下的语句，把字符串结果强转成int类型**  

```
SELECT (SELECT usename FROM pg_user LIMIT 1)::int;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZp1WgWut5MEKia81tyXAyNSKtJMjRAKAkcBPgKUPfoDjko7micIazrkzw/640?wx_fmt=png&from=appmsg "")  
  
就会报错查询语句，把结果带出来  
  
  
如果报错可控在查询参数里面，可以使用 
```
||
```

  
 拼接SQL语句触发错误，原理是一样的  

```
SELECT 'a' || (SELECT version())::int;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQmZ4VGACwOAS9xFKqAiaHgZugEl1mFzeIcwFIMqibQ0lD90ViavSSq8HsPQVN3OSPoW4WBgyMu314Ew/640?wx_fmt=png&from=appmsg "")  
  
可见结果中也是把信息报错了出来  
  
  
结语  
  
感兴趣的可以公众号私聊我  
进团队交流群，  
咨询问题，hvv简历投递，nisp和cisp考证都可以联系我  
  
**内部src培训视频，内部知识圈，可私聊领取优惠券，加入链接：https://wiki.freebuf.com/societyDetail?society_id=184**  
  
**加入团队、加入公开群等都可联系微信：yukikhq，搜索添加即可。**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06sHdBhSTMMClOr5wLWmLYIl6Yry9n3ZIL97tylQib5YLOuJFxndeFMEg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
END  
  
  
