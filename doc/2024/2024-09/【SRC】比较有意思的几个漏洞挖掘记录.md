#  【SRC】比较有意思的几个漏洞挖掘记录   
红猪  Z2O安全攻防   2024-09-13 21:08  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
# sql注入  
  
某条数据，点击详情的数据包，单引号报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI6385Z23QfwtnnmCd6538QpsdS6iaV0cP86JOtmxAtsISNECa9ITt91A/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
再加一个正常  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIH7rn1axRicFcZqdn5TJVfV2rM6aTUnxU7gyKEMkR6geqJllSzB0AYaw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
本以为是一次平平无奇的sql注入，没想到绕了一天才绕过去，下面放几张测试失败的截图  
  
首先就是404，不知道规则是啥样的，下面语句应该是没问题的就会404,1=1让语句不通就会500  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugID3BUOMSI5E0v7AFvUvASmFcibTwgNR3aQvrlyicEIBlwggrdsevpx6uQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
试了下orcale的注入方法，又爆403，这里'||55||'会返回空数据，'||1/0||'会爆500，这里判断语句能想到的都试了，全403，最奇怪的是只有语句正确才会403，少写一个D就会500，不知道这什么匹配逻辑，不过试了一些插入空白字符啥的也都不行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIamyia5a3wGwULM5jCMBr9EiawAQicJnhgBfb7EfaM0v5CmicFcvenX5DZQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里我又跑了一遍字典，全404、500、403，期间尝试结合分块传输、参数污染、垃圾数据、白名单、高并发均未绕过去  
  
最终经过我的不断测试,插入下面payload回显特别慢，最终显示数据量太大，不过in这个关键字我理解的不是很透彻，有懂的师傅可以解答下  
```
'OR+1+in+1+and+'a'+in+'a
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIIeDLaHlQYZAr6DicCTUFduAsUKqtsBwTic9xGtKQe4yK7L5pa9ha05qA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
当1 in 5 的时候整个结果为false，返回为空  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIm0MFiav8fvEVjYHwADHvqicDIV2UwGTHmOpVxXX6H4032tMnjBeXyQ3Q/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
直接注下user的长度  
```
'OR+1+in+length(user)+and+'a'+in+'a
```  
  
只有相等时会卡死，很明显为7位  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIc6M6RPBhZYr17dvoWlMF0ulowI7W0JoBMv6j5HP2ZMEiayvTXf8MiaHg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
直接用instr函数注用户名  
```
'OR+1+in+instr(user,'u')+and+'a'+in+'a
instr函数代表后面那个字符在前面字符串第一次出现的位置
例如:
instr('user','u')返回1
instr('user','us')返回1
instr('user','s')返回2
```  
  
第一位为S  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIyEedibxsRw8QrUT6AZyomfRGIYU5siaetMOicAP0Ofu7L1ib9QXibGTsvQQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
第二位为H，其他同理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIFzUUVT7u3CQmSfevTXhjt5wc6bPia68B2VARLa9GrFvu00IvqYqGHicQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
# 任意用户名密码重置  
  
玩的某个游戏，手机号换了，申诉成功给我发了邮件，可以看到id和token  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIP5U5v5APqh8PWbbmXibfCI4X7iaS3JgEPj7EerfPzwPWAGVshvoTiagFg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里直接更换id访问，进行更改密码，显示错误  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIdhseq9bs4KBwX6iaNk2jJufxdHZJ4fKbEgfk0KiaS1j8xqEw6ScjpEzA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
简单测了测，id随便改，token为空  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIksRqEL2bVpc0LeV9e4wvnalxPtbc22Pl5rRMlics6nvib3n5ZiaJyHhfA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
直接修改密码成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIFrEBW8AjpQ6zvbHtetrCnpwYXcylZd93GGWOGVaRIYI4QibJcVbYqsw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里因为不知道目标账号的id，只能随机修改，因为手机号基本就跟id绑定，于是找到了申诉的功能点，这里输入手机号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIV5TTqibx5fsJz8VZwIicmia0HIZ455RDz0r99sMFrehOQ2wfe0AicNibFcw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
可以看到返回了id  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIZGSdoQqXg4EC5HsHQPaut5oFNT43wCvj56cC0KEUosHaRKVEvUd9FQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
下一步就是要知道目标的手机号，经过我的不懈寻找，在游戏app的登录界面，有个忘记账号功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI7zyoFkkdiaNticT7ibD08aJlthWVKecUAFG4ibPpFpfAQaWf7CqrUANgXw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里输入手机号或者游戏的uid就可以看到一些信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIkQhJBibTQVFDEwSn8e2s7LcjzwStJPEWtvhial0txX1pTNQchbxW0epA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里游戏uid是公开的，资料就能看到，不过手机号只有前三位和后四位  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI0f0SEfBU5qicS1gtJPjeOU7hx799hKQPC3vj7SJxib3ZtO06aPYH3cng/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIdxBX3ds45koU2icibL7KrIIyrLdTcCqOpK5YmHLQslfes5GrEU3avusw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
在官网找回密码处，这里输入手机号抓个包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIRNKPdlD7AhZticviaJHb4dqZNhIzIwCnWOVuR06CAWjEsaxQqUQAqwPA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
输入不对的手机号会提示错误，因为我们知道前三位还有后四位，爆破起来还是很快的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIyFQYK7OGC6w6ndvXfxNoshicr5dU8GSiaYzVV2JibIGA5JAknCrBxlKWg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
最后只得到几个真实存在的手机号，这时候就可以去游戏app登陆界面去对比，手机号正确的话，返回的UID是一样的，这里也可以抓包写个脚本去判断，因为真实存在手机号就几个，我就直接手动尝试的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIcuRxKARo8JhDA2qxh86j1VSSSh4FQkz2pYaMkzUW2MSpic9PCPbiaibcw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
确定了目标手机号就知道了id，就可以想修改谁的密码就可以修改谁的了  
# 某站测试记录  
  
目标站主域名有两个，a和b代替 ，这里主要目标是a，b应该是以前用的，首先是爆破出来了两个demo站demo.atest.com和demo.btest.com 会提示ip无法访问，访问demo.btest.com  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIGOgCGEUTJhC4ddLToDY7fuV1Uv5akupeib3sb0WFDmPMdrODKTRjZpw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
另外一个也一样  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIicicUMteaiaQIynW3WHQfq01icCxh13lErVNjzK7FQ6C7bNVOWMusncEGA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里直接插xff头绕过的  
```
X-Forwarded-For:127.0.0.1
X-Forwarded:127.0.0.1
Forwarded-For:127.0.0.1
Forwarded:127.0.0.1
X-Requested-With:127.0.0.1
X-Forwarded-Proto:127.0.0.1
X-Forwarded-Host:127.0.0.1
X-remote-lP:127.0.0.1
X-remote-addr:127.0.0.1
True-Client-lP:127.0.0.1
X-Client-lP:127.0.0.1
Client-lP:127.0.0.1
X-Real-IP:127.0.0.1
Ali-CDN-Real-IP:127.0.0.1
Cdn-Src-lp:127.0.0.1
Cdn-Real-lp:127.0.0.1
CF-Connecting-lP:127.0.0.1
X-Cluster-Client-lP:127.0.0.1
WL-Proxy-Client-lP:127.0.0.1
Proxy-Client-lP:127.0.0.1
Fastly-Client-lp:127.0.0.1
True-Client-lp:127.0.0.1
X-Originating-lP:127.0.0.1
X-Host:127.0.0.1
X-Custom-lP-Authorization:127.0.0.1
```  
  
这里是创建订单成功了，返回了一个地址，  
https://cashier.xxxx.xxxx  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIpwVh8UpZ7r3oRnMQI5pfmnpiafbercQacuOJ35BKBqdLomdILou9Bng/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
访问之后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI0rHGgchUXqa7oTOWqDZmr4MIibI4Uiaw1zPibtm7wPDpOZzuGuTqEt7aA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
因为这是订单信息，所以我猜测前面子域名是后台的  
  
构造  
https://cashier.atest.com 访问之后401，添加xff头直接访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIOlicKYTicdPwa2re3dJSXchjYeUiaV6htsbDQGN8z7z7vzB05ibjCzS21w/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里a网站应该也是一样的规则  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIQEibySmZRia8yictPKR7Ks4SCd4bPAwyXsiaCfib0ick4cD7yZMWs2GdeaXA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
因为是测试后台，这里直接将test删除，访问  
https://cashier.a.com 显示无法访问，修改xff头仍然失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIcs62VeUKJXlpSjrzP8OfEYVSvuCcRhsVsxWeBW2HKHUrKHSriauYXwg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
只能从测试站入手了，首先是爆破出来了用户密码，但是却无法登录，不过返回了token，这里前端看到了webpack的接口信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIQE23xiaSmZJ57rwqpu9guib4ugia4icMFAreOsF9ibticicSicFOUKdEofbe6w/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
在JS存在好多接口和接口配置包的构造并且还有API路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIwXdH0l5hDH27aa0icSEibOsYG1gP1Oj7vL48j1XQ8ia3Bk5Vm3evzRibEA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIL37er0aPxrX3BaDZM9V3KLX5tibBSYvJv1obmG0Btb965v7mmGEicJ6Q/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
抓个登录接口的包看下格式拼接就好  
  
有的接口有未授权，有的接口需要权限，但是爆破成功的数据包里面是有返回token的，于是带着这个token访问就可以了，但是均为测试站点的数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIaicRDPJc42KUmsJ7nM1cZbSQVQIeDZ3WD3zulgiamL3afAiaMqcWEF75Q/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
于是猜测管理后台地址也是有这些接口的，直接更换请求的host，成功获取到真实数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIytxVtPlLrFM29ia40az8sSuFNA2dzP2D5tE61aumPlO5xn0xJjy8HHA/640?wx_fmt=png&from=appmsg "null")  
  
****  
**原文地址：https://forum.butian.net/share/3692**  
  
### SRC专项漏洞知识库  
  
  
建立了一个  
src专项圈子  
，内容包含**src漏洞知识库**  
、**src挖掘技巧**  
、**src视频教程**  
等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCOPMibnJIeBT6Yv0RwBJT9AFHKEbo3BxYkLnE00jVuoLicSOBCIzMiaJKQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDC8hpqQ1G8kzo1SPO24866oUqXhtqiaYwE9o4Js5IuHv5WxM7sfjCjWpg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**书籍****" 获取  网络安全书籍PDF教程**  
  
**回复“**  
**字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档合集**  
  
****  
点个【 在看 】，你最好看  
  
