#  Src挖掘之比较有意思的几个漏洞挖掘记录   
xhys  Z2O安全攻防   2024-11-11 21:19  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
# sql注入  
  
某条数据，点击详情的数据包，单引号报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMEic2uicAxuQa9hFbibXWVQJLzMJLboJTAIkXCGpkeziaOyDEweibB462Xjg/640?wx_fmt=png&from=appmsg "")  
  
再加一个正常  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMoTZZsiaaHooGENaiaAj8cibPWHyXdeOvWZ7UubVvZAuW7KngibUne462Cg/640?wx_fmt=png&from=appmsg "")  
  
本以为是一次平平无奇的sql注入，没想到绕了一天才绕过去，下面放几张测试失败的截图  
  
首先就是404，不知道规则是啥样的，下面语句应该是没问题的就会404,1=1让语句不通就会500  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOM8ZIUicpn8C1FfpQ4jicWwnNBhpqjZGlfIlJ1o1jxiaTP01UIG0L2agRPg/640?wx_fmt=png&from=appmsg "")  
  
试了下orcale的注入方法，又爆403，这里'||55||'会返回空数据，'||1/0||'会爆500，这里判断语句能想到的都试了，全403，最奇怪的是只有语句正确才会403，少写一个D就会500，不知道这什么匹配逻辑，不过试了一些插入空白字符啥的也都不行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMdlibpFgKvcbkjVl0526KAUQGwdLP9O2f7mRZxFLEeicoaE2rTqcibQgug/640?wx_fmt=png&from=appmsg "")  
  
这里我又跑了一遍字典，全404、500、403，期间尝试结合分块传输、参数污染、垃圾数据、白名单、高并发均未绕过去  
  
最终经过我的不断测试,插入下面payload回显特别慢，最终显示数据量太大，不过in这个关键字我理解的不是很透彻，有懂的师傅可以解答下  
```
'OR+1+in+1+and+'a'+in+'a

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMFXOyvibmgBw09jkk2svkw4xSibWDHEbFyjQw7f2iaQIIrMIHyMbbojHug/640?wx_fmt=png&from=appmsg "")  
  
当1 in 5 的时候整个结果为false，返回为空  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMFrrCLEJpV0W8dhkZwRF1ry1n0952XYU8MKftFSqc55KIodbj9Racqw/640?wx_fmt=png&from=appmsg "")  
  
直接注下user的长度  
```
'OR+1+in+length(user)+and+'a'+in+'a

```  
  
只有相等时会卡死，很明显为7位  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMvwPTGp3axdX3YcURODgiafuibC1ef0n8rmtHiaAcrWWmO4UiakoeRYiaq6g/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMQI7bteUIE7333l0zrH2OOicYqNoWuOWIiaydJ0QvDPWoiav1eswoos1Sw/640?wx_fmt=png&from=appmsg "")  
  
第二位为H，其他同理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMmzwfGREfkBJRCwiaE0GTvELRhcjJHb0qewERTMicV06DJNJ6jic5hZCFQ/640?wx_fmt=png&from=appmsg "")  
# 任意用户名密码重置  
  
玩的某个游戏，手机号换了，申诉成功给我发了邮件，可以看到id和token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMLaYBB8aMzOyLrGSt9oJCd6oQNuOJwjBF9h2CaROg4bwwvKHQd9I2dQ/640?wx_fmt=png&from=appmsg "")  
  
这里直接更换id访问，进行更改密码，显示错误  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMWetSev7P4pUaqlETO9GdtZRjNCpgdL08mfavN8TRvPbrDngJgAgqXQ/640?wx_fmt=png&from=appmsg "")  
  
简单测了测，id随便改，token为空  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMicr61ndXic866I1fV7zQzv8Ll8Q3ibwTb7wr2eHEPCACsXjoXgwzSxM2A/640?wx_fmt=png&from=appmsg "")  
  
直接修改密码成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMYGWaBicxVdCBNxtXCVhvP7nId27FYfJOO8g0ibg2OZsiaiaaLxRxu4B6xQ/640?wx_fmt=png&from=appmsg "")  
  
这里因为不知道目标账号的id，只能随机修改，因为手机号基本就跟id绑定，于是找到了申诉的功能点，这里输入手机号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMjEO5Pq5VTCUzz31f8e6HqxSCRM1km0WP6hHTVyt7GfrXQQLcjsIXZw/640?wx_fmt=png&from=appmsg "")  
  
可以看到返回了id  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMQCen5yuZCVjXnfdQ6oiaOUhKnCaFlxVQB0um4hbTbJibUOTYQQkRIpkw/640?wx_fmt=png&from=appmsg "")  
  
下一步就是要知道目标的手机号，经过我的不懈寻找，在游戏app的登录界面，有个忘记账号功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMiaj2wvx9xHPzaC08bBRdV7x61IYOmNG0yUlxFNmUSSqfZy1FPqErmFg/640?wx_fmt=png&from=appmsg "")  
  
这里输入手机号或者游戏的uid就可以看到一些信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMjX5GN1jtib64thleZP2Kic8aBJdxUzpyRiaH5JRss8pmA067PhoQkSKvg/640?wx_fmt=png&from=appmsg "")  
  
这里游戏uid是公开的，资料就能看到，不过手机号只有前三位和后四位  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMJyoF5O217td6Z8fhtv2ibT9YKxVQOZib7QK0vjx6BRnB9gehDGF81BIQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMiatQbUrCNTjfibBV2iatF5bnTmpFzUziajuMNPvVHuiaGxD4n0Lv6XUVSLg/640?wx_fmt=png&from=appmsg "")  
  
在官网找回密码处，这里输入手机号抓个包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMjOcfCIpl5mbjf5GdqCwY9mnkKroic5ZgKpE4ficVsnN1GNJBGej5AgYQ/640?wx_fmt=png&from=appmsg "")  
  
输入不对的手机号会提示错误，因为我们知道前三位还有后四位，爆破起来还是很快的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMZ6zuxZ94NKLcsFA3m5cIJkJDLW27Mcwjo55uiaZr7yMoNGsH8JTrKLA/640?wx_fmt=png&from=appmsg "")  
  
最后只得到几个真实存在的手机号，这时候就可以去游戏app登陆界面去对比，手机号正确的话，返回的UID是一样的，这里也可以抓包写个脚本去判断，因为真实存在手机号就几个，我就直接手动尝试的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMWS3ibv9kZaJoDRwaH198mcAKH7zqhlL252llu9DnskxJHXC6TKS2XFw/640?wx_fmt=png&from=appmsg "")  
  
确定了目标手机号就知道了id，就可以想修改谁的密码就可以修改谁的了  
# 某站测试记录  
  
目标站主域名有两个，a和b代替 ，这里主要目标是a，b应该是以前用的，首先是爆破出来了两个demo站demo.atest.com和demo.btest.com会提示ip无法访问，访问demo.btest.com  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMzaEZMTRw2Q0ork7Mje6Vnc2ozsaM3SCPZRm3tryKWcl8Sml2oNCykg/640?wx_fmt=png&from=appmsg "")  
  
另外一个也一样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMBgXDgAKun5qyklL59EpFPD79k1skqZ9pdMico1nMia7wDV8AB4rZLTzg/640?wx_fmt=png&from=appmsg "")  
  
这里直接插xff头绕过的  
```
X-Forwarded-For: 127.0.0.1
X-Forwarded:127.0.0.1
Forwarded-For:127.0.0.1
Forwarded:127.0.0.1
X-Requested-With:127.0.0.1
X-Forwarded-Proto:127.0.0.1
X-Forwarded-Host:127.0.0.1
X-remote-lP:127.0.0.1
X-remote-addr:127.0.0.1
True-Client-lP: 127.0.0.1
X-Client-lP:127.0.0.1
Client-lP: 127.0.0.1
X-Real-IP:127.0.0.1
Ali-CDN-Real-IP:127.0.0.1
Cdn-Src-lp:127.0.0.1
Cdn-Real-lp:127.0.0.1
CF-Connecting-lP:127.0.0.1
X-Cluster-Client-lP:127.0.0.1
WL-Proxy-Client-lP:127.0.0.1
Proxy-Client-lP:127.0.0.1
Fastly-Client-lp: 127.0.0.1
True-Client-lp: 127.0.0.1
X-Originating-lP:127.0.0.1
X-Host: 127.0.0.1
X-Custom-lP-Authorization:127.0.0.1

```  
  
这里是创建订单成功了，返回了一个地址，https://cashier.xxxx.xxxx  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMuvHiaX5ENIcK1czmUIN5QjnibpiaKr9I0hOjlOwQdM5GAyVELsPviceu0Q/640?wx_fmt=png&from=appmsg "")  
  
访问之后  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMeYyfD0suFibRp7oibesibCr3kk5vHgq7grcvC56VVJjVsw4cMAgR3neUw/640?wx_fmt=png&from=appmsg "")  
  
因为这是订单信息，所以我猜测前面子域名是后台的  
  
构造https://cashier.atest.com 访问之后401，添加xff头直接访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMqu7kGzDQ7gGkzUdL8692eJbBXs3oXGibiaX78etXpEP6DNZudGyX0c9w/640?wx_fmt=png&from=appmsg "")  
  
这里a网站应该也是一样的规则  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMYzzv1m373P6PI88fyKE0PA34kicE0eEleT6FQIu484WcdP72qwWG1iaw/640?wx_fmt=png&from=appmsg "")  
  
因为是测试后台，这里直接将test删除，访问https://cashier.a.com 显示无法访问，修改xff头仍然失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOM8SFgsNSyOGzQwszWLpiama0fbprvicTVvicHlzKzliavBxwHQ9cRzTN4pQ/640?wx_fmt=png&from=appmsg "")  
  
只能从测试站入手了，首先是爆破出来了用户密码，但是却无法登录，不过返回了token，这里前端看到了webpack的接口信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMOMcebEd2mtg62BwdxqbBuDtMWyXD6FhTLh4NdiaZR4hEdFDLI0yLNyg/640?wx_fmt=png&from=appmsg "")  
  
在JS存在好多接口和接口配置包的构造并且还有API路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMBoR4oKBXfCIQb6rOBaES55h0SI2WvKXwuuqcvPAM8x7kCLZf3GNZkQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMNguh9rib4AHseok4KZELibm3VBLlP6MVxj62iaavibggCRz6Usogs42sGA/640?wx_fmt=png&from=appmsg "")  
  
抓个登录接口的包看下格式拼接就好  
  
有的接口有未授权，有的接口需要权限，但是爆破成功的数据包里面是有返回token的，于是带着这个token访问就可以了，但是均为测试站点的数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMZAS0dkNHw4HjOpTpmHWxlXH9COnEAWljyU9dDR1qmVpibh6AVFeYUTw/640?wx_fmt=png&from=appmsg "")  
  
于是猜测管理后台地址也是有这些接口的，直接更换请求的host，成功获取到真实数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqerTibAA0zfFicsI2E66rKOMuOQj5Vvqosq2iapibgfIT1iaLvZ2NjK7Nrpwo1VaobLlZhydQiamcClDxA/640?wx_fmt=png&from=appmsg "")  
- 原文地址：  
https://forum.butian.net/share/3692  
  
- 排版来自：亿人安全  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOABrvjQvw6cnCXlwS05xyzHjx9JgU7j83aReoqqUbdpiaMX2HeudxqYg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYgNUapJqQxicbYTJoohoBK32iat5p76xlsgd6bdhZsdAgtNzPEv9CEOh96qgHK3ibHHBa4kRibjQeuibw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6JWUFIwPbP7Au1PYLXTplb3bbFZFlaYDtXXTqPdzOO6iaFz8F7r8WUPw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
