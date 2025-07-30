#  教育edusrc-证书站挖掘-逻辑漏洞篇   
原创 PWN师傅  PwnPigPig   2024-02-16 10:15  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgFBWrNLFjzY0sFbeqIv5icrgOY0fhI7MoOMjbpK4ibShPTFH1iaUbqWrI5T6dVH2Uetud/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgFiaXE5iaHsSA5vWIict4kuUhwniaqse02pVbvwPZoxJzHdl9ic3gicgRKQhOPc6Fsq64b54/640?wx_fmt=svg&from=appmsg "")  
  
  
# 一眼定睛  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOhibMeBVsiaLKJlC6WVYm6KgNWNvvmpKQYPxzRvGw9lqotUAsWKvmicF3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
没错,就是他了  
  
重生之鹰图语法:  
  
icp.name="四川大学"  
  
&&web.body="注册"  
  
&&web.body="登录"  
  
很快哈,一眼定睛个系统  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOWiao7pucNZDiaXrdTtPvoRs5yh2PrLxREslfEsYT3drs4P5CuCuQjZTg/640?wx_fmt=jpeg&from=appmsg "")  
  
注册好一个用户后,来到忘记密码功能  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOurGCbGibz3Jrxd0JCPT7E7x0hw6km4GD3OAwmRAeUy6QcMuq0bJuOTw/640?wx_fmt=jpeg&from=appmsg "")  
  
这里先输入正确的验证码,然后下一步进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOV7GWsq2JySCZibj0icsvfJXkvicn8fVCwHBa86dMykgeJic2vGMQxiaDGYw/640?wx_fmt=jpeg&from=appmsg "")  
  
抓取响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOeP6DQ7cTouzb2KtbHIIxrevxZHibuoXKwhbfnWZrLVtMlkba3slaHEw/640?wx_fmt=jpeg&from=appmsg "")  
  
这里的302跳转到重置密码是依靠Location:  
  
/index.php?&m=User&a=resetPwd&_t=17054**71852**&mobile=1881924****参数中的_t来认证经过多次尝试发现:  
```
HTTP/1.1 302 Moved Temporarily
Server: *
Date: Wed, 17 Jan 2024 06:10:52 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location:
/index.php?&m=User&a=resetPwd&_t=1705471852&mobile=1881924****

HTTP/1.1 302 Moved Temporarily
Server: *
Date: Wed, 17 Jan 2024 05:10:12 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location:
/index.php?&m=User&a=resetPwd&_t=1705468212&mobile=1881924****
Vary: Accept-Encoding
Content-Length: 0

HTTP/1.1 302 Moved Temporarily
Server: *
Date: Wed, 17 Jan 2024 05:23:51 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location:
/index.php?&m=User&a=resetPwd&_t=1705469031&mobile=1881924****
Vary: Accept-Encoding
Content-Length: 0

HTTP/1.1 302 Moved Temporarily
Server: *
Date: Wed, 17 Jan 2024 05:33:39 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location:
/index.php?&m=User&a=resetPwd&_t=1705469619&mobile=1881924****
Vary: Accept-Encoding
Content-Length: 0
```  
  
我们会发现Location:  
  
/index.php?&m=User&a=resetPwd&_t=17054**71852**&mobile=1881924****这里进行输入多次正确验证码后下一步抓响应包,发现_t=17054是固定不变的,只需要遍历后5位爆破,从而达到成功重置密码的效果  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEONORTcpjG3iakc2keO4Cwl2Libhy7nCibF2wnLC11fN6odtn63x6OXjlFA/640?wx_fmt=jpeg&from=appmsg "")  
  
(这里的重置密码页面并不能直接重置,因为有&_t=后面为鉴权的东西,所以需要遍历出来)由于有WAF,需要Burp挂上代理池来遍历_t的参数进行爆破,这里使用的是快代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEO0rswZotoxMqbic3L7t2Rp2X9iazOrnCfTLP1z2UtUp0VGFtLMIhBvN2g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOeAqFZQtsupRMOfmhFI6IfECfkCgk39mpCYtgEt2husBskVv97fgEFA/640?wx_fmt=jpeg&from=appmsg "")  
  
这个包是如下图重置密码点击确定,然后对Referer头的_t=17054后5位进行Add  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEO5N7NpdezVw3xcj2icKS0O7y65a2Xfpiapic1rSEfDM3QYwZjkWiaKZ4Reg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEO9FVsC9M79LZ7PiaCBibQE5YqEQk37QfhOgNzNKqNHWUTQk9y65R5ZQOQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEO8AuDoxDuMwEcXFEGhu6BsaeyJo17ASRuULy40cLHiaAKxmEZIqhSneg/640?wx_fmt=jpeg&from=appmsg "")  
  
直到跑出正确的为止(跑出Length的长度不一样)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOFbHmjm5gVrJkPeGPLRufnUs5kddYVFib3otdiceibKhGbsVx4ySdgGCyw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOibLUzeyE3Du6RQR8pIIjCtNKOMdGtSiaQh01ReLtSGjVF4hVsuCuW2Qw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOnnaiaSBWiblZ7uNjgk7DhnWBbmBxtRCP9pGXAtGYF5wKN6dljqdTstUA/640?wx_fmt=png&from=appmsg "")  
  
也是成功拿下证书  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8qhiaRkiadySoicuFSyicwyElEOUzvRicbiadforLeLDtusIfALNaeibbpTVBMkAjLe54Wdgvl3pibobpzrOQ/640?wx_fmt=png&from=appmsg "分隔线")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgF527Fj3MNSgG1IYqSLmPHSFhbOTsvWeGkTJwm7JXC2LEsK1NyxTJyWW6N4HXtwMwj/640?wx_fmt=svg&from=appmsg "")  
  
# # 往期推荐 #  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgFalTu6Vd1Gic5mRqqQCfT6Skngic3oOOBNTIAGV0lpnzZCcNrJBhGFmgup4GqQfW6fs/640?wx_fmt=svg&from=appmsg "")  
  
  
[红队-四层网络下的域渗透攻防](http://mp.weixin.qq.com/s?__biz=MzkyNDI2NjQzNg==&mid=2247489770&idx=1&sn=7481b459898ec6340ca9762da0e8578f&chksm=c1d92241f6aeab57cced992a23f9cc8e59251d8ced95b9c65a0ccb20f08a5ced41b86766474c&scene=21#wechat_redirect)  
  
  
[CNVD通用型漏洞挖掘-cnvd证书的刷洞技巧](http://mp.weixin.qq.com/s?__biz=MzkyNDI2NjQzNg==&mid=2247489361&idx=1&sn=c6b64f159c5fb64e554a2f3be855402c&chksm=c1d92dfaf6aea4eca6ab21cc753c6cb271aadbefc330f0366c0fcd19d76e5454b0a82f987c13&scene=21#wechat_redirect)  
  
  
[cnvd通用型漏洞挖掘思路](http://mp.weixin.qq.com/s?__biz=MzkyNDI2NjQzNg==&mid=2247485210&idx=1&sn=4b41b2ac302eda8c53a3b4d820f38f03&chksm=c1d93db1f6aeb4a75d32032b2f3b6887d4e94f4bc63cf3e2d726b70fc33687d2983465565e42&scene=21#wechat_redirect)  
  
  
  
###### 交流群  
  
  
交流群人数已满,加我微信号PWNCat拉入  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgFiaXcEicjpaebtYgt5dLpjBjLQlia2vpMlgIwAo2ooNkib4Z7dtibHgdtn2gkIG1GM6rHC/640?wx_fmt=svg&from=appmsg "")  
  
~  
  
