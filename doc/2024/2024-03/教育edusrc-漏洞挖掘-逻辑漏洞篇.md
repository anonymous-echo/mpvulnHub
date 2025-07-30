#  教育edusrc-漏洞挖掘-逻辑漏洞篇   
 迪哥讲事   2024-03-15 22:38  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgFBWrNLFjzY0sFbeqIv5icrgOY0fhI7MoOMjbpK4ibShPTFH1iaUbqWrI5T6dVH2Uetud/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1cWGtq68jEgFiaXE5iaHsSA5vWIict4kuUhwniaqse02pVbvwPZoxJzHdl9ic3gicgRKQhOPc6Fsq64b54/640?wx_fmt=svg&from=appmsg "")  
  
  
# 一眼定睛  
  
  
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
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
