#  利用已知cms漏洞getshell   
点击关注→_→  黑客白帽子   2024-06-29 10:21  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
  
  
**进入管理后台**  
  
显而易见，目标  
靶机  
使用了yxcms，通过百度可以查询到yxcms的目录结构，得到  
yxcms  
的后台路径：/index.php?r=**/index/login访问http://1***2/yxcms//index.php?r=**/index/login  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfwKk6qEybbmicJfODKQ6DjicviacuLJS0Anwhq1M3xeCP46ctmFaAMEfYw/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
使用yxcms默认用户名密码，***登录后台，直接登录成功，接入管理后台页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvffaPRoYOVkZF8Oibf7vkzwc0yJzia4ngEMEgPbiaeZquI8XL3WFVoABsqA/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**写入webshell**  
  
在前台模板功能中我们可以直接写入一句话木马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfibY7Zzcff1ibGRtEraQ0QvmrkjN6Jba4Y2mz9a9g9f9J3VfIYibCGht2g/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Burpsuite  
抓包后，并没有发现写入文件后返回具体文件路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfuGOYz6fhDSan4Ky8yCEzonDnXPsNXkX0fL18wS0kjvTuYPsZ0ohk4Q/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
不过yxcms泄露了robots.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfPxl97N925vtLMxvMu9ggpvAlUONIb57U0Fubhc1mk2KwMjAF6icevaA/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
通过泄露的文件路径，一步一步推测找出我们上传的shell_test.php一句话木马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfVfwAzc3DdzsPzTSMVf26jrt55xLIXJGLDwGwS2lTcSsdAfGlMKoIwA/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
蚁剑连接shell_test.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfmOSYqSysmiay0GZU46ggeasNvqdoqpTk9UN2eFhR5eu6IDmib6ncDoJQ/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
成功拿下靶机权限...  
  
拿下服务器权限后就要植入后门，植入后门的方法大致有两种——MSF和Cobalts Strike。这里演示Cobalts Strike的方式。关于MSF生成后门  
  
详见：https://www.cnblogs.com/C0ldCash/p/13733067.html  
  
**生成exe可执行后门**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfMa15DHR6TKwoFicURc6j1MhGYv6OEPfxk7vZANYricbq8LAfZq25TAvg/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**执行exe后门**  
  
利用蚁剑将exe后门上传到靶机  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfJrAa7ucfykXq0fA9ibk16ZG27KLPW9uFCNxsPhyXH3zgP6oIniaUn91Q/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在蚁剑中使用终端命令行执行exe后门  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3Ilvfe4l7nhrv0l9Rm0h513YbxibfsFvGzA2oqtOHn11IZaFlVqTS7goKWIg/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Cobalt Strike中靶机上线  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfniaCXt4x9HtM3KMkP8wRUPkmeicl5BFlEOKqs1nKBFIjdnuliaZEC8qkA/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
探测本机信息  
  
1.执行系统命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfCIjkvI8IG7SKIEf8lo8TicbFEa1fibMMxbRy3mAWlgT8esWQoHOtXDUQ/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2.探测域信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3Ilvf3yvpO37XGbgJF2uWSgpHWPecBMBIAxkTf2IxxMIzicKc5MibEfLrWic0Q/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
3.Mimikatz抓取本机密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfQibXnX2akr6lX4qb8f5x7rMTRbOCibmAJjreClHWStSL879MGg3v56rA/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSjRTX5GfF5KTCjDUFP3IlvfnM3e4yNoWKCcWe6oMqLbicGqXRsPibUx7C4lCich0KtL8EKTGI375hjcQ/640?wx_fmt=png&from=appmsg&tp=nowebp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
成功抓取本机**istrator用户开机密码  
  
**利用cobalt strike提权**  
  
****  
****  
  
**提权到SYSTEM系统权限账户**  
  
**内网信息收集的主要目的就是查找域控以及域内的其他主机**  
  
**判断是否存在域**  
- ****  
**使用 ipconfig /all 查看 DNS 服务器：**  
  
  
  
****  
  
**发现 DNS 服务器名为 god.org，查看域信息：net view**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650939865&idx=1&sn=773462fd879df4c210ad316ed538483a&chksm=8bac6d26bcdbe4302b3b28dac2f62deaa16dc687bff0062a8ca5d90f6b124e3d2685544fdc03&scene=21#wechat_redirect)  
  
**下载地址**  
  
****  
**二个月前资源汇总**  
  
https://kdocs.cn/l/cq  
EYzWfs0kUS  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
