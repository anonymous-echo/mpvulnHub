#  IIS中间件漏洞   
A 八方  丁永博的成长日记   2024-12-23 02:16  
  
```
原文链接：
https://blog.csdn.net/qq_48368964/article/details/140998220
```  
  
  
一、IIS PUT漏洞  
  
》》》漏洞描述《《《  
  
IIS Server 在 Web 服务扩展中开启了 WebDAV ，配置了可以写⼊的权限，造成任意⽂件上传  
  
》》》影响范围《《《  
  
版本：IIS 6.0  
  
》》》环境搭建《《《  
  
fofa："IIS-6.0"  
  
本地搭建2003 server  
  
》》》漏洞复现《《《  
  
开启 WebDAV 和写权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpF7QUoPyibRoJ15JSpFePc0BfBzZQWTQwH8OPYm4jGBvIgibZ83WQlfhDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFlmXiaDp6hXP1XgrX2MkBiaCg199ro8t0BuzcbxRo7yHicMKd4nJnLJmug/640?wx_fmt=png&from=appmsg "")  
  
⽤burpsuite 提交OPTIONS 查看⽀持的协议 ：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFepH9Igo8YCqp4Q2CvxDY2waOgAibL2tiaAEmgUbvThv065BqHxD1CzFg/640?wx_fmt=png&from=appmsg "")  
  
⽤PUT上传⽂档，但不能直接上传⽅法脚本⽂档，可以先上传⼀个其他类型的⽂档，然后移动成 脚本⽂档（内容为asp的一句话木马）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFrEKPQUXicf4EEYicb2z1jIZjfkDx9zgUkIz7xVFmR0K6tBsYjhm9vQhA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFg2NMslSNxpKOECCydGC8gTRyShvoo1ySib5Es0yGOg0yiawSKJ73mZHw/640?wx_fmt=png&from=appmsg "")  
  
使⽤MOVE命令将其更名为脚本⽂档后缀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFSgVUZL6lWK3ftd7law6oY4iaAKQKYdxMUP1xo2GUEhZVbPuecv1hWug/640?wx_fmt=png&from=appmsg "")  
  
5.用中国蚁剑连接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFv5uUVQx93b6ZNxxo5fKtkPsIdhFBPpU6EUwkVFnZKGovNgWmiabCofg/640?wx_fmt=png&from=appmsg "")  
  
  
二、IIS RCE-CVE-2017-7269  
  
》》》漏洞描述《《《  
  
Microsoft windows Server 2003 R2中的 Interne信息服务IIS6.0中的 WebDAV服务中的  
  
ScStoragePathFromUrl函数中的缓冲区溢出允许远程攻击者通过以 If:<http:// 开头的⻓标头执  
  
⾏任意代码 PROPFIND请求。  
  
》》》影响范围《《《  
  
WiNdows Server 2003 R2上使⽤IIS6.0并开启 WebDAV扩展。  
  
》》》漏洞复现《《《  
  
WiNdows Server 2003 R2 上使⽤IIS6.0并开启 WebDAV扩展  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFoibGcJI2mDhE3qRWT1ic18CNJc95lIkNniaR8rLs86qRgB3fYPF0XytsA/640?wx_fmt=png&from=appmsg "")  
  
2.将 GitHub - g0rx/iis6-exploit-2017-CVE-2017-7269: iis6 exploit 2017 CVE-2017-7269 下载并放到kali里面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFKEEa1olxZs2B0ibDxebUD3DqwFHZsYwJt37ZvbS0cHxXXpuvME9U6HA/640?wx_fmt=png&from=appmsg "")  
  
3.kali开启监听  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFVrbeg8tsnOiavGuGYfiaEtfRWQqD8LgOInhknU7w7nC1PJ1W6RrQeL3g/640?wx_fmt=png&from=appmsg "")  
  
4.kali下载⼯具，nc监听  第一个ip为2003ip 第二个为kali ip  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFdUA5Aiahhxh3GOwV1m4kA0ErCKpdDoFKP5cHSffusFoDZvoicLiajW2FQ/640?wx_fmt=png&from=appmsg "")  
  
成功监听  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFxxRdJ8D66RMuajPMglYjp96HeEV5B51GIQvrAQlPOQebB0H0P2LmpA/640?wx_fmt=png&from=appmsg "")  
  
三、IIS7⽂件解析漏洞  
  
》》》漏洞描述《《《  
  
        HTTP.SYS是Microsoft Windows处理HTTP请求的内核驱动程序，为了优化IIS服务器性能，从IIS6.0引 ⼊，IIS服务进程依赖HTTP.SYS。HTTP.SYS远程代码执⾏漏洞实质是HTTP.SYS的整数溢出漏洞，当攻击者向受影响的Windows系统发送 特殊设计的HTTP 请求，HTTP.sys 未正确分析时就会导致此漏洞，成功利⽤此漏洞的攻击者可以在系统 帐户的上下⽂中执⾏任意代码。主要存在Windows+IIS的环境下，任何安装了微软IIS 6.0以上的Windows Server 2008R2/Server 2012/Server 2012 R2以及Windows 7/8/8.1操作系统都受到这个漏洞的影响验证这个漏洞。  
  
》》》影响范围《《《  
  
Windows7、Windows server 2008 R2、Windows8、Windows server2012、Windows8.1和Windows server 2012 R2、IIS7.5、IIS8.0、IIS8.5  
  
》》》环境搭建《《《  
  
windows server 2012 IIS8.5  
  
》》》漏洞复现《《《  
  
访问网站，编辑请求头，增加字段  
```
Range: bytes=0-18446744073709551615
```  
  
若返回码状态为416 Requested Range Not Satisfiable，则存在HTTP.SYS远程代码执⾏漏洞。  
  
burp抓包修改请求头：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpF4SB20d5icCOM8OpuBUj1Uuuqk4Zbk3DT39Rbichiafs5fDxajSr2xOssA/640?wx_fmt=png&from=appmsg "")  
  
  
POC ：  
```
https://github.com/davidjura/MS15-034-IIS-Active-DoS-Exploit-PoC
```  
  
可以造成⼀个ddos的效果：填上地址 填上端⼝ 主⻚图⽚ iis8.5的是（iis-85.png），其他的可以根据百度查，每个版本的欢迎⻚都不 ⼀样 选择 y  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFCHuD6Qh1oqaecHTwP6lBcDG7f6Oicr8SVDjns0e7w8iaY2zeHz5ibehPA/640?wx_fmt=png&from=appmsg "")  
  
这时候就可以看到虚拟机已经变卡了，甚⾄蓝屏。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqrsGE7B6fjXibXaUI879nLpFCkSKPRtt2uKZfnObCFdJ1cXTKmQxRic2J4RYsnlqVKFRBrSUiaJbxYzg/640?wx_fmt=png&from=appmsg "")  
  
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
  
好文**推荐******  
  
- [免登录读取别人的WX聊天记录](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247487346&idx=1&sn=9810af860afd8f94e1cf2ccf81a7e13f&chksm=c20a2c55f57da543fe1bdc21e670d036cb10efccf4d102a4bf9cb7c3956786858230c8172b54&scene=21#wechat_redirect)  
  
  
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
  
  
  
  
  
