#  一次完整的Jwt伪造漏洞实战案例   
原创 Tai  Code4th安全团队   2024-12-17 14:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQGQG6ibYpsQ9hibUNQ9JogaBM4ETcLDdyuTknYvxjLbGCEQFKUEwbwpummEIZzqUcA3Mhaj6yJqd9Q/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
本文章由团队师傅[Tai]授权发布  
  
  
  
**某次漏洞挖掘**  
时  
遇到了任  
意用户登录漏洞，这次的漏洞案例是由于  
jwt  
存在弱密钥，攻击者可以伪造  
jwt  
，从而获取非授权访问权限。此外站点还存在弱口令，可以通过弱口令登录  
druid  
后台，查看敏感信息。  
  
首先通过微信搜索小程序，找到目标。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdmRwVvibC5kPLJomSiadTpMl0oPlM1NpWgZ592naoGgYZbV1I9icZ53y9w/640?wx_fmt=jpeg "")  
  
点击进入小程序，点击我的-微信登录  
  
观察数据包，可以看到服务器生成了一个  
jwt值  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdVABtafRnDjX3lYmaE78D0xfpib0IbvOhV8PibWnY0llrI7ib57Ag4uI5g/640?wx_fmt=jpeg "")  
  
这边就直接尝试爆破该Jwt值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpd3FicQwSFTL827u6ianWZK5Y8rwKKUGdMR7KoUFyqTUJlye1ibUOEKn44w/640?wx_fmt=png&from=appmsg "")  
  
爆破发现其使用了  
JJWT  
，且原始密钥为  
abcdefghijklmnopqrstuvwxyz  
  
  
解密该  
jwt  
，发现其中有个  
user_id  
字段  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdckffyuJ6osqI9icGO7RXsnmL48DnWg8vickryQPaN7IFkyNFTNfZNicrw/640?wx_fmt=png&from=appmsg "")  
  
用  
python  
脚本遍历  
user_id  
的值，范围为  
1-4103  
  
根据不同的user_id，用密钥再生成不同的获取  
jwt值  
  
然后在  
/system/api/getUserInfo  
接口上获取  
jwt  
用户信息。  
  
```
key ="abcdefghijklmnopqrstuvwxyz" 
secret = base64.b64decode(key[:len(key) - (len(key) % 4)])  # Base64 解码密钥
```  
  
此处使用的Python生成脚本如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpd8g26vvdnlsnROhf9iaKbLSrcxDibA25jniaxJdJDMmxXlfNdGOaKDsNLA/640?wx_fmt=png&from=appmsg "")  
  
注意，服务器是通过判断  
user_key  
来判断  
jwt  
是否在有效期，如果爆破的时候服务器返回  
jwt  
过期，请重新进入小程序刷新一个  
jwt  
在遍历  
user_id  
。  
  
  
  
之后成功遍历出所有用户的信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpd7QJboaratJFDxRcfHwUgCpAStFf1bGyUb3RYliaCdBO4mgroSBwP6yg/640?wx_fmt=png&from=appmsg "")  
  
在用户中发现了测试账号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdRFayDTibDF8LAzdr3JKQDnV4BzWWdianLF2NByzdnFSeiby5mQBg4KWYA/640?wx_fmt=png&from=appmsg "")  
  
尝试登录这个账户，先清空小程序缓存，重新进入小程序，点击我的，进行抓包抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdskE3gO9n36fSbiajxEbwMEodLe6XpKvm6KTmMb8F5Zd0nFFr23oqVpQ/640?wx_fmt=png&from=appmsg "")  
  
修改返回包的  
jwt  
为测试账户的  
jwt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpda1NNxvWArBxeG4y89vqqZXMuIahmXYbibiad8RnRvIuh6vBYduN8K3VA/640?wx_fmt=png&from=appmsg "")  
  
包放出去，可以看到成功登录该测试账号，存在任意用户登录漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdMwtxVawVhqv1icDHsicLxEy0cxQYWtSiaQm2I0EEWY66keZJibN4aB3AIw/640?wx_fmt=png&from=appmsg "")  
  
  
然后是druid弱口令的挖掘  
  
目录爆破该路径，注意请求头要带上  
jwt  
，否则服务器会响应  
401，爆破出了/sysyem路径，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdSicC6viaD0LKic8ROibibepTicibUxQuMDiaPnIGfquGuJwlE2wH8CsoJ7Sqog/640?wx_fmt=png&from=appmsg "")  
```
https://xxxx/system/
```  
  
接着就发现了  
druid的  
后台  
```
https://xxxx/system/druid/login.html
```  
  
  
同样，访问的时候请求头也要带上  
jwt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdnO14xQQe7LrF1gVG14IektgzibcYRiceFDAIPP6libt0Ae3FSMSj8icIiaQ/640?wx_fmt=png&from=appmsg "")  
  
使用弱口令  
admin/123456登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdJaWIJTfJvTIcbv1LTzp2HibrfYxicSRVmXibr0KCSkU42iboToxhja6Xicg/640?wx_fmt=png&from=appmsg "")  
  
后面还扫出了  
spring  
一些端点的信息泄漏，但是并没有发现有价值的信息，此外还发现了  
swagger  
接口文档，由于站点敏感，没有继续对接口测试  
  
之后又发现该域名  
8081  
端口还开了个系统，一眼看上去是若依系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdicWzn1SicjCt0cOdJdPkK7RCYibMVIPXRib61iaOWnx5dE6Lia8x01eHW7mw/640?wx_fmt=png&from=appmsg "")  
  
从浏览器的URL路径提取插件  
findsomething中  
找到了一些接口  
  
拿小程序搞到的  
jwt  
，放到如下接口爆破，可以看到这个系统用户的信息，包括账号和密文的密码  
```
GET /prod-api/system/user/getInfo HTTP/1.1
Host: xxx:8081
source-client: miniapp
tenant-id: 1001
Authorization: {{file:line(E:\Yakit\Yakit\yakit-projects\temp\tmp297600343.txt)}}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdickBRnnkQ8E2bsR66SpiaawLWCQqWCAjeuHr0tPQWek9zwLgZcmdU24Q/640?wx_fmt=png&from=appmsg "")  
  
可以证明这些  
jwt  
对该系统有效，但是没有具体的密码登录，现在只能调用该系统里接口获取数据，非常不方便；于是我找到了如下接口，里面显示了该系统的初始化密码为  
Eedssrcpt2024!  
  
注：数据包里  
jwt  
随便填一个有效的就行  
```
GET /prod-api/system/config/2 HTTP/1.1
Host: xxn:8081
tenant-id: 1001
Authorization: eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjozNTU4LCJ1c2VyX2tleSI6IjFiMDBkNTg3LTUyOGQtNGEwMS05NDY0LTQ5YzJkY2YyY2ViZiIsImRlcHRfaWQiOm51bGwsInRlbmFudC1pZCI6MTAwMSwidXNlcm5hbWUiOiJcdTVmYWVcdTRmZTFcdTc1MjhcdTYyMzdfODY1MCJ9.89FqNollbb7u2blR3PDDnHdbs5XStPjR9l5iQXwXlsaXBU7n7YKDh8ZZQMXWbcoUlRnG1m7nIgnLoZ_ajfxH-A
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpdToEMicCa5S7MlUXhjQDicYnEONmtz4chohnObudy08SZPjD6Q3HYHcSg/640?wx_fmt=png&from=appmsg "")  
  
于是随便找了个用户名尝试登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpd84IBRC9Ss4A6kSDtgvF8DiaeiakajWiafk4ib8uic0A9mssice1Ypqdrdicow/640?wx_fmt=png&from=appmsg "")  
  
使用初始密码Eedssrcpt2024!  
成功进入后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSd29k2XG3Gex6IFWtGbkpd9rffialncknZf6a2lAbtTwPCRe4ayaf4FMRh5h9WeyrmbTqNhFjKl7g/640?wx_fmt=png&from=appmsg "")  
  
到此渗透测试结束  
  
  
  
  
**每个初学挖洞的小白都有一个美梦**  
：是否可以在我学习挖洞技能的时候，有位师傅手把手指导，不仅教会我各种技术，还能带着我一起接项目挣钱，让我的技能和钱包同时“升级打怪”。  
  
    还真别说，现在这个天降大饼的美梦来了！FreeBuf知识大陆帮会《安全渗透感知大家族》，正好为你提供了这样的机会。在这里，你既能  
学到知识  
，又能  
做项目赚钱  
，还能在项目实践过程中与大佬们  
交流思路、夯实基础  
。  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651303102&idx=1&sn=6bd3abdb7109cc66aba29c207220abb3&chksm=bd1c3e358a6bb723efafa4f60e95a264aeea48508f9acef1444e8d5dded986457f046c39e3a2&scene=21#wechat_redirect)  
  
该**SRC漏洞挖掘出洞课程**  
，是由团队内部师傅根据实际挖洞经历整合的适合挖掘漏洞但是缺乏思路、刚接触学习漏洞挖掘不出漏洞的师傅们的漏洞挖掘教程。  
  
第一期课程价格  
199  
，这价格还要什么自行车？课程正在持续更新中~  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485154&idx=1&sn=90f1bce91e53a5bf538bdef11fe15b2d&chksm=c2516dcbf526e4dd6d75254b70743d30902a7f0288d001148a41cc05e2d0b9fb09702d2ea03e&scene=21#wechat_redirect)  
  
**致远A8**  
，又称致远互联A8协同管理软件，是面向中型、大型、集团型组织（集团版OA）的数字化协同运营中台。A8版本的系统小版本较多，本次分析用的是致远A8 V7 SP1版本源码。  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247484688&idx=1&sn=928f50f70991a1979dcefb8d02cb02d6&chksm=c2516e39f526e72fae6fe053cf7ab537692bd5581a5552dfe7bfcee0588bd7e5c0d793f2f84b&scene=21#wechat_redirect)  
  
  
  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
了解更多安全相关内容~  
  
  
