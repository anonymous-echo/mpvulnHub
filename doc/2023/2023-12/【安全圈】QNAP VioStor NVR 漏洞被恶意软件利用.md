#  【安全圈】QNAP VioStor NVR 漏洞被恶意软件利用   
 安全圈   2023-12-17 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaueJ5iaMrdZd96GWXqDfsgENdlJ4l02TEDQekO8UnNlcoy2ibZjeQibEpSEe7jNsia6XGWyr7NKsjn1A/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
恶意软件  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljdQAK37picRUTUYQwKQPibicc1O38nchXQnDx7XKyia2IhNJFUjNZYX7HK71TNqYz2fp2sB27uJ7ibWdw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
一个名为  
“InfectedSlurs”  
的基于   
Mirai   
的僵尸网络正在利用   
QNAP VioStor NVR  
（网络录像机）设备中的远程代码执行   
(RCE)   
漏洞来劫持并使它们成为其   
DDoS  
（分布式拒绝服务）群的一部分。  
  
该僵尸网络由 Akamai   
的安全情报响应团队   
(SIRT)   
于   
2023   
年   
10   
月发现，他们观察到路由器和   
NVR   
设备中两个零日漏洞的利用情况，可能从   
2022   
年底开始。  
  
当时，由于供应商尚未发布补丁，Akamai   
选择不披露有关   
InfectedSlurs   
所利用的缺陷的任何信息。  
  
随着有关两个零日漏洞的安全更新或信息的发布，Akamai   
发布了两份后续报告   
(1  
、  
2  
）以填补   
11   
月底  
   
原始报告  
   
中留下的空白  
.  
  
InfectedSlurs   
利用的第一个零日漏洞被追踪为   
CVE-2023-49897  
，影响   
FXC AE1021   
和   
AE1021PE WiFi   
路由器。  
  
供应商于   
2023   
年   
12   
月   
6   
日发布了安全更新  
   
，固件版本为   
2.0.10  
，并建议用户恢复出厂设置并在申请后更改默认密码。  
  
僵尸网络攻击中的第二个零日漏洞是 CVE-2023-47565  
，这是一个高严重性操作系统命令注入，影响运行   
QVR   
固件   
4.x   
的   
QNAP VioStor NVR   
型号。  
  
QNAP   
于   
2023   
年   
12   
月   
7   
日发布了  
公告  
   
，解释了之前未知的问题已在   
QVR   
固件   
5.x   
及更高版本中修复，适用于所有积极支持的型号。  
  
由于版本 5.0.0   
已发布近十年，因此推断   
Infected Slurs   
僵尸网络的目标是旧版   
VioStor NVR   
型号，这些型号在初始设置后从未更新过固件。  
  
供应商建议对易受攻击的 NVR   
设备采取以下操作：  
  
以管理员身份登录 QVR  
，前往  
“  
控制面板  
”  
系统设置  
< /span>”  
找到适合您的特定型号的正确版本。浏览  
”  
选项卡，然后单击  
“  
固件更新  
,'  
选择  
“  
固件更新  
→     
控制面板  
“  
  
最后，点击  
“  
更新系统  
”  
并等待   
QVR   
安装更新。  
  
此外，建议通过  
“  
更改   
QVR   
上的用户密码  
”ControlPanel → < /span> ,'  
输入新的强密码，然后点击  
“”  
。应用更改密码  
→   
用户  
 →   
权限  
   
  
已达到 EOL  
（寿命终止）的   
VioStor NVR   
型号可能没有包含固件   
5.x   
或更高版本的可用更新。  
  
这些设备不会收到安全更新，因此唯一的解决方案是将其替换为更新的、受积极支持的型号。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhCw6TGbJsh6bJHUeHonc625JS0MCVeP5yAYXZmuPGniciaw9fDnkuFVQlKhsReLXJW1O3e0r0T0rLw/640?wx_fmt=png&from=appmsg "")  
[【安全圈】曾注册超 7.5 亿个欺诈账户！微软查获越南网络犯罪团伙](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050722&idx=1&sn=d389bf057069e282638d241f3a5f208d&chksm=f36e3962c419b074a4c6d61598123d96a98b0a099ccfbdc3d573f3285e894c769355942efa18&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhCw6TGbJsh6bJHUeHonc62q7VayFr4KqLlmdVZ9ib0zKURBY9ibrBkzk4Dicm3Q2QZicVpTes5nsVKVw/640?wx_fmt=png&from=appmsg "")  
[【安全圈】戴尔紧急通报PowerProtect产品中的多个高风险漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050722&idx=2&sn=5d24ce039ab3faa04e3ee2290d2d2f6b&chksm=f36e3962c419b074f215589bc2a104aaa40fab98dc5115d965e7f36e69e10571f58bacb8a83d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljm28DrN8Bnn2TNSLNVWDZ4ECl0asIYckYN8yh19TgNn9RjOMm6PWHTEKbTtwAE2lhj7FsAucXV8g/640?wx_fmt=png&from=appmsg "")  
[【安全圈】美国一银行工程师离职删库，影响较大，被判刑！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050722&idx=3&sn=6ba242fc6d13dd2da11e1957c11d869a&chksm=f36e3962c419b0740bbf80593c5b8a2cee95d663ff18cac2d4b341ff24e31f185e8f7c901c6a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ0lCLo41YhGriawGLic3oG43JRTSiaFhhiajaQNItHS4ic5aTwYibCSRIVoxzA/640?wx_fmt=jpeg "")  
[【安全圈】瑞士中部法院遭受网络攻击，4.5万公民数据有被盗风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050722&idx=4&sn=8cee95ee3b2df88da023745dbe6aa88d&chksm=f36e3962c419b0747703deda6d38c43e3cfb263518f65ff2f71d3a102af81b9c734c306ac645&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
  
  
  
