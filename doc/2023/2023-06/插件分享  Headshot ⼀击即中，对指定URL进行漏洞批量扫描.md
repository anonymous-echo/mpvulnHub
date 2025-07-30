#  插件分享 | Headshot ⼀击即中，对指定URL进行漏洞批量扫描   
原创 kv2  GobySec   2023-06-05 18:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjLTMIjhRPrloPMpJ4nXfwsIjLDB23mjUrGc3G8Qwo770yYCQAnyVhPGKiaSgfVu0HKnfhT4v5hSWcQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKCOJflJYoKf2WCAmLibq4ur6yyXkSrnD4gvN2ib4BKibogib3vmKIujNrRChBRgm1Vfq3WlCzGfas3bw/640?wx_fmt=png "")  
  
  
  
G  
o  
b  
y  
社  
区  
第  
   
2  
4  
   
篇  
插  
件  
分  
享  
文  
章  
  
全  
文  
共  
：  
2445  
   
字  
   
   
   
预  
计  
阅  
读  
时  
间  
：  
7  
   
分  
钟  
  
  
在⼀次真实的攻防场景中，我们发现了⼀个存在 Struts2 漏洞的地址，这个地址在我们通过 Fuzz 获得的⼆级⽬录下，这使得 Goby 的爬⾍没有办法爬取到这⼀个⻚⾯，但是我们通过其它 Struts2 专扫⼯具检测发现这个地址确实存在 Struts2 远程代码执⾏漏洞，⽽且经过分析，Goby 中的 PoC 是能够检测出这个漏洞的，于是这让 Goby ⾯临了⼀个尴尬的局⾯，我明明知道这个 URL 地址有漏洞，Goby 也有这个漏洞的 PoC，⽽且这个 PoC 可以使⽤，但是我们却没有任何办法让 Goby 能够检测到这个漏洞。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**01 丝滑的 Struts 漏洞检测**  
  
这个问题让⼈有点如鲠在喉了，于是我开始着⼿解决这个问题，捣⿎了这⼀个插件：**Headshot，其功能是给⽤户提供⾃定义选择 PoC 以及输⼊ URL 地址的渠道，让⽤户在真实的攻防场景中，能够较快的对指定 URL 地址完成 PoC 检测和利⽤，**  
这使得我们在⾯对类似   
Struts2   
这样的攻防场景的时候，可以更为灵活的使⽤   
Goby   
来解决问题。最终  
的插件其貌不扬，但让整个过程变得⾮常丝滑：  
  
  
如果你想亲身体验一下，在 Vulfoucs（  
https://vulfocus.cn  
）上，针对Struts2漏洞有着非常全面的靶场：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKCOJflJYoKf2WCAmLibq4urIwD58huAzRAff1ibtKuZg3aPfy6ZAt8IICutMz9IMQq7X8GIicPBgv4g/640?wx_fmt=png "")  
  
可以选择   
struts-s2-001  
 代码执行（CVE-2007-4556）来进行演示，当点击   
Submit  
 按钮之后，页面上出现了明显的 Sturts2 特征：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKCOJflJYoKf2WCAmLibq4uribZWKebkWFJECZFQzwUia5zH9ljE8ezyA3SNfBnFpassFzbQIL1gyYvA/640?wx_fmt=png "")  
  
Struts2 系列漏洞在真实的攻防场景中属于典型漏洞了，利用难度低，危害程度大，使用面广，而且还有着极易识别的特征，一般来说在信息收集过程中，发现页面上有这类  
似   
.action   
或   
.do  
 的链接，就说明目标极有可能使用了 Struts2 框架，这时就可以使用 Headshot 对目标进行快速检测：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIMmvjFibkZ3n9PRakszLHIOGdVRMlQibJPzFAXD6yfbSFaePCeRXtxKsIV5v5AakA5Oz1hBrh3mZKw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**02 自定义 URL 地址******  
  
有的目标会出现这样一种情况，当直接访问目标端口，会得到一个 Apache 的 403 界面（如图所示），除此之外无任何其他有效指纹特征，但当我们进入到   
oa  
 目录（别问我是怎么知道这个目录的）下之后，则访问到了真实的业务系统，这在一些企业的业务系统中尤为常见，在这种情况下原始版本的 Goby 是没有办法对目标进行检测的，因为在建立扫描任务的时候，无法自定义目录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKCOJflJYoKf2WCAmLibq4urYkh2gfcaLibU0MlBEVCoHQQjKn6nQPIHvYk99516QQEQEh9lWAzajTA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKCOJflJYoKf2WCAmLibq4urrialX6nTVxNnPokOD9iaQ77icdjqJ61bOP5kVjVdtcdewuJV9KvIhZvcQ/640?wx_fmt=png "")  
  
现在你可以使用 Headshot 很方便的对目标完成检测（视频全程无加速）：  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**03 批量快速检测漏洞**  
  
攻防高手在进行渗透测试的时候，需要挣时间，看手感，比如已经知道目标使用的是 WebLogic 或泛微、致远等各大 OA 系统的时候，我们只希望很快的对目标历史上出现的高危漏洞做快速检测。这在 Headshot 上将变得尤为简单：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**04 未来**  
  
Headshot 是 Goby 在插件功能上的一次尝试，以往的插件只能对 Goby 主流程的输入输出做修饰，比如 FOFA（从 FOFA 中提取扫描目标，输入给 Goby 进行扫描）、ShellHub（从 Goby 利用结果中提取 Webshell 进行 Webshell 管理）、TaskQueue（设置定时任务以及任务队列，输入给 Goby 进行扫描）等等，但 Headshot 不一样，**Headshot 实现了漏洞检测以及漏洞利用的拆分，不再依赖 Goby 主流程**，为了达到这个效果，我利用了 Goby 对外开放的三个的接口:  
- goby.debugPoc  
 判断目标是否存在漏洞，并返回验证的交互数据包以及验证结果；  
  
- goby.openExp  
 打开对应Exp的验证界面；  
  
- goby.getPocSearch  
 依据条件  
查询 PoC，并返回查询的结果列表；  
  
通过对三个接口的组合拼装，就形成了 Headshot，其实通过这些接口还可以做很多事情，比如可以针对某一类专项漏洞开  
发专用扫描工具，或者一键漏洞批量利用工具，也可以通过这两个接口对接其他工具作为漏洞扫描能力的补充，如果你有好的想法希望编写一个独一无二的 Goby 插件，可以在 Goby 官网了解更多关于 Goby 扩展程序的信息，那里有非常详细的开发文档，也欢迎大家加入我们官方社群一起交流插件开发。Goby 会陆续对外开放更多的能力，以便于用户可以使用 Goby 做更多更酷的事情。  
  
最后大家可以 Goby 客户端中的**扩展程序**一键下载体验 **Headshot**（见文末视频教程），Respect~~（**尝鲜体验此插件需前往官网 gobysec.net 或点击文末原文下载 Goby Beta 2.4.9**  
）  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**05 Reference**  
- Goby   
(  
https://gobysec.net  
)  
  
- Vulfocus   
(  
https://vulfocus.cn  
)  
  
- Goby-Doc   
(  
https://gobysec.net/doc  
)  
  
- Goby-Extensions   
(  
https://gobysec.net/extensions  
)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
> 插  
件  
开  
发  
文  
档  
：  
  
h  
t  
t  
p  
s  
:  
/  
/  
g  
o  
bysec  
.net  
/  
d  
o  
c  
  
  
  
  
**关于插件开发在B站都有详细的教学，欢迎大家到弹幕区合影~**  
- h  
t  
t  
p  
s  
:  
/  
/  
w  
w  
w  
.  
b  
i  
l  
i  
b  
i  
l  
i  
.  
c  
o  
m  
/  
v  
i  
d  
e  
o  
/  
B  
V  
1  
u  
5  
4  
y  
1  
4  
7  
P  
F  
/  
  
**更多插件分享**  
**：**  
  
  
[• Goby团队 | Shellhub 让 Goby 打通渗透流程](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247509889&idx=1&sn=90e34dac9b437584c4d4de9eebac9f28&chksm=eb844c21dcf3c5376cd98c3bfd3bc3802b9e25903c22b54c5def3a670c64f9dd05d5856f777e&scene=21#wechat_redirect)  
  
  
[• Zhe | Vulfocus 快速启动环境一键打靶](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247509989&idx=1&sn=a23f5b6a7eed2a39382e7a2cbcf17b4a&chksm=eb844c45dcf3c5531af956d0d65a16e32aefd8d9e5c6f0c55c75420f580dc56c55a005e0ca6f&scene=21#wechat_redirect)  
  
  
[• 天河 | 快速编码和加解密的CyberChef](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247514768&idx=1&sn=c2ab74c35c542b22089ca8c0ac0a4cc9&chksm=eb845130dcf3d826b3a4cc4d8969eef3fdd3b0dcb19a21c64705d7b73048965cc6b12016c367&scene=21#wechat_redirect)  
  
  
[•](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247507887&idx=1&sn=e96ce68003cb29820272bf20ee20963c&chksm=eb84340fdcf3bd19cd30d45ea1c84076cf853f750da1dc34058bac189cd6f0db13e3858565d7&scene=21#wechat_redirect)  
  
 [adeljck | 检测带外（Out-of-Band）流量的Ceye](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247515222&idx=1&sn=c349aebd09dfa461d38760fa192a687e&chksm=eb8457f6dcf3dee057ac1abb743ee9c008b3012ab8884cce19d156f9485865ee59ffcc9450a0&scene=21#wechat_redirect)  
  
  
[•](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247507887&idx=1&sn=e96ce68003cb29820272bf20ee20963c&chksm=eb84340fdcf3bd19cd30d45ea1c84076cf853f750da1dc34058bac189cd6f0db13e3858565d7&scene=21#wechat_redirect)  
  
 [hututuZH | GoPass系列免杀基础（一）](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247521822&idx=1&sn=e24bd083ea362d1715b274adfc046521&chksm=eb847dbedcf3f4a8f0bc17d92c170b5cb0144a8b2b885c40417357c750aed84b47fa9c07addb&scene=21#wechat_redirect)  
  
  
  
更  
多  
   
>  
>  
   
   
插  
件  
分  
享  
  
  
  
G  
o  
b  
y  
   
欢  
迎  
表  
哥  
/  
表  
姐  
们  
加  
入  
我  
们  
的  
社  
区  
大  
家  
庭  
，  
一  
起  
交  
流  
技  
术  
、  
生  
活  
趣  
事  
、  
奇  
闻  
八  
卦  
，  
结  
交  
无  
数  
白  
帽  
好  
友  
。  
  
也  
欢  
迎  
投  
稿  
到  
   
G  
o  
b  
y  
（  
G  
o  
b  
y  
   
介  
绍  
/  
扫  
描  
/  
口  
令  
爆  
破  
/  
漏  
洞  
利  
用  
/  
插  
件  
开  
发  
/  
   
P  
o  
C  
   
编  
写  
/  
   
使  
用  
场  
景   
/  
   
W  
e  
b  
s  
h  
e  
l  
l  
   
/  
漏  
洞  
分  
析  
   
等  
文  
章  
均  
可  
）  
，  
审  
核  
通  
过  
后  
可  
奖  
励  
   
G  
o  
b  
y  
   
红  
队  
版  
，  
快  
来  
加  
入  
微  
信  
群  
体  
验  
吧  
~  
~  
~  
- 微  
信  
群  
：  
公  
众  
号  
发  
暗  
号  
“  
加  
群  
”  
，  
参  
与  
积  
分  
商  
城  
、  
抽  
奖  
等  
众  
多  
有  
趣  
的  
活  
动  
  
- 红  
队  
版  
付  
费  
渠  
道  
：  
h  
t  
t  
p  
s  
:  
/  
/  
g  
o  
b  
y  
s  
e  
c  
.  
n  
e  
t  
/  
s  
a  
l  
e  
  
戳  
这  
里  
领  
取  
一  
份  
插  
件  
任  
务  
吧  
！  
> https://github.com/gobysec/GobyExtension/projects?type=classic  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKCOJflJYoKf2WCAmLibq4urCTsnx2u8k3CEXzPaGZpHfkakwLU2ibNsqvicSnqZZIjwgibib5Mr08Micwg/640?wx_fmt=png "")  
  
