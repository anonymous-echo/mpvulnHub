> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486552&idx=1&sn=41c4e4a40fd104f53e22f5a7143c88ad

#  记一次企业src漏洞挖掘连爆七个漏洞！  
小黑子安全  小黑子安全   2025-07-12 07:27  
  
自从上一篇作者开发的  
yakit  
漏洞自动检测插件介绍后，作者又开启插件进行了企业src的漏洞挖掘之旅，此次挖掘竟然连爆  
7  
个漏洞，作者自己都没想到插件竟然这么给力！  
  
接下来就详细介绍作者是如何通过  
yakit  
启动自研插件挖出七个漏洞的！  
  
第一步——代理设置，开启插件  
       
（  
  
会的师傅们可以跳过）  
  
浏览器设置好代理，使用浏览器插件  
 S  
witchy  
Omega   
设置代理  
  
为  
 127.0.0.1  
：  
8080   
，让浏览器的流量经过本机  
8080  
端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavdBRa9O0s7chGVjVKGjMSs5WZmUnLRiciaM7Zxa6v6C2Dk8nUkDhH7Nfw/640?wx_fmt=png&from=appmsg "")  
  
浏览器插件安装：浏览器右上角三点——扩展——应用商店——搜索框搜索  
S  
witchy  
Omega  
——安装  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaaveoicnibpryLd7ia0jzhvxTMH08eGia51cbibwVqKkicVlpdoq6syIPmJCKBQ/640?wx_fmt=png&from=appmsg "")  
  
第二步——yakit  
  
开启监听  
  
yakit中创建一个项目打开，在如下界面设置监听本机  
8080  
端口——点击启动劫持  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav8DaImeE1VxJ33WA5thwAvMKmv07AucwY3vAtNtK7jVFXBFsjI9PcHg/640?wx_fmt=png&from=appmsg "")  
  
来到抓包界面——选中作者的插件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavrjFHp13Bic9oYicPEcCEkAjSk6SNiaFzAWWhAB5v2Kh1XT5QDhBJEmEtA/640?wx_fmt=png&from=appmsg "")  
  
此时即可开始漏洞挖掘，对目标做信息收集，然后在浏览器“点点点”目标网站的功能点触发流量，  
yakit  
获取流量后插件就会对所有流量进行漏洞检测。  
  
漏洞检测结果会展示在此处  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav1mRSzCRfMIKW9iaibhatafbgmRsVnlLSrQrIuqziawo4r0rCZ4Z19uMYQ/640?wx_fmt=png&from=appmsg "")  
  
七大漏洞！  
  
一、被动目录扫描插件发力——登录接口弱口令  
  
被动目录扫描插件爆出了一个登录接口，于是尝试  
  
test  
/  
test  
  
成功返回token。目前已修复  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavVeXs9OuicXKPa2NE16Q0XlMI4mBIWrp4WoPVI6vjPpSiayx1rWgmPI2Q/640?wx_fmt=png&from=appmsg "")  
  
提交通过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavXTVCsGLQ0vsnQkTRSZVynJ5picr651sFZmeHV5ViaKoia5Sv73cIzem4g/640?wx_fmt=png&from=appmsg "")  
  
二、  
fuzz  
立大功——管理员账户创建接口（已修复）  
  
上一个漏洞发现接口  
***/***/  
login  
    
就思考会不会存在其他接口于是对  
 /login   
进行fuzz，成功爆出创建管理员接口：  
***/***/  
RegisterManager  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavAuSNpbmtJxvTMwiaSLFzPvRd2e6iboxXMbrLsbLeRGicU8nJmGy5yWFNw/640?wx_fmt=png&from=appmsg "")  
  
成功创建管理员  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavKG1jPzw4QIlgM26zMiaIUKibXnfhJxRZqDnI5rs6kXwScbdHFDXEic4tQ/640?wx_fmt=png&from=appmsg "")  
  
三、被动目录扫描插件再现奇迹——swagger接口泄露，可控制所有接口！（已修复）  
  
查看漏洞结果发现  
/swagger/index.html  
  
目录泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav0hkDKbLQWVzXwkSZR9gMicicmwxoAgGfVp6YFLyURkx4YFQtiayw6nakg/640?wx_fmt=png&from=appmsg "")  
  
访问发现里面有所有接口泄露，且全部可控。如：创建管理员、登录、获取用户数据等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav4deicToGNqibFTIV89sTstVwC2qqaHVC1A7huq1cgoR7Vwy731rtiaWWQ/640?wx_fmt=png&from=appmsg "")  
  
最后因为无法找到接口对应网站功能点，严重级别的漏洞只给了中危，我  
tm  
哭死  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavmKOPcibTXTXV66ic2G81zbzaawBS3aGq6hCxicuViaQgxPMBiaCibxdbyEWw/640?wx_fmt=png&from=appmsg "")  
  
四、被动xss扫描插件展现神力——反射型xss  
  
就是复现一下，就不细说了。全靠插件发力！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavLiaDW7kNac6cVJH3MEu2QCGvxzgzzUflbW7hdkicLEQFAf5PLNw7YgSw/640?wx_fmt=png&from=appmsg "")  
  
成功通过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav38vYR2PAPsmibk3ToRCI7pbhiary2gtFtU21MwKOjkeAlT166ocOTDVw/640?wx_fmt=png&from=appmsg "")  
  
五、作者发出神力——url重定向  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavO8sKvTEMZuA6az9oA7vZicIMLEicia2buM3qsXpk6C3fwNz4Hcic6ibTgKA/640?wx_fmt=png&from=appmsg "")  
  
成功得吃  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavlbgYjZAGpad8x8X8HM6yiaM7R5ookBxjwDUHylYZfib7ahAX2fZtWDYA/640?wx_fmt=png&from=appmsg "")  
  
六、被动sql注入检测插件奇迹再现——两个sql注入！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav4R7pLQCuZDl1Sczd37IZiaPk1A9icjD4NZozLX8JEiatXnmyplCdz7UBw/640?wx_fmt=png&from=appmsg "")  
  
复现成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavIib8FB6YCrXc2UbGvmG2v6qpHoiasLGkian27Dd2AXN4iaicBxZ4d2xibPlw/640?wx_fmt=png&from=appmsg "")  
  
得吃  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavIbp79S9jdFVwicYoG8eyKHEbNJiaKibmibktUqeOiaHAWqdDPABUiaG2yPFg/640?wx_fmt=png&from=appmsg "")  
  
以上漏洞都是不需要任何技巧的，作者只是开启插件在目标网站用鼠标“点点点点”就挖掘出这么多漏洞，完全  
  
“零基础”“  
  
零成本”挖洞  
  
目前一共开发了四个插件：  
  
被动  
sql  
注入检测  
  
被动  
xss  
扫描优化版  
  
被动目录扫描好人版  
  
被动  
ssrf  
及  
log4j  
检测  
  
插件使用教程：  
https://mp.weixin.qq.com/s/vQ9r86AwmxKAyZnb3t1FLw  
  
知识星球——小黑子安全圈  
[  
精华版  
]  
    
开业大吉！  
  
每一个插件都是非常实用的，有没有用作者也已经通过  
  
企业  
src   
漏洞的挖掘来证明了，并且只需要开启插件  
  
点击鼠标就可以全自动挖掘漏洞。  
  
需要获取插件的小伙伴可以扫描下方二维码加入我的知识星球，星球  
 99  
元  
/  
年  
  
，前  
50  
个加入的  
 77  
元  
/  
年。  
  
加入知识星球的同学会提供  
  
yakit  
  
安装  
  
和  
  
插件  
  
使用教程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaav5veFmMtgjPMXxwegcp5dQ4Ow5aepgDwTyUdOOq0PsjeBPJZibuhZRYg/640?wx_fmt=jpeg&from=appmsg "")  
  
本星球只提供精华内容，没有烂大街的东西。会持续更新  
yakit  
插件和各种漏洞漏洞探针和利用工具，哪怕你是什么都不懂的小白用了插件点点鼠标就能挖到漏洞。  
  
注！！！红包返现！！！拉新活动！！！  
  
星球接受使用插件挖到漏洞的投稿，我审核通过会返  
30  
红包，直接微信转，文章我会发公众号  
(  
每人仅限一次  
)  
。  
  
拉新人加入星球待满三天也会返  
20  
红包  
(  
微信直接转  
)  
。插件会一直优化和上新，欢迎大家加入星球。  
  
  
