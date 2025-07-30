#  记一次小程序渗透测试到通杀RCE(0day)   
 实战安全研究   2024-11-29 14:39  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**朋友委托我帮忙测一下他搭建的小程序，记录一下，从一个小程序开始挖掘，直接挖到通杀所有同类型站点的组合拳RCE，部分截图厚码请见谅.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEM3rKX8IGzSvUmF7EgkSJhmO4ISRe1BsxhmUjRp2bQtpLAahibDpHwPWQ/640?wx_fmt=webp&from=appmsg "")  
## 0x01前期准备  
  
**寻找小程序目录可以通过设置-文件管理-打开文件夹-Applet目录里就是存放小程序的文件夹了.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMDBY8J8Vp1abNIToEicicmxdIG6TqVQVapQVYiaWACx4x5aBkY7atMVpBQ/640?wx_fmt=webp&from=appmsg "")  
  
**先用Wxapkg 1.5.0工具对小程序进行反编译解包，这工具还挺方便的，能自动扫描存在的小程序，然后拿到前端的源码，里边包含了一堆Api接口.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMvEp3dhvWX3z2I3Q1rmjU6osWtZiaZiax8fujMdEoWwyicAUcEVHSsrB7g/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMD3dWoMJ9MSt0GdxsLX8LaotbQrXG4PYSwp3dMUd1a52swd8SR5SMgw/640?wx_fmt=webp&from=appmsg "")  
  
**写了个脚本自动提取小程序中的Api接口，将所有接口都导出来.**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMYIKF5Q7MegXmpnVvndb6AIlgxnloibZcB3LTRKxcz1oIcxKwBRX8zqw/640?wx_fmt=webp&from=appmsg "")  
  
**然后就是启动 Proxifier 设置好需要拦截的程序为目标小程序，这里可以通过先打开目标小程序，然后在任务管理器中的进程中找到 WeChatAppEx 然后右键打开文件位置，就能找到目标小程序所在的文件夹，之后在Proxifier中设置好代理为 127.0.0.1:8080 即可.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMwHO9yBibeGdx19lBcnBuc50DVvRqGjTMb0FyILrCTECpSjRdYA8EaFg/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEM0UaEibxHjjdENlntpaia7MFib76dNhibC8mImDicCE6vCmnYnsCtWaVa8aA/640?wx_fmt=webp&from=appmsg "")  
  
**然后继续打开小程序，当Proxifier 中出现一堆wechatappex.exe 时，说明拦截在运行了，只需启动BurpSuite 即可抓到包，就可以开始愉快地玩耍了(Ps:这里也能抓微信浏览器里的包).**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMZxTibWJTAvgAu4SliaBVR1H7bgZRiaKeJiaJa5a7QpZeNbG52Yjr5rGuibw/640?wx_fmt=webp&from=appmsg "")  
## 0x02 渗透测试  
  
**直接访问目标小程序后端网址发现是一处登录入口，测试过弱口令，逻辑漏洞，无果.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEM5zVl5rleicwd2KDKvAicHJkLRRlBw2vBbNMd9Jr4hGsFCaJBtWcDmuiaw/640?wx_fmt=webp&from=appmsg "")  
  
**将所有Api接口放到BurpSuite的插件中批量Fuzz，发现大部分接口都需要在个人中心登录后访问，于是去登录了一下，不久便找到了一处可疑的地方，发现有一处地方将参数赋值为' 就会发生报错，因此判断这里很有可能存在SQL注入.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMiaIVLMuFZbXTzXMBd8FsfCnibGZOEGqTJJLXRrADCDoZw4HKUhCC6Csg/640?wx_fmt=webp&from=appmsg "")  
  
**二话不说直接上Sqlmap，看看能不能一把梭，非常幸运，经典的联合注入+时间盲注，貌似没装任何的Waf，看看能不能直接跑出管理员账户密码.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMjFSBmcU5dvbfxPqvNuaiaFcMO8dKibthnhTVAIeAKZQ4Q0BibGoia76j7w/640?wx_fmt=webp&from=appmsg "")  
  
**可以跑出管理员的账号密码，拿去Cmd5解密，发现是一条付费记录，起飞，直接找人去解开这md5.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMmpdKaJsriasE3ktRqdVD6S0CG7BQ6pficQowxE8uVibOBficfTca0vjpVw/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMFV7Y1noM6gBj2bnGQibfYQdBeiaK4fOe9jZiaKnTZR8L8tJY3eWZCia7cg/640?wx_fmt=webp&from=appmsg "")  
  
**成功登录进后台，开始挨个测试哪里可以上传文件，发现后台所有功能点都只能传图片文件，不能突破后缀.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEM2m9ACgmTiaIGBXiczTh0iaKgLENeA4sibEhgVzhdUkPyibo4263BvNMH8OQ/640?wx_fmt=webp&from=appmsg "")  
  
**后台的接口比小程序前端的接口多了十数倍，遂打开经典的SuperSearchPlusTools，开始寻找能利用的接口，sql注入已经不需要了，只需要找上传的接口，花了挺久的时间寻找.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMNKSib8oicPcFmyJZibLOib8siazOcnz6ErBiaTyoaHSA8pca8vyl4y6BiaibOg/640?wx_fmt=webp&from=appmsg "")  
  
**终于在一处十分隐蔽的接口处，找到了上传文件的地方，这里通过base64编码图片后直接上传文件，并且没有对文件名进行过滤，导致能直接传，起飞!**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMibF0a328e9kFumEg5OZeP4xfFvibXQM2HBAQ113bCicUxXs6MmXkUMUzA/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMv6LVmTv5CWhIbWFAPO9F1eiace932pPxeh3TYwweESknMnnN48ZedQg/640?wx_fmt=webp&from=appmsg "")  
  
**直接连接蚁剑上去拖裤一把梭(bushi)，后续将该系统漏洞报告打包发给朋友，拿到指纹后发现该系统使用量还真不少，fofa就能查到1.6w条记录，算是小小通杀咯**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMicYK1WO89Jp5cj9LiazwoxKh7MynOiaSW8S90zIfrXQZ9iblocTtLCGcibg/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMgfibfB3Syn2iaM8jAjk20cC4RH4Z1jtNhZJq3fSLCyZawpOQ8siaO50ZA/640?wx_fmt=webp&from=appmsg "")  
## 0x03 纷传圈子  
  
完整工具已放在纷传圈子中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有1700+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**圈子目前价格为78元，现在星球有500+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于11.26日更新**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMxmfGhcPzwxUyCuibfT7IiaSgpfMX4I18XQ9zd2thgFV1sZZc3fg1vn2w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上百套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通源码网VIP，已开通各大源码站VIP**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
