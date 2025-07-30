#  某云盘系统 API 端点无限制上传漏洞解析   
Massa  神农Sec   2025-04-18 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
原文链接：  
https://forum.butian.net/article/673  
  
作者：  
Massa  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**漏洞背景**  
  
  
在某次赚钱的时候,发现出现了这个系统的低版本 搜索了很久相关只找到了一个  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYoycZ2nEfThvho9ek5NJY6FibicYro4o13fJTNBkW5riatMSqL5B9ROzoQ/640?wx_fmt=png&from=appmsg "")  
  
简短的一句话 但没有其他漏洞细节 于是本地搭建挖一下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 漏洞限制条件**  
  
![image-20250306174220208.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYMWuENDUxZKsAOXQRV6qmBrIwZ3ebu8aocxXtbTye0fop5JCb1jj6Cg/640?wx_fmt=png&from=appmsg "")  
  
首先是需要一个账号来调用后台的插件  
  
但是本套系统默认两个账号  
  
guest:guest demo:demo  
  
还有一个就是要知道web的路径 当然这个后面说  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 漏洞分析**  
###    
  
定位到函数 发现有一个in['file']的参数  
  
![image-20250306174557708.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY5hkSpY5e8nJzeGZibZwlzo1TNgbUuNxP6F2daRbgR5oEmZjPpia7dCLQ/640?wx_fmt=png&from=appmsg "")  
  
跟进in 在controller里面可以看到这个参数  
  
![image-20250306175026755.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYfJLVgqqwP3NPrFO4iaO7nyVicm3SKYR9lMkeFEv51YZvw0rIBvgEPwbA/640?wx_fmt=png&from=appmsg "")  
  
![image-20250306182032074.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYicJ4qgXylETAlYJVY03zlem1ox1QHUdpictT1DUtDRGOZBnj5SmibMShQ/640?wx_fmt=png&from=appmsg "")  
  
还是全局变量 很容易判断他可以直接传参数  
  
跟进这个可以发现有一个get_path_ext  
后缀  
  
![image-20250306182255890.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYibOZDJB4oibGXp81hmnnmJPhYF8xrjBwrl3BS7jVQW83vFEyWmk3Xfhg/640?wx_fmt=png&from=appmsg "")  
  
可以发现只限制了数量和一些不可见字符 并没过滤php  
  
继续跟进unzip_filter_ext 可以发现他过滤了 .user.ini .htaccess  
  
![image-20250306182624887.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY31xuOxzOUZDItl3KiaGzT0AhJSM8Qb56mefribqVJlX8ThlHmGnDNXlA/640?wx_fmt=png&from=appmsg "")  
  
但是有一个checkExt检查后缀 但是逻辑有点问题  
  
在这里有一个不允许的名单  
  
还会不断的merge  
  
![image-20250306185117546.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYeBfBxtvS2Oian2kdXjTUQf20ydqAvcavCqcyrOl9iaticO7JCFSU6P0Cw/640?wx_fmt=png&from=appmsg "")  
  
在这里进行判断  
  
![image-20250306185314860.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYyYbX3QC1dAZL6yTpp7U0gRlxw4gcHIG20IQ7GUfo56Iw9ZzxHkAFDw/640?wx_fmt=png&from=appmsg "")  
  
逻辑错误点在这里 我们这里的$file是php 而后面的则是.php  
  
因为stristr的意思是在前面的字符串查找后面的 而在php字符串里并不包含.php  
  
所以在这里我们可直接传入php  
  
![image-20250306190635350.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYboiax3Oia1hAYCghHPdBz7qEPvD4Fu7KFZXmO2f4mufqmpo8vJJXsB8g/640?wx_fmt=png&from=appmsg "")  
  
打印了下 $infoData发现为NULL 那后面$linkfile就是单纯的网页地址  
  
而且他会对一个url发起请求并保存文件  
  
我们可知$cachefile 的后缀是php 其实就可以直接写文件了  
  
在目录下放一个/1.php的马  
  
![image-20250306194818702.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYSK3XkszmRhUkTUPKIgZug1xcMsVwnzhryluxpiaf3Bhhaw13OrQHV1A/640?wx_fmt=png&from=appmsg "")  
  
直接进行访问  
  
![image-20250306191647101.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYgl2p8BamJV1c4S85jMC7TaOibHlG6KVGRvDO4VJGatlsp1EpXib8ntRg/640?wx_fmt=png&from=appmsg "")  
  
发现在响应头里会有php文件名 但实际上  
  
![image-20250306191716494.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY3oLOh6aFIvjjzZ1IAQI3D20A7KfGFnovaNmoibk6sRibmo0YLRtydmfg/640?wx_fmt=png&from=appmsg "")  
  
在这里也写了完整的生成语句  
  
![image-20250306191943227.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYicZP2JhXdiaurVEbBE88dgwPSiaTKYd88DhX0EGgzDAsqvm8Yic5iacGfSw/640?wx_fmt=png&from=appmsg "")  
  
但是我们发现在生成文件的时候还是有一个目录的  
  
![image-20250306192008663.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYmHJSWv6Hk0mVibsfFXG1lbevEjVCKHgEAlJfohWJC0DkonCuIQpaCeg/640?wx_fmt=png&from=appmsg "")  
  
回到刚才代码  
  
我们查看cacheFile类  
  
![image-20250306192121007.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYuxIumylsuAzLxHibPDh7Dv09vcO4uG8Qgf0InVYrMdNNc7gy3GbtzaA/640?wx_fmt=png&from=appmsg "")  
  
在这里有一个hash_path  
的生成  
  
可以选择下断点 或者直接var_dump  
下变量  
  
发现大致目录如下  
  
![image-20250306192340806.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY1pTTUmfoPr3LaeXUclp6ricuNGPAPlkMAVILar7F0S1V7NicpdWyyniaQ/640?wx_fmt=png&from=appmsg "")  
  
其实可以推断出来 /var/www/html/data/User/guest/home/ 为一般漏洞利用的hash_path  
  
而且你会发现虽然说他在前面设置了一个随机生成的系统密码  
  
但实在底下只是进行了md5的编码就把$path写进来了 所以  
  
![image-20250306194548339.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYdUGunhdB4Oib6Y5QtXdkiaGuAWDwKUQmBS11ia3Vtk00cU6rpPvfA0KhQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20250306194412913.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYXvjFC7PnoLibOJNlLArOM0bicNcBxMrRW8cAZLic1CD4VjNPCrvIHo3aQ/640?wx_fmt=png&from=appmsg "")  
  
只要文件不变 md5值是不变的  
  
![image-20250306194654634.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYFrHThKWW0h8jJKvcqC2pKwURlWIfiaDkw2KnVBd7cRF1jC6KXsz6p6g/640?wx_fmt=png&from=appmsg "")  
  
构造poc即可写木马  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 修复方案**  
  
官方的修复中  
  
![image-20250306194957952.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoY8ibIVsMcpzx7f7QWeykbw702Gvdzw2arGsOlqQHLufS9CAtfyp7fpXw/640?wx_fmt=png&from=appmsg "")  
  
在这里把文件返回头给注释掉了 但是我们上文提了自己生成也可以  
  
可以看到在path生成上完善了 拼接了$pre 没办法再进行路径的查找  
  
![image-20250306195030619.png](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYP2QoVqXK2UB0NBWolMqTxZEKQ982LMKJyTsB47mYlhecZOFX13tZqg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 内部圈子详情介绍**  
  
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
  
星球现价 ￥40元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于400人 40元/年  
  
星球人数少于600人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWeuMPBRkPema0jlwibpxWEDJSWyZvtpib5n7NJiaM1lqSeSYeiaKmFrRj7wfHjEWkgTH2zZHiaxKsG2MQ/640?wx_fmt=png&from=appmsg "")  
  
  
欢迎加入星球一起交流，券后价仅40元！！！ 即将满600人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYZYx1WKX3mtsCeiblhQKkonJr1BXj5mlefZE8U2ibUnyibG9ZvbibNMC8Rg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
  
