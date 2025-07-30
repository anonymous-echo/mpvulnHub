> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTQ4MzQ4Ng==&mid=2247484210&idx=1&sn=522f16f64c49ddd7f300f95fd8b33ef4

#  【0day挖掘】怎么用“Rotor Goddess”轻松出洞  
 shadowsec   2025-07-17 01:36  
  
## 1 前言  
  
这段时间心情糟糕，用URLfinder和JSfinder的时候感觉速度好慢，有些路径还摸不到，  
美化也有点不适应，用二开的又感觉差点意思，用熊猫头插件是不错，但是总感觉需  
要手动的去拼接访问，并且碰上数据过长的显示还会错误，就感觉用什么都不是滋味吧  
！  
  
    
  我在想，有没有一种工具，可以进行JS文件的扫描判断，提取出敏感路径和参数，并且还自带大模型进行风险评估，或者是对页面进行爬虫收集路径，并给出响应和长度，还能建议的判断漏洞呢？于是就心血来潮，写了这么一个工具，中文名叫：“转子女神”。希望能让这个工具名扬四海吧！接下来展示工具实战案例。  
## 案例1  
  
说来这个出洞的方式，真是想象不到的简单和顺利。HXW 师傅在对一个站点进行常规  
扫  
描  
时，原本只是抱着测试工具的心态随手跑了一下，却发现了一个可疑的URL  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA92to96JOCQf5p7m4yFt42FbwXj0gx9I6OSzewlZbmxBDdZb3iblrULw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAC0k3ovdoaj7GrAYnAh2YayF4nOsmhDo74FAxcBvunnUjvy0VCib12Xw/640?wx_fmt=png&from=appmsg "")  
  
URL比较敏感，并且页面提示了“可能存在 SQL 注入”的风险  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhACeZMwHicFEAibHVpJhjlsYcBAvDXWeK619klez2sgBaeXaicu1vyyGszA/640?wx_fmt=png&from=appmsg "")  
  
手动访问该 URL发现是信息泄露，返回了一些基本数据。将type的值更改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA3XtEmlTvOoiaVrDP3JUB9ZQPDVfZYUiaFPrj1aFm3YcvEu9l0Nkv5TmA/640?wx_fmt=png&from=appmsg "")  
  
简单尝试xss语句，捕获反射型xss一枚，第二个漏洞到手。出于严谨测试思路，师傅继续围绕该参数进行注入尝试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAw9I34t8yx0wKAIf1Z1A4vkBhIKmF8qyonO3kggvbY6q8dqQlofeGzA/640?wx_fmt=png&from=appmsg "")  
  
通过手动构造发现该点存在明显的 SQL 延时注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAQzwMs2hm4iatu49aodsVBMC5lPVg3YP0QOdb7fM1jKUGHmk07A6bZdA/640?wx_fmt=png&from=appmsg "")  
  
确认注入点后，直接上了 sqlmap 一把梭，成功拿到了数据库信息。后面审计框架的时候发现是个0day，进一步通过 FOFA 和 Quake 进行资产测绘后，发现受影响的目标数量不小  
，具备一定的影响面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAKeLibNEETmtnv7eiagFReKaZDPMYpd06I4PfAjOmk7pGib4dyLttP5cGQ/640?wx_fmt=png&from=appmsg "")  
## 案例2  
  
来自。师傅的投稿。原本是在群里讨论自己发布的一个工具，顺带聊到了其他师傅最近的一些“出货”情况。这位师傅表示自己也刚刚爆出了一个与 JWT 相关的漏洞。起初在对某站点进行常规扫描时，他注意到一个 URL 的行为比较可疑  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAhfdIY0wdw2vVKpgHrjyZ4zvOpX2MtxeoYq3qz4eJrTSOmhic2bZHIpQ/640?wx_fmt=png&from=appmsg "")  
  
就立马在威胁匹配里查看参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA04TTZfoOgNtg7fF1wGkOdYD4LPYZxpZibiaVQtofeFU4RTqGVGkdNM9g/640?wx_fmt=png&from=appmsg "")  
  
发现泄露了JWT且有效  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA3kNvR59lMoAxw19nxp6ph1j5FMm6pqMZ4BDFF5FwSmN3ZCDkNf3wJQ/640?wx_fmt=png&from=appmsg "")  
  
随机使用该JWT请求页面成功返回权限数据  
## 案例3  
  
来自NY师傅的投稿。转子女神扫描站点的时候发现有很多的身份证泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUceyG7X0leiaEZO1DX6b0xibar3sTH8ZGRfHWwLwavg8u2ukfquZajJgsGNXrvSBgHqhPic6TDG142jBlw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezL4VPU9U05ghXZIM3QRRUiazsUR6kbmmmsXTfxgVp4icmHM3s5LRC5R6W5VHxeKrykmXKN9hFUnLicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezL4VPU9U05ghXZIM3QRRUiakz5RAhElvia1ce3eu7Im0wPE8TJBLyiaQDZHaic6zibJ3uibfLBQAAAK2qA/640?wx_fmt=png&from=appmsg "")  
  
无压力的出货信息泄露。  
## 案例4  
  
来自【落樱时】师傅的投稿：这位师傅在进行黑盒测试的时候，扫描的过程中发现了一个敏感的页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezg7oLRsEA2L4yJUpMDznXGLCwqSmAPTs2lUETQqfZkWAqn0y3lCTzPVMAdJXq6oXRDlxSnibkdrfQ/640?wx_fmt=png&from=appmsg "")  
  
经过查看，该厂商的资产超过1.5e  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezg7oLRsEA2L4yJUpMDznXGniaxNibIMp7hllwyOUpUflDWwnxiamBx93Y7HJIolaeUY9fn4G8icSMXTA/640?wx_fmt=png&from=appmsg "")  
  
请求后是这样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezg7oLRsEA2L4yJUpMDznXGjTGgX4ibQqhMvnb2icqQ1ibw7MQhiaC1gE6RwZzZkQOwDDkLs02V81giaqg/640?wx_fmt=png&from=appmsg "")  
  
查看响应头会发现拿到了session，将session填入到这个请求下，进行fuzzer，并遍历包中的ROLE_ID，成功拿到管理员的账号密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezg7oLRsEA2L4yJUpMDznXGJw7dibcHadXxuKfDZvI7e5Ze0oRdO2zZ8eAVeYd4Zib41ZeD5FwdCTtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezg7oLRsEA2L4yJUpMDznXGXXianJBaI5a8iaIlVia4XNkCrT65zEWoKHTVSwV5Gw58wIpxRbkickYXmQ/640?wx_fmt=png&from=appmsg "")  
  
成功登陆进后  
台系统  
，该漏洞已由今天，提交至CNVD国家漏洞平台。  
## 最后  
## 下载地址及作者联系方式：  

```
http://zhuanzi.com.cn/
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpnicWoZFUxr5GQ5SygQ91Z1JXVickgXBpibf8dkNEibNV3AE4qz7mTcQ7icF89x8urzkh82cM2azUjelHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FnaToS7EzpnicWoZFUxr5GQ5SygQ91Z1JDHv1vhan16dXoiabAh8Jf3X7voA1U2NwRHe5iaVHpmSuAShmTtpXUcwQ/640?wx_fmt=jpeg "")  
  
