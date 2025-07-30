> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247485463&idx=1&sn=fcff1fc7cec09f4a4904d2901369bed0

#  Web篇 | 从防御到绕过：剖析长亭雷池WAF防护机制与SQL注入绕过测试  
原创 零日安全实验室  零日安全实验室   2025-07-01 16:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFvd3KJPb4t5P6IWBdvRbnm48o5iaNpBKaQMd7CksgE44atZRl3Em4NoQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFOemQx5dgnCINFartApsk2LAK2nCt6nvUia6lXMYiaYPbWJibWbIiapZcicA/640?wx_fmt=png&from=appmsg "")  
  
  
免责声明！  
  
本  
公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，
```
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法
```


```
。
```

  
  
  
  
  
**目 录**  
  
> 前言  
> 部署环境  
> 安装雷池WAF  
> 雷池WAF的基本原理  
> 雷池WAF的主要功能  
> SQL注入测试  
> 总结  
> 官方交流群及社区  
  
  
1  
  
前言：  
  
SafeLine（雷池）是一款简单易用且防护效果出色的 Web 应用防火墙（WAF），能够有效保护 Web 服务免受各类黑客攻击。  
  
雷池通过监控和过滤 Web 应用与互联网之间交互的 HTTP 流量，实现对 Web 服务的安全防护。其可抵御包括 SQL 注入、XSS、代码注入、命令注入、CRLF 注入、LDAP 注入、XPath 注入、远程代码执行（RCE）、XML 外部实体注入（XXE）、服务器端请求伪造（SSRF）、路径遍历、后门上传、暴力破解、CC 攻击、恶意爬虫等多种常见攻击方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFpMwLA23icibU9zZ4W1WZicc7cNC2w02nicuxY31Lf3VMoiauKEPQArYNL8A/640?from=appmsg "")  
  
今天我们就以SQL注入为例尝试绕过耳熟能详而又闻名于世的雷池 WAF！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFov1Ohmp4a3rFKbWplukffKBPMlyml15XmyjIrIib8jQVrNI4UpQcLbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFPIiaIiaRryt7GXVpaIGmRImd8KqSL9oAgmoMoO83CticmEgRFjWTH3xoA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFofzic1k2gCDcNlicncL9W1WibbXJ46ouc0Dr9j91ZKBJ7DZ60gnSEautw/640?from=appmsg "")  
  
2  
  
部署环境：  
- 操作系统：Linux  
  
- CPU 指令架构：x86_64, arm64  
  
- CPU 指令架构：x86_64 架构需要支持 ssse3 指令集  
  
- 软件依赖：Docker 20.10.14 版本以上  
  
- 软件依赖：Docker Compose 2.0.0 版本以上  
  
- 最低资源需求：1 核 CPU / 1 GB 内存 / 5 GB 磁盘  
  
3  
  
**安装雷池WAF：**  
  
官网地址：  

```
https://waf-ce.chaitin.cn/
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFngGs4S1VNSyS5w2eWKsOuXYRcqw0FwBLSS2HzGiaJvLsDIsasjqdFOw/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
3分钟即可完成自动安装，一键安装命令：  

```
bash -c &#34;$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/manager.sh)&#34;
```

  
4  
  
**雷池WAF的基本原理：**  
  
雷池基于Nginx  
进行开发，  
作为反向代理接入网络。来自互联网的流量可能是正常用户，  
也有可能是恶意用户，  
雷池通过在 Web   
服务和互联网之间设置一道屏障，  
将恶意流量进行阻断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFx3KwiaBwrKmPEsvZiapibckxXEpZZmloTR7opfwdAibgk4X8rv77Ldia96A/640?from=appmsg "")  
  
5  
  
雷池WAF的主要功能：  
  
**1**  
  
# CC防护—等候室  
  
  
  
等候室好耳熟啊，我们在腾讯会议上网课或者会议的时候，老师时常把迟到的同学会放到等候室以至于方便统计考勤人数。  
  
雷池等候室是参考餐馆等位  
的模式，专为网站设计的一套限流方案，用于解决流量高峰可能会冲垮网站服务器的问题  
。  
  
雷池  
 WAF 默认是不启用等候室功能的，如果需要开启等候室，只需要在界面上点击  
CC防护  
 按钮，然后配置等候室的相关参数即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFOwsbAobyZ90bgC10a1yBkamyeetQh2CDib1iaVOIa4z0pNS4Ciaib39mWw/640?wx_fmt=png&from=appmsg "")  
  
允许同时访问的用户数  
：看名字就很好理解，表示网站同时最大能容纳的用户数量，超过这个数量就要开始等位。  
  
活跃超时时间  
：成功进入雷池的用户如果一段时间在网页上没有操作，就会被踢出房间重新排队。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFa5VYb89eqdILKsGtQdStgu7Gz72JoQxERrMF782zZX4iblbBhg1IqJw/640?wx_fmt=png&from=appmsg "")  
  
2  
  
# CC防护—频率限制  
  
  
  
实施访问频率限制，可以设置每个  
 IP 地址的请求频率和速率。当某个IP 地址的请求频率或速率超过设定的阈值时，会自动阻止该 IP 地址的后续请求。  
  
这种机制有助于防止恶意用户通过大量请求对网站进行攻击，如  
 CC 攻击等。此外，还通过用户行为分析，能够识别出异常的请求模式，进一步增强对恶意请求的防御能力。  
  
3  
  
# Bot防护—动态防护  
  
  
  
所谓动态防护，是在用户浏览到的网页内容不变的情况下，将网页赋予动态特性，即使是静态页面，也会具有动态的随机性。雷池作为反向代理程序，经过雷池的网页代码都将被动态加密保护，动态防护可以实现很多效果，比如：  
- 保护前端代码的隐私性  
  
- 阻止爬虫行为  
  
- 阻止漏洞扫描行为  
  
- 阻止攻击利用行为  
  
开启动态防护功能后，网站的安全性将得到显著提升。它不仅能实时分析并拦截恶意流量，还能对  
 HTML 和JavaScript 代码进行动态加密，确保每次访问时这些代码都以随机且独特的形态呈现。这种动态加密技术有效增加了攻击者自动化利用程序的难度，使爬虫和自动化攻击工具难以识别和解析网站内容。  
  
对比以下  
 html 页面被动态加密前后的比较, 如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFClPmjjgVIqiaPdqcp65gRCKJEcQyibFk2ibGBY1TbXHWh7HyU9ic5Np9QA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFia4m2vjftxjao6ibdaMDkFQWEPCKumdBcxzgDtog0spXFDibx2F9xAk7w/640?wx_fmt=png&from=appmsg "")  
  
再来对比以下  
 js 脚本被动态加密前后的比较, 如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFSgYnIFeygcvJmQ81vGTYpa0gzx7skazmbjstAic9J9CEvA1OClozdzg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFH0Eib6hf5ibQV3ASfNwVaeNO3FUkVU8gusgfuWUicsCNmxMYbXicu6JKvQ/640?wx_fmt=png&from=appmsg "")  
  
4  
  
# Bot防护—人机验证  
  
  
  
互联网上有来自真人用户的流量  
, 但更多的是由爬虫, 漏洞扫描器, 蠕虫病毒, 漏洞利用程序等自动化程序发起的流量。  
  
识别真人用户对提升网站的安全性至关重要  
, 也是防爬虫  
, 防扫描  
的关键。  
  
该功能开启后，当用户访问您的网站时，雷池会预先检查客户端环境的合法性，如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFj6vYWtKsDtzdZmTy23rX1La4MKlRicZnIP2ST2iaEI7fGk7O4m73NznQ/640?wx_fmt=jpeg "")  
  
雷池会根据当前客户端环境的综合行为进行打分判断：  
- 客户端的源  
 IP 是否有过其他恶意行为  
  
- 客户端是不是真实浏览器  
  
- 客户端是否存在监控或调试行为  
  
- 浏览器内的键盘鼠标行为是否符合人类的习惯  
  
等等  
  
5  
  
# Bot防护—请求防重放  
  
  
## 雷池WAF如何开启防重放功能？  
  
在左侧导航栏选择  
防护应用  
，在页面的应用卡片中点击  
BOT防护  
，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFQ5uoRGyOnGASrlHIMjlhzHn6kRKn1fWCdwJPYdcvhT9bmvJpPJWNQw/640?from=appmsg "")  
  
6  
  
SQL注入测试  
  
随便来个  
payload测试，触发了waf规则  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFQiazT7aqNlnrDl1pIUBQb6ibGkf6cOk0AUddFbDYm3m3t2NLGlK6XnYw/640?wx_fmt=png&from=appmsg "")  
  
雷池waf后台可以看到详细的日志  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFYWETv5ZfqohwWmxFEoic5dgzozJI3sjV6yCOcgjbxeznic66IJjupJCg/640?wx_fmt=png&from=appmsg "")  
  
使用我最常用的判断paylaod：'OR+'a'='a'+OR+'a'='b，直接被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFN7GTuv4BCg9IJ3GWDgaaT79AibrFOwP8mzMpdY4P42CDp8gNDQTVicZQ/640?wx_fmt=png&from=appmsg "")  
  
将等于号替换成  
like，依然被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFsxfVRZALnJtY1oOdFm2eYap6tkYMCfzjnx04fRV3r6oNzd2RCQUNRw/640?wx_fmt=png&from=appmsg "")  
  
这里使用  
||绕过or，cot是余切函数，成功执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFrQ6o66j1wibCROib178JkO73k6JzicQxSKulU7YQ6acrJ8uZ9qGFfPlgA/640?wx_fmt=png&from=appmsg "")  
  
cot(0)则是分母为0无意义，也可以说是无穷大，导致数据库报错，减号运算符也可以用，我们下一步就是寻找可以使用的截取字符串函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFP5dVA3tsCNboK5kReD9xHdsNJqnybWyZ17wNgU2wsjQaobiaTK5vsZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFNNmR4AcfCZyVd9ibcFrHx5ibqDMhNrib0bIE0lkE4ml10zd0KTYIe9tIA/640?wx_fmt=png&from=appmsg "")  
  
拿出以前经常用的的position函数依然被过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFGUnZ39BXEGe5Ee6QxoaTy2oyTVlZ6XT9jYODCAcEvgEUYynK90x4Ow/640?wx_fmt=png&from=appmsg "")  
  
这里尝试垃圾字符依然被拦截，其他知道的函数都试了，都被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFERYjx8IkBYPovAywNEITiaicK2KL8x2EkTyuF25HDzNmY2lZ0AyaSZrA/640?wx_fmt=png&from=appmsg "")  
  
7  
  
总结：  
  
总结来说雷池waf对于sql注入拦截还是挺完美的，能测出来有sql注入，但是很难再进行下一步，因为它并不是单纯的针对某些关键词的过滤，而是有着独特智能语义分析+ai驱动技术，对未知攻击的防御能力远超依赖规则的产品。  
  
对于接触安全设备不多的大学生特别友好！！！强烈推荐，可以练手做渗透，强化专业技能。很感谢长亭对这么一个好的安全产品开源，让我们网安的兄弟们更加热爱网络安全。  
  
8  
  
官方交流群及社区：  
  
官网：https://waf-ce.chaitin.cn  
  
官方社区：ttps://rivers.chaitin.cn/discussion  
  
帮助文档：https://docs.waf-ce.chaitin.cn/zh/home  
  
社区版微信交流群，有任何问题进群交流。群里有雷池官方的技术支撑人员，随时在线支撑，有啥问题可以提出来，一起交流学习！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xBfPOENp2MsJUwmDrH3XUfFNQZgQJzWv41UbeibibM6dLfDM9b608kmgCeK4dBw89byBbf85PIm5MOA/640?from=appmsg "")  
  
  
