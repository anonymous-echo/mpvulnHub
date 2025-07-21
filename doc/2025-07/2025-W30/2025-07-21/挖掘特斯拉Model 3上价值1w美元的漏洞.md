> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247487079&idx=1&sn=0984778c1477c705ac5a212a760fff88

#  挖掘特斯拉Model 3上价值1w美元的漏洞  
原创 玲珑安全  玲珑安全   2025-07-21 09:53  
  
> 本文所述漏洞均已修复，未经授权请勿进行非法渗透测试。  
> 原文出  
处：  
https://samcurry.net/cracking-my-windshield-and-earning-10000-on-the-tesla-bug-bounty-program  
  
  
![打破我的挡风玻璃，在特斯拉漏洞赏金计划中赚取 10,000 美元](https://mmbiz.qpic.cn/mmbiz_jpg/MfP1wx4aGjqQ5qfx6DcXDcZoMdRuGEnCsvbrriaLFTb2Oj2JV6apDP6aVrCicDO3LYRtn0xGjKEZTjR9VtEbicDOw/640?wx_fmt=jpeg&from=appmsg "")  
## 前言  
  
特斯拉 Model 3 不仅是一辆跑得飞快的电车，更像是一台连接互联网的超级计算机。它内置网页浏览器，提供免费的高级 LTE 服务，支持空中软件更新，使这辆车具备了许多电脑才有的特性。  
  
今年年初，我终于入手了一辆特斯拉。在不断折腾和驾驶它的过程中，我玩得非常开心，也顺便挖掘出了一些有趣的漏洞。  
## 正文  
  
故事开始于车辆的“为你的车辆命名”功能——一个允许你为车设置昵称的选项，这样每次收到充电完成等推送通知时，App 里就会显示这个名字。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/MfP1wx4aGjqQ5qfx6DcXDcZoMdRuGEnCh2bzibpa0NylZEpwKa5gcMVuiaBNqpFbCpXNyaVUvwCw74QzUEKbfrYg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
一开始，我给车取名为“%x.%x.%x.%x”，试图验证是否存在类似 2011 款 BMW 330i 的格式字符串攻击漏洞，但遗憾的是没有任何反应。随后，我发现这个输入允许很长的字符串，于是把车名设置成了 XSS Payload，心想这或许会在某个管理后台触发。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/MfP1wx4aGjqQ5qfx6DcXDcZoMdRuGEnCcCWLMqB0HiaQqpx0hIeb2NxUP3KibSiaOYvIzicdz91wicJtDkS2VmsU0tw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
我还花时间探索车内自带的网页浏览器，试图让它加载一些文件或者奇怪的 URI，虽然没找到突破口，但过程颇为有趣。那晚没有任何收获，我便放弃了，并忘了自己已经将车名设为盲 XSS Payload。  
  
几个月后的一个公路旅行中，一块不知道哪里飞来的大石头击裂了我的挡风玻璃。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/MfP1wx4aGjqQ5qfx6DcXDcZoMdRuGEnCdICLvGrJXlUlHN9DqIvnAUQVhUO03n2dC0FMlTJd4M8FGfJvribDhGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
我通过特斯拉 App 预约了维修，然后继续开车。  
  
第二天，我突然收到短信通知，有人正在处理这件事。  
  
我顺手查看我的 XSS hunter，竟然发现 Payload 被触发了。  
> Vulnerable Page URL  
> https://redacted.teslamotors.com/redacted/5057517/redacted  
>   
> Execution Origin  
> https://redacted.teslamotors.com  
>   
> Referer  
> https://redacted.teslamotors.com/redacted/5YJ31337  
  
  
客服人员在“redacted.teslamotors.com”域下访问我的车辆信息时，意外执行了我设置的 XSS Payload。  
  
XSS hunter 附带的截图显示，该页面用于查看车辆的重要统计数据，且通过 URL 中递增的车辆 ID 进行访问。引用头（Referer）中包含了我的车辆 VIN 号码作为参数。  
  
截图中展示了汽车的最新状态信息，例如速度、温度、软件版本号、轮胎压力、是否锁定、警报状况，以及许多其他细节数据。  

```
VIN: 5YJ3E13374KF2313373
Car Type: 3 P74D
Birthday: Mon Mar 11 16:31:37 2019
Car Version: develop-2019.20.1-203-991337d
Car Computer: ice
SOE / USOE: 48.9, 48.9 %
SOC: 54.2 %
Ideal energy remaining: 37.2 kWh
Range: 151.7 mi
Odometer: 4813.7 miles
Gear: D
Speed: 81 mph
Local Time: Wed Jun 19 15:09:06 2019
UTC Offset: -21600
Timezone: Mountain Daylight Time
BMS State: DRIVE
12V Battery Voltage: 13.881 V
12V Battery Current: 0.13 A
Locked?: true
UI Mode: comfort
Language: English
Service Alert: 0X0
```

  
此外，页面中还有关于固件、CAN 查看器、电子围栏位置、配置项以及一些代号功能的标签页：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MfP1wx4aGjqQ5qfx6DcXDcZoMdRuGEnCyvn2MdI0x3juZkIt3TNliapLK4V3IaJwoMvKK8sR2iaaz88hdzNWicE8Q/640?wx_fmt=png&from=appmsg "")  
  
  
同时，客服人员能够向车辆推送更新，甚至修改车辆配置。我推测，应用程序通过 DOM 中不同的超链接实现了这些功能。  
  
虽然我没有实际尝试，但很可能攻击者通过递增发送到车辆状态（vitals）端点的 ID，就能提取并篡改其他车辆的信息。  
  
如果我是试图攻破该系统的攻击者，可能需要先提交几次支持请求，但最终通过分析 DOM 和 JavaScript，我就能掌握足够的环境信息，从而伪造请求，达到预期目的。  
  
凌晨 2 点，我带着疲惫和兴奋，向特斯拉漏洞赏金计划提交了报告。他们将其归类为 P1 漏洞，12 小时内进行了紧急修复。两周后，特斯拉确认了漏洞的严重性，并支付了我 10,000 美元的赏金。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MfP1wx4aGjqQ5qfx6DcXDcZoMdRuGEnCVJV8UEicz1qmf2OT9bdto7GNWG3iclgp7v1JrJicc1ydvribRtsVgVeKQg/640?wx_fmt=png&from=appmsg "")  
  
时间线：  
  
2019 年 6 月 20 日 06:27:30 UTC — 报告提交  
  
2019 年 6 月 20 日 20:35:35 UTC — 漏洞分类处理并发布紧急修复  
  
2019 年 7 月 11 日 16:07:59 UTC — 赏金发放及问题解决  
  
****  
**培训咨询v**  
  
  
**linglongsec**  
  
****  
****  
****  
**SRC漏洞挖掘培训**  
  
****  
玲珑安全第一期SRC漏洞挖掘培训  
  
  
玲珑安全第二期SRC漏洞挖掘培训  
  
  
玲珑安全第三期SRC漏洞挖掘培训  
  
  
玲珑安全第四期SRC漏洞挖掘培训  
  
  
玲珑安全第五期SRC漏洞挖掘培训  
  
  
玲珑安全第六期SRC漏洞挖掘培训  
  
  
****  
**往期文章分享**  
  
****  
**入侵Chess.com并获取5000万客户记录**  
  
****  
**利用Cookie Sandwich窃取HttpOnly Cookie**  
  
  
[记住，不要在 XSS 中使用 alert(1)](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247487049&idx=1&sn=0431eff40c4f13bca4cec21369e2ac93&scene=21#wechat_redirect)  
  
  
  
[入侵全球最大的航空公司和酒店奖励平台](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486932&idx=1&sn=2637bc5362a6baebe08c97de465d8ab7&scene=21#wechat_redirect)  
  
  
  
[啊？谁把我黑了？？（二）](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486901&idx=1&sn=e37d94d6331114f0a1f78f4f40c8fb5c&scene=21#wechat_redirect)  
  
  
  
[啊？谁把我黑了？？（一）](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486885&idx=1&sn=c40e614c67e8829e30bbc6df7f7a1ba2&scene=21#wechat_redirect)  
  
  
  
[仅凭车牌号，黑客如何远程控制起亚汽车？](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486873&idx=1&sn=43f50a3cc083c19519786a2febe161cb&scene=21#wechat_redirect)  
  
  
  
[黑进斯巴鲁——只需车牌号，10秒接管车辆](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486860&idx=1&sn=468f0cbffdbbc77dba97f69d9d73dc04&scene=21#wechat_redirect)  
  
  
  
[要挂科了？那就黑一下教务处系统吧...](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486677&idx=1&sn=66f24e57c29ed5efa98599452843fd71&scene=21#wechat_redirect)  
  
  
  
[价值10w的Google点击劫持漏洞](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486716&idx=1&sn=360e3382bd90ee5e9748403f5a97ee0e&scene=21#wechat_redirect)  
  
  
  
  
**玲珑安全B站公开课**  
  
https://space.bilibili.com/602205041  
  
  
  
**玲珑安全QQ群**  
  
191400300  
  
  
