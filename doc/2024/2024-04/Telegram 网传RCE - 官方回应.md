#  Telegram 网传RCE - 官方回应   
 Ots安全   2024-04-11 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
4月9日  
区块链  
安全公司 CertiK 发布了一份新  
报告  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacfibtyicmWIWZPfwic9JjdvTlvG8ND6N18cl8UVJaAVXo1Lic3oLnYicVpicszNSYVD41DVLALSSZhLbDA/640?wx_fmt=png&from=appmsg "")  
  
[随后视频RCE传出 - 安全告警 - Telegram 网传RCE](http://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247506102&idx=1&sn=8ff8078f81ac1c055305104f2948b803&chksm=9bad91fdacda18ebe1e1032c8c1ebe1de37170e794f6e396038089b13ac9e6f3f01a1160313a&scene=21#wechat_redirect)  
  
   
  
  
**相关消息4月10日，Telegram官方回应称：**  
在对作为样本和攻击尝试提供给我们的试验材料进行调查和分析期间，没有发现对 Telegram Desktop 行为的非法干扰，  
该判定是与 Telegram 开  
发团队同时做出的。  
  
  
鉴于 Telegram 服务器上图像处理的具体情况，PNG 样本与该问题无关，而只有正确制作的易受攻击的 JPG 才可能被服务器视为有效，这可能表明存在与 mozjpeg 相关的问题。  
  
  
尽管声称其中一个样本将R9寄存器中的数据覆盖为0x666，但我们没有发现这种行为，而且，一项声明并不能成为该漏洞的有力证据。在没有任何额外信息的情况下，这只是猜测。  
  
  
测试的Telegram版本为4.16.0至4.16.6，  
有关执行测试的环境的信息：  
  
CPU: AMD EPYC™ 7502P 32-Core (Zen2)  
  
Architecture: x86_64  
  
Platform: Windows 10 Version 22H2 (OS Build 19045.4291)  
  
  
分析和调试Telegram源代码的起点：  
  
```
- https://github.com/desktop-app/lib_ui/blob/master/ui/image/image_prepare.cpp#L434

- https://github.com/desktop-app/lib_ui/blob/master/ui/image/image_prepare.cpp#L415

- https://github.com/desktop-app/lib_ui/blob/master/ui/image/image_prepare.cpp#L452

- https://github.com/desktop-app/lib_ui/blob/master/ui/image/image_prepare.cpp#L440

- https://github.com/telegramdesktop/tdesktop/blob/84ce72ec7a7f39dddeea5c311a4ec1eb2776847b/Telegram/SourceFiles/storage/file_download.cpp#L160

- https://github.com/telegramdesktop/tdesktop/blob/84ce72ec7a7f39dddeea5c311a4ec1eb2776847b/Telegram/SourceFiles/storage/file_download.cpp#L164
```  
  
  
然而，在这么短的时间内，可能有些事情我们没有注意到。  
  
  
⚠️ 如果您成功开发了 POC - 请直接通过 security@telegram.org 联系 Telegram，因为您将有资格获得 10,000 欧元起的付款。  
  
  
**别走，这里有往年Telegram RCE文章阅读：**  
  
https://positive.security/blog/url-open-rce  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacfibtyicmWIWZPfwic9JjdvTldI8Jcyo3j07rZ2AS11TATicialdMDrbnYSdmsIck2Tsk5yE173wich46w/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
