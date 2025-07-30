> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531254&idx=2&sn=286fdda800d5d1c0abd1ce128e3e2bd9

#  Bluenoroff（APT38）实时基础设施追踪  
 Ots安全   2025-06-23 13:49  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
朝鲜威胁行为者的称谓往往有很大重叠，使归因分析变得复杂。因此，一些安全研究人员将所有朝鲜国家支持的网络行动统称为Lazarus Group，而不是追踪单个集群或子组织，例如Andariel、APT38 (Bluenoroff)和APT43 (Kimsuky)。其中，Bluenoroff（也称为APT38）是一个与朝鲜侦察总局 (RGB)有关联的、具有经济动机的子组织。自 2014 年左右出现以来，APT38 已对至少38 个国家的银行、金融机构、赌场、加密货币交易所、SWIFT 端点和 ATM 进行了大规模网络攻击。值得注意的事件包括2016 年孟加拉国银行劫案，该组织成功窃取了8100 万美元，以及 2018 年Bancomext和智利银行的重大入侵事件，其中一些事件涉及旨在掩盖痕迹  
和破坏事件响应工作的破坏性有效载荷。  
  
区分 Lazarus Group 与 Bluenoroff (APT38)  
  
拉撒路集团概况  
- 国家赞助：由朝鲜政府支持，具体与侦察总局（RGB）有关。  
  
- 活跃时间：至少 2009 年。  
  
- 核心活动：  
  
- 网络间谍活动  
  
- 知识产权和数据盗窃  
  
- 破坏性网络攻击  
  
- 全球目标概况：世界各地的政治实体、关键基础设施、企业和战略部门。  
  
- 关键操作：  
  
- 索尼影业攻击（2014）： Novetta 发起的一次高调擦除器攻击，是“百视达行动”的一部分。  
  
- 与多项操作相关，例如：  
  
- Operation Flame  
  
- Operation 1Mission  
  
- Operation Troy  
  
- DarkSeoul  
  
- Ten Days of Rain  
  
归因与子群复杂性  
- 归因挑战：朝鲜 APT 在工具、基础设施和人员方面经常重叠。  
  
- 部分研究人员的统一标签：一些分析人士将所有朝鲜网络活动归入“拉撒路集团”，尽管其中存在区别。  
  
- 值得注意的子群：  
  
- 安达利尔——以军事为中心的行动  
  
- APT38（Bluenoroff） ——出于经济动机  
  
- APT43（Kimsuky） ——间谍活动和信息收集  
  
Bluenoroff / APT38 概述  
- 隶属：拉撒路小组，也向侦察总局汇报。  
  
- 成立时间： 2014年左右。  
  
- 主要关注点：全球范围内的金融网络犯罪。  
  
- 攻击目标：  
  
- 银行和金融机构  
  
- 加密货币平台  
  
- 赌场和自动取款机  
  
- SWIFT 系统端点  
  
- 备受瞩目的事件：  
  
- 孟加拉国银行抢劫案（2016 年）：成功窃取 8100 万美元。  
  
- Bancomext（墨西哥）和智利银行（2018 年）：包括盗窃和破坏技术。  
  
初始枢轴  
  
枢轴来源：  
  
搜寻从 IP 地址104[.]168[.]151[.]116开始，该地址被归因于 APT38 (Bluenoroff) ——朝鲜 Lazarus 集团的一个以经济为目的的分支组织。  
  
枢轴策略：APT38 IP – 104[.]168[.]151[.]116  
  
通过 HTTP 标头进行枢转  
  

```
Protocol: HTTP/1.1
    
 Status Code: `404 Not Found`

Headers:
     `Content-Type`: `text/plain; charset=utf-8`
        
    `X-Content-Type-Options`: `nosniff`
        
     `Content-Length`: `19`



JARM 29d29d00029d29d00041d41d000000301510f56407964db9434a9bb0d4ee4a
```

  
  
为 APT38 基础设施构建 Shodan 搜索规则  
  

```
ssl.jarm:3fd21b20d00000021c43d21b21b43d76e1f79b8645e08ae7fa8f07eb5e4202 HTTP/1.1404 Not Found Content-Type: text/plain; charset=utf-8 X-Content-Type-Options: nosniff Content-Length: 19 org:&#34;Hostwinds Seattle&#34;
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1ziaJiaIktZoRCaC9BDzPNyfWQOHXl5zf3ia9rgNGJ0HK83h4E3tK52VYBw/640?wx_fmt=png&from=appmsg "")  
  
验证结果  
  
104[.]168[.]151[.]116 > 1/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zUiaRXFB1jbKGOgJdobtFPZjX8Gx0zxXB66HAGoKp4ib9iaDWCW5ibH6fzQ/640?wx_fmt=png&from=appmsg "")  
  
恶意使用 IP 地址：104[.]168[.]151[.]116  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1z0YrFQETTAwUFibClUjAVOAIUnI9emfjzLefjBeDG5mHh8v4U9x5A7kw/640?wx_fmt=png&from=appmsg "")  
  
域解析模式  
  
新发现的网络钓鱼域名在结构和主题上与之前通过初始 IP 地址104[.]168[.]151[.]116解析的域名类似。192  
  
[.]119[.]116[.]231 > 1/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zMYibmIjDPEr1INHE7unNGE0tG94pPEgofMpco4icicicORqgiaPGWUT4Nxw/640?wx_fmt=png&from=appmsg "")  
  
观察到的网络钓鱼域名与之前解析的域名在结构和主题上表现出很强的相似性  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zWZQ8o3JgEGyA1rId1zamj3DWBtylhHvpnic2ibgB4Ig7v3YsH4BkrbdQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zubRZ8vVbuvz270MSUlaCXsyHwp8BTx3XVXjeZh9zqd1GlTjVxLSOrA/640?wx_fmt=png&from=appmsg "")  
  
通过在每个域名上进行切换，我们获得了另外 4 个 IP  
  

```
140.82.20.246
156.154.132.200
198.57.247.218
192.64.119.169
```

  
  
140[.]82[.]20[.]246 > 10/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zbhtHsUuv1BaVk10EykUKZxuwlL6BZIFCsVZnNHXapzMDibast0DqHfQ/640?wx_fmt=png&from=appmsg "")  
  
156[.]154[.]132[.]200 > 2/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zxNv6Ixjc1rvpYEnd1FRrbyxYjpCcFVnBdymEK6QU2mE31HtAyw871w/640?wx_fmt=png&from=appmsg "")  
  
198[.]57[.]247[.]218 > 1/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zOdspIgKN8tcdWzqoQoJISHAaZVx4Rba9yu0sNPTrV8ficuX2kib2kKEA/640?wx_fmt=png&from=appmsg "")  
  
192[.]64[.]119[.]169 > 0/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1za0RbrzrXPNYlpibsZHVOLNgYlBe3LDIz9e7m953nl3BExic819mqOtibw/640?wx_fmt=png&from=appmsg "")  
  
此 IP 解析bellezalatam[.]com  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zXJoJ7t2yG4Xqvd4fVqVibW4YuhxnfsViaghlNSicOob98ARf8U0mF1GiaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zYmVGMKlY2kUxSuEBMGEoI1HMXVzvG58hqMzkh4Qvhn6NJzMn6oMkmA/640?wx_fmt=png&from=appmsg "")  
  
198[.]54[.]117[.]242 > 2/94 检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1z6AJKLFx60HaZ3tWXpiboSC9EicFTf6uCWFW9Zqv91QDMazZlYzgPzZMQ/640?wx_fmt=png&from=appmsg "")  
  
此 IP 解析为amirani.chat  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zIiboSoT18d2qeN14DfjSXF5HglqxwIZ8N0J46u0jV7oWSSfLibuUiahTQ/640?wx_fmt=png&from=appmsg "")  
  
已发现该恶意软件正在与 IP 地址为104[.]168[.]136[.]24 的已知命令和控制 (C2) 服务器进行通信。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zVWnFrmsdgznJ6Nv4dYUcckyDnGvvBDgNp7CHeVvZYQULP1rm0icxbXA/640?wx_fmt=png&from=appmsg "")  
  
该恶意软件样本：localfile~.x64  
  
(SHA-256:dbe48dc08216850e93082b4d27868a7ca51656d9e55366f2642fc5106e3af980 ) 已被确认为Cosmic Rust恶意软件家族的一部分，该家族由APT38 (Bluenoroff)发起，该组织是朝鲜 Lazarus 集团的一个以经济为目的的分支组织。Cosmic Rust 专门针对macOS 平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zpmr3OPzy10cicNbFxgNwmQVuJxEhVaCuEx5kpTcb52BTjHtbp1mG6lA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zXdmFzPvTbOiclGtXA6tic7VOYfkSWyCSWRewicVtJEaMicDw7BpyM5VohQ/640?wx_fmt=png&from=appmsg "")  
  
我正在准备额外的Shodan 狩猎规则，以收集更多信息并扩大调查范围。  
  

```
HTTP/1.1 404 Not Found Content-Type: text/plain; charset=utf-8 X-Content-Type-Options:
nosniff Content-Length: 19 org:&#34;Hostwinds Seattle&#34;
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1ztPqOCcsg5SAIcUZia9QD0wHkpXyhdUk3YPMudBKBpEtbQVcYicHcuJ5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafUqOQcWUseMJ2kb3gdun1zf7jlPaC4TYypO1vUBw2hFWP70wPCZ4xUYMsccnuQJZYkmdmIUqOVpA/640?wx_fmt=png&from=appmsg "")  
  
IOCS  
  

```
140.82.20.246
156.154.132.200
198.57.247.218
192.64.119.169
198.54.117.242
104.168.136.24
firstfromsep.online
socialsuport.com
gost.run
nicrft.site
instant-update.online
huang-5@1581526809
huang-6@1581526872
hwsrv-587720.hostwindsdns.com@1723789657
```

  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
