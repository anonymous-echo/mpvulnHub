#  Open-Source Intelligence Summit 2024议题慢递   
原创 Avenger  威胁棱镜   2024-11-05 12:04  
  
SANS 举办的开源情报峰会，探讨 OSINT 与其他形式的情报工作之间的关系。  
若是通过本文的介绍，或者是查看官网议程安排后，对其中某些议题感兴趣的话，就可以在官网下载议题对应的材料进行扩展阅读。（PS：笔者根据自身的认知局限与好恶为部分议题打了推荐查看的星级，不代表对议题实际内容高下的评判，只是为部分时间宝贵的读者再节约些时间，这部分议题相对来说可能更加值得一看。  
  
**重新思考威胁指标****⭐⭐⭐**  
  
“数据”是需要过滤、收集和处理才能使用的，“证据“是与事件或外部遥测初步分析相关的数据，“指标  
”是分析和理解后反映攻击行动的证据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpumZ1sKjibfvElssWqORIUK0ff1FEAXV7uvxr5O4XPib3YKW1EqyN4FpyQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
”指标“是“某事”发生的迹象，事后查看这些事是如何发生的，事前查看这些事为什么会发生。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuND4A2uwjD1ZKhKVBpYorDnMiatdYvH2jU4t3dL2Ndo1hkPAR5nkLEdQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
随着概念范围越来越宽，”指标“一词已经被业界玩坏了，  
MITRE 在重新审视什么是”指标“。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuHD3THIBwYHruj4NCyvLYiaZXsrOlfoNJ9IpYhyADiacvRWXwVDnAjG0w/640?wx_fmt=png&from=appmsg "")  
  
  
  
想要超越单纯的数据呈现，就必须要持续完善与丰富更多信息，才能搞清楚发生了什么（  
Observable）以及怎么知道（  
Indicator）发生了事情。  
  
**OSINT 中的证据收集****⭐⭐⭐**  
  
提取图片的  
 EXIF 信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuRGevFosByDccdTkb3PFjSlCHWks5uIKu7RW33Zcjo9TmGO3CicnxeVA/640?wx_fmt=png&from=appmsg "")  
  
  
  
提取  
 YouTube 的元数据：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuUeTiaS9bIOoPx4yicVKmm7wKz6XmzFnYR5QtZuib5ibumiahNOrrGap6LVA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuqxdicrHSXGrvxlAr9QcFjGOtFyWvJb5pdevM5d7xvf9ed419GM1UyLw/640?wx_fmt=png&from=appmsg "")  
  
  
  
```
https://mattw.io/youtube-metadata/
https://citizenevidence.amnestyusa.org/
```  
  
  
研究人员还列出了一些其他工具，感兴趣的话可以找来议题看原文：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuFGRMp1rjFphs7pC7sHX6h24DebKev69C2msOIn6SVpTK6wPECziaAJw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**地缘政治网络风险评估框架****⭐⭐**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuoTygibHrPsy7kmzQHT9CibUGXyPujBibIpIkA9wRxYjKuAGFMcCOsPhgQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
当武装冲突发生时，一个国家所面临的网络风险就在增加。网络空间中的强国在陷入冲突时，会将网络作为攻击的手段。跨国企业也会受到地缘政治紧张局势影响，也会加剧该组织的风险。（注：  
HCSS Cyber Arms Watch. 2022 分析了网络武器）  
  
典型风险场景如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuaUpucUmTkS3ibnnxYiaCiaMlI0k4YDpr8fySzibHHydtnaYy06dHmwLRrg/640?wx_fmt=png&from=appmsg "")  
  
  
  
组织与冲突关系十分复杂，包括办公区位置、供应商归属等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu2oIhbxywTk5FIy8wZZttbOicQ3eDRUfXjGeJkUhUbtfSwHreIAucib4w/640?wx_fmt=png&from=appmsg "")  
  
  
  
把这些因素整合在一起，形成风险识别的框架：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpua04mwYYneMrtfTeAicb6uuWb1qI3hibyhXIFDdtQiaTq3jHd28icNic8ZKw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**俄罗斯互联网信息收集****⭐⭐**  
  
寻找始终可靠的俄罗斯   
VPN 服务很有挑战性，俄罗斯联邦通信机构   
Roskomnadzor 对西方国家提供的   
VPN 服务严格管控，并且要求服务提供商提供执法机构的访问权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpunPaY0pGibEtbaoEKv22O6eHzpFmY2tGCicmrxXNOic4GxD6nticpdVv6Qg/640?wx_fmt=png&from=appmsg "")  
  
  
  
俄罗斯主要的社交媒体平台如下所示，  
VK 是年轻人喜爱的平台被称为俄罗斯的   
Facebook。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuGIbHVMj1v05fxzGI3VPtFS7Ouibp8hoqu7XFZ4GgFibia3Q9c5ZE5y9NQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
开源工具  
 Spevktator 可以从俄罗斯主要新闻媒体以及   
VK 收集信息， 以此识别俄罗斯网络空间的情绪与舆论趋势。  
  
平台  
 Search4Faces 可以针对俄罗斯人员进行面部识别，比对从  
 VK 收集的超过  
 10 亿张图片。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu8iaSeJcvCfphd5xGMJicX6IbZ63IpcgkjTVMO6AUHyKhuvfgyt8TsvwA/640?wx_fmt=png&from=appmsg "")  
  
  
  
通过该平台，可以发现其中一个士兵叫  
 Sergey Moldanov b，出生于  
 1983 年  
 7 月  
 25 日。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuA3l1iamsfZDic2cicIYgocl1vbO4JVbJrKdrBhia7O5MPTDsyRObF3HXmQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
XSS.in 与   
Exploit.in 俄语网络犯罪论坛中，也有大量的被窃数据、黑客工具在进行交易。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuZlyVJ71ET1yeagzUShVGIf2Sqn2w5bHwMkdyf1cF2af46QCUVeTIHg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**威胁情报的转变****⭐⭐**  
  
提供的什么是最有价值的？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpul2ajVuM8syAJyulO9taURvUI9VCHlPEa3UuicXQIibxuXpiaoxReTrzDg/640?wx_fmt=png&from=appmsg "")  
  
  
  
参与信息共享的方式？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuGbq5uLebsoqUX7mSQ8YXoCjsRFQhu6gJk4jsF4EVXOj9NsV6iaiatEhw/640?wx_fmt=png&from=appmsg "")  
  
  
  
这些方式质量如何？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuZEn2RhwtxQ0KTEnhVMpTj9KiaHV2rV4HfPVPiaPk1vtOfDIyFL0hzIIA/640?wx_fmt=png&from=appmsg "")  
  
  
  
超过六成的人每周参与小于五个小时：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQputVxeGCeMhwiaicrW7qHhT9Nc5rJcgtmcicZIYDOL41oSjvWe3oeIGAibMg/640?wx_fmt=png&from=appmsg "")  
  
  
  
最大的困难是什么？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuOqwJFjibRwUA4wnTuy9RsPafLDg7iciblYibRFTSeIdRU33eVicC0bslnKw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**威胁情报自动化的工程尝试****⭐⭐**  
  
威胁情报最大的来源是披露的新闻与报告，其次是社区和厂商的数据源。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu8B9Rj58PuyrQ4cGdnVtqQbRcmfaSvZiaVqSB8oXoowtiaY2sf6LVvucw/640?wx_fmt=png&from=appmsg "")  
  
  
  
OSINTER 的多次大版本更新：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuxSLbXl9gI6j8shcic6flu8jvuUJwdIq6mfjHrG5BfXMAC6doPwazdrw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuLVwVBPJct9llyvY0hXwvRgBCeLhVL0XOkibqr1Lj3OwzMzNSg7u4iadg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuqrbhibQSGAXAYWaBmQrCic1VMPF2iaCuLu1ctnhriaQymvJUGfP4icvB44g/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuUfEpt4UpiaoyOCe6IP76Oia3cW27WNwibAvmpbkqHHcF7r5En71BOx44A/640?wx_fmt=png&from=appmsg "")  
  
  
```
https://github.com/OSINTer-Platform/OSINTer
```  
  
**威胁情报中的大模型****⭐**  
  
可以利用人工智能来增强处理问题的能力，例如那些需要耗费时间去理解的事情、需要处理海量数据的事情、新入门的人学习曲线陡峭的问题以及在野威胁的快速演变问题等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu5brSEE68nKghg5G6umcU93k0mrorhWN4ErlblyuvM1ZXFrT42ibhKaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
当然大模型也存在许多短板，例如并不能提供个性化的数据（个性化）、对最新消息的更新不及时（及时性）、输出可能是猜测而来并没有事实依据（表达幻觉）以及知识的覆盖范围有限（覆盖面）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuzRHiaTFBqia4XAUL8k06iazqcM9XouOvUhE4vEpXQ63nUD3dL5IMg45oQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
业界的实践是用少量的   
PROMPT 来引导大模型进行理解，提高准确性和适应能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu2YWibu6g4fU1ibS5qNYUSaWHzgeor8TLGyn2QxibFIURZJ9rC4icxOUYWA/640?wx_fmt=png&from=appmsg "")  
  
  
  
利用大模型来总结   
Lazarus 组织新攻击动向，包括远控木马  
CollectionRAT 的使用、通过开源工具获取立足点、重用攻击基础设施等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuoWB1FkdS5VPXcc0nYfv8iapx5By4psuiaBn9iava8r6IekeKRxKV5GlEA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**AI对威胁情报的影响****⭐**  
  
可以在数据处理、快速模式分析、创意辅助、快速收集信息等方面提供帮助：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuvEAAMzRXbtUNubib3kEgzFRMrBib8E9Yu6BiaLuDG19qLXjicMXbia2kXuw/640?wx_fmt=png&from=appmsg "")  
  
  
  
由于目前还是对上下文感知存在缺陷，以及数据存在偏见和不干净的数据等导致还是存在缺陷，相信随着技术的演进，可以慢慢被业界解决。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpubicrt9qmAGWw1YuIBepJ3A4eyW6eUQiaiaV0hft0zuKoKIB6ZZjoqxGGQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**识别华盛顿特区的武装直升机****⭐**  
  
许多直升机都配备了  
 ADS-B 应答机，在  
978Mhz 或  
 1090Mhz 上传输未加密信号。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuAAYdGRdblyeYL1Dqt5yzQJwawSPsu4USImBKnzS8SJHHiaIBbQl5c4Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
美国联邦航空管理局规定，管理人应根据私人飞机所有人或经营人的要求，阻止飞机的注册号公开传播或展示，但向政府机构提供的数据除外。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu8H598Bob036S8LbbJaWaoa1EmBpepCs8ia8fcpltUQvxUQR4SbNsaDA/640?wx_fmt=png&from=appmsg "")  
  
  
  
社区的力量是无穷的，再结合社交网络上传播的图片进行定位。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuRoxHYdSWIVrKscOA695SwlPE7nQGSC1pVT1gkkib8OWOfCsccn7QLPg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuKOjbC7gjOBo8nr2JQxl1ibCibCVvibksLjLIFMbRB83NSY8yI6aGC9Wyw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**情报中的地理位置分析****⭐**  
  
好漂亮的照片？这是在哪里拍摄的呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuVgrGdicPMsD1tzUbLYoD7yIhpTV6QsRu0Nw2A6bc2QcfVDhYY3htWtQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
左侧明显是林肯纪念堂，林肯纪念堂和华盛顿纪念碑中间的是参议院的旗杆。从国家广场上空俯瞰，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuI7Npw3Dfacd78SpobbdiaIoNGKBa5crS7nsDWhUGS0qQfXdZKPtGRug/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuW2ggWTibkq6laPicTsvSTlhIU45TFY0KeuY0oQRpMvAyxt4mvU6jVNIA/640?wx_fmt=png&from=appmsg "")  
  
  
  
基于画面信息还可以找到其他标志线：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuBVvd5icQWBuf9ZUIdBicKiaqSnBA3RRsbh2rnWRdg3j6q8tTjJnRQu9Rg/640?wx_fmt=png&from=appmsg "")  
  
  
  
交汇点即为最可能的拍摄地：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuJXtkzrKCLQiaiaJRWv9VEn1OjXCha0o49H87qrzTxe9nvYo22JDfsvBA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**勒索软件即服务攻击者行为聚类****⭐**  
  
不同的攻击者在不同的攻击事件中可以看到相同的攻击行为，一旦攻击者找到有效攻击链，很可能会持续使用。一些相似点如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpufFYVqkoPeCs9fAlicbwhpIJia7lyet68q3cbEqJANtBUbSQhOpriaZtcg/640?wx_fmt=png&from=appmsg "")  
  
  
  
Sophos 在三个月内应急六次   
Royal 勒索软件攻击，两起与  
 STAC5485 攻击行为相似：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQputWhkibIX6MODdxHMf1iatkf9KGe7x7YD7iciaiaVscZaAelavPttAxS0RJg/640?wx_fmt=png&from=appmsg "")  
  
  
  
ViceSociety  和  
  Rhysida  Ransomware  数据泄  
露网站每月发布的帖子如下所示，  
2023 年  
 6 月与  
 7 月存在重叠期。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuT6QXFUmB8VSlhia058ibGwdPOEK6QTqC5XBDuu8SVnnvNT8osho5IvOw/640?wx_fmt=png&from=appmsg "")  
  
  
  
可以将各厂商的报告关联起来：  
  
Sophos 的   
STAC 5485→ 微软的  
 Storm-0216  
  
CrowdStrike 的  
Twisted Spider →  
 Mandiant 的   
UNC2198  
  
Sophos 的   
STAC 5279 →
微软的  
 Vanilla Tempest  
  
Sophos 的   
STAC 5381→ 微软的  
 Vanilla Tempest  
  
Sophos 的   
STAC 4910→ 微软的  
 Storm-1567  
  
**跟踪云端恶意软件****⭐**  
  
Tracking Legion 是以云为中心的僵尸网络，从  
 2021 年  
 2 月开始活跃并通过   
Telegram 进行销售。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuZezvBztROrBSPXSfoXYt2CjhKR0TExH9Ok0SLGZEmOqlJElgTvBrIg/640?wx_fmt=png&from=appmsg "")  
  
  
  
查看各种调试信息，期望获得各种凭据信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpufPzd8gj3a1CzmU0spKHUt0IyGHpK2rtUuHo41qlo1c5FZxLmuT4YLg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpulGSlZBooltnyolcQPiaxFoMdW57bOZ6Kibrtx0fziafwPvibC8ldIHX4vw/640?wx_fmt=png&from=appmsg "")  
  
  
  
P2PInfect 是  
 2023 年  
 7 月披露的  
 Rust 僵尸网络，针对   
Redis 与  
 SSH 进行攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuDZNUhk2aIGplx5YhMeic3JuXhhib2N1kIq7sDOZO7yKmiblicEZsWC9f0Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
随机扫描  
 /16 前缀查找暴露的   
SSH 服务器：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuicVWSibiawRJVNDEYwOAicYGKicXjT0TtoaDicKhaPb0sRqW5LwN262HY59A/640?wx_fmt=png&from=appmsg "")  
  
  
  
感染量最大的是中国、美国和德国：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuCealvFSDNiauW7qlPnrbOWNfuuqeRsI6kt1Hiat0sGt1V79nOlFNr5JQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**车辆信息的跟踪****⭐**  
  
VIN 车辆识别码是制造时的唯一代码，有四处主要的位置：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu0oicaITA1jSch8uvPw6ffz8CcvwB7Tc4ibDlpppTOwEhUzbfxBibfrt9A/640?wx_fmt=png&from=appmsg "")  
  
  
  
该识别码可以解析出多个字段：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpue6HF5rAxqXI3RomJplm7HcNUBTiaC5qw7uyF7rZzYatqRWRZlg3rctg/640?wx_fmt=png&from=appmsg "")  
  
  
  
通过车辆数据顺藤摸瓜找到个人数据，此处不举例了可能会被举报。  
  
**广告滥用****⭐**  
  
在   
B2C 广告领域，用户才是商品本身。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu1IOqUicWnTTVlf0JKsmQEibQ7xic5lMYyaib8F5dLrKEKK5BMC5B3zfemw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpu4JQyt76h9ZTiaggBlXBjW6Qa9Y8k4g307fCUDnUket6fWXGQFAepgJw/640?wx_fmt=png&from=appmsg "")  
  
  
  
这里面就有很多很多猫腻，研究人员可以深入分析：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYb98Gz7rXZiacDQ6tCaBKQpuS1pFcAO7W7Cr1agX0pAf3NMwTibXhT9KTr9zepe9HW3N8WyE9ONX3eQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
