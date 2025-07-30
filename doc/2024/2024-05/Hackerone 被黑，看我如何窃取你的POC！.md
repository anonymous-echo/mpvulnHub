#  Hackerone 被黑，看我如何窃取你的POC！   
原创 一个不正经的黑客  一个不正经的黑客   2024-05-03 23:09  
  
#   
  
**免责声明**  
  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。  
如有侵权烦请后台告知，我们会立即删除并致歉，谢谢！  
  
1  
  
#   
### 漏洞细节   
  
这是我作为漏洞赏金平台上直接向上游提交重要漏洞的经历故事。  
  
“Alhamdulillahi rabbil alamin”（感谢真主，全世界的主宰）无疑是我要说的第一句话！  
  
这是我作为漏洞赏金平台上直接向上游提交重要漏洞的经历故事。  
  
我是如何找到那些重要漏洞的呢？让我们首先谈谈基础知识。  
  
你有 web/app 编程的先验经验吗？  
  
当然你对 CRUD 是熟悉的！但如果你对此还不了解，CRUD 用于将数据处理到数据库中 [1]。  
  
CRUD 代表创建（Create）、读取（Read）、更新（Update）和删除（Delete），这对于使用关系数据库实现健壮应用至关重要 [2]。然而，如果应用程序过于复杂，其背后的系统就不再是简单的 CRUD。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJgn1uXibEZZBicsWnQD5xpot3rYx9Vx9Zce7UtGSMOCEoC9AvOiaLW1EfA/640?wx_fmt=png&from=appmsg "")  
  
  
CRUD（创建、读取、更新、删除）概念与发现漏洞相关，因为它提供了一种有结构的方式来与应用程序中的数据进行交互。通过了解如何创建、读取、更新和删除数据，您可以识别出应用程序行为中的潜在漏洞或不一致之处。  
  
让我们更仔细地看看我如何应用 CRUD 基础知识来绘制一个菜单/功能的映射，特别是“报告”菜单。以下是它包括的内容：  
- **创建报告**：识别创建新报告的功能。  
  
- **编辑报告**：查看如何修改现有报告。  
  
- **关闭报告**：调查关闭或完成报告的流程。  
  
- **创建评论**：理解用户如何向报告添加评论。  
  
- **编辑评论**：评估修改现有评论的能力。  
  
- **创建摘要**：分析创建摘要的方式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJCMhaXbXGVL9eAicwC61IHicvy4ks2pdCqXS1IcbSl7ptGya1C8rjhNgA/640?wx_fmt=png&from=appmsg "")  
  
  
我是否一贯地做到了呢？我是否应该在一个菜单上测试各种操作中的漏洞？是的，这就是几天前我经常在 HackerOne 上四处潜伏（侦察）的原因，每天都专注于一个菜单。我想找到 IDOR！以下是我对可能发生的 IDOR 的假设（这些只是假设！）：  
- IDOR 编辑受害者报告  
  
- IDOR 关闭受害者的报告  
  
- IDO 创建对受害者报告的评论  
  
- IDOR 删除评论  
  
- 直到 IDOR 编辑受害者报告摘要。  
  
现在你刚刚看到了我为 IDOR 攻击创建的攻击场景是什么样的（关键：在受害者不知情的情况下执行相同的操作，对吧？）。  
  
在涉及 VAPT（漏洞评估与渗透测试）时，这个阶段属于“信息分析和规划”。  
  
在信息分析和规划阶段，测试人员分析扫描期间识别出的风险，以确定一旦受害者被利用，风险将发生的原因和后果。  
  
渗透（利用）阶段则专注于外部真实风险 [3]。然而，在漏洞发现的背景下，我分析了报告的特性，并制定了直接攻击的计划（如果上下文有些远离，我很抱歉）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJDzdCoQHYTbbNE9wwUqLG2F7DWBHUQuel853tfJ4PwlPy4dvzoLC6zA/640?wx_fmt=png&from=appmsg "")  
  
  
攻击与渗透，在这个阶段，我开始直接在目标上进行预先准备的测试场景，例如从“IDOR 编辑报告”到“IDOR 编辑评论同时包含文件”，并尝试绕过防御措施！然而，结果并不如预期（我以为它足够安全！），因为我总是收到“was_successful”: false 的响应。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJdRv6kiaJEyaPbcPnABT9WevVcKqqZnJxb8hWkacZ6HgcHLUkER4NDuw/640?wx_fmt=png&from=appmsg "")  
  
  
时间已经很晚了，眼睛也有些疲惫，明天再来吧！  
  
🛌🏻💤 第二天，周末到了，我度过了一个更长的夜晚来完成所有的场景，但是我仍然没有找到漏洞，直到最后一个场景“编辑摘要”，我没想到我能够**使用其他账户的文件附加到攻击者的摘要报告**上，无论是在草稿还是已提交的报告上都是如此。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJfcNSiaibMAwjWKp1bMTWQ549Iq1HIXQEfODrSwUnXzGWibYNQVL0vSibicg/640?wx_fmt=png&from=appmsg "")  
  
  
我立即写了一份完整的报告，并发送给了 HackerOne 的漏洞赏金计划！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJtDpCoTqticZYD5HNR1iahB8cMOYJ1vPAdxlDL4LtA4tIVTxEgo0Pmhiag/640?wx_fmt=png&from=appmsg "")  
  
  
之后会发生什么？我一边祈祷，一边劝告自己“这是一个有效的报告！” 但是，我还是不太相信，因为那里的活动非常频繁，即使是顶级感谢的账户也可能对同一个账户多次报告漏洞，你确定我的发现没有被他们报告过吗？你确定没有重复的报告吗？  
  
是的，3天过去了，我问了一下“有更新吗？”考虑到承诺的时间是3天。第四天，我的报告收到了工作人员的评论，我仍然不确定！通常，如果是重复的报告，会立即关闭，幸运的是，我的报告是有效的！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJodtUnBdVORriaiaia2uW5dmiblObmjLNvxt6ydOibsrSEH1TIvf2y2SxCaw/640?wx_fmt=png&from=appmsg "")  
  
  
第二天，他们给出了一份惊人的赏金！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoatic9iciao2zVL8vjOdyH2oJE9jN4vW5WqDMWggr0spGcGSvaBNTAGApvgMowFRKnicicbXW5OIiadSdw/640?wx_fmt=png&from=appmsg "")  
  
  
摘要功能是从什么时候开始存在的？我感到非常幸运能在那里找到它。原谅我的啰嗦，这只是一个故事，技术细节在HackerOne报告中。下次再见！  
  
author:  KreSec  
  
Source: https://kresec.medium.com/hackerone-got-hacked-how-can-i-steal-your-poc-01a9132c5aeb  
### 漏洞点评   
  
IDOR的本质是逻辑漏洞，跟框架无关，如果开发人员没有对全部功能非常理解，那么很可能在某一个小地方出现问题，导致能够引用到其他地方的资源，造成IDOR(不安全的对象引用），通过这个实际的漏洞案例，相信能增强各位小伙伴挖掘到IDOR漏洞的信心。  
  
下面是为公众号新开的对外群，公众号毕竟也差不多小1w用户（四舍五入，经常后台有人问有没有群），欢迎大家加入这个公众号技术交流群哦。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrAqEibAf8bQIOnucYfMcKic8vaLmadYpV8CX9llOqrt23VCs1qYS7otibpLE5WAk9yQjwe1GrKkILBQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
（过期的话，就+运营微信，发最新的加群二维码就好了）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4SgTNngvfiaGVQR5rlcAqAWDBIAMFRCcr519vOaL3cE5RrhUVrgUHQEOB1KMib47bc2KDuvI1MozJp4Ft8ZyMGeg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGBU0kh4SKvnIhkAfe7vdugJSicVCTnBkftwB6EAJHY7dqibqdBia8gnHLKPGrmS5wNlAFOO0mtaYzHIR5ics7c6WA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N1nD0VywusW2gzicajXPpbHUhgSkn4fZbpbVUT4ic7xelaUT9oXrp0YoXFS9eh1ItgQ8Evhyxnq6XRiafzZI6gmDA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
资源获取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NDiboWwKicy0DnMZbrGVVfZgRV8cEN8wibMLriawm2LogEGCwwlzXsX52OJ4jYyiaOo7hE2ogMLm7wYN81FIJ6mTgTw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz/yqVAqoZvDibHW4ynpBjRrolMxOZtKTiaYgGib3Z1r7qO6vXvLcXPmzYxbdQeJ8vcQcICOj6WbeuYRM3kdvBzehtkA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**1.关注本公众号**  
  
**2.点亮右下角的“在看”“点赞”有惊喜哦**  
  
**3.添加运营微信哦，第一时间获取公众号最新资源（备注: 资源哦）**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMr8kG1O4NgYP33908zK6C0zWIErqrHeR9R7S0jSEVMFPRpK31YtUFFnvjoMFOHicZH0Nicdu7L4bvvA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EibWKSHMJJrBpgzdgHaxqFqA8Eib4or9NIHALsnhKcaRvbbR7Do1TaNO0pQMywkt7VW7KFXFy0l8LoSWz51cNzbw/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
IT'S RAINING NOW  
  
合作联系运营微信  
  
微信号：  
sec1993  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/oXlYa1jYhSaibnfGia5ibreXlktKIRqmALbbtGWtkJYMRPCbiceZjHowxE0uWW3tA4CdKicn6eRnC3HKQVAogerG9IA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvzAgbCtVoFmUY6wD3Ejiba8Q79PEydVnicVOwZ2Gic2QaLanB9JJLMEafMpPibAd4YVH1LUgfBcZqGJjLwqDTl8dA/640?wx_fmt=png "")  
  
公众号往期好文  
  
![](https://mmbiz.qpic.cn/mmbiz_png/V6eVlEyL3kcwT76DJ6TTVZSwHRuhRcL6MQRribTMYqR45IXmRqfpicyPrYfA1FicHMViaWuV4Eib5AVmEPdo7O8hSHQ/640?wx_fmt=png "")  
  
  
往期推荐  
  
  
  
[网络安全有未来了！大学生接班人](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505315&idx=1&sn=11fec9f2e92e3df37cb926c9a211e59e&chksm=c0ce2edaf7b9a7cce7ccba3081dadce0760866201f86e4cfb8767b95c6f62500d2d78be68c3f&scene=21#wechat_redirect)  
  
  
[别错过呀，2024最新的网安交流群！](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505305&idx=1&sn=938e67d86cb0004ebbd86962d3c293a8&chksm=c0ce2ee0f7b9a7f6aa8b129d15cb5572402bfcecc3c11a4e37816f36f981a77b200b4aabc0ae&scene=21#wechat_redirect)  
  
  
[MacOS 微信最新版下强开小程序Vconsole调试模式](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505299&idx=1&sn=caf0e540294da3728f1e61e485d404e4&chksm=c0ce2eeaf7b9a7fcd8ec3e200bd9076ef47e2b72f1791a721b28d8ab64f56792d609833a7d8d&scene=21#wechat_redirect)  
  
  
[网络安全疑似色情行业？脱裤是什么操作](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505028&idx=1&sn=6df94c15e9a5cc13fabc3202c2d7f70d&chksm=c0ce2ffdf7b9a6eb15177769240fed0f1b87d2a9a28bf76b903ba414480b480718c6ed2156cd&scene=21#wechat_redirect)  
  
  
[你就是马丁？](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505019&idx=1&sn=85ccee31c6089f57e1055f88f6f8960b&chksm=c0ce2f02f7b9a61485fc5d3aac9f4f7234c779a1bb06c46b88398ed3d1dfa76ae87a8dd897b7&scene=21#wechat_redirect)  
  
  
[史上最方便一键永久激活Window/Office](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505001&idx=1&sn=7ed1c9b0d55f1a26a043067cc8b624d4&chksm=c0ce2f10f7b9a60675a3b3a2fd5c07e71ea8718356129c2bd3cea74e5bb702f1356fbdc4386c&scene=21#wechat_redirect)  
  
  
[开始攻击GarphQL吧！](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247504909&idx=1&sn=df79e9003140fd1230cd47d9aa6bb06f&chksm=c0ce2f74f7b9a6621c45b1e01791d800c1e24dab52c87de060da64b9806710f37db4044760b6&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/O3y1JuFx05r8uoAPJ3tib2K1j5C8Z6eHDRicncMvBE4aQCiaH9AgvFwjyIX0ZTVq0w9dRgEaDqtw2ryUibIDqrhT3A/640?from=appmsg&wx_fmt=png "")  
  
  
  
点个  
在看你最好看  
  
  
  
PARENTING TRAINING  
  
