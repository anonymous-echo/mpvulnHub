#  代码审计|SpringKill如何用CodeAuditAssistant挖掘0day教程公布   
 TtTeam   2025-04-22 03:27  
  
   
  
# 如何快速复现 / 挖掘一个漏洞？CodeAuditAssistant 高阶技巧  
> SpringKill，网络安全建设 | SAST/IAST研究员 | 开源安全工具开发者，专注于静态分析(SAST)、动态分析(IAST)领域的安全研究与工具开发  
  
Github:https://github.com/springkill  
  
  
我和Unam4  
 最近发布了一个新的IDEA  
 代码审计辅助插件CodeAuditAssistant  
 ，测试阶段目前也收到了很多反馈，那么今天就从一个漏洞实战案例出发来详细讲解下插件的使用技巧。  
**(本文是SpringKill的调用链审计，以SpringKill的自述角度来讲解如何使用CodeAuditAssistant 挖掘0day)**  
  
## 挖掘目标 - Apache hertzbeat  
  
**https://github.com/apache/hertzbeat**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicN1CkcLrRT5Bq1qVYDYHrHwMOxnyibHPy9DLccMHeHLk0gITL1L10YiaxQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNbUJMLyHTwtW40p8onTGOl83gHMMiaf5uvDyhpgErZQ7hicjjGZ6CdNcg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNicZ1Jy1kFPvQZoneft38dnHHibcY4wC4WsrNSUYFk2HJ2eib8s7DLVw0Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNJhvLTzgV9qddn3FPZUkeAv7iacy9eN7GibXtajK3JX5MpRQ7wyV8bzVg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 2024补天大会议题 - JNDI新攻击面探索  
  
PPT地址：https://forum.butian.net/share/3857  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNQibKah2OIgo3x4THqd73KE6dIhGicVhfyv26icuTqqqHjVPiaanqIeCGpQ/640?wx_fmt=png&from=appmsg "")  
  
  
Github：https://github.com/unam4  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNCCyGQeLicO02L2z5BNOiaTibgXRZW1SOUiaLQLc57Kj8LfL6EHMO5icxtcg/640?wx_fmt=png&from=appmsg "null")  
  
  
unam4  
以绕过  
的角度来讲解漏洞发现，SpringKill  
本文以发现注入点  
的角度来介绍如何快速挖掘0Day。  
  
## 第零步：关于调用链  
  
调用链（Call Chain）顾名思义就是方法间的调用所组成的链条，在人工代码审计中我们往往更想快速找到方法被调用的地方进行进一步的确认。  
  
那么这个过程中对于单线程  
执行的程序（比如我录得视频中的Log4j  
 ）其实检测是相对简单的（只需要处理好抽象 / 接口即可，必要时处理依赖注入等，这里不展开说），但是对于一些多线程  
 执行才能触发的漏洞（比如定时任务），其实是不能轻易从一个调用链发现整个漏洞的调用的（因为设置定时任务  
和运行定时任务  
可能并不是同一个线程），所以本文从多线程漏洞的识别方式出发，带你感受CodeAuditAssistant  
 带给你的效率提升。  
## 第一步：查找 SInk  
  
如果不是很特殊的触发点，你都可以通过SinkFinder/Sink  
 查找器进行查找，当然对于你自己的独家 Sink  
，可以用传统 ctrlf 大法或者使用后续上线的Sink 自定义  
功能。  
  
完成调用图构建和Sink  
初始化之后，通过 Sink 查找我们找到了一个危险的JNDI  
方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNIFQwb1WxAhupKMfg1xsNJbY9uaP1icLBP6OA1ZBNWOUyun8LGDoGAicQ/640?wx_fmt=png&from=appmsg "null")  
  
  
接下来我们右键点击该方法后，选择作为 Sink 点搜索  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNObRk3ew1fKymCVL1AlAYt9Kuuj0xLb3cZ7O5bxMwLp2WuW94blyWlw/640?wx_fmt=png&from=appmsg "null")  
  
  
现在你就可以从搜索结果中看到这个方法的调用链了，我们展开调用链进行查看：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicN2o5LlzzC6rYrTEzggGbIicQn0NRZGTzo9TckCbL75NZ1eM1VOdQOtrQ/640?wx_fmt=png&from=appmsg "null")  
  
  
跟踪到第一个方法run  
 中，在这里，调用链的第一部分结束，程序运行时的最后一段结束，接下来我们就要跟踪该类中的字段了，通过查看字段定义，我们继续跟踪到monitorId  
 字段：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNHEyFN2PA8RP6xya1A88EGM2UkSgHoXVLr9ibn6F33FKRbBuShiaLwLSQ/640?wx_fmt=png&from=appmsg "null")  
  
  
ctrl 点击并发现这个字段被赋值的地方：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicN1HyKopjIjYS4Dib5ibge14GCA3TByo4piajOv2DdYZXGfaXyot04vXiatw/640?wx_fmt=png&from=appmsg "null")  
  
  
进入后，我们继续手动跟踪，找到 task 方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNRZiajick7qeTmCvHFa5K3Aa7UWkunA63vGLHJaMx7qcfQ1Inss3YIhRA/640?wx_fmt=png&from=appmsg "null")  
  
  
接下来找到对task  
赋值的地方后，我们再次将这个方法作为 Sink 搜索：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNULQ2bEib499ujRozBGebnORFl03ISjjFnVYvT9YPOtCTo84fF9I0y4w/640?wx_fmt=png&from=appmsg "null")  
  
  
至此，你找到了这个这个漏洞的起始点Service  
 层的detectMonitor  
方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNc8K1obv25B20wyia5z6SZGaS9kJyoZsmAnA0ykPCUrrEKrHJs6lVOzw/640?wx_fmt=png&from=appmsg "null")  
  
  
那么我们再来实际运行一下查看，发现多线程调用中确实同上所述：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNWZicJu2CAfEFoibd9mVicOqYg5h56orIicPd3sia20775OS1kSWRmRDHyBQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNMaKZa3dPYkAkCR5hYmSD55gpPxbjEQA0uRnYQEE3ovpgwSKChMG2cw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hFPkDXcMlMsItnV9OKcTENTwSOyNDnicNJ537j0skzaKJibJD7PrDzCP65yHqaT35UsS3MlrSOVe0gm6vq3vu2BQ/640?wx_fmt=png&from=appmsg "null")  
  
  
这个也就是我和 Unam4 的 Hertzbeat 的一系列绕过漏洞的触发过程了，最后附上插件连接：  
```
https://github.com/SpringKill-team/CodeAuditAssistant
```  
  
  
  
