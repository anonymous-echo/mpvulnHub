#  首次利用OpenAI o3模型发现Linux内核零日漏洞   
 安全内参   2025-05-26 10:46  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
  
12000行代码看100遍揪出，无需调用任何工具，修复方案也比人类好。  
  
  
AI成功找到Linux安全漏洞，还是**内核级别的零日漏洞**  
。  
  
刚刚，OpenAI总裁转发了独立研究员  
Seen Heelan的实验成果：用o3模型找到了Linux内核SMB实现中的一个远程零日漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOp3sEeqRfzMFzxic24bH3fSwJ683BI2CiciaaicESH3PKuCVdC1lrogu1Ug/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
更让人惊讶的是，整个过程中**没有用到任何复杂的工具**  
——没有脚手架、没有智能体框架、没有工具调用，仅仅是o3 API本身。  
  
这个漏洞被编号为CVE-2025-37899，是SMB”注销”命令处理程序中的一个释放后使用（use-after-free）漏洞。  
  
据作者透露，这是首次公开讨论的由大模型发现的此类漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPO6Osawam0FHGV6Z2NN2l9K7lQ5iawQxWG9Sybrd86DThppaozzsRKOWg/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
有网友看过发现过程后感叹，原以为会有很疯狂的实验设置，但其实只是把一堆代码缝到一起，让o3检查100次。  
> 希望其他白帽黑客已经开始像这样检查其他关键操作系统了。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOL90Dicz3IKftwDCZvLLCJUQrDiaJ63uOjrLA3nBiboCN54iasXCPeQmKoQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
OpenAI首席研究官Mark Chen表示：像o3这样的推理模型正开始助力深度技术工作和有意义的科学发现。接下来一年，类似这样的成果将会越来越普遍：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOGeuRrib1a9fzFvotaxdXSrSvI7lBKwI4RkJUEKKtic4eIcwxIkssD5lw/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
## AI不仅找到漏洞，还能辅助修复  
  
Sean Heelan是一位独立研究员，专注于基于大模型的漏洞研究和漏洞利用自动化生成。  
  
他原本在手动检查Linux内核的KSMBD（内核态SMB3协议实现）漏洞，想要暂时远离大模型相关的工具开发。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOv3MwEkymOCuUW0wbCRd6DsbqgJ0jpDiawViagDeXqdg3shE8VkKHaarg/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
但o3发布后，他忍不住想测试一下：”既然我手里已经有这些漏洞，不如看看o3能不能找到它们？”  
  
他先用一个自己手动发现的漏洞CVE-2025-37778作为测试。这是Kerberos认证路径中的一个释放后使用漏洞，是测试大模型能力很好的基准，因为：  
- 它是Linux 内核远程攻击面的一部分  
  
- 它并不简单，发现他需要理解如何触发特定的会话状态、认证函数的多条执行路径、跨函数的对象生命周期管理  
  
- 但它也并非极其复杂，作者本人可以在10分钟内带着同时了解涉及到的约3300行代码  
  
接下来开始实验之前，还需要搞清楚一个问题，该给大模型展示哪些代码？  
  
理想情况当然是大模型读取整个代码库并输出结果，但实践中上由于上下文窗口的限制还无法事先。  
  
最终Heelan为 LLM 提供了“会话设置”命令处理程序的代码，包括它调用的所有函数的代码等等，直到调用深度达到3（这是包含推理漏洞所需代码所需的深度），还包含了命令处理器、连接建立/拆除、请求分发等完整上下文。  
  
提示词中告诉o3专门寻找use-after-free漏洞，提供KSMBD架构说明，强调要避免误报，每个实验运行100次，统计成功率。  
  
相关代码和提示词已开源在GitHub上。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOialPibnIibYOuBO9fVDOvMrricKJMqJ1uqcNl889memZ3GZcyqsQb2Vq7g/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
Heelan还按同样流程测试了Claude3.7和Claude 3.5作为对比，结果o3的表现让人眼前一亮：  
- OpenAI o3: 100次运行中成功找到8次漏洞  
  
- Claude 3.7: 100次中找到3次  
  
- Claude 3.5: 100次中一次都没找到  
  
此外有意思的的是，o3和Claude的输出风格完全不同。  
  
o3生成的像人类写的漏洞报告，结构清晰、重点突出  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOLekCgwZSJ9iasWUHscxHX91vzAKMHo895cVoOa5KfdvXfGRCBTW7LRQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
Claude更像思维流或工作日志，细节丰富但略显冗长。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOam8Ggwlib1T7CZBpibcAQZS0zQS68b38ckicp6SkgwaMXXFGHNL4PcDaQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
接下来发生的事情更精彩了。  
  
Heelan想测试o3在更大代码量下的表现，于是给它提供了所有SMB命令处理程序的代码，约**12000行**  
代码。  
  
虽然找到原始漏洞的成功率降到了1%，性能明显下降。但在运行结果中，o3报告了一个全新的漏洞。  
  
Heelan自己之前也不知道这个漏洞，它同样是由于sess->user的释放造成的，但这次是在会话注销处理程序中。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOy6ib0rgicL3oxw4tmibhBmMwdR9PRDpxPEYjG02Fw2aAQzDaMicDTEfrLg/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
o3自己对这个漏洞的解释如下。  
> 当一个ksmbd工作线程还在执行使用sess->user的请求时，另一个处理同一会话SMB2 LOGOFF的线程释放了该结构。没有同步机制保护该指针，所以第一个线程会解引用已释放的内存——这是一个经典的释放后使用漏洞，会导致内核内存损坏和任意代码执行。  
  
  
更有意思的是，研究员发现o3不仅能找到漏洞，某些情况下修复方案比人类更完善。  
  
对于之前的Kerberos认证漏洞，Heelan最初提出的修复是简单地将指针置空：  
```
if (sess->state == SMB2_SESSION_VALID) {
    ksmbd_free_user(sess->user);
    sess->user = NULL;  // 添加这行
}
```  
  
但o3的报告中有指出这个修复不够充分，因为SMB协议允许两个不同的连接”绑定”到同一个会话，在释放和置空之间的短暂窗口期，另一个线程仍可能访问这个指针。  
  
最终Heelan承认，如果使用o3来找和修复原始漏洞，“理论上”会比自己完成更好。  
  
之所以加上“理论上”的限定，是因为现在AI误报的比例有点高，人类很难认真仔细地查看o3的每份报告。  
  
不过他也认为随着技术的发展，这个比例只会越来越低。  
  
Heelan在报告结尾感慨道：  
> 大模型在程序分析技术的能力空间中，处于一个比我们见过的任何东西都更接近人类的位置。考虑到创造力、灵活性和通用性，LLM更像是人类代码审计员，而不是符号执行、抽象解释或模糊测试。  
  
  
他特别强调，如果你从事安全研究工作，现在应该开始密切关注了：  
- 专家级研究员不会被取代，反而会变得更高效  
  
- 对于10000行以内的代码问题，o3有相当大的概率能解决或帮助解决  
  
- 虽然仍有约1:50的信噪比问题，但这已经值得投入时间和精力  
  
不过也有人看到了其中的风险：  
  
如果坏人利用AI的能力找到类似的漏洞并攻击系统又如何呢？  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDlyrecNfQhnStib9TWefkPOuqeVu3mHsutzQkMicospwlBicicrpPGdiaHbQWr8BKzMzFa8tPNyzGMQ4Q/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：  
量子位  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
