#  英特尔CPU新型漏洞可泄露特权内存敏感数据   
邑安科技  邑安全   2025-05-14 09:31  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v7T54TklESlCO3EibopMCruks85eiahMWTxU8xacAd0dBjo7VE9290RxHMKVv0bUIWywLWha8CtC9g/640?wx_fmt=png&from=appmsg "")  
## 漏洞原理分析  
  
现代英特尔CPU普遍存在的新型"分支特权注入"漏洞（Branch Privilege Injection），可使攻击者从操作系统内核等特权软件分配的内存区域窃取敏感数据。这些内存区域通常存储着密码、加密密钥、其他进程内存及内核数据结构等关键信息，其防护至关重要。  
  
苏黎世联邦理工学院研究人员Sandro Rüegge、Johannes Wikner和Kaveh Razavi发现，虽然针对Spectre v2漏洞的缓解措施已有效防护六年，但最新发现的"分支预测器竞态条件"攻击方法成功绕过了这些防护。该漏洞被命名为"分支特权注入"，编号CVE-2024-45332，本质是英特尔CPU分支预测器子系统中存在的竞态条件问题。  
## 技术机制详解  
  
分支目标缓冲器（BTB，Branch Target Buffer）和间接分支预测器（IBP，Indirect Branch Predictor）等组件作为专用硬件，会在分支指令解析前预测执行路径以保持CPU流水线满载。研究人员发现英特尔分支预测器的更新操作与指令执行不同步，导致更新过程可能跨越特权边界。当发生用户模式到内核模式的特权切换时，存在短暂时间窗口使更新关联到错误的特权级别，从而破坏用户态与内核态的隔离机制，使非特权用户可窃取特权进程数据。  
  
研究团队开发的攻击方法首先训练CPU预测特定分支目标，然后通过系统调用将执行流切入操作系统内核，最终实现攻击者控制的"代码片段"（gadget）的推测执行。该代码会访问载入缓存的机密数据，并通过旁路攻击渠道将内容泄露给攻击者。在启用默认防护措施的Ubuntu 24.04系统上，该攻击成功读取包含哈希密码的'/etc/shadow/'文件，峰值泄露速率达5.6 KB/秒，准确率99.8%。  
## 影响范围与修复方案  
  
CVE-2024-45332影响第九代及之后所有英特尔CPU，包括Coffee Lake、Comet Lake、Rocket Lake、Alder Lake和Raptor Lake等系列。研究人员指出："自第九代（Coffee Lake Refresh）起的所有英特尔处理器均受影响，甚至在第七代（Kaby Lake）处理器上也观察到绕过间接分支预测屏障（IBPB，Indirect Branch Prediction Barrier）的情况。"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v7T54TklESlCO3EibopMCru19AdX3n7nWS6oJpdmsaw13ssJ7uvXrznic3l0nia7F3ibrNJruslLvKnw/640?wx_fmt=png&from=appmsg "")  
  
**受影响的处理器系列**  
   
  
经测试，Arm Cortex-X1、Cortex-A76以及AMD Zen 5和Zen 4芯片因不具备相同的异步预测行为而不受影响。虽然攻击演示基于Linux系统，但由于漏洞存在于硬件层面，Windows系统理论上同样存在风险。  
## 缓解措施与性能影响  
  
研究团队于2024年9月向英特尔提交漏洞报告，后者已发布微码更新修复受影响型号。固件级缓解方案会导致2.7%的性能损耗，软件缓解方案则根据CPU型号不同产生1.6%至8.3%的性能影响。虽然普通用户实际风险较低，且攻击需要满足多项严苛条件，但仍建议用户及时更新BIOS/UEFI和操作系统补丁。完整技术细节将于2025年USENIX安全会议上公布。  
  
原文来自:   
www.bleepingcomputer.com  
  
原文链接:   
https://www.bleepingcomputer.com/news/security/new-intel-cpu-flaws-leak-sensitive-data-from-privileged-memory/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
