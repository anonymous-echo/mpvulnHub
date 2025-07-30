#  英特尔CPU曝安全漏洞，攻击者大量窃取数据   
 网络安全应急技术国家工程中心   2023-05-04 15:25  
  
据BleepingComputer 4月24日消息，近日在 Arxiv.org 上发表的一篇技术论文揭示了一种针对多代英特尔CPU的攻击手法——利用新的侧信道攻击，让数据通过 EFLAGS 寄存器泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176mx2qEvrI4r7XP4NfMBn6Tkdk8KmoK8iae4ppKc1RRsIQZo0mUv2WqkxvrWqRia3lwDNtcIvjhxRfdA/640?wx_fmt=jpeg "")  
  
这一与众不同的侧信道攻击由清华大学、马里兰大学和中国教育部计算机实验室 (BUPT) 的研究人员共同发现，它不像许多其他侧信道攻击那样依赖缓存系统，而是利用瞬态执行中 EFLAGS 寄存器变化的缺陷，影响JCC（条件代码跳转）指令的时序，进而通过时序分析从用户内存空间中提取数据。  
  
EFLAGS 寄存器是一个 CPU 寄存器，保存着与处理器状态相关的各种标志，而 JCC 指令是一个 CPU 指令，能允许根据 EFLAGS 寄存器的内容进行条件分支。  
  
攻击分两个阶段进行，第一阶段触发瞬时执行并通过EFLAGS寄存器对内部数据进行编码，第二阶段测量KCC指令解码数据的执行时间。实验数据表明，该攻击针对 Intel i7-6700 和 Intel i7-7700 实现了 100% 的数据检索（泄漏），并且对更加新型的 Intel i9-10980XE CPU 也取得了一定突破。该项实验是在 Ubuntu 22.04 jammy 上进行，Linux 内核版本为 5.15.0。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icLDSOTFbJzNmS0Lbc7r4wBoDZR9Kun00n1wuAHu7YAFw1poP1ibicwBg1hUzjC3wXCvwJQfLG2icRow/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
攻击概述  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icLDSOTFbJzNmS0Lbc7r4wBwZ7Wv6Tia920M04KwE1LiarOqCCUS6gwg1aapn3eECBXaMvGvKy2hdBg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
用于计时瞬态执行攻击的伪代码  
  
但研究人员指出，这种计时攻击不如缓存状态侧信道方法可靠，并且为了在最新的芯片中获得更高的准确性，这种攻击必须重复数千次。他们承认，攻击的根本原理仍然难以捉摸，并假设英特尔 CPU 的执行单元中有一个缓冲区，如果执行要撤销，需要时间来恢复，如果接下来的指令取决于缓冲区的目标，这个过程会导致停滞。  
  
但研究人员仍然提出了一些重要的缓解措施，例如更改 JCC 指令的执行，使对抗性执行在任何情况下都无法测量，或者在瞬态执行后重写 EFLAGS 以减少其对 JCC 指令的影响。  
  
总体上，该攻击作为 Meltdown 的旁路，Meltdown是2018年发现的一个关键安全漏洞，影响到许多基于x86的微处理器。该漏洞能够利用“预测执行”（speculative execution）的性能优化功能，使攻击者绕过内存隔离机制来访问存储在内核内存中的敏感数据，例如密码、加密密钥和其他私有数据。  
  
虽然目前可以通过软件补丁、微代码更新和新的硬件设计来缓解Meltdown 漏洞，但仍没有任何解决方案可以 100% 解决问题，此次发现的新型攻击方法甚至仍可能在已打补丁的系统中起作用，这具体取决于硬件、软件和补丁配置。  
  
**参考来源：**  
  
https://www.bleepingcomputer.com/news/security/intel-cpus-vulnerable-to-new-transient-execution-side-channel-attack/  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
