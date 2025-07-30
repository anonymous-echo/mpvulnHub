#  英特尔CPU曝新型漏洞，特权内存敏感数据面临泄露风险   
 FreeBuf   2025-05-14 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38xyNIp0kYIkmaicicgibRRp3otdSs0qYxTsKYewrKdDQlh30H0I2ctZUV3tLkCNaLp58hiaczwMBWsZg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
现代英特尔CPU普遍存在的新型"分支特权注入"漏洞（Branch Privilege Injection），可使攻击者从操作系统内核等特权软件分配的内存区域窃取敏感数据。这些内存区域通常存储着密码、加密密钥、其他进程内存及内核数据结构等关键信息，其防护至关重要。  
  
  
苏黎世联邦理工学院研究人员发现，虽然针对Spectre v2漏洞的缓解措施已有效防护六年，但最新发现的"分支预测器竞态条件"攻击方法成功绕过了这些防护。该漏洞被命名为"分支特权注入"，编号CVE-2024-45332，本质是英特尔CPU分支预测器子系统中存在的竞态条件问题。  
  
### Part01  
### 技术机制详解  
  
  
分支目标缓冲器（BTB，Branch Target Buffer）和间接分支预测器（IBP，Indirect Branch Predictor）等组件作为专用硬件，会在分支指令解析前预测执行路径以保持CPU流水线满载。研究人员发现英特尔分支预测器的更新操作与指令执行不同步，导致更新过程可能跨越特权边界。当发生用户模式到内核模式的特权切换时，存在短暂时间窗口使更新关联到错误的特权级别，从而破坏用户态与内核态的隔离机制，使非特权用户可窃取特权进程数据。  
  
  
研究团队开发的攻击方法首先训练CPU预测特定分支目标，然后通过系统调用将执行流切入操作系统内核，最终实现攻击者控制的"代码片段"（gadget）的推测执行。该代码会访问载入缓存的机密数据，并通过旁路攻击渠道将内容泄露给攻击者。在启用默认防护措施的Ubuntu 24.04系统上，该攻击成功读取包含哈希密码的'/etc/shadow/'文件，峰值泄露速率达5.6 KB/秒，准确率99.8%。  
  
### Part02  
### 影响范围与修复方案  
  
  
CVE-2024-45332影响第九代及之后所有英特尔CPU，包括Coffee Lake、Comet Lake、Rocket Lake、Alder Lake和Raptor Lake等系列。研究人员指出："自第九代（Coffee Lake Refresh）起的所有英特尔处理器均受影响，甚至在第七代（Kaby Lake）处理器上也观察到绕过间接分支预测屏障（IBPB，Indirect Branch Prediction Barrier）的情况。"  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38xyNIp0kYIkmaicicgibRRp3o328icYICJxvGNm2cdRkBQ8PgobtSpTW0QIic54wM8PVNjNJic12cVk3fg/640?wx_fmt=jpeg&from=appmsg "")  
  
受影响的处理器系列 来源：苏黎世联邦理工学院  
  
  
经测试，Arm Cortex-X1、Cortex-A76以及AMD Zen 5和Zen 4芯片因不具备相同的异步预测行为而不受影响。虽然攻击演示基于Linux系统，但由于漏洞存在于硬件层面，Windows系统理论上同样存在风险。  
  
### Part03  
### 缓解措施与性能影响  
  
  
研究团队于2024年9月向英特尔提交漏洞报告，后者已发布微码更新修复受影响型号。固件级缓解方案会导致2.7%的性能损耗，软件缓解方案则根据CPU型号不同产生1.6%至8.3%的性能影响。虽然普通用户实际风险较低，且攻击需要满足多项严苛条件，但仍建议用户及时更新BIOS/UEFI和操作系统补丁。  
  
  
**参考来源：**  
  
**New Intel CPU flaws leak sensitive data from privileged memory**https://www.bleepingcomputer.com/news/security/new-intel-cpu-flaws-leak-sensitive-data-from-privileged-memory/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320343&idx=1&sn=4092a85b3c9cd6eea8dc0dcb48620652&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
