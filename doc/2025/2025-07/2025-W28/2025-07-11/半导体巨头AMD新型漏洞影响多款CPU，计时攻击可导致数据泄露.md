> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324803&idx=1&sn=c3170ccca7509e132f790f5050e51312

#  半导体巨头AMD新型漏洞影响多款CPU，计时攻击可导致数据泄露  
 FreeBuf   2025-07-11 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKCutfDQc0RMEbwJ4cqLzPlS7ShAR0ic6mzw385QIOje8pO86ia1JdQJNQ/640?wx_fmt=png&from=appmsg "")  
  
  
半导体巨头AMD近日警告称，其多款芯片组存在新型漏洞，可能导致信息泄露风险。这种被称为"瞬态调度攻击"（Transient Scheduler Attacks，TSA）的攻击方式，会通过CPU在特定微架构条件下的指令执行时序，形成推测性侧信道漏洞。  
  
  
**Part01**  
## 漏洞详情与CVE编号  
  
  
AMD在安全公告中表示："在某些情况下，攻击者可能利用这种时序信息推断其他上下文的数据，从而导致信息泄露。"这些漏洞是微软与苏黎世联邦理工学院研究人员在研究现代CPU对抗Meltdown和Foreshadow等推测执行攻击时发现的，他们通过虚拟机、内核和进程等安全域之间的隔离压力测试发现了这些问题。  
  
  
2024年6月经过负责任披露后，这些漏洞被分配了以下CVE编号：  
  
  
1. CVE-2024-36350（CVSS评分：5.6）- 某些AMD处理器中的瞬态执行漏洞可能允许攻击者推断先前存储的数据，可能导致特权信息泄露  
  
  
**2. CVE-2024-36357（CVSS评分：5.6）- 某些AMD处理器中的瞬态执行漏洞可能允许攻击者推断L1D缓存中的数据，可能导致跨特权边界的敏感信息泄露**  
  
****  
**3. CVE-2024-36348（CVSS评分：3.8）- 某些AMD处理器中的瞬态执行漏洞即使用户模式指令防护(UMIP)功能已启用，仍可能允许用户进程推测性地推断控制寄存器，可能导致信息泄露**  
  
****  
**4. CVE-2024-36349（CVSS评分：3.8）- 某些AMD处理器中的瞬态执行漏洞即使在禁用读取的情况下，仍可能允许用户进程推断TSC_AUX值，可能导致信息泄露**  
  
  
**Part02**  
## 受影响处理器型号与修复措施  
  
  
AMD将TSA描述为影响其CPU的"新型推测性侧信道漏洞"，并已为受影响处理器发布微码更新，涉及产品包括：  
  
- 第三代AMD EPYC处理器  
  
- 第四代AMD EPYC处理器  
  
- AMD Instinct MI300A  
  
- AMD Ryzen 5000系列桌面处理器  
  
- 带Radeon显卡的AMD Ryzen 5000系列桌面处理器  
  
- AMD Ryzen 7000系列桌面处理器  
  
- 带Radeon显卡的AMD Ryzen 8000系列处理器  
  
- AMD Ryzen Threadripper PRO 7000 WX系列处理器  
  
- 带Radeon显卡的AMD Ryzen 6000系列处理器  
  
- 带Radeon显卡的AMD Ryzen 7035系列处理器  
  
- 带Radeon显卡的AMD Ryzen 5000系列处理器  
  
- 带Radeon显卡的AMD Ryzen 7000系列处理器  
  
- 带Radeon显卡的AMD Ryzen 7040系列处理器  
  
- 带Radeon显卡的AMD Ryzen 8040系列移动处理器  
  
- AMD Ryzen 7000系列移动处理器  
  
- AMD EPYC Embedded 7003  
  
- AMD EPYC Embedded 8004  
  
- AMD EPYC Embedded 9004  
  
- AMD EPYC Embedded 97X4  
  
- AMD Ryzen Embedded 5000  
  
- AMD Ryzen Embedded 7000  
  
- AMD Ryzen Embedded V3000  
  
**Part03**  
## 技术原理与攻击变种  
  
  
AMD指出，从内存读取数据的指令可能会出现"虚假完成"现象——当CPU硬件预期加载指令会快速完成，但存在某些条件阻止其完成时就会发生这种情况：  
  
  
在这种情况下，依赖操作可能会在检测到虚假完成之前就被调度执行。由于加载实际上并未完成，与该加载相关的数据被视为无效。加载操作稍后将重新执行以成功完成，所有依赖操作将在有效数据就绪时重新执行。  
  
  
与预测性存储转发等其他推测行为不同，遭遇虚假完成的加载不会导致最终的流水线刷新。虽然与虚假完成相关的无效数据可能会被转发给依赖操作，但使用这些数据的加载和存储指令不会尝试获取数据或更新任何缓存或TLB状态。因此，无法使用标准瞬态侧信道方法推断这些无效数据的值。  
  
  
但在受TSA影响的处理器中，这些无效数据可能会以攻击者可检测到的方式影响CPU执行其他指令的时序。  
  
  
AMD表示根据虚假完成相关无效数据的来源，已识别出TSA-L1和TSA-SQ两种变体：分别源自L1数据缓存或CPU存储队列。  
  
  
**Part04**  
## 潜在影响与利用条件  
  
  
在最坏情况下，利用TSA-L1或TSA-SQ漏洞的成功攻击可能导致：  
  
- 操作系统内核向用户应用程序的信息泄露  
  
- 虚拟机监控程序向客户虚拟机的信息泄露  
  
- 两个用户应用程序之间的信息泄露  
  
TSA-L1是由L1缓存使用微标签进行数据缓存查找时的错误引起的，而TSA-SQ漏洞则发生在所需数据尚不可用时，加载指令错误地从CPU存储队列检索数据的情况下。在这两种情况下，攻击者都可以推断出L1缓存中存在的任何数据或被旧存储使用的数据，即使这些数据是在不同上下文中执行的。  
  
  
不过，利用这些漏洞需要攻击者先获得对机器的恶意访问权限，并具备运行任意代码的能力，无法通过恶意网站进行利用。AMD强调："利用TSA所需的条件通常是暂时的，因为CPU检测到虚假完成后，微标签和存储队列都会更新。因此，要可靠地窃取数据，攻击者通常需要能够多次调用受害者以重复制造虚假完成条件。当攻击者和受害者之间存在现有通信路径（如应用程序与操作系统内核之间）时，这种情况最有可能实现。"  
  
  
**参考来源：**  
  
AMD Warns of New Transient Scheduler Attacks Impacting a Wide Range of CPUs  
  
https://thehackernews.com/2025/07/amd-warns-of-new-transient-scheduler.html  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324737&idx=1&sn=8f0843cf1d51ac50bd1eae4a5f0e4c87&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
