#  英特尔新漏洞：Spectre 和 Meltdown 问题以新面貌重现   
会杀毒的单反狗  军哥网络安全读报   2025-05-19 01:02  
  
**导****读**  
  
  
  
苏黎世联邦理工学院和阿姆斯特丹自由大学的研究人员披露了英特尔处理器中导致内存泄漏和  
Spectre v2  
攻击的新漏洞。这些发现表明，尽管  
Spectre  
和  
Meltdown  
漏洞披露已有七年，但推测指令执行问题仍然构成重大威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaHy0fWeLnxelkLiauI5TbsvhRBeYbZZhA1tSGdiaELysrU2NvbBHn8Ue4IEiaPlDOHNcKfYVZuiaXaRoQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
研究人员发现了三个关键漏洞，分别是分支权限注入和训练单独漏洞。  
  
  
CVE-2024-45332（BPI - 分支权限注入） - 利用竞争条件，允许以内核权限注入不正确的预测。该攻击使得打破用户进程和系统内核之间的隔离成为可能。  
  
  
CVE-2024-28956（ITS - 间接目标选择） - 与选择错误有关，影响第 9 至第 11 代英特尔酷睿处理器和第 2 至第 3 代至强服务器。  
  
  
CVE-2025-24495（Lion Cove BPU） ——与 Lion Cove 架构中的实施问题有关。  
  
  
训练 Solo攻击允许推测性地接管同一域（例如内核）内的指令流，从而绕过 Spectre v2 之后引入的安全措施。  
  
### 什么是 BPRC？  
###   
  
BPRC   
是由于英特尔处理器中分支预测器操作的异步特性而导致的一类错误。  
  
  
预测器更新（例如分支目标缓冲区  
 - BTB  
）与特权上下文切换（例如从用户模式到内核模式的转换）不同步，从而导致竞争条件。  
  
  
可能会注入带有不正确权限标签的分支预测  
 -   
例如在用户模式下学习到的预测可以在内核模式下使用。研究人员描述了三种主要变体：  
  
  
BPRCU -> K –   
即用户  
 ->   
内核边界违规。  
  
BPRCG -> H –   
违规客户机  
 ->   
虚拟机管理程序边界。  
  
BPRCIPBPB——IBPB  
屏障旁路。  
  
### BPI机制如何运作？  
###   
  
BPI 是一种新的攻击机制，允许精确注入标记为kernel-mode来自用户进程级别的分支预测。攻击者利用权限更改指令（例如）的执行syscall和 BTB 的更新之间的竞争条件。  
  
  
这会导致任意内核内存泄漏 - 即使在已完全修补且启用了所有保护措施的现代 Linux 系统上也是如此。  
  
### Spectre 和 Meltdown漏洞  
###   
  
2018 年披露的Spectre（CVE-2017-5753 和 CVE-2017-5715）和Meltdown （CVE-2017-5754）漏洞。它们利用推测指令执行从内存中泄露数据，以及用户进程和内核之间的内存隔离缺陷（Meltdown）。  
  
  
BPI 等新漏洞是这些机制的演变——它们通过在改变权限级别时操纵预测器的状态来绕过以前引入的修复（例如 Spectre v2 中的eIBRS ）。  
  
### 漏洞影响和缓解建议  
###   
  
BPI 攻击会导致虚拟机和管理程序之间的数据泄露。用户是否会成为利用这些漏洞的网络钓鱼攻击的目标？在适当的条件下，可能是的。  
  
  
英特尔已经发布了微补丁，但生产环境中的全面迁移可能需要数月时间。建议立即应用固件更新并监控制造商有关安全配置的建议（例如，禁用 AMD 的 cBPF）。  
  
  
尽管十年来一直在努力对抗针对处理器的攻击，但新的变种仍然不断出现。这表明硬件安全必须朝着进程之间微架构状态的完全隔离发展。  
  
  
I  
ntel  
安全公告：  
  
https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01247.html  
  
  
新闻链接：  
  
https://sekurak.pl/nowe-luki-w-procesorach-intel-powrot-do-problemow-spectre-i-meltdown-w-nowej-odslonie/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
