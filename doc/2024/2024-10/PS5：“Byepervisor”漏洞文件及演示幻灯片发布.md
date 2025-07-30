#  PS5：“Byepervisor”漏洞文件及演示幻灯片发布   
 Ots安全   2024-10-26 13:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadLNsyib1NANzd4Fo0ibFgDgWcFI1Fib2vqYEFPj626ncliajEib50KNqJFYOSHjG2MuqVUUYoZ2wTBPVg/640?wx_fmt=webp&from=appmsg "")  
  
继昨天在 Hardwear.io 信息安全会议上展示了PS5 虚拟机管理程序的漏洞（或者具体来说是 2 个漏洞）之后，PlayStation 黑客SpecterDev现在发布了虚拟机管理程序漏洞的文件以及演示的幻灯片。  
  
对于所有兼容固件 (2.xx/1.xx)，漏洞利用包括内核转储代码和解密 SELF（加密 ELF）文件的代码。此外，那些有幸使用固件 2.50 的人应该能够享受随附的 HEN（Homebrew Enabler）。  
  
**什么是 Byepervisor**  
  
PS5 Hypervisor 是一种中间件，旨在保护主机的固件（尤其是其内核）免受恶意攻击。Hypervisor 特别在内核上强制执行仅执行内存 (XOM) 规则，以防止攻击者读取/写入系统的关键部分。它是 PS5 安全性的关键组成部分，绕过或破解它一直被认为是完全控制 PS5 系统的重要部分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadLNsyib1NANzd4Fo0ibFgDgWJR7g415ibyVsaHQNHku2fYWqMpeQFThkicCXlSPsMvictEIDxUYQhV2Og/640?wx_fmt=webp&from=appmsg "")  
  
Byepervisor 是针对 PS5 Hypervisor 早期版本的漏洞，适用于固件 2.xx 和 1.xx。这是 SpecterDev 的漏洞，PlayStation 黑客于 2024 年 10 月披露了该漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadLNsyib1NANzd4Fo0ibFgDgWERWxcxibSKoQ0ibYMhUnvJY2588ia1oPCgaCaCbQ76K6ia5cYQhYntf8aQ/640?wx_fmt=webp&from=appmsg "")  
  
摘自自述文件：  
  
PS5 虚拟机管理程序漏洞，适用于 <= 2.xx 固件。存储库中包含两个漏洞和漏洞链，它们彼此独立，可以使用任何一个。提供一个漏洞主要只是为了保存（/_old_jump_table_exploit），只需要使用主要漏洞链（QA 标记漏洞）。  
  
  
**下载并使用 Byepervisor**  
  
您可以从https://github.com/PS5Dev/Byepervisor下载 Byepervisor 漏洞源代码：  
> 您确实应该自己从源代码构建它（如果您不能/不愿意这样做，我会大胆地说，这种工具在目前状态下可能不适合您），但 Zecoxao 在这里提供了一个编译版本：https: //qiwi.gg/file/5j5w6925-byepervisornologger（来源）  
  
  
  
> SpecterDev 演示文稿的幻灯片也可以在https://github.com/PS5Dev/Byepervisor/blob/main/Byepervisor_%20Breaking%20PS5%20Hypervisor%20Security.pdf找到  
  
  
  
  
**重要说明（摘自自述文件）**  
- 目前 Homebrew Enabler (HEN) 仅支持 2.50 FW，稍后将添加对其他固件版本的支持。  
  
- 漏洞利用负载（byepervisor.elf）需要发送两次，一次是在挂起系统之前，另一次是在恢复之后。  
  
- 您必须手动将系统置于休息模式  
  
- 目前，QA 标志漏洞的内核转储不包含虚拟机管理程序的 .data 区域，如果这对您很重要，请在移植后使用跳转表漏洞进行转储或先禁用嵌套分页（这是 TODO）  
  
**如何使用（摘自自述文件）**  
1. 在 webkit 或 BD-J 中运行 UMTX 漏洞链并运行 ELF 加载器  
  
1. 发送 byepervisor.elf  
  
1. 使系统进入休息模式  
  
1. 电力系统恢复  
  
1. 再次发送 byepervisor.elf （如果您使用 John Tornblom 的 ELF 加载器，则 ELF 加载器应在恢复后继续接受有效载荷，否则需要再次运行 UMTX 漏洞利用程序）  
  
**PS5 Byepervisor 漏洞 – 下一步是什么？**  
  
虽然目前 HEN 仅支持 2.50，但很有可能所有固件 2.xx/1.xx 都将在未来几天或几周内获得 HEN 支持（这项工作已经在进行中）。即使对于我们当中那些对 PS5 黑客攻击感兴趣的用户来说，这显然仍然是少数用户，但也希望这将有助于发现更多漏洞，包括更高版本的固件。由于内核转储/解密现在在这些固件上相对容易，PS5 固件反编译将更广泛地发生，这将为该场景带来有趣的发现。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
