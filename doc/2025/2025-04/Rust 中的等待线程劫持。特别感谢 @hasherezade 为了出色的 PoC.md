#  Rust 中的等待线程劫持。特别感谢 @hasherezade 为了出色的 PoC   
 Ots安全   2025-04-24 13:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
等待线程劫持技术是一种隐秘的进程注入方法，它会劫持目标进程中的等待线程来执行 Shellcode。它通过操纵线程的返回地址来规避 SuspendThread 或 SetThrea  
dContext 等常见的检测触发器。阅读本文了解更多信息  
https://research.checkpoint.com/2025/waiting-thread-hijacking/。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafpmt78gHtLo9Dia8TjNZWib9tlzEjA1r0RFnq4FCEnGHMXxwiaWpvryTOyUJaAbQLMLcibV9zqLBvlpQ/640?wx_fmt=png&from=appmsg "")  
  
下载 PoC  
  
  
https://download.5mukx.site/#/home?url=https://github.com/Whitecat18/Rust-for-Malware-Development/tree/main/WaitingThreadHijacking  
  
  
编译/运行  
  
```
cargo build --release
```  
  
  
  
```
./target/release/WaitingThreadHijacking.exe<PID>
```  
  
  
  
致谢/参考文献  
  
博客 - https://research.checkpoint.com/2025/waiting-thread-hijacking/  
  
作者：Hasherezade - https://github.com/hasherezade/waiting_thread_hijacking  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
