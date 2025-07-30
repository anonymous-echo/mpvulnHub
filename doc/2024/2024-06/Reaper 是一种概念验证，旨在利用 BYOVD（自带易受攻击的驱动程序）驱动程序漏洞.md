#  Reaper 是一种概念验证，旨在利用 BYOVD（自带易受攻击的驱动程序）驱动程序漏洞   
 Ots安全   2024-06-02 12:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckM9m1wmAYf5Mj0fL6mgibM2C8wDZEWZyBlXRg338X74g6YNChFWWibdFQ/640?wx_fmt=png&from=appmsg "")  
  
Reaper 是一种概念验证，旨在利用 BYOVD（自带易受攻击的驱动程序）驱动程序漏洞。这种恶意技术涉及将合法的易受攻击的驱动程序插入目标系统，从而使攻击者能够利用该驱动程序执行恶意操作。  
  
Reaper 专门设计用于利用 2.8.0.0 版本中 kprocesshacker.sys 驱动程序的漏洞，利用其弱点获取对目标系统的特权访问和控制。  
  
注意：Reaper 不会终止 Windows Defender 进程，因为它具有保护功能，Reaper 是一个简单的概念证明。  
  
特征  
- 终止进程  
  
- 暂停进程  
  
帮助  
```
      ____
     / __ \___  ____ _____  ___  _____
    / /_/ / _ \/ __ `/ __ \/ _ \/ ___/
   / _, _/  __/ /_/ / /_/ /  __/ /
  /_/ |_|\___/\__,_/ .___/\___/_/
                  /_/

          [Coded by MrEmpy]
               [v1.0]

Usage: C:\Windows\Temp\Reaper.exe [OPTIONS] [VALUES]
    Options:
      sp,                   suspend process
      kp,                   kill process

    Values:
      PROCESSID             process id to suspend/kill

    Examples:
      Reaper.exe sp 1337
      Reaper.exe kp 1337
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxcksC8qU4TMtGYmicgCkBM65wOxW4f7zv21emb5Tf0EichL3YFmvxzqKJzw/640?wx_fmt=png&from=appmsg "")  
  
安装  
  
您可以直接从源代码编译它，也可以下载已编译的版本。您需要 Visual Studio 2022 才能进行编译。  
  
注意：可执行文件和驱动程序必须位于同一目录中。  
```
https://github.com/MrEmpy/Reaper
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
