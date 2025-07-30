#  Pwn2Own 2021 Parallels Desktop VM 逃逸漏洞   
 Ots安全   2024-03-24 12:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
Parallels Desktop 虚拟机管理程序的完整概念验证利用（Pwn2Own 2021 温哥华）。  
  
  
**技术演练视频：**简单错误的高级利用（幻灯片）  
  
https://youtu.be/6UhgLteN-PU  
  
**进一步学习：**管理程序漏洞研究：最新技术（幻灯片）  
  
https://youtu.be/1bjekpgZCgU  
  
几十年来，我的演讲和课程所建立的系统内部结构没有任何变化。  
  
**故事博客**  
  
https://zerodayengineering.com/research/pwn2own-2021-vm-escape.html  
  
  
**笔记**  
  
虚拟机逃逸漏洞通常需要客户操作系统中的内核权限。在此漏洞利用中，我选择将逆向工程工具门协议实现 ( prl_pwn.py) 卸载到 Python 模块，同时保持低级内核代码 ( km) 最少，足以实现攻击接口 - 这是对系统中最小特权原则的认可。软件工程，我们在重要的漏洞利用开发中错过了很多。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacOLK0TatdnJoX9rE4DDXyicm8cO14yPMdTSTWAG0GCIgs29z80CPgnd9V0G8ffEuToGG9hWXWptew/640?wx_fmt=png&from=appmsg "")  
  
发现错误  
  
协议原型代码也经过精心设计，将低级 API 封装到非常简单的高级漏洞利用代码中。  
  
这是我们目前所处的大局：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacOLK0TatdnJoX9rE4DDXyicmNZsRR0tvBdIvz6jd4vrxeRP6gLXDPcwVj5Coc2Q10eicAvOdxhjJcg/640?wx_fmt=png&from=appmsg "")  
  
管理程序攻击面模型  
  
Python 代码通过内核模块导出的 Linux 设备与内核进行交互km。我必须弄清楚的一件事是如何通过接口传递指针，而 Python 本身无法做到这一点。  
  
  
doit.sh只是一个 bash 包装器，它确保盒子处于正确的状态，并将攻击组合在一起。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
