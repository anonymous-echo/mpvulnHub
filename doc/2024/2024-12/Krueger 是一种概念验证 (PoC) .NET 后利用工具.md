#  Krueger 是一种概念验证 (PoC) .NET 后利用工具   
 Ots安全   2024-12-30 12:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
Krueger 是一种概念验证 (PoC) .NET 后利用工具，用于远程终止端点检测和响应 (EDR)，这是横向移动程序的一部分。Krueger 通过利用 Windows Defender 应用程序控制 (WDAC) 来完成此任务，WDAC 是 Microsoft 创建的内置应用程序控制实用程序，能够在用户和内核模式级别阻止代码。利用对目标远程设备的管理权限的 Krueger，攻击者可以快速将 WDAC 策略放入磁盘并执行远程重启，从而阻止 EDR 服务在启动时启动。  
  
execute-assemblyKrueger 还可以使用和inlineExecute-Assembly（@anthemtotheego ）等工具从内存中运行。此外，为了防止在从内存执行 Krueger 时需要从磁盘加载 WDAC 策略，Krueger 在编译时插入了 .NET 程序集内的嵌入式 WDAC 策略，该策略可以从内存中读取并在运行时写入目标。  
  
有关此技术的更多信息，请访问我们的博客：https: //beierle.win/2024-12-19-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac7iaOjnpbN5kwE2QHLbJBKToVMdJiaNU6HGfoWv4nwVLpvJzkoI9uA9icdnEfsEXD0K13S7SALh92yw/640?wx_fmt=png&from=appmsg "")  
  
项目地址：  
  
https://github.com/logangoins/Krueger  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
