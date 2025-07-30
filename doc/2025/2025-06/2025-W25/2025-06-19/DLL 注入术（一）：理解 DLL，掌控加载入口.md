> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyNTUyNTA5OQ==&mid=2247485540&idx=1&sn=226a92e7b10d6effe9bd3c9c5f8145f1

#  DLL 注入术（一）：理解 DLL，掌控加载入口  
原创 仇辉攻防  仇辉攻防   2025-06-18 14:10  
  
📌   
**免责声明**  
：本系列文章仅供网络安全研究人员在合法授权下学习与研究使用，严禁用于任何非法目的。违者后果自负。  
  
一、什么是DLL？  
  
1、DLL 是 Dynamic Link Library（动态链接库）的缩写，是 Windows 系统中的一种可执行文件格式，扩展名为 .dll。它的本质是一个模块化的程序组件，可以被其他程序调用其中的函数、资源或类库，而不需要把这些代码直接编译进主程序中。   
  
2、DLL 是一组可被多个程序共享调用的函数或资源集合，通常以 .dll 文件形式存在。  
  
3、几乎所有的exe都加载DLL  
  
4、类似linux系统中共享对象文件（Shared Object, .so 文件）  
  
二、DLL分类  
<table><thead><tr><th><section><span leaf="">类型</span></section></th><th><section><span leaf="">示例</span></section></th><th><section><span leaf="">特点</span></section></th></tr><tr><td><strong><span leaf=""><span textstyle="" style="font-weight: normal;">系统级 DLL</span></span></strong></td><td><code><span leaf="">kernel32.dll</span></code><section><span leaf="">, </span><code><span leaf="">user32.dll</span></code><span leaf="">, </span><code><span leaf="">ntdll.dll</span></code></section></td><td><section><span leaf="">Windows 提供的核心 API，所有软件都依赖它们</span></section></td></tr><tr><td><strong><span leaf=""><span textstyle="" style="font-weight: normal;">软件自带 DLL</span></span></strong></td><td><code><span leaf="">photoshopcore.dll</span></code><section><span leaf="">, </span><code><span leaf="">steam_api64.dll</span></code><span leaf="">, </span><code><span leaf="">msword.dll</span></code></section></td><td><section><span leaf="">由应用自身开发，只供其自身或插件使用，功能模块化</span></section></td></tr><tr><td><strong><span leaf=""><span textstyle="" style="font-weight: normal;">第三方库 DLL</span></span></strong></td><td><code><span leaf="">libcrypto.dll</span></code><section><span leaf="">, </span><code><span leaf="">zlib1.dll</span></code><span leaf="">, </span><code><span leaf="">opencv_core.dll</span></code></section></td><td><section><span leaf="">第三方组件打包成 DLL，被多个项目共享调用</span></section></td></tr><tr><td><strong><span leaf=""><span textstyle="" style="font-weight: normal;">自定义 DLL</span></span></strong></td><td><code><span leaf="">payload.dll</span></code><section><span leaf="">, </span><code><span leaf="">backdoor.dll</span></code></section></td><td><section><span leaf="">攻防演练中红队编写用于注入或劫持的 DLL</span></section></td></tr></thead></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJTrZxzibH7apwAMZibXBg7Uj4KRShss6kcPf2y0KA5jCxDoNiawJF3eUJ3FyOibIjiadPflWjkz2pdMEQ/640?wx_fmt=png&from=appmsg "")  
  
三、关于DLL编写  
  
1、攻防实战中99%是“自己写DLL”！  
  
2、DLL 可以用 C/C++、Rust、C#、Go 等语言编写，但需注意 ABI 兼容性。  
  
3、实战中，编写用于注入的自定义DLL，最常用C/C++，写法类似于shellcode加载器。  
  
VS创建新项目→动态链接库DLL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJTrZxzibH7apwAMZibXBg7UjmdO0sE8EKHCPTuFFYYMzy3Koqs0Fc5YbZX4FwVfPeWpEhjVbghuaXQ/640?wx_fmt=png&from=appmsg "")  
  
默认自带两个cpp文件:dllmain.cpp/pch.cpp   
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJTrZxzibH7apwAMZibXBg7UjkBrXLgLkXYvhFC3BLSbOxzYHOdEHLkibnv7sibdv1EfxRkicIJQMic41KQ/640?wx_fmt=png&from=appmsg "")  
  
**4、DLL文件可以反编译成源码吗？**  
  
DLL和EXE本质是一样的，都是PE文件，都是机器码，可以被反编译，能看到汇编代码和部分伪C代码，但很难100%还原成开发者的源码。除非是.NET的DLL，否则只能还原功能逻辑，变量名和结构都变了。   
  
四、常见DLL运行方式  
  
DLL需要被其他程序（比如你写的EXE、目标软件或注入器）加载后才能运行，不能直接双击！  
<table><thead><tr><th><section><span leaf="">方法</span></section></th><th><section><span leaf="">场景</span></section></th><th><section><span leaf="">能力</span></section></th></tr><tr><td><section><span leaf="">写 EXE 调用</span></section></td><td><section><span leaf="">测试 / 开发阶段</span></section></td><td><section><span leaf="">最稳最通用</span></section></td></tr><tr><td><section><span leaf="">插件方式</span></section></td><td><section><span leaf="">Photoshop、游戏插件等</span></section></td><td><section><span leaf="">根据程序加载机制</span></section></td></tr><tr><td><section><span leaf="">DLL 注入</span></section></td><td><section><span leaf="">免杀、内存加载</span></section></td><td><section><span leaf="">高级场景，需权限和技术</span></section></td></tr><tr><td><section><span leaf="">rundll32</span></section></td><td><section><span leaf="">特定格式导出函数</span></section></td><td><section><span leaf="">限制多，已被安全工具关注</span></section></td></tr></thead></table>  
示例：exe调用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJTrZxzibH7apwAMZibXBg7Uj35WY2dAFULKbwgClNnX1tpNp5gmrmItdSriaFFFux4UETAWT9FScwfg/640?wx_fmt=png&from=appmsg "")  
  
五、DLL注入的意义和价值  
  
DLL注入是指将一个DLL动态链接库植入到目标进程的地址空间中，使其加载并执行你指定的代码。它本质上是一种进程注入技术，是一种攻击手段，用于实现绕过安全软件检测、权限提升、持久化等目的。   
<table><thead><tr><th><section><span leaf="">意义/价值点</span></section></th><th><section><span leaf="">具体说明</span></section></th><th><section><span leaf="">典型应用场景</span></section></th></tr></thead><tbody><tr><td><section><span leaf="">执行任意代码</span></section></td><td><section><span leaf="">可以在目标进程中运行攻击者自定义代码，包括shellcode、反射DLL等</span></section></td><td><section><span leaf="">自定义软件载荷执行</span></section></td></tr><tr><td><section><span leaf="">持久化驻留</span></section></td><td><section><span leaf="">通过注入系统关键进程，实现进程重启、系统重启后的持续驻留</span></section></td><td><section><span leaf="">持久化后门</span></section></td></tr><tr><td><section><span leaf="">绕过安全防护</span></section></td><td><section><span leaf="">利用白名单进程或系统进程执行，绕过杀软/EDR行为检测</span></section></td><td><section><span leaf="">免杀、攻防对抗</span></section></td></tr><tr><td><section><span leaf="">权限提升</span></section></td><td><section><span leaf="">注入高权限进程，获得更高的系统权限</span></section></td><td><section><span leaf="">SYSTEM提权、服务提权</span></section></td></tr><tr><td><section><span leaf="">数据窃取与操控</span></section></td><td><section><span leaf="">读取或篡改目标进程中的敏感数据、劫持输入输出</span></section></td><td><section><span leaf="">密码抓取、流量劫持</span></section></td></tr><tr><td><section><span leaf="">API劫持/功能增强</span></section></td><td><section><span leaf="">Hook目标进程API，实现API劫持、流量转发、功能扩展</span></section></td><td><section><span leaf="">流量中转、监控、注入马</span></section></td></tr><tr><td><section><span leaf="">对抗沙箱与分析环境</span></section></td><td><section><span leaf="">注入特定进程，隐藏自身行为，逃避动态分析与沙箱监测</span></section></td><td><section><span leaf="">反分析、反溯源</span></section></td></tr><tr><td><section><span leaf="">便于横向移动与渗透</span></section></td><td><section><span leaf="">注入远程目标进程，实现横向移动与进一步内网渗透</span></section></td><td><section><span leaf="">横向渗透、内网突破</span></section></td></tr><tr><td><section><span leaf="">无需文件落地更隐蔽</span></section></td><td><section><span leaf="">通过反射DLL注入等技术，仅在内存中运行，避免生成可疑文件</span></section></td><td><section><span leaf="">文件less攻击、免杀攻击</span></section></td></tr></tbody></table>  
六、主流DLL注入方式  
  
在实际攻防实战中，DLL 注入技术并非单一形式，而是由多种手段构成的体系，常见方式包括但不限于：  
  
1、远程线程注入（Remote Thread Injection）  
  
通过远程创建线程，调用 LoadLibrary 等 API 实现目标进程加载指定 DLL。  
  
2、线程劫持（Thread Hijacking）  
  
暂停目标线程，修改其执行上下文并重定向至注入逻辑，再恢复执行。  
  
3、反射式 DLL 注入（Reflective DLL Injection）  
  
将 DLL 加载器与 DLL 融为一体，实现不依赖 LoadLibrary、不落地的内存加载方式。推荐阅读深入分析文章：  

```
https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html
```

  
4、APC 注入（Asynchronous Procedure Call Injection）  
  
向目标线程排队插入回调函数，在系统切换执行时触发自定义 DLL 加载或 Shellcode 执行。  
  
5、DLL 导入表注入  
  
修改目标 PE 文件，使其在加载时自动引入并加载指定自定义 DLL。  
  
6、DLL 劫持（DLL Hijacking）  
  
如利用 DLL 搜索顺序的优先级，放置伪造 DLL 于目标应用加载路径中，诱导其加载并执行自定义代码。  
  
七、总结  
  
DLL 注入是 Windows 平台上功能强大、形式多样的进程干预技术，在红队演练、自定义样本研究、动态检测绕过等领域具有广泛应用价值。掌握基础逻辑与结构，是构建对抗策略的重要前提。  
  
[#DLL注入]()  
 [#动态链接库]()  
 [#远程线程]()  
 [#反射加载]()  
 [#红队演练]()  
  
  
