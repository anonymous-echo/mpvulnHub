#  Win32k的内部结构以及可能出现的漏洞   
xiaohui  嘶吼专业版   2023-06-26 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
2022年1月下旬，一个新的微软Windows特权升级漏洞(CVE-2022-21882)被发现，经分析，这是Win32k用户模式回调函数xxxClientAllocWindowClassExtraBytes中的一个漏洞。早在2021年，微软报告了一个非常类似的漏洞（CVE-2021-1732），并进行了修复。不过分析发现，CVE-2021-1732的补丁不足以阻止CVE-2022-21882。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    Win32k背景信息  
  
在Windows NT 4.0之前，Microsoft在名为Client-Server Runtime SubSystem（CSRSS.exe）的用户模式进程中实现了Win32 API的GUI功能。然而，用户模式和内核模式之间的上下文切换计算成本高昂，并且需要大量内存消耗。  
  
为了消除这些问题并提高整个Windows操作系统的速度，微软决定将Windows子系统(窗口管理器、GDI和图形驱动程序)转移到内核中。这种转变始于1996年的Windows NT 4.0。  
  
这一变化是通过一个名为Win32k.sys的内核模式驱动程序实现的，现在被称为内核模式Windows子系统，Windows子系统的用户模式组件仍然驻留在CSRSS中。  
  
尽管迁移到内核大大减少了所需的消耗，但微软不得不采用一些老办法，例如在客户端地址空间的用户模式部分缓存管理数据结构。事实上，为了进一步避免上下文切换，一些管理结构在历史上仅以用户模式存储。然而，为了消除内核地址泄漏，微软已经开始实现使用这些结构的用户模式和内核模式副本的方法，以防止内核地址存储在用户模式结构中。  
  
此外，由于Win32k需要一种方法来访问这些用户模式结构，并支持一些现有的用户模式功能，如窗口挂钩，因此实现了用户模式回调来促进这些任务。  
  
用户模式回调允许Win32k回调到用户模式，并执行诸如调用应用程序定义的挂钩、提供事件通知以及将数据复制到用户模式或从用户模式复制数据等任务。这意味着微软在实现用户模式回调和保持数据完整性方面面临着巨大安全挑战。  
  
研究发现，在进行用户模式回调之前，许多对象没有被正确锁定，这使得用户模式代码可以在用户模式回调期间销毁这些对象，从而导致释放后使用（UAF）漏洞。尽管微软已经解决了许多问题，但用户模式回调在今天仍然被滥用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    Windows GUI API  
  
在讨论Win32k内部结构之前，我们将简要介绍一个使用Win32 API创建和销毁窗口的简单C程序。这将使我们开始了解图形窗口是如何以编程方式创建和操作的。它还允许我们检查定义每个窗口及其菜单的底层结构。  
  
如下图所示，示例程序首先定义一个窗口类。进程必须先注册一个窗口类，然后才能创建WNDCLASSEX结构中定义的窗口类型。首先，窗口类对象被声明为WNDCLASSEX wcx ={}，然后填充窗口类结构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEEWOG5EPLdGqWiaCW9kH6s4QXjL0crhACcj3mMJMogzg6MkxiaVuflCzQ/640?wx_fmt=png "")  
  
定义窗口类  
  
窗口类的元素如下所示：  
  
cbSize：此结构的大小（以字节为单位），将此成员设置为sizeof（WNDCLASSEX）。  
  
style：窗口类样式，它可以是类样式的任意组合。  
  
lpfnWndProc：指向处理类中发送到窗口的所有消息并定义窗口行为的函数的指针。通常，默认窗口过程至少用于某些消息。但是，自定义窗口过程通常用于创建独特的窗口体验。  
  
cbClsExtra：在窗口类结构之后要分配的额外字节数，系统将字节初始化为零。  
  
cbWndExtra：在窗口实例之后要分配的额外字节数。系统将字节初始化为零。不要将其与cbClsExtra混淆，后者对该窗口类的所有窗口都是通用的。该值通常为0，但如果不是0，则内存通常用于存储跨窗口的非恒定数据；  
  
hInstance：包含类的窗口过程的实例的句柄。标识注册该类的应用程序或.DLL。在此处将hinstance参数分配给WinMain。  
  
hIcon：类的句柄，LoadIcon(NULL, IDI_APPLICATION)加载默认图标。  
  
hCursor：类光标的句柄，LoadCursor(NULL, IDC_ARROW)加载默认光标。  
  
hbrBackground：类背景笔刷的句柄，GetStockObject (WHITE_BRUSH)返回一个白色笔刷的句柄。返回值必须强制转换，因为GetStockObject返回的是泛型对象。  
  
lpszMenuName：指向一个以null结尾的字符串的指针，该字符串指定类菜单的资源名称，该名称显示在资源文件中。如果不需要菜单栏，则此字段可以为NULL。  
  
lpszClassName：用于标识此窗口类结构的类名。  
  
hIconSm：小类图标的句柄。  
  
既然窗口类的属性已经定义好了，我们需要使用RegisterClassEx()在应用程序中注册，如下图所示。如果失败，RegisterClassEX()返回0。否则，它返回一个惟一标识所注册类的类原子。注册窗口类将定义该类及其关联的结构成员到Windows。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEYA1mP4RuFoHn1mSlpOjb9aNicJKNDPwj9ic9z58Qj8RBIy4phgZsX5tA/640?wx_fmt=png "")  
  
正在注册的窗口类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    创建窗口  
  
一旦注册了窗口，我们就可以通过调用CreateWindowExA()来创建窗口类的实例，如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEfOZjQQf6etjWciaOu9daPJP0EwPTKFEBw0IicKUX9QZXymd72cQyvibaw/640?wx_fmt=png "")  
  
创建窗口的代码  
  
CreateWindowEX的参数如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEsU89VcnVicq0s3BVsSvEHTftpib7Rc7CMCH7HdHOia6xT8ib1Zst1cSV9A/640?wx_fmt=png "")  
  
CreateWindowExA函数原型  
  
下面列出了每个参数的简要说明：  
  
dwExStyle：正在创建的窗口的扩展窗口样式，在这种情况下，我们将其设置为WS_EX_LEFT的默认窗口常数，这为窗口提供了通用的左对齐属性。  
  
lpClassName：类名，取自调用RegisterClassEX时声明的wcx.lpszClassName。  
  
lpWindowName：窗口名称。  
  
dwStyle：所创建窗口的样式，在本例中，我们使用WS_OVERLAPPEDWINDOW，它创建了一个顶层(父)窗口。  
  
X：窗口的初始水平位置。对于重叠窗口或弹出窗口，x参数是以屏幕坐标表示的窗口左上角的初始x坐标。对于子窗口，x是窗口左上角相对于父窗口客户区左上角的x坐标。如果x设置为CW_USEDEFAULT，系统将选择窗口左上角的默认位置，并忽略y参数。  
  
Y：与上述相同，但适用于Y坐标。  
  
nWidth：窗口的宽度。  
  
nHeight：窗口的高度。  
  
hWndParent：正在创建的窗口的父窗口或所有者窗口的句柄。  
  
hMenu：菜单的句柄，或指定子窗口标识符，具体取决于窗口样式。对于重叠或弹出窗口，hMenu标识要与该窗口一起使用的菜单；如果要使用类菜单，则它可以为NULL。  
  
hInstance：要与窗口关联的模块实例的句柄。  
  
lpParam：传递给窗口的窗口过程的额外信息。如果没有要传输的额外信息，则传递NULL。  
  
一旦调用CreateWindowEx()创建了窗口，就在内部创建了窗口，也就是说，已经分配了内存并填充了其结构，但没有显示。为了显示窗口，我们调用ShowWindow()函数。  
  
ShowWindow()获取从CreateWindowEXW()调用获得的句柄和从WinMain()获得的状态变量nCmdShow。nCmdShow变量确定窗口在屏幕上的显示方式，例如，它是正常的、最大化的还是最小化的。  
  
ShowWindow()仅控制应用程序窗口的显示方式。这包括诸如标题栏、菜单栏、窗口菜单、最小化按钮等元素。客户端区域是应用程序显示数据的区域，例如在文本编辑器中输入文本的区域。客户端区域是通过调用UpdateWindow()函数绘制的。  
  
如果将WS_VISIBLE窗口样式指定为CreateWindowEXW()函数的dwStyle参数，则不需要调用ShowWindow()函数，Windows会为用户调用它。同样，如果不指定WS_VISIBLE样式，也不调用ShowWindow()函数，窗口将对视图保持隐藏状态。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    窗口消息和窗口过程  
  
调用UpdateWindow()之后，窗口就完全可见并可以使用了。在为Windows编写更简单的控制台应用程序时，该应用程序会根据控制台中的用户输入进行显式函数调用。  
  
在窗口应用程序中，用户通常可以通过输入文本、点击按钮和菜单或仅仅通过移动鼠标来与应用程序交互。这些操作中的每一个都有自己的特殊功能。为了实现这一点，微软实现了一个事件驱动系统，该系统将用户输入（如键盘、鼠标或触摸）的消息中继到每个应用程序中的各个窗口。这些消息由每个窗口内的函数处理，称为窗口过程。  
  
Windows为每个线程维护一个消息队列，该队列将中继任何影响窗口状态的用户输入事件。然后，Windows将这些事件转换为消息，并将它们放入消息队列。应用程序通过执行类似于下面中的代码来处理这些消息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEe3NUkJF1icATNb15zmVXx98NmJr8pfUyfZRZHdORElC9H5eiaf0ribK1A/640?wx_fmt=png "")  
  
窗口消息队列循环  
  
GetMessage()函数用于从消息队列中检索下一条消息。MSG参数是一个结构，它包含所分配的窗口过程正确处理消息所需的消息信息。  
  
MSG结构的成员中包括其窗口过程接收消息的窗口的句柄（hwnd），以及包含标识符的消息，该标识符确定对窗口过程的请求内容。例如，如果消息包含一个WM_PAINT消息，它会告诉窗口过程窗口的工作区已更改，必须重新绘制。  
  
TranslateMessage()函数可将虚拟密钥消息转换为字符消息，但这对于当前的讨论并不重要。DispatchMessage()将消息发送到由msg结构中的窗口句柄标识的窗口，由该窗口类定义的窗口过程处理。  
  
到目前为止，通过执行以下操作，示例代码已经完成了定义窗口类：  
  
注册窗口；  
  
创建由窗口类定义的窗口实例；  
  
在屏幕上显示窗口；  
  
进入消息循环；  
  
窗口过程决定了显示什么以及如何响应用户输入。Windows提供了一个默认的窗口过程来处理应用程序未处理的任何窗口消息，并且它为任何窗口正常运行提供了最基本的功能。  
  
窗口过程是定义窗口的所有功能的地方，且它们可能会非常复杂。不过，我们目前只对Microsoft的默认窗口过程DefWindowProc()感兴趣。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    窗口结构  
  
如上所述，Windows现在通过Win32k.sys在内核中管理GUI对象，如菜单、窗口等。当创建窗口对象时，会在称为tagWND的数据结构中跟踪其属性。  
  
不过，微软删除了许多Win32k调试符号，这使得获得这些结构的透明度变得更加困难。基于一些逆向工程，下图显示了Windows 10版本21H1中的结构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEARPRaicKdG447LPFnavjVfBicwYv2gKrlOGjkPjibr59UcZQCHKwwcfeA/640?wx_fmt=png "")  
  
标记WND父结构  
  
在调用xxxCreateWindowEx期间查看HMAllocObject，其中发生了结构的分配，我们可以确认该结构的大小为0x150（336）字节。  
  
在调用HMAllocObject之前的WinDbg输出如下图所示。你可以看到第四个参数，它表示分配大小，存储在r9寄存器中，等于0x150。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEvvXrPFMBnUCvYCFziaajDUPsDEvSGX4tAyxWWlJKRh9OVWQlEt78n5A/640?wx_fmt=png "")  
  
WinDbg输出显示HMAllocObject的输入参数  
  
tagWND结构在线程环境块(TEB)的Win32ClientInfo条目中被引用，为了防止内核模式地址泄露，它已被删除了。  
  
内核tagWND结构中的第一个条目是窗口句柄。在内核中，每个窗口都有一个与之相关联的代表性tagWND结构。  
  
在分析CVE-2022-21882期间，此结构将很重要，但现在，我们将重点关注偏移量0x28。我将其标记为*pWND，因为微软不再提供符号。此外，微软不再为这个结构提供名称，在过去它被称为state或WW。据微软称，这些名称已被弃用，不再在内部使用。要知道它是tagWND数据的用户模式版本，不包括内核地址，且它的结构与其父tagWND结构不同。这个子结构既存在于内核中，也存在于用户模式中。这就是Windows管理数据的方式，以避免泄露内核地址，因为任何用户模式应用程序都将使用位于用户模式桌面堆上的tagWND结构的副本，因此将无法看到任何内核模式地址。  
  
接下来继续将子结构称为tagWND结构，不过，它的结构与上面的父tagWND结构不同，但在其他研究中仍然通常称为tagWND。  
  
子标签WND结构如下图所示，通过逆向工程确定了元素及其偏移量。  
  
在关于创建窗口的部分中讨论的WNDCLASSEX结构的许多元素可以在tagWND结构中看到。因此，很明显，当创建窗口时，通过WNDCLASSEX结构分配的属性被传递给内核并存储在tagWND结构中。然后将属性传播到内核和用户模式桌面堆中的用户副本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEbo3n7Ir2RInvdC9ORLzsrMwMHIW7sicywB0of2OGW9sdE7VpaAzwRnw/640?wx_fmt=png "")  
  
tagWND结构的用户模式安全副本  
  
下面两个图分别显示了父tagWND和用户模式安全tagWND结构的内核副本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAE7sxLQiblj9XiaXBFicI2qRQ3T5ynl2ClEK0seWlb9yG9AKkYgibRiaYdPFQ/640?wx_fmt=png "")  
  
父tagWND结构的内存转储  
  
上图是父tagWND，你可以看到句柄(偏移量0x00)与下面的复制tagWND的句柄相同。你还可以看到父结构具有内核地址，而用户模式安全副本仅具有用户模式地址。最后，注意父tagWND+0x28是指向子tagWND副本地址的指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEB5cnrQhwduQfqELSCgwFeH40GhwZJvNc1MicK8K7w5HicxjlvmXq7BlQ/640?wx_fmt=png "")  
  
子tagWND结构的内存转储  
  
有几种方法可以泄露窗口对象的内核模式地址，Win32k中存储由用户模式代码设置的属性的所有对象（例如，窗口、菜单）通常被称为用户对象。  
  
所有用户对象（tagWND结构的用户模式副本是众多对象之一）都在通常称为UserHandleTable的每个会话句柄表中进行索引。尽管tagWND结构并不总是用户模式安全的副本，并且曾经包含内核地址。  
  
过去，可以通过UserHandleTable用User32.dll中名为gSharedInfo的可导出结构来定位tagWND对象。从Windows 10版本1703起，这个方法将不再有用。由于微软不断努力消除内核地址泄露，他们已经从UserHandleTable中删除了桌面堆中对象的内核地址。  
  
窗口管理器使用位于User32.dll中的非导出函数HMValidateHandle验证句柄。在Windows 10版本1803之前，窗口管理器返回内核模式指针，指向要验证其句柄的对象，该指针通常用于泄露此地址。尽管内核地址泄漏已经被修复，但当我们稍后查看这两个漏洞时，这种方法将非常重要。  
  
从Windows 10版本1703开始，任何由SetWindowLong写入的字节都不再写入内核。这个修复有效地消除了这种创建任意写入的技术。  
  
确定感兴趣的对象在内核中的位置，以绕过内核地址空间布局随机化（KASLR）。因此，非常需要知道桌面堆的位置。从Windows 10 1607版本开始，微软就开始添加缓解措施，试图阻止漏洞编写者在内核中定位桌面堆及其相关对象。这些缓解措施包括从UserHandleTable中删除内核地址，如上所述，以及在每个进程的线程环境块(TEB)中的Win32ClientInfo结构中删除对桌面堆的内核指针引用。此外，HMValidateHandle现在为传递给它的任何对象句柄返回用户模式（相对于内核模式）指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    用户模式回调  
  
由于windows子系统主要位于windows内核中，而windows本身在用户模式下运行，因此Win32k必须频繁地从内核调用到用户模式。用户模式回调提供了一种机制来实现诸如应用程序定义的挂钩、事件通知以及从用户模式向内核复制/从内核复制数据等项目。  
  
当进行用户模式回调时，Win32k调用KeUserModeCallback，并使用它想要调用的用户模式函数的关联ApiNumber。ApiNumber是位于USER32 .dll (USER32!apfnDispatch)中的函数表的索引。在每个进程的User32.dll初始化期间，该表的地址被复制到进程环境块(PEB) (PEB. kernelcallbacktable)。  
  
在即将进行的漏洞分析中，我们将展示如何通过KernelCallback表钩住用户模式回调，并展示该表在WinDbg中的样子。KeUserModeCallback的函数原型及其相关参数如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAE66FS7parYJumRSWZMzm7xYLTp2scbPKpPHX3Cg5tEeDKUlCEkicc3zQ/640?wx_fmt=png "")  
  
KeUserModeCallback函数原型  
  
用户模式回调输入参数通过InputBuffer传递，而回调函数的输出在OutputBuffer中返回。在调用系统调用时，ntdll!KiSystemService或ntdll!KiFastCallEntry在内核线程堆栈上存储一个trap帧(TRAP_FRAME)，以保存当前线程上下文，并在返回到用户模式时启用寄存器恢复。  
  
为了在用户模式回调中转换回用户模式，KeUserModeCallback首先使用线程对象持有的trap帧信息将InputBuffer复制到用户模式堆栈。然后创建一个新的trap帧，EIP设置为ntdll!KiUserCallbackDispatcher，替换线程对象的TrapFrame指针，最后调用ntdll!KiServiceExit将执行返回给用户模式回调调度程序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAErwxFFmF884rJMby4TTfvhD0GYEtNzOu2N3YkZVI2fYYyFKKQFMPfsQ/640?wx_fmt=png "")  
  
KiUserCallbackDispatcher函数原型  
  
一旦用户模式回调完成，就会调用NtCallbackReturn以恢复内核中的执行。此函数将回调的结果复制回原始内核堆栈，并恢复保存在kernel_stack_CONTROL结构中的trap帧（PreviousTrapFrame）和内核堆栈。在跳转到它先前停止的位置之前(在ntdll!KiCallUserMode中)，内核回调堆栈被删除。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEYtIV3AaTqZg3zeCByB165AsApQLiauXW8XT4utR1kluAElrnoZiaVzfA/640?wx_fmt=png "")  
  
函数原型  
  
如果Win32k在调用用户模式回调时没有释放资源，并且该用户模式回调允许应用程序冻结GUI子系统，则Win32k将无法在GUI子系统被冻结时执行其他任务。因此，Win32k总是在调用用户模式回调时释放资源。在从用户模式回调返回时，Win32k必须确保引用的对象仍然处于不受信任的状态。在未执行适当检查或对象锁定的情况下对此类对象进行操作可能也确实会造成安全漏洞。事实上，研究人员确定了这些类型漏洞的多个实例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEgMANngDfJKAGB1fwe1CIOpXFexBxrQpQwruq7ljUGgdgwKicOAVVibnA/640?wx_fmt=png "")  
      

    总结  
  
本文介绍了如何使用Win32 API创建GUI对象，如窗口和菜单，还介绍了用于管理这些对象的用户模式和内核模式数据结构。  
  
参考及来源：https://unit42.paloaltonetworks.com/win32k-analysis-part-1/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28WpjliaE92LONVq2rJD3FAEwZ9r3kVibv3OqnKaamJq53X1vsk6Le62YesMV7XkWwHKyd9B5MI0IKA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
