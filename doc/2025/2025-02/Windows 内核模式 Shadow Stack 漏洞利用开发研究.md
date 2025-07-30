#  Windows 内核模式 Shadow Stack 漏洞利用开发研究   
Connor McGarr  securitainment   2025-02-26 11:49  
  
> 【翻译】Exploit Development Investigating Kernel Mode Shadow Stacks on Windows  
  
## 简介  
  
不久前我在加利福尼亚的 SANS HackFest 2024 上做了  
一个演讲  
。我的演讲简要介绍了 Windows 上一些基于虚拟机监控程序的安全功能 - 特别是围绕通过 Virtualization-Based Security (VBS) 实现的缓解措施。此外，  
大约一年前  
我注意到"内核模式硬件强制堆栈保护"是 Windows 安全中心 UI 中可用的功能 (在此之前，启用此功能必须通过未记录的注册表项完成)。这个 UI 开关实际上是 Intel CET Shadow-Stack 功能在内核模式堆栈上的用户友好名称。  
> Intel CET 技术上指的是多个功能，包括间接分支跟踪 (IBT) 和 Shadow-Stack。Windows 不实现 IBT(而是利用现有的 Control Flow Guard 功能)。因此，本博文中提到的 Intel CET 实际上特指 shadow stack 功能。  
  
  
由于这个功能终于可以通过文档化的方式启用 (加上网上关于 Windows 如何实际实现内核模式 CET 的信息并不多),我认为值得在 SANS HackFest 的演讲中包含这部分内容。  
  
在准备演讲幻灯片时，由于演讲范围包括多个缓解措施以及一些关于虚拟机监控程序内部的内容，我没有花太多时间深入研究该功能的所有细节。这主要是因为这需要对 Secure Kernel 进行一些逆向工程。到目前为止，在 Secure Kernel 中进行动态分析不仅未记录且不受支持，而且也相当困难 (至少对我这样的人来说是这样!)。  
  
然而，天意如此，就在我演讲结束后，我的朋友   
Alan Sguigna  
 给我发来了一份   
SourcePoint debugger  
 - 它能够调试 Secure Kernel(以及更多功能!)。考虑到 KCET(内核模式 Intel CET) 已经在我的脑海中，因为我刚刚做了一个包含它的演讲，我认为这是一个很好的机会来写一篇关于我喜欢的东西的博客 - 漏洞利用缓解措施和 Windows 内部机制！本博文将分为两个主要部分：  
1. "NT (ntoskrnl.exe  
) 视角"(例如，检查 NT 如何启动内核模式 shadow stack 的创建)  
  
1. "Secure Kernel 视角"(例如，我们将展示 NT 如何 (以及为什么) 依赖 Secure Kernel 来通过使用 SourcePoint 主动调试 Secure Kernel 来正确促进内核模式 shadow stacks!)  
  
本博文中的"内部机制"将_不_围绕我的好朋友 Alex 和 Yarden 在  
这里  
博客中提到的那些内容 (比如展示指令集的添加、CPU 规范的变化等)。我希望在这篇博文中涉及的是 (尽我所能，我希望!) 关于 Windows 特定实现内核模式 Intel CET 的细节、为支持 shadow stacks 所做的更改、我的逆向工程过程、堆栈创建代码路径中不同情况的细微差别，以及 (我认为最有趣的)NT 如何依赖 Secure Kernel 来维护内核模式 shadow stacks 的完整性。  
  
我 (虽然我知道我不配) 有时会被问到关于逆向工程的方法论。我认为这是一个很好的机会来为那 1-2 个真正关心的人展示一些这方面的内容！像往常一样 - 我不是专家，我只是在谈论我觉得有趣的与漏洞利用和 Windows 内部机制相关的事情。欢迎任何评论、纠正和建议 :)  
。让我们开始吧！  
## tl;dr CET、线程和堆栈  
  
简单介绍一下本博文的主要主题 - Intel CET 包含一个称为 Shadow-Stack 的功能。该功能负责缓解基于   
ROP  
 的攻击。ROP 允许攻击者 (可以控制与正在/将要执行的线程相关的堆栈) 伪造一系列在执行过程中原本不存在的返回地址。由于 ret  
 会将堆栈指针加载到指令指针中，并且考虑到攻击者可以控制堆栈的内容 - 这允许攻击者通过_重用_应用程序中存在的现有代码 (我们在 .text  
 段或其他可执行代码位置中找到的一系列伪造的返回地址) 来控制指令指针的内容。攻击者经常使用 ROP 的原因是因为内存损坏 (一般来说) 会导致内存的_损坏_。损坏内存意味着你可以写入该内存 - 但随着数据执行保护 (DEP) 和任意代码保护 (ACG) 的出现，可写的内存区域 (如堆栈) 是_不_可执行的。这意味着攻击者需要_重用_应用程序中存在的现有代码，而不是像"过去"那样直接写入他们自己的 shellcode。Shadow-Stack 功能通过维护一个受保护的"shadow stack"来工作，该堆栈包含基于正常执行的堆栈_应该_是什么样子的不可变副本。每当发生 ret  
 指令时，会在"传统"堆栈 (攻击者可以控制) 和 shadow stack(攻击者无法控制，因为它受硬件或更高安全边界保护) 之间进行比较。如果传统堆栈的返回地址 (包含 ret  
 指令的地址) 与 shadow stack 不匹配，我们可以推断有人损坏了堆栈，这可能表明存在基于 ROP 的攻击。由于堆栈损坏可能导致代码执行 - CET 强制进程死亡或系统崩溃 (在 KCET 的情况下)。  
  
有了这个基本的理解，我首先想深入探讨一个大多数人可能熟悉，但可能不是_每个_读者都熟悉的细微差别。正如你可能在计算机科学 101 中学到的 - 线程负责执行代码。在执行过程中，特定线程需要存储它可能在短期内需要的信息 (变量、函数参数以及返回地址)。线程将这些信息存储在_堆栈_上。有一个专门的内存区域与"堆栈"相关联，每个线程都被分配了该区域的一部分，从而产生每个线程的堆栈。所有这些都是说，当我们提到"堆栈"时，我们实际上指的是"每个线程的堆栈"。  
  
考虑到我们在这篇博文中讨论的是_内核模式_ Intel CET - 我们的思维会立即跳转到思考_内核模式_堆栈的保护。由于用户模式线程有用户模式堆栈，内核模式线程有内核模式堆栈是很合理的 - 这是非常正确的！然而，我想强调的主要事情是内核模式堆栈不  
仅限于内核模式线程。用户模式线程_也_有一个相关的内核模式堆栈。Windows 上线程的实现将用户模式线程视为具有两个堆栈。一个用户模式堆栈_和_一个内核模式堆栈。这是因为用户模式线程可能会在内核模式下实际执行代码。一个很好的例子是_系统调用_。系统调用通常在发出它的特定线程的_上下文_中发出。系统调用将导致 CPU 进行转换以开始在 CPL 为 0(内核模式) 的情况下执行代码。如果用户模式线程调用系统调用，并且系统调用需要执行内核模式代码 - 让内核模式在_用户模式_堆栈上存储_内核模式_信息 (攻击者可以直接读取) 将是一个巨大的安全漏洞。我们可以在下面看到 svchost.exe  
 即将进行系统调用，并且执行在用户模式 (ntdll!NtAllocateVirtualMemory  
)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnkbpialFM1KMicGP5Ej3XCbEUMqMQ1IPXEQvhcacQDB0UlqtmUnNbRC2Q/640?wx_fmt=png&from=appmsg "")  
  
在执行 ntdll!NtAllocateVirtualMemory  
 中的 syscall  
 指令后，执行转移到内核。如果我们看下面的图像，当执行进入内核时，我们可以看到这是之前在用户模式下执行的完全相同的线程/进程/等，但 RSP(堆栈指针) 现在包含一个_内核模式_地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn53xmPHYGDLk1AtDllbOib1LgicCxRVHzhqarGibFMqDGia7DMOiaeaN87bg/640?wx_fmt=png&from=appmsg "")  
  
这对某些人来说可能看起来很基础 - 但我的重点是为了不熟悉的读者理解。虽然内核模式 Intel CET 当然是一个内核模式漏洞利用缓解措施，但它不仅仅特定于系统线程，因为用户模式线程将有一个相关的内核模式堆栈。当启用该功能时，这些相关的内核堆栈将受到 KCET 的保护。这是为了在稍后看到用户模式线程接收 KCET 保护的场景时消除混淆。  
## 线程和堆栈创建 (NT)  
  
线程堆栈的创建有各种场景和条件，其中一些场景需要更多"特殊"处理 (如 DPC 的堆栈、每个处理器的 ISR 堆栈等)。我想在这篇博文中特别关注的是介绍与新用户模式线程相关的内核模式堆栈的 KCET shadow stack 创建是如何工作的。对于普通系统线程来说，这个过程相对类似。  
  
当一个给定的线程被创建时，这会导致内核管理的 KTHREAD  
 对象被分配和初始化。我们的分析从 nt!PspAllocateThread  
 开始，就在线程对象本身被创建之后 (nt!ObCreateObjectEx  
 使用 nt!PsThreadType  
 对象类型) 但尚未完全初始化。内核模式堆栈尚未配置。堆栈的配置作为线程初始化逻辑的一部分发生在 nt!KeInitThread  
 中，该函数由 nt!PspAllocateThread  
 调用。请注意，initThreadArgs  
 不是一个记录在案的结构，我尽我所能逆向工程了参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnDdicr7KmURCPiaNSWEeOK1JgMTLiaFMVia48IMYNoy0v8FsDLYzXYJKXuA/640?wx_fmt=png&from=appmsg "")  
  
在上面的图像中，我们可以看到对 nt!KeInitThread  
 的调用中，系统提供的线程启动地址被设置为 nt!PspUserThreadStart  
。这将执行线程的更多初始化。根据正在创建的线程的_类型_，这个函数 (和适用的参数) 可以改变。例如，系统线程会调用 nt!PspSystemThreadStartup  
,而_安全线程_会调用 nt!PspSecureThreadStartup  
(这超出了本博文的范围，但如果我有时间的话，也许我会在未来的文章中讨论!)。还要注意 nt!KeInitThread  
 的第一个参数，即 Ethread->Tcb  
。如果你不熟悉，ETHREAD  
 对象中的前几个字节实际上是相应的 KTHREAD  
 对象。可以通过 ETHREAD  
 对象的 Tcb  
 成员访问这个 KTHREAD  
 对象。KTHREAD  
 对象是线程的_内核_版本，ETHREAD  
 对象是_执行者_版本。  
  
继续，一旦执行到达 nt!KeInitThread  
,线程初始化中最先发生的事情之一就是线程的内核堆栈 (即使我们正在处理用户模式线程)。这是通过调用 nt!MmCreateKernelStack  
 完成的。这个函数可以配置为在内核模式下创建_多种_类型的堆栈。我们不会研究对 nt!MmCreateKernelStack  
 的第一个明显调用，而是将注意力转移到如何调用 nt!KiCreateKernelShadowStack  
,正如我们在下面可以看到的，这显然是 shadow stack "乐趣"将会发生的地方 (并且也会调用 nt!MmCreateKernelStack  
!)。作为一个争议点，传递给 nt!MmCreateKernelStack  
 的参数 (在这个特定情况下与 shadow stack 创建无关) 是未记录的，我在这里尽可能地逆向工程了它们。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn3W5XrogukJBv4iarmcSBGPZ8JGdiaXuUhamDtY6HvUgdCULHHYG2Rzmw/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到，显然，导向 nt!KiCreateKernelShadowStack  
 的代码路径由 nt!KiKernelCetEnabled  
 控制。查看这个全局变量的交叉引用，我们可以看到它是作为调用 nt!KiInitializeKernelShadowStacks  
 的一部分设置的 (这个函数由 nt!KiSystemStartup  
 调用)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn5vCicAkkOjpmBEJVsmHHfHj5YYkb3ofdz4AjyTXicsfkiaIdXVA50bUvQ/640?wx_fmt=png&from=appmsg "")  
  
查看实际的写操作，我们可以看到这发生在提取 CR4 控制寄存器的内容之后。具体来说，如果 CR4 寄存器的第 23 位 (0x800000  
) 被设置，这意味着当前 CPU 支持 CET。这是第一个"门",可以这么说，是必需的。我们稍后会看到它不是本节末尾 NT 在内核模式 shadow stack 创建中的唯一一个。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn1EvvL1q7FlQeYY7aiaP6VWoM3CBaH9L0Vrsc4h1TqC03icLa4Nqic5W8w/640?wx_fmt=png&from=appmsg "")  
  
如果支持 CET，要为其创建 shadow stack 的目标线程 (作为一个争议点，在本博文中未描述的其他场景中，可以向 nt!KiCreateKernelShadowStack  
 提供一个空线程) 的 Thread->MiscFlags  
 位掩码的第 22 位 (0x400000  
) 被设置。这个位对应于 Thread->MiscFlags.CetKernelShadowStack  
 - 这很有意义！虽然，正如我们提到的，我们正在处理一个_用户模式_线程，这是其_内核模式_堆栈 (因此，内核模式 shadow stack) 的创建。  
  
然后我们可以看到，基于 MiscFlags  
 的值或我称之为"线程初始化标志"的值，传递给 nt!KiCreateKernelShadowStack  
 的参数之一 (特别是 ShadowStackType  
) 被配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnGkVnqsJalmGFTLiaunSibgW9zJAahk920vEdKBZyFb1qfiaXEHibibwD0IA/640?wx_fmt=png&from=appmsg "")  
  
最后两个代码路径取决于 Thread->MiscFlags  
 的配置方式。第一个检查是查看 Thread->MiscFlags  
 是否设置了第 10 位 (0x400  
)。这对应于 Thread->MiscFlags.SystemThread  
。所以这里发生的是，如果我们要为其创建内核模式 shadow stack 的线程是系统线程，则 shadow stack 类型被定义为值 1  
。  
> 对于不熟悉且好奇我如何确定位掩码中的哪一位对应于哪个值的读者，这里有一个例子。正如我们所知，0x400  
 在按位与操作中使用。如果我们查看二进制中的 0x400  
,我们可以看到它对应于第 10 位。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn6KiagXhmG6TLJiaibU1QUtLCbLKvCRpghMktbmXHqE1lzkdIPtzaP4uSQ/640?wx_fmt=png&from=appmsg "")  
> 如果我们在 WinDbg 中使用 dt nt!_KTHREAD  
,我们可以看到 MiscFlags  
,在第 10  
 位 (从 0  
 开始偏移) 对应于 MiscFlags.SystemThread  
。这种方法对于未来的标志也是正确的，也是我们如何确定 MiscFlags.CetKernelShadowStack  
 的方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn2cpkNf4FX92vsK0lcWo3I0UAGXVft3ibxECfGhlLRa0VE3mqNXsgWVA/640?wx_fmt=png&from=appmsg "")  
  
继续，可以采取的下一个路径基于以下语句：ShadowStackType = (miscFlags >> 8) & 1;  
。这实际上做的是将掩码中的所有位向"右"移动 8 位。这里想要的效果是将第 8 位 (从 0 开始偏移) 移动到第一个 (第 0) 位置。由于 1  
,在十进制中，在二进制中是 00000001  
 - 这允许第 8 位 (从 0 开始偏移) 与 1 进行按位"与"。换句话说，这检查第 8 位 (从 0 开始偏移) 是否被设置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnGs7cZudVhuiaw5CKsj8L7U83QOS0rO9zMcHyjMtWsodic8Yzfx2VibBXQ/640?wx_fmt=png&from=appmsg "")  
  
如果我们查看 nt!KeInitThread  
 的原始反汇编，我们可以看到这确实发生在这里。为了验证这一点，我们可以在按位与操作上设置一个断点。然后我们可以"模仿"与操作，并告诉 WinDbg 如果 r14d  
 在执行与 1  
 的按位与后为非零则中断。如果达到断点，这将向我们表明目标线程_应该_是"安全线程"。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnaa6a34icmDaHxpA9Udr0nYJonYEJUwiaibgH0VagFKicPFqseYgQf28fcQ/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到在我们达到断点后，我们处于调用 wininit!StartTrustletProcess  
 的代码路径中。我不会过多地详细介绍，因为我有时会在不相关的主题上过多展开，但_trustlet_(如_Windows Internals, Part 1, 7th Edition_所称) 指的是"安全进程"。我们可以将这些视为在 VTL 1 中运行的特殊受保护进程。  
  
在达到断点时，目标线程操作在 RDI 寄存器中。如果我们检查这个线程，我们可以看到它驻留在 LsaIso.exe  
 中 - 这  
是  
与凭据保护相关的"安全进程"或 trustlet。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnia12IAic4gEB8YiaIwKmzIDHB1hwPDANjZrF1lK4NeaUgudSEbzceoztQ/640?wx_fmt=png&from=appmsg "")  
  
更具体地说，如果我们检查线程对象的 SecureThread  
 成员，我们可以清楚地看到这是一个安全线程！虽然我们不会检查安全线程的"流程",但这是为了验证我们之前提到的代码路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnFZxlBqiapPwgH8odo7Qd4rNmVia3rygj95ulgzSicXTk0Bv4KM0eTMicdw/640?wx_fmt=png&from=appmsg "")  
  
在 (又一次) 跑题之后 - 这里可以采取的另一个代码路径是 SecureThread  
 为 0  
 - 意味着 ShadowStackType  
 也是 0  
。值 0  
 我只是称之为"普通用户模式线程",因为没有其他特殊值来表示。对于我们的目的，对于我们特定的用户模式线程具有内核模式 shadow stack 创建的代码路径，堆栈类型将始终为 0  
。  
  
这意味着在这个特定的代码路径中 (从 nt!KeInitThread  
 调用 nt!KiCreateKernelShadowStack  
) 设置非零值 ShadowStackType  
 的唯一其他方法是让 (initThreadFlags & 8) != 0  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnKEyBKPOPf5GsFxkATwcAsvTiaFLwWXk0bDoT673CGENvwnQsFNIiab8g/640?wx_fmt=png&from=appmsg "")  
  
现在，如果我们回想一下_用户模式_线程是如何调用 nt!KeInitThread  
 的，我们可以看到 Flags  
 总是显式设置为 0  
。对于我们的目的，我只是表示这些标志来自 nt!KeInitThread  
 的其他调用者，特别是像内核的初始线程这样的早期线程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnsrgbBibmQ21ibYIXJdMFMVF01MmjQ9Fc9FpAD15fr2qicFP5WyWqicEZEg/640?wx_fmt=png&from=appmsg "")  
  
nt!KeInitThread  
 然后最终会调用 nt!KiCreateKernelShadowStack  
。正如你之前记得我提到的，nt!MmCreateKernelStack  
 是一个"通用"函数 - 能够创建_多种_类型的堆栈。那么 nt!KiCreateKernelShadowStack  
 只是 nt!MmCreateKernelStack  
 的包装器就不足为奇了 (它使用一个未记录的结构作为参数，我已经尽可能地逆向工程了)。还值得注意的是，在用户模式线程代码路径中，通过 nt!KeInitThread  
 调用 nt!KiCreateKernelShadowStack  
 时，堆栈标志 (第三个参数) 总是设置为 0  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnGYqCNmHAjT4eqWfqtmmEg5Gfn1Zff2pX49fGibaBiatzwUGb9tD8XRQA/640?wx_fmt=png&from=appmsg "")  
  
考虑到 nt!MmCreateKernelStack  
 的灵活性可以服务于多种类型的堆栈创建，shadow stack 创建的逻辑包含在这里是有意义的。事实上，我们可以看到在成功调用 (大于 0  
 或 0  
 的 NTSTATUS  
 代码表示成功) 时，shadow stack 信息被存储。  
  
当执行到达 nt!MmCreateKernelStack  
 时 (对于 shadow stack 创建),实际上可以采取两个代码路径。一个是使用已经"缓存"的堆栈，这是一个可以重新用于新堆栈的空闲缓存条目。另一个是实际分配和创建一个新的 shadow stack。  
  
在 nt!MmCreateKernelStack  
 中首先要做的是复制并存储调用的参数 - 另外 allocateShadowStackArgs  
 被初始化为 0  
。这是一个未记录的结构，我尽我所能逆向工程了，如果我们命中"新堆栈分配"代码路径而不是"缓存堆栈"代码路径，可能会在调用 nt!MiAllocateKernelStackPages  
 时使用。此外，选择一个特定的"分区"作为操作的"目标分区"。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnGSKjiahU49xxKdmiaiaoRVZEh00nUWXysvDGcRManXp56suurkrdnOf1A/640?wx_fmt=png&from=appmsg "")  
  
首先你可能想知道 - nt!MiSystemPartition  
 从哪里来的，或者分区这个术语一般？这个全局变量的类型是 nt!_MI_PARTITION  
,根据_Windows Internals, Part 1, 7th Edition_,"由[内存分区的]自己的内存相关管理结构组成，如页面列表、提交费用、工作集、页面修剪器等"。我们可以将这些分区视为内存管理相关结构的容器，例如，像 Docker 容器 (这个概念类似于如何使用虚拟化来隔离内存，每个 VM 都有自己的页表集)。我不是这些分区的专家，而且它们 (至少对我来说) 似乎没有很好的文档记录，所以请阅读我刚才提到的_Windows Internals, Part 1, 7th Edition_的相应部分。  
  
系统分区始终存在，这就是这个全局变量。这个系统分区代表系统。分区也可能与目标进程相关联 - 这正是 nt!MmCreateKernelStack  
 所做的。  
  
我们可以从之前的图像中看到，目标线程的存在被用来帮助确定目标分区（回想一下我之前提到过一些“特殊”情况，其中没有提供线程，我们在这篇博客中不会讨论这些情况）。如果存在目标线程，我们将从承载目标线程的进程中提取“分区 ID”，以便为其创建一个 shadow stack。所有已知分区的数组由全局变量 nt!MiState  
 管理，该变量存储了许多常用信息，例如系统内存范围、池范围等。对于我们的目标线程的进程，没有与之关联的分区。这意味着提供了 0  
 的索引，即系统默认分区的索引。这就是函数知道在缓存路径命中时如何索引已知的缓存 shadow stack 条目的方式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn6SWvDnX38ibMYn5K4STEibBZicg6enaDOT84AITZzKInjeWgAdUtj3A1g/640?wx_fmt=png&from=appmsg "")  
  
接下来的代码路径围绕着发生的堆栈操作类型。如果我们回想一下，nt!MmCreateKernelStack  
 从输入结构中接受一个 StackType  
 参数。我们在 nt!KiCreateKernelShadowStack  
 中调用的“中介” ShadowStackType  
 值提供了 StackType  
 值。当 StackType  
 为 5  
 时，这指的是“正常”的非 shadow stack 操作（例如创建新的线程堆栈或扩展当前堆栈）。由于 5  
 的 StackType  
 被保留用于“正常”堆栈，我们知道 nt!MmCreateKernelStack  
 的调用者提供了不同的值来指定“边缘”情况（例如“类型”的 kernel shadow stack）。在我们的情况下，这将被设置为 0  
。  
  
与堆栈类型一起，一组“堆栈标志”（StackFlags  
）提供了关于当前堆栈操作的更多上下文。一个例子是表示堆栈操作是否是新线程堆栈的结果或现有堆栈的扩展。由于我们特别关注 shadow  
 堆栈操作，因此我们将跳过“正常”堆栈操作。此外，对于用户模式线程的内核模式 shadow stack 路径，StackFlags  
 将被设置为 0  
。  
  
接下来，nt!MmCreateKernelStack  
 将确定堆栈的大小。堆栈标志位掩码的第一个位表示是否需要非常规（更大）堆栈大小。如果 不需要  
，则会收集一些信息。具体来说，在内核模式 shadow stacks 的情况下，我们将进入 else  
 路径。请注意，这里还捕获了一个名为 cachedKernelStackIndex  
 的变量。实际上，在用户模式线程的内核模式 shadow stack 操作中，该变量将被设置为 3  
，因为 stackType  
 是空的。这将在后面发挥作用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn6CvJpbGmycHoKpEUsAAsbZGzgR9tgTFzoBlics0FQibZmxiaLsBC237VA/640?wx_fmt=png&from=appmsg "")  
  
在这一点上，我注意到 KPRCB  
 发生了变化，我在互联网上找不到其他信息，所以我认为值得在这里记录，因为我们无论如何都需要讨论“缓存堆栈”路径！在某些情况下，可以从当前处理器（KPRCB  
）中检索到缓存堆栈条目，以处理堆栈创建。我注意到的变化在于 KPRCB  
 现在有 两个  
 缓存堆栈区域（由 Prcb->CachedStacks[2]  
 跟踪）。旧的结构成员是 Prcb->CachedStack  
，自 Windows 10 1709 以来就存在了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn7XyPR2fRXD08tejTUcfK7jenJbqickIVL1yKDPOvr2DibSiaiakNhmzCAQ/640?wx_fmt=png&from=appmsg "")  
  
在上述情况下，我们可以看到当 StackType  
 为 5  
 时，CachedStacks[]  
 索引被设置为 0  
。否则，它为 1  
（由反编译器中的变量 prcbCachedStackIndex  
 跟踪）。  
> 请注意，cachedKernelStackIndex  
 被突出显示，但对我们 还  
 不重要。  
  
  
这意味着这个新的 CachedStacks[]  
 索引专门用于缓存 shadow stacks！请注意，在上面的截图中，我们看到 nt!MiUpdateKernelShadowStackOwnerData  
。此检查通过检查 prcbCachedStackIndex  
 是否设置为 1  
 来进行，该值用于 shadow stacks。当找到堆栈的缓存条目时，“所有者数据”会被更新。实际上，这会将与 shadow stack 页相关联的 PFN 与目标 shadow stack 关联起来。  
  
实际上，除了使用 PRCB 的缓存之外，还有第二种方法可以为请求新 shadow stack 的调用者使用一个空闲且未使用的 shadow stack。这第二种方法，我稍后会展示，也将使用 nt!MiUpdateShadowStackOwner  
，并依赖于 cachedKernelStackIndex  
。  
  
PRCB 缓存是如何填充的？当堆栈不再需要时，调用 nt!MmDeleteKernelStack  
。此函数可以调用 nt!MiAddKernelStackToPrcbCache  
，该函数负责重新填充 Prcb->CachedStacks[2]  
 管理的两个列表。nt!MmDeleteKernelStack  
 的工作几乎与 nt!MmCreateKernelStack  
 相同 - 除了结果是删除。它们甚至接受相同的参数类型 - 这是一个提供有关要创建或删除的堆栈信息的结构。具体来说，对于 shadow stack 场景，这个结构中有一个我命名为 ShadowStackForDeletion  
 的成员，仅在 nt!MmDeleteKernelStack  
 场景中使用。如果可能，已删除的堆栈将存储在 Prcb->CachedStacks[]  
 的适当索引中 - 在我们的情况下是第二个（1  
 来自 0  
 索引），因为第二个是用于 shadow stacks。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn3zP5JoicU1cjfGOUgnpyRnNnYIS7bIEyINyeDveMvMEib5fSh8Fib0MbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnqqE48icYLNg0YhOicLq0npy992x7mAlR5RH3tdDvNg8tWKdNTuNmCKvg/640?wx_fmt=png&from=appmsg "")  
  
由于各种原因，包括没有可用的缓存堆栈条目可供 PRCB 使用，请求新 shadow stack 的调用者可能无法通过当前处理器的 PRCB 接收缓存堆栈。在可以检索到缓存堆栈的情况下，调用者可能会通过目标分区的 FreeKernelShadowStackCacheEntries  
 列表接收它。处理器分组被称为 NUMA（非均匀内存架构）系统上的 节点  
，许多现代系统在其上运行。Windows 将在 nt!_MI_NODE_INFORMATION  
 结构中存储有关给定节点的特定信息。这些结构的数组由分区对象管理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnLNEFPia3hgKXYfpJcUxY52ThjebyVGSHae6v6uhsibVfXfpAvBDAkickg/640?wx_fmt=png&from=appmsg "")  
  
每个节点，除了处理器的 KPRCB  
，还有一个可供使用的空闲缓存堆栈列表！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnC3HA80frxOWaia6Ttzm6Zpfa7liaWVj5qxvEnyXVzrjYIutLPG02yXdA/640?wx_fmt=png&from=appmsg "")  
  
该节点信息结构的 CachedKernelStacks  
 成员是一个包含 8 个 nt!_CACHED_KSTACK_LIST  
 结构的数组。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqniawyn1WedNsibYW1yP15mpSI4bn5ZA7ZCT2VlKTVxvOHgEgNNicRhSh1Q/640?wx_fmt=png&from=appmsg "")  
  
正如我们之前提到的，捕获的变量 cachedKernelStackIndex  
 在 nt!MmCreateKernelStack  
 函数开始时表示，在命中此缓存堆栈路径的情况下，从哪个列表中获取条目。每个列表包含一个单链表的空闲条目以供使用。如果找到条目，shadow stack 信息也会如我们之前所见被更新。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnYpkLb9mXibKNfZTTTkUYozTvOlMXBqTEQ6wwfDVSOGHqpReibTuSPU1w/640?wx_fmt=png&from=appmsg "")  
  
此时，执行将返回到 nt!MmCreateKernelStack  
 的调用者。然而，也有可能创建一个新堆栈 - 这就是“精华”所在。所有这些堆栈缓存条目之所以可以如此轻松地重用，是因为它们的安全性/完整性在完整的“新”路径中被正确配置过一次。  
  
对于“新”堆栈路径（对于 shadow 和非 shadow，尽管我们将重点放在 shadow stacks 上），首先通过 nt!MiReservePtes  
 为堆栈页面保留 PTE。使用全局 nt!MiState  
，获取用于 PTE 保留的特定系统 PTE 区域。由于可以有两种类型的堆栈（非 shadow 和 shadow），因此现在有 两个  
 系统 PTE 区域用于内核模式堆栈。任何不等于 5  
 的堆栈类型都是 shadow stack。相应的系统 VA 类型是 MiVaKernelStacks  
 和 MiVaKernelShadowStacks  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnz2nrp2cQgcxuibWZAhuXX6G97rJmVU3HFDFShhGic6myiauvWckJoGILQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnybm0pbXrmrSNPWP2poGykicdEr1yIPxEBay0eGrJxP2yzJTIlZCl2kQ/640?wx_fmt=png&from=appmsg "")  
  
在保留 PTE（在我们的情况下是 shadow stack PTE）之后，nt!MmCreateKernelStack  
 实际上完成了它的工作。该函数将调用 nt!MiAllocateKernelStackPages  
，这将有效地映射由 PTE 保留的内存。此函数接受一个参数 - 一个类似于 nt!MmCreateKernelStack  
 的结构，我称之为 _ALLOCATE_KERNEL_STACK_ARGS  
。如果此函数成功，反向工程的 nt!MmCreateKernelStack  
 参数的 StackCreateContext->Stack  
 成员将填充目标堆栈的地址。在我们的情况下，这是 shadow stack 的地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn9mIebwK1ALX05usOBG9rOEGNuZOLOHbTvkbEViccB1dJthtodrDSeaQ/640?wx_fmt=png&from=appmsg "")  
  
nt!MiAllocateKernelStackPages  
 将执行一些标准操作，这对我们来说并不有趣。然而，在 shadow stack 操作的情况下 - 会发生对 nt!VslAllocateKernelShadowStack  
 的调用。在此调用之前会发生几件事情。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnrIP6LObvDic5cQWkBAdeC2DCX8C68rcJqzTP1MjyibLicjyz1ktpsXyCw/640?wx_fmt=png&from=appmsg "")  
  
作为对 nt!MiAllocateKernelStackPages  
 的调用的一部分，nt!MmCreateKernelStack  
 将准备参数，并存储一个我命名为“PFN 数组”的空指针。此 PFN 数组不包含 nt!_MMPFN  
 结构，而是字面上包含与目标 shadow stack 地址相关联的“指针 PTE”的原始/物理 PFN 值。指针 PTE 本质上意味着它是指向一组映射到给定内存区域的 PTE 的指针。此指针 PTE 来自之前在 nt!MmCreateKernelStack  
 中对 nt!MiReservePtes  
 的调用，来自 shadow stack VA 区域。这个“PFN 数组”保存了来自此指针 PTE 的实际 PFN。之所以称其为“PFN 数组”，是因为根据我的逆向工程，它可以存储多个值（尽管我总是注意到只存储了一个 PFN）。原因是 nt!VslAllocateKernelShadowStack  
 将调用 Secure Kernel。因此，Secure Kernel 可以直接获取原始 PFN 并将其乘以页面的大小来计算指针 PTE 的 物理  
 地址。指针 PTE 很重要，因为它指向为目标 shadow stack 保留的所有 PTE。  
  
我们还可以看到，此调用受到 nt!_MI_FLAGS  
 位 ProcessorSupportsShadowStacks  
 的限制。ProcessorSupportsShadowStacks  
 是在初始化“引导”shadow stacks（如 ISR 特定的 shadow stacks 等）时设置的。设置此位的条件是 nt!KiKernelCetEnabled  
，我们之前已经看到过（nt!KiInitializeKernelShadowStacks  
）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnmxib9v34SnCkVYKH0uczhash6Yy2zjLhopWyJYGhEvcqejZhpj06gvA/640?wx_fmt=png&from=appmsg "")  
  
我们之前只简单提到过，但我们说如果 CR4 寄存器中设置了相应的位以支持 CET，则 nt!KiKernelCetEnabled  
 被设置。这只是 部分  
 正确。此外，LoaderParameterBlock->Extension.KernelCetEnabled  
 必须被设置，其中 LoaderParameterBlock  
 是 LOADER_PARAMETER_BLOCK  
 类型。这对我们来说为什么重要？  
  
nt!VslAllocateKernelShadowStack  
，正如我们刚才提到的，将实际导致对 Secure Kernel 的调用。这是因为 nt!VslAllocateKernelShadowStack  
，类似于我之前帖子中展示的内容，将导致一个安全系统调用。  
  
这意味着 VBS 必须  
 运行。这意味着可以合理地假设，如果 nt!KiKernelCetEnabled  
 被设置，并且 MiFlags.ProcessorSupportsShadowStacks  
 被设置，系统必须知道 VBS（更具体地说，在我们的情况下是 HVCI）正在运行，因为如果这些标志被设置，将发出安全系统调用 - 这意味着 Secure Kernel 是存在的。由于   
作为引导过程的一部分  
 LOADER_PARAMETER_BLOCK  
 是从 winload.exe  
 到达我们的，我们可以直接在 IDA 中查看 winload.exe  
，以查看 LoaderParameterBlock->Extension.KernelCetEnabled  
 是如何设置的。  
  
在 winload.exe  
 中，容易找到的函数是 winload!OslSetVsmPolicy  
。在此函数中，有一个调用到 winload!OslGetEffectiveHvciConfiguration  
。此函数通过输出样式参数“返回”多个值。其中一个值是布尔值，表示 HVCI 是否启用。确定 HVCI 是否启用的方法是通过注册表项 HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity  
，因为在引导过程的这一点上，注册表已经对 Windows 可用。它还将读取当前的 CI 策略，这些策略显然能够启用 HVCI。如果 HVCI 被启用，系统才会去检查内核 CET 策略（winload!OslGetEffectiveKernelShadowStacksConfiguration  
）。这也将从注册表中读取（HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks  
），在这里可以指明是否为“审计模式”，这将导致在内核 CET 被违反时生成 ETW 事件，或者“完全”模式，在这种模式下将导致系统崩溃。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnIZyib7jv4Dggu1TqquvNjFmLPFw8NLaHibnic2LIkwvVqLY6CaI8iaqt0A/640?wx_fmt=png&from=appmsg "")  
  
我强调这一点的原因是为了说明内核 CET **要求**  
 在 Windows 上启用 HVCI！我们将在下一节中具体看到原因。  
  
接下来，这个对 nt!VslAllocateKernelShadowStack  
 的调用将导致一个安全系统调用。请注意，_SHADOW_STACK_SECURE_CALL_ARGS  
 不是公共类型，只是我在 IDA 中基于逆向工程创建的一个“自定义”本地类型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqniciaNvzvTgZTCY2YicwshvFiaqR15SibibjIc6T2slQS15I2PicvPpQ7eI99A/640?wx_fmt=png&from=appmsg "")  
  
我们现在可以看到将传递给 VTL 1/Secure Kernel 的参数。这是 VTL 0 中 shadow stack 创建的结束！执行现在将接管 VTL 1。  
## 使用 SourcePoint 调试 Secure Kernel  
  
SourcePoint for Intel  
   
是  
 一款新软件，能够与特定板（在这种情况下是 AAEON UP Xtreme i11 Tiger Lake 板）配合使用，能够“调试不可调试的内容”。SourcePoint（我使用这个术语来指代“调试器”）通过利用 JTAG 技术和 Intel Direct Connect Interface（DCI）来实现这一点。我不会在这篇博客中详细介绍设置 SourcePoint 的整个过程。请遵循   
这个  
 链接到我的 GitHub wiki，其中有关于此的说明。  
## Shadow Stack 创建（Secure Kernel）  
  
通过动态分析 Secure Kernel 的能力，我们可以将注意力转向这一工作。由于我在之前的帖子中   
已经展示  
 了有关安全系统调用的基本知识，因此我不会在这里花费太多时间。我们将从 securekernel.exe  
 中的安全系统调用调度函数 securekernel!IumInvokeSecureService  
 开始。具体来说，在我使用的 Windows 版本中，安全系统调用编号（SSCN）为 230  
，这将导致 shadow stack 创建操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn6VWDeFI82nZwHeOzpU2BdPOIXNcpVTUlBVKkBX1ibdJh9GaLaPMslZg/640?wx_fmt=png&from=appmsg "")  
  
首先要做的是从 NT 中获取提供的 shadow stack 类型，并通过 securekernel!SkmmTranslateKernelShadowStackType  
 将其“转换”为“Secure Kernel 特定”的版本。在我们的案例中（用户模式线程的内核模式 shadow stack），Flags  
 返回值为 2  
，而转换后的 shadow stack 类型也是 2  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnE3Eo8U9Ewkzmcfvjjj0rRu7IrB6xcd8tcs8akFCsZEg8JZk7DErn4w/640?wx_fmt=png&from=appmsg "")  
  
在 SourcePoint 中，我们简单地在 securekernel!SkmmCreateNtKernelShadowStack  
 上设置一个断点。我们可以看到，对于此操作，“转换后的 shadow stack”是 2  
，这表示用户模式线程接收内核模式 shadow stack。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn6cKmTs4rPLTn7zQjt0RS3icd3az3jYNmByQw5ictJgEtlibmFgfaETHGg/640?wx_fmt=png&from=appmsg "")  
  
securekernel!SkmmCreateNtKernelShadowStack  
 首先要做的是验证几个先决条件的存在，例如当前机器上是否存在 KCET，以及 shadow stack 类型是否有效等。如果这些条件为真，将调用 securekernel!SkmiReserveNar  
，这将保留一个 NAR，或 Normal Address Range  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnnbkhyApTS8fL4LMzbiaSJTbevbC3mFKuPWL4wQTVZRtCaI2h4Oibm70w/640?wx_fmt=png&from=appmsg "")  
  
根据 Windows Internals, 7th Edition, Part 2  
，Normal Address Range“[表示] VTL 0 内核虚拟地址范围”。NAR 的存在使得 Secure Kernel 能够“意识到”特定的 VTL 0 虚拟地址范围。NAR 是为各种内存区域创建的，例如 shadow stacks（如我们的案例）、内核 CFG 位图页面以及其他需要 VTL 1 服务/保护的内存区域。这通常包括与加载的映像（驱动程序）相关的内存区域。  
  
当前的 NAR 存储在所谓的“稀疏”表中。这种表（用于 NAR 和 Secure Kernel 中的许多其他数据类型，如我在之前的   
博客  
 中提到的）包含许多条目，只有使用的条目被映射。然而，我在逆向工程和调试中注意到，在某些情况下，这似乎并非如此。在与我的朋友   
Andrea Allievi  
 联系后，我终于明白了原因！只有 驱动程序  
 NAR 被存储在稀疏表中（这就是为什么在我之前的博客中关于一些基本 Secure Kernel 图像验证时，我们看到加载的驱动程序使用了稀疏表）。在这些“单次”情况下，也称为“静态”NAR（用于 CFG 位图、shadow stacks 等），NAR 不存储在稀疏表中 - 而是存储在 AVL 树中 - 通过符号 securekernel!SkmiNarTree  
 跟踪。此树跟踪 多种  
 类型的静态 NAR。此外，还有一个特定于 shadow stack 的列表，通过 securekernel!SkmiShadowStackNarList  
 跟踪。  
  
作为 NAR 创建逻辑的一部分，当前的 NAR（与正在创建的目标 shadow stack 区域相关）被添加到与 shadow stacks 相关的 NAR 列表中（如前所述，它也被添加到通过 AVL 树根 securekernel!SkmiNarTree  
 跟踪的“静态”NAR 列表中）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnItBIAnTA2icpKjN9YicILBNMZozl5jq0kkytJv2kNTD7ibJpVsCMvOiaibA/640?wx_fmt=png&from=appmsg "")  
> 作为附注，请注意，我并不打算为这篇博客的目的逆向整个 NAR 结构。需要注意的主要事项是，NAR 使 VTL 1 能够跟踪 VTL 0 中的感兴趣内存，并且 NAR 包含的信息，例如要跟踪的内存基区域、区域中的页面数量、相关的   
secure image  
 对象（如果适用）以及其他项目。  
  
  
跟踪与 shadow stacks 相关的 NAR 的一个主要原因是，有几个场景需要对所有 shadow stacks 完成工作。这包括 Secure Kernel Patch Guard (SKPG) 执行的 shadow stack 完整性检查，以及计算机进入休眠状态时。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnDuABFfecbibXNWkJbNxxM43ou0nLTDdanViaczZxJ1nDqapxun978Yjg/640?wx_fmt=png&from=appmsg "")  
  
接下来，在 NAR 创建之后，您会注意到多次调用 securekernel!SkmiGetPteTrace  
。此功能用于维护各种内存目标（如 NTE、PTE 和 PFN）的状态转换。我在与 Andrea 再次交谈后了解到，为什么我总是看到这些调用失败。之所以这些调用与我们无关（以及为什么它们不成功，从而限制了额外代码），是因为记录每一个转换将非常昂贵，并且并不重要。因此，只有在某些情况下才会进行记录。在下面的示例中，securekernel!SkmiGetPteTrace  
 将跟踪与 shadow stack 相关的 NTE 的转换（因为 NTE 是保留 NAR 功能的一部分）。对于不熟悉的读者，NTE 被称为“正常表项”，每个“感兴趣的页面”都有一个 NTE，Secure Kernel 希望在 VTL 0 中保护（请注意，我并没有说 每个  
 页面在 VTL 0 中都有一个与 VTL 1 相关的 NTE）。NTE 存储并通过全局数组索引，就像历史上在 NT 中的 PTE 一样。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn7N518AkQQhtIc4HIQ44nAGceWaHF3PknJQ3oDES9pkW2ghhGrGcn6A/640?wx_fmt=png&from=appmsg "")  
  
请注意，上述截图中的 KeGetPrc()  
 调用是错误的。这是因为，尽管 KeGetPrc()  
 只是简单地获取 [gs:0x8]  
 中的内容。然而，正如内核和用户模式都利用 GS 进行各自的目的，Secure Kernel 也是如此。Secure Kernel 中的“PRC”数据是其 自己的  
 格式（线程对象和进程对象也是如此）。这就是为什么 IDA 不知道如何处理它。  
  
在跟踪 NAR（和 NTE）之后，跳过上述记录机制，调用 securekernel!SkmiClaimPhysicalPage  
 的循环被调用。这里利用了两个参数，物理帧对应于作为原始指针 PTE 提供的原始参数，以及一个位掩码，可能是一组标志，用于表示操作的类型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnvUu5JVc8Lsr6ibFY7ibwV4FLMsb6IUfqGSYlj3OKE0kc8WUYJym8sqWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnCkICFVRVdUjvzY4kCAIqQ8Jrvk2gvFXJtiaibqpQkibpJJUVYyrYQCnJA/640?wx_fmt=png&from=appmsg "")  
  
此循环将遍历与 shadow stack 区域相关的 PTE 数量，调用 securekernel!SkmiClaimPhysicalPage  
。此函数将允许 Secure Kernel 拥有这些物理页面。这主要通过在 securekernel!SkmiClaimPhysicalPage  
 中调用 securekernel!SkmiProtectPageRange  
 来实现，将页面设置为在 VTL 0 中为只读，从而允许我们稍后将其映射到 Secure Kernel 的虚拟地址空间中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnice3GurycwJRV0dwTyoNWibP40HA3G1lLzHMSzMfkkw3TibRgm9eY5M3Q/640?wx_fmt=png&from=appmsg "")  
  
现在您会看到，我在此调用中注释了这将标记页面为只读。我是如何验证这一点的？对 securekernel!SkmiProtectPageRange  
 的调用将在底层发出一个超调用（vmcall  
），超调用代码为 12  
（十进制）。正如我之前在关于 HVCI 的   
帖子  
 中提到的，代码 12  
，或十六进制的 0xC  
，对应于 HvCallModifyVtlProtectionMask  
 超调用，根据 TLFS（  
Hypervisor Top Level Functional Specification  
）。此超调用能够请求修改给定来宾页面的保护掩码。如果我们检查超调用的参数，使用 SourcePoint，我们可以更清楚地了解此调用的作用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnHD5ViaNnu5sFwo6durwLR73ibnWJDSUsleiaxTISibdibgfO0NJn2bV8XvQ/640?wx_fmt=png&from=appmsg "")  
1. 字节 0-8（8 字节）是目标分区。-1  
 表示“自我”（#define HV_PARTITION_ID_SELF ((HV_PARTITION_ID) -1)  
）。这是因为我们正在处理根分区（请参见之前提到的关于分区的 HVCI 帖子）  
  
1. 字节 8-12（4 字节）表示要设置的目标掩码。在这种情况下，我们有一个掩码为 9  
，对应于 HV_MAP_GPA_READABLE | HV_MAP_GPA_USER_EXECUTABLE  
。（这实际上只是意味着将页面标记为只读，我与 Andrea 讨论过为什么 HV_MAP_GPA_USER_EXECUTABLE  
 存在，这是一个无关的兼容性问题）。  
  
1. 字节 12-13（1 字节）指定目标 VTL（在这种情况下为 VTL 0）  
  
1. 字节 13-16（3 字节）是保留的  
  
1. 字节 16-N（N 字节）表示要应用权限的目标物理页面。在这种情况下，它是 VTL 0 中 shadow stack 的物理地址。请记住，物理地址是 身份映射  
 的。内存的物理地址在 VTL 1 和 VTL 0 的眼中是相同的，只是在不同的 VTL 中，处理器当前执行时应用了不同的权限集。  
  
这防止了 VTL 0 的修改，并允许 Secure Kernel 现在安全地映射内存并根据需要初始化它。映射到 Secure Kernel 的方式是通过称为 hyperspace  
 的内存区域。保留了来自 hyperspace 区域的 PTE，并用适当的控制位和目标 shadow stack 区域的 PFN 填充内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnAQda4U06PZdbf0lyxY6lFs2p8Ej7JKaeNTHkvicCdPHlkhsP3QmW0FQ/640?wx_fmt=png&from=appmsg "")  
  
Hyperspace 是一个内存区域，根据 Windows Internals 7th Edition, Part 1  
，可以将内存临时映射到系统空间。在这种情况下，它被临时映射到 Secure Kernel 虚拟地址空间，以初始化 shadow stack 所需的信息（然后在更改提交后可以移除此映射，这意味着物理内存本身仍将被配置）。在 shadow stack 区域映射后，内存被清零，并调用 securekernel!SkmiInitializeNtKernelShadowStack  
 来初始化 shadow stack。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnURHhencbsvicewPmZeVERKVr6moUJNCF6iaibdeN0QTg2jYPfIKD46ibmQ/640?wx_fmt=png&from=appmsg "")  
  
此函数的主要重点是根据 shadow stack 的类型  
 正确初始化 shadow stack。如果您阅读   
Intel CET 规格  
 关于监督（内核）shadow stacks，有一些有趣的内容。  
  
对于给定的 shadow stack，在偏移量 0xFF8  
（我们将其称为 shadow stack 的“底部”，是的，我知道堆栈是向较低地址增长的！）存在一个称为“监督 shadow stack 令牌”的东西。令牌（我们将其称为令牌）用于验证 shadow stack，并提供元数据，例如当前堆栈是否忙（例如，正在处理器上被积极使用）。如前所述，令牌很重要，因为它用于 验证  
 监督 shadow stack 是一个实际的 有效  
 shadow stack 在内核模式下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqny3XCJlLEgAeXfdHmqOoSrzGHsvptZcLv1HUSKicRIjMopqNT8ia0DYtg/640?wx_fmt=png&from=appmsg "")  
  
当 Secure Kernel 正在处理内核模式 shadow stack 创建操作时，配置令牌是 Secure Kernel 的工作。令牌可以以以下三种状态之一创建：  
1. 令牌存在，且“忙碌”位被设置，意味着此 shadow stack 将在处理器上处于活动状态  
  
1. 令牌存在，且“忙碌”位被清除，意味着此 shadow stack 不会立即在处理器上处于活动状态  
  
1. 为令牌值提供零（NULL）值  
  
技术上有两种类型的令牌 - 第一种是“正常”令牌（设置了忙碌或非忙碌位），但还有一种称为 恢复  
 令牌。当上述第三种情况发生时，这将导致创建恢复令牌，而不是“实际”令牌（尽管可以为恢复和“常规”令牌一起指定配置）。  
  
恢复令牌是一个“金丝雀”，CPU 可以用来定位先前的 shadow stack 指针（SSP）值。字面上来说，正如名称所暗示的，这是一个 恢复  
 点，操作系统（在我们的情况下是 Secure Kernel）可以在 shadow stack 创建操作期间创建，以允许当前执行在稍后时间“切换”到此 shadow stack。  
  
恢复令牌通常与 saveprevssp  
（保存先前的 SSP）指令结合使用，以允许 CPU 切换到新的 shadow stack 值，同时保留旧的。当发生恢复操作（rstorssp  
）时，将处理恢复令牌。rstorssp  
 的结果是返回与恢复令牌相关联的 shadow stack（在令牌经过验证和确认后）。这允许 CPU 切换到新的/目标 shadow stack（在 Intel CET 规格中有一节称为“RSTORSSP 切换到新的 shadow stack”，概述了此模式）。  
  
在我们的案例中（用户模式线程的内核模式堆栈），仅采用恢复令牌路径。这实际上发生在 securekernel!SkmiInitializeNtKernelShadowStack  
 的 结束  
 处。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnWNiaKwBtBSqJ4afBqL9R6U27oCicnghnsKxhUNOYt3RbqNvChBdTh5tg/640?wx_fmt=png&from=appmsg "")  
  
在我谈论恢复令牌之前，我刚刚提到恢复令牌的设置发生在初始化逻辑的末尾。让我们首先看看在进入恢复令牌的更多细节之前，初始化函数中首先配置的其他项目。  
  
另一个主要配置的项目是返回地址。需要设置此地址，以便我们希望执行在 VTL 0 中恢复。我们知道，具有内核模式 shadow stack 的用户模式线程在 Secure Kernel 中被标记为 2  
。目标返回地址是从 securekernel!SkmmNtFunctionTable  
 中提取的，基于此标志值。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnDrUDFBlTiaaZhR9aaficTVHp6F1j6LAFmaCzoKLZviaR1YVRkIt0YYtNg/640?wx_fmt=png&from=appmsg "")  
  
使用 SourcePoint，我们可以看到这实际上指向 nt!KiStartUserThread  
（Flags & 2 != 0  
）。我们可以看到这被存储在目标 shadow stack 上（SK 当前映射的目标 shadow stack 在下面的图像中位于 R10  
 中）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnSIv1ARZIRsRjQicSJlGowH8iaP21ZxicaicQUPOTHGnwNalMKov3L456eA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnnSMXNHiaZsJSAA7ia9McnA7Rhe0XKtHOzAWNh3hxAb3hUP4a72KyPfYA/640?wx_fmt=png&from=appmsg "")  
  
在返回地址复制到 shadow stack 后，这也是 OutputShadowStackAddress  
 被填充的地方，它直接返回给 VTL 0 作为 VTL 0 虚拟地址空间中的目标 shadow stack。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnWNiaKwBtBSqJ4afBqL9R6U27oCicnghnsKxhUNOYt3RbqNvChBdTh5tg/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到，OutputShadowStackAddress  
 将简单地包含地址 shadow_stack + 0xff0  
（加上掩码 1  
）。在我们的案例中，这是恢复令牌！恢复令牌就是 shadow stack 上令牌的位置（在我们的案例中为 shadow_stack + 0xff0  
 或与 1  
 进行或运算）。  
  
此外，根据 Intel CET 规格，恢复令牌的最低位保留用于表示“模式”。1  
 表示此令牌与 rstorssp  
 指令兼容（我们稍后将讨论）。  
  
回到之前，我提到这是一个恢复令牌，但并没有真正说明我是如何知道的。我是如何验证这一点的？我稍微跳过了一点，让安全系统调用返回（别担心，我仍然会展示 shadow stack 创建的完整分析）。当调用返回时，我检查了返回的 shadow stack 的内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnLQqDt8mrviaQWRjTpYGH9NtCNlf34gFibsqibxdEIpbnib6ibx0Vms0no2g/640?wx_fmt=png&from=appmsg "")  
  
如上所示，如果我们清除恢复令牌的最低位（该位保留用于“模式”），并使用此令牌转储内存内容，则此恢复令牌确实指向从安全系统调用创建的 shadow stack！这意味着，至少我们知道我们正在处理一个监督 shadow stack 令牌（即使我们还不知道是什么类型）。如果这是一个恢复令牌，则该令牌将指向“当前”shadow stack（在这种情况下，当前并不意味着当前正在执行，而是指从目标 shadow stack 创建操作返回的 shadow stack）。  
  
要确定这是否是恢复令牌，我们可以在此令牌上设置一个访问中断断点，以查看它是否被访问。这样做后，我们可以看到它被访问了！请记住，访问中断断点会在执行完 offending 指令后中断调试器。如果我们查看前面的指令，我们可以看到这是由于 rstorssp  
 指令的结果！这是一条“恢复保存的 shadow stack 指针”指令，它消耗了恢复令牌！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqndGZndXVcCmqphJ0WWJks2kibK6YBYlqibQwEnVjKwsHGdat2iasXEMB8A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnR1SbNWbF8QxERXHT8TkvnQHoiaH8Zib2fDJHJv1Wbe2bww0OicsFZdoYg/640?wx_fmt=png&from=appmsg "")  
  
当发生 rstorssp  
 指令时，恢复令牌（现在是 SSP）被替换（交换）为“先前 SSP”令牌 - 这是旧的 SSP。我们可以在倒数第二张截图中看到，恢复令牌被替换为其他地址，即旧的 SSP。如果我们检查旧的 SSP，我们可以看到与此堆栈相关的线程正在执行与我们的目标 shadow stack 类似的工作。  
  
这概述了如何在安全系统调用的结果下切换到目标 shadow stack！为“在范围内”的 shadow stack 创建了一个恢复令牌，当执行返回到 VTL 0 时，使用 rstorssp  
 指令作为执行的一部分切换到此 shadow stack！感谢我的朋友   
Alex Ionescu  
 一如既往地为我指明了恢复令牌的方向。  
  
接下来，在初始化完成后（令牌和目标返回地址已设置），Secure Kernel 对 shadow stack 的使用完成，这意味着我们不再需要 hyperspace 映射。请记住，这只是 Secure Kernel  
 对目标 shadow stack 的映射。尽管此页面将从 Secure Kernel 的 虚拟地址空间  
 中取消映射，但这些更改仍将保留在 物理  
 内存中。通过检查与目标 shadow stack 相关的 物理  
 内存，可以看到这一点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnianiat2u5a0XXt4AUlkMA0B4OKyTXESryBHcINaXkV7AJtpBV6BVQPBA/640?wx_fmt=png&from=appmsg "")  
  
在准备好 shadow stack 后，实际上最后要做的事情是 Secure Kernel 为相关的 物理  
 页面提供适当的权限。这同样是通过 securekernel!SkmiProtectSinglePage  
 的 HvCallModifyVtlProtectionMask  
 超调用来完成的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnyPYrWiaUTHC0bicQTDia3VT1cYqicZCpjSeoCBxkoaDKReIOzdJ0c2T9Kw/640?wx_fmt=png&from=appmsg "")  
  
所有参数都是相同的，除了标志/掩码。HV_MAP_GPA_READABLE  
（0x1  
）与似乎是一个未记录的值 0x10  
 结合在一起，我将其称为 HV_MAP_GPA_KERNEL_SHADOW_STACK  
，因为它没有官方名称。  
Intel SDM 文档  
对此提供了一些见解。我们称之为 HV_MAP_GPA_KERNEL_SHADOW_STACK  
 的掩码位可能在 EPTE 中设置第 60 位（SUPERVISOR_SHADOW_STACK  
）。这肯定是我们 0x11  
 掩码中的 0x10  
 所表示的。这将标记页面在 VTL 0 的上下文中被视为只读，并且也被超管视为内核模式 shadow stack 页面！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnhcZBibb45RLOgb90nC2JwdfqpnuTmrfiak2x9hfCL7221VjibCWictI3jQ/640?wx_fmt=png&from=appmsg "")  
  
在保护更改发生后，这就是在 Secure Kernel 中 shadow stack 创建过程中发生的所有有趣事情的结束！然后将 shadow stack 返回给 VTL 0，目标线程可以完成初始化。我们现在将注意力转向一些仍然需要 SK 支持的有趣边缘情况！  
## 内核 shadow stack 辅助功能  
  
到目前为止，我们已经看到了 Secure Kernel 如何准备内核模式 shadow stack。现在这一切都完成了，值得调查 Secure Kernel 负责的一些完整性检查和额外验证。在 ntoskrnl.exe  
 中有一个名为 nt!VslKernelShadowStackAssist  
 的安全系统调用。正如我们所看到的，它从几个不同的场景中被调用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnftZZY5EZRHjib6Y0UdrUQhibOU8p37OYmApmXUd6k4B8VpmPib5S95EMg/640?wx_fmt=png&from=appmsg "")  
  
在某些情况下，我们可以看到 shadow stacks 需要 合法  
 的修改。NT 将这些情况委托给 Secure Kernel，因为它是一个更高的安全边界，可以防止未经授权的“利用”这些情况。让我们检查其中一种情况。例如，考虑以下调用堆栈。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn6Y30EYxxE0ICicZmh3MibNLEWia5H3X7X2DCNnExJb8at4Of4unmQFVWA/640?wx_fmt=png&from=appmsg "")  
  
在这里，我们可以看到，作为文件打开操作的一部分，该操作执行了访问检查。如果未授予适当的访问权限，则会引发异常。这可以通过检查 NTFS 中引发异常的过程来看到，上面的调用堆栈标识了引发此异常的来源。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnA0I2tY11ygMeVJ7kP6nISzVPF9PUuJaTC1Q5LJ0jLqCcEnvsexbxNQ/640?wx_fmt=png&from=appmsg "")  
  
在这种情况下，最终会调度一个异常。当调度异常时，这显然会改变线程的上下文。为什么？因为线程不再执行之前的操作（访问检查）。它现在正在处理异常。然后调用适当的异常处理程序，以便可能纠正当前的问题。  
  
但是在调用异常处理程序之后，还有另一个问题。如果异常可以得到满足，我们如何让线程“回到”它之前正在做的事情？实现这一点的方法是 显式  
 构建和配置一个 CONTEXT  
 结构，该结构设置适当的指令指针（指向我们之前正在执行的操作）、堆栈、线程状态等。我们需要恢复的项目列表中的一项是堆栈。现在考虑我们实现了 CET！这也意味着我们需要恢复适当的 shadow  
 stack。由于 shadow stack 对于作为攻击缓解措施非常重要，因此我们不希望将这项工作委托给 NT，因为我们将 NT 视为“不可信”。这就是 Secure Kernel 的作用！Secure Kernel 已经知道 shadow stacks，因此我们可以将恢复适当 shadow stack 的任务委托给 Secure Kernel！这看起来是这样的。  
  
我们可以将导致安全系统调用调用的步骤视为“准备” CONTEXT  
 结构，包含恢复执行所需的所有适当信息（这些信息是从展开信息中收集的）。然而，在实际让执行恢复之前，我们要求 Secure Kernel 恢复适当的 shadow stack。这是通过 nt!KeKernelShadowStackRestoreContext  
 完成的。我们可以首先看到，CONTEXT  
 记录已经准备好将指令指针设置回 Ntfs!NtfsFsdCreate  
，这是我们在引发异常之前正在执行的函数，如果我们回顾之前显示的异常调用堆栈截图。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnicEg4dOuJhUczWJiaklicz6YY7MSZaHJqL1X5edNZOOSDicEGsFfz4fxrg/640?wx_fmt=png&from=appmsg "")  
  
作为异常恢复过程的一部分，再次检查内核 CET 的存在，并执行名为 rdsspq  
 的指令，将值存储在 RDX 中（该值用作 nt!KeKernelShadowStackRestoreContext  
 的第二个参数），然后调用目标函数以恢复 shadow stack 指针。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnxaRoZK0uiaTwHlUn9sjZoWsAds7YyRvBcTZKChqiaTT87fjLUA227NDA/640?wx_fmt=png&from=appmsg "")  
  
rdsspq  
   
是  
 一条将读取当前 shadow stack 指针的指令。请记住，shadow stacks 在 VTL 0 中是 只读  
 的（我们正在执行的地方）。我们可以读取 shadow stack，但无法破坏它。此值将由 Secure Kernel 验证。  
  
然后调用 nt!KeKernelShadowStackRestoreContext  
。检查 CONTEXT.ContextFlags  
 中的掩码 0x100080  
 的存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn2DLcTyH6N1lh13lNoskAATTplOgc6BIxHibqLsibOkWJEkQepwCRA7Cw/640?wx_fmt=png&from=appmsg "")  
  
0x100080  
 实际上对应于 CONTEXT_KERNEL_CET  
，这是最近（相对而言）添加到 Windows SDK 的一个值。CONTEXT_KERNEL_CET  
 表示内核 shadow stack 上下文信息存在于 CONTEXT  
 中。唯一的问题是 CONTEXT  
 是一个文档结构，不包含  
 与内核模式下的 shadow stack 信息相关的任何字段。这实际上是因为我们 技术上  
 正在处理一个名为 CONTEXT_EX  
 的 未记录  
 结构，我的朋友 Yarden 和 Alex 在他们的   
博客  
 中讨论了用户模式 CET 内部。这一结构被扩展为包含一个   
文档化的  
 KERNEL_CET_CONTEXT  
 结构。KERNEL_CET_CONTEXT.Ssp  
 从结构中提取，并传递给安全系统调用。这是为了通过 Secure Kernel 进一步验证 shadow stack 的完整性。  
  
nt!VslKernelShadowStackAssist  
 然后将发出安全系统调用，提供验证所有内容所需的适当信息，并实际设置恢复的 shadow stack 指针（由于异常）。 （请注意，我称第二个参数为“可选参数”。我不确定它是否可选，因为大多数时候，当这是一个非零参数时，它来自 KTRAP_FRAME.Dr0  
，但我也看到过其他组合。我们在这里只是展示与异常相关的功能，而不关心其他场景）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnBlzwiaeLdZGHcytUMJiaia6OuNibMHrK9jLbCvXyyaaJRaktYvXEI8AXLQ/640?wx_fmt=png&from=appmsg "")  
  
这将使执行在 Secure Kernel 中重定向到 securekernel!SkmmNtKernelShadowStackAssist  
。在我们的案例中，执行将重定向到 SkmiNtKssAssistRestoreContext  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnUMnxHiaFPeF3Gv1Aqiaa4xZJ14cq7j2dbUdicfjSgjoUVRFgddwp21iang/640?wx_fmt=png&from=appmsg "")  
  
securekernel!SkmiNtKssAssistRestore  
 将在这里执行大部分工作。此函数将调用 securekernel!SkmiNtKssAssistDispatch  
，该函数负责验证上下文记录（特别是目标指令指针），然后实际更新 shadow stack 值。每当执行与 shadow stack 相关的指令（例如 rdsspq  
）时，目标 shadow stack 值将从监督 shadow stack MSR 寄存器中提取。例如，环 0 的 shadow stack 可以在 IA32_PL0_SSP  
 MSR 寄存器中找到。  
  
然而，我们必须记住，内核 CET 要求  
 启用 HVCI。这意味着 Hyper-V 将存在！因此，当通过 securekernel!SkmiNtKssAssistDispatch  
 更新 shadow stack 值时，我们实际上希望设置 VTL 0 的 shadow stack 指针！请记住，VTL 0 在技术上被视为“虚拟机”。  
Intel CET 规格  
 将来宾的 shadow stack 指针寄存器定义为 VMX_GUEST_SSP  
。这是 VTL 0 的 VMCS 的来宾状态的一部分！再次感谢 Andrea 指出这一点！  
  
VMCS 信息是如何更新的？当给定的 VM（在我们的案例中为 VTL 0）需要请求超管的服务（如超调用）时，将执行 vmexit  
 指令以“退出 VM 上下文”并进入超管的上下文。当发生这种情况时，各种“来宾状态”信息将存储在称为虚拟机控制结构的每个 VM 结构中。VMX_GUEST_SSP  
 现在是该保留的来宾状态的一部分，只有  
 超管能够操作 VMCS。这意味着超管控制来宾 shadow stack 指针（VTL 0 的 shadow stack 指针！）。VMX_GUEST_SSP  
 和 VMCS 维护的许多其他“寄存器”被称为“虚拟处理器寄存器”，可以通过超管更新 - 通常通过 vmwrite  
 指令。  
  
正如我刚才提到的，我们知道我们不希望 VTL 0 中的任何人能够写入此寄存器。为了避免这种情况，就像更新 VTL 0 页面（技术上是 GPA）的权限一样，Secure Kernel 请求超管执行此操作。  
  
如何更新来宾 shadow stack 指针？Secure Kernel 中有一个通用函数，名为 securekernel!ShvlSetVpRegister  
。此函数能够更新 VTL 0 的虚拟处理器寄存器（这将包括我们刚才提到的 VMX_GUEST_SSP  
）。这个函数之前已经被我的朋友 Yarden 在她的博客文章中写过   
关于 HyperGuard 的第三部分  
。此函数有一个目标寄存器，这是一个类型为   
type  
 HV_REGISTER_NAME  
 的值。这些寄存器值中的大多数通过 TLFS 进行了文档化。问题是我们案例中使用的寄存器类型是 0x8008E  
，这 不是  
 文档化的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnyTADEaXKg1hibLtmiaX46J7UDUeQr8icfOH53LdY3xFNiaJn0Tqk7icS0bg/640?wx_fmt=png&from=appmsg "")  
  
然而，正如我们之前提到的，我们知道由于正在发生的操作（由于上下文恢复而恢复 shadow stack），VTL 0 的 shadow stack 将因此需要更新。我们知道这不会是 IA32_PL0_SSP  
，因为这不是超管的 shadow stack。VTL 0 是一个“虚拟机”，正如我们所知，因此我们不仅可以推断，还可以通过 SourcePoint 确认目标寄存器是 VMX_GUEST_SSP  
。  
  
要检查 VMCS 更新，我们首先需要找到在 hvix64.exe  
（或 AMD 系统的 hvax64.exe  
）中操作发生的位置（这是 Hyper-V 二进制文件）。在 VMX 根模式下运行的 CPU（CPU 不在 VM 的上下文中执行）可以执行 vmwrite  
 指令，指定目标虚拟处理器寄存器值，并更新适当的来宾状态。由于 hvix64.exe  
 不包含任何符号，因此我很难找到该位置。从 Intel 关于 CET 的文档开始，VMX_GUEST_SSP  
 的目标值为 0x682A  
。这意味着我们需要定位任何时候 vmwrite  
 发生到此值。当我找到 hvix64.exe  
 中的目标地址时，我在目标函数上设置了一个断点。我们还可以在 RDX 中看到 Secure Kernel 希望设置的目标来宾 shadow stack 指针。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqn0YmVicRIDBuwlYbibEzKVa0HIRTXgiaPz8RiaPqqYXFLGhIWIlT3kR2EPw/640?wx_fmt=png&from=appmsg "")  
  
然后，我们可以使用实际的 SourcePoint 调试器的 VMCS 查看功能，实时查看 VMX_GUEST_SSP  
 的更新。  
  
之前：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnjibsu0Wib6CgkPZ40T7MUnZ10p3q2JqNGK3mI09VdH4vXkfNlXH5icicnA/640?wx_fmt=png&from=appmsg "")  
  
之后：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO3dxJtYg6nRGicIWfFnLUqnW9xThBQ5DjatbS3PSiboBUzj92fIleyuMaoOXToL2J6gUTQLB3CBcng/640?wx_fmt=png&from=appmsg "")  
  
这就是 Secure Kernel 在发生上下文恢复操作等情况下发出超调用以更新 VTL 0 的 VMCS 来宾状态中的 VMX_GUEST_SSP  
 的方式！  
  
感谢我的朋友   
Alex Ionescu  
、Andrea 和 Yarden 帮助我解答我遇到的各种行为问题。这是恢复操作的结束，securekernel!SkmmNtKernelShadowStackAssist  
 最终将返回到 VTL 0！  
## 结论  
  
我希望您发现这篇博客文章信息丰富！我在写作过程中学到了很多。我希望您现在能明白，为什么在 Windows 上需要 Secure Kernel 来支持内核模式 shadow stacks。感谢 Alan Sguigna 发送给我强大的 SourcePoint 调试器，以及我的朋友 Andrea、Yarden 和 Alex 帮助我理解我所看到的某些行为并回答问题！以下是我使用的一些资源：  
- Intel CET 规格文档  
  
- https://cseweb.ucsd.edu/~dstefan/cse227-spring20/papers/shanbhogue:cet.pdf  
  
- Intel SDM  
  
- https://xenbits.xen.org/people/andrewcoop/Xen-CET-SS.pdf  
  
  
  
