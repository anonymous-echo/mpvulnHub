#  通过系统调用 (POC) 绕过 AV/EDR 挂钩   
原创 影域  影域实验室   2024-08-19 14:36  
  
**免责声明：**  
  
本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。  
  
# 为了绕过 AV/EDR，通常会解除任何 AV/EDR 挂钩。但是，要解除 AV/EDR 挂钩，我们需要调用一个著名的 Win32 API VirtualProtect ，它最终会调用 ntdll.dll中的 NtVirtualProtectMemory ，并且大多数 AV/EDR 也可能都会挂钩它。然后出现了一种称为 直接系统调用 的技术，它可以帮助我们摆脱这种情况，即系统调用不会经过 ntdll 模块，因此放置在 ntdll 模块中的挂钩在系统调用期间不会受到影响。但是，不是来自 ntdll 或其他已知模块的系统调用被认为是可疑的。可以使用一种称为 挂钩涅槃的技术来检测直接系统调用 ，其中 使用了检测回调。  
  
每次内核返回到用户模式时， 都会检查  
**RIP寄存器以查看***  
*RIP** 指向的地址是否 在已知的模块地址范围内，否则将手动制作系统调用。  
  
由于会检查 RIP 指令来检测手动系统调用，因此可以通过间接跳转到系统调用指令所在的 ntdll 地址空间来绕过它。但是，我们不会这样做，而是利用 VEH   
**（向量异常处理程序）**  
 来修改上下文，尤其是 RIP 寄存器，以将我们带到系统调用地址。  
  
**注意**  
 ：我们将手动定位系统调用地址。此外，我们将在此 POC 中使用 VEH，因为当内核将控制权传递给 ring3 时，VEH 是第一个处理异常的。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylotg4RBMvZKpw0yJou3XXiaG9srmMIia9iaVnaIkWx1mibUHyGBRJGuLYKQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylBuicd5YRHpD60aupI0z6pUsibNqoYzjGZXB7SPG6Dz0lDP0aImXq9Gpw/640?wx_fmt=other&from=appmsg "")  
  
现在我们将定义我们将在此 POC 中使用的 NT API。现在我们需要初始化 NT API。在此之前，我们需要找出触发异常的方法，因为有多种方法可以触发异常（除以 0、int 3 等）。  
  
对于这个 POC，我们将使用   
**访问冲突异常（这是有原因的）**  
。以下是 NT API 的初始化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylWMricfHjNCQM7aTtrrbvicDG93TgreeV9X5ro27ibTJVRNA14He9EyE9A/640?wx_fmt=other&from=appmsg "")  
  
我们已经   
**用系统调用号**  
 而不是地址初始化了 NT API，调用此函数将导致异常 (   
**EXCEPTION_ACCESS_VIOLATION**  
 )。现在你可能已经明白为什么我们要用相应的系统调用号初始化 NT API。这样做有两个原因：  
1. **触发异常**  
  
1. **通过 RIP 指令将系统调用号传递给 VEH 处理程序。如果我们触发了其他异常，我们可能需要做额外的工作来将系统调用号传递给处理程序。**  
  
每当发生异常时，都会保存当前执行状态并将执行转移到异常处理程序；这样做是为了在处理异常后恢复正常执行。通常信息保存在以下结构中：  
1. KTRAP_FRAME   
：保存当前执行状态，即 CPU 寄存器和其他内容  
  
1. EXCEPTION_RECORD   
：记录异常代码，异常地址，下一个异常记录等信息。  
  
现在我们需要在 ntdll 中找到系统调用地址，以便我们可以修改 RIP 寄存器并将其设置为矢量处理程序中的系统调用地址。对于此 POC，有多种方法可以执行此操作，我们将检索随机 NT API 函数的地址并计算系统调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylCLzygZvZF4GruWK4UibDq47uq5PGhMyztqRFUSDzLzIAzRe6wxjXYaQ/640?wx_fmt=other&from=appmsg "")  
  
这个想法是从检索到的函数基地址遍历字节，直到我们得到我们正在寻找的指令字节序列，即   
**“ret”指令后的 syscall 指令。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiayls023gIXYsoCJnogRUHohj0vwTLAFJibETOhoOEYWRj2c4ZDrOgAwDEg/640?wx_fmt=other&from=appmsg "")  
  
现在，在处理程序中，我们将模拟系统调用存根。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylUfVbcgBv9Ul0bgl96FdC5Kxckd3GyONvRlAytvZZeeB0iaib2O8DqnibA/640?wx_fmt=other&from=appmsg "")  
  
之后我们将像平常一样调用 NT 函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylviaKC0gnZkNkOy31KjXuQrxgw5yib8zl0KuicZK2TumzDSCugLF0picYpw/640?wx_fmt=other&from=appmsg "")  
  
以下是执行流程：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylP7fP93H9IKDibVb27xjPlvsD5ibD7ddme2vVT4HGuqTGFibPo6ew3W9icg/640?wx_fmt=other&from=appmsg "")  
  
使用   
**直接系统**  
调用进行测试。代码经过修改，包含“   
**syscall-detect.dll**  
 ”（来自   
**syswhispers**  
），因为它将检测系统调用并阻止进一步的程序执行。Notepad.exe 用作测试代码注入的案例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiayltXppOhlBnGMkdVFJaBBwFkWPpBaoHcwboXMR6z2hACnVHqFDUdE4nQ/640?wx_fmt=other&from=appmsg "")  
  
使用矢量系统调用。能够成功使用系统调用检测 DLL 执行代码注入。无需解除任何对象等，因为我们已利用矢量异常处理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7SRRiazcGjCKyLBeRwJHvibiaylRsm1eEYcicxZr5qzSibzUSaiaSBgo7AMSGhYO9ZKp8ibzUcoeaxsOCLfzQ/640?wx_fmt=other&from=appmsg "")  
  
在启用 Bitdefender 的环境中测试了以下手动系统调用检测项目：  
  
https://github.com/xenoscr/manual-syscall-detect  
  
https://github.com/jackullrich/syscall-detect  
  
**要点：**  
1. 由于我们的系统调用经过了 Ntdll RIP 检查，因此手动系统调用检测被绕过  
  
1. 系统调用地址是在内存中计算的，因此我们不需要解除 AV/EDR 挂钩  
  
1. **在正常应用程序中调用AddVectoredExceptionHandler**  
本身看起来很可疑，因此需要做更多的工作才能隐秘地   
  
1. 仍然可以跟踪系统调用号来检测恶意行为  
  
1. 它只在 Bitdefender 上进行了测试，因此现在说它也能在其他 AV/EDR 上工作还为时过早  
  
## 打个广子  
  
**我们拥有专业的团队，可承接渗透测试，攻防演练，应急响应、钓鱼演练、ctf培训等比赛项目**  
  
****  
****  
****  
  
