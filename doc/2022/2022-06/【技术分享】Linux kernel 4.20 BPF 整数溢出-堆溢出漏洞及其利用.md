#  【技术分享】Linux kernel 4.20 BPF 整数溢出-堆溢出漏洞及其利用   
原创 ww9210  安全客   2022-06-16 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb4AYflVRQJaiaEkeT1A94HMxSNXevc931RAboviae7oaiblTAIpdrzHvB3pbWicZCFiavjFg6bJmyWYFTg/640?wx_fmt=png "")  
  
  
****内容简介  
  
我们可以100%稳定触发这个漏洞，并且可以利用它来进行本地提权获得root权限。这篇文章主要分析漏洞的成因以及基本漏洞利用方法。  
  
**漏洞板块**  
  
BPF(Berkeley Packet Filter)模块[1]是用于支持用户态自定义包过滤方法的内核模块，目前各大Linux发行版都默认开启了bpf支持，关于bpf官方文档的介绍如下：  
> Linux Socket Filtering (LSF) is derived from the Berkeley Packet Filter.Though there are some distinct differences between the BSD and LinuxKernel filtering, but when we speak of BPF or LSF in Linux context, wemean the very same mechanism of filtering in the Linux kernel.  
> BPF allows a user-space program to attach a filter onto any socket andallow or disallow certain types of data to come through the socket. LSFfollows exactly the same filter code structure as BSD’s BPF, so referringto the BSD bpf.4 manpage is very helpful in creating filters.  
  
  
**漏洞分析**  
### 引入时间  
  
该漏洞位于kernel/bpf/queue_stack_maps.c文件中，于2018-10-19在commit  
  
f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92  
中为bpf模块引入了名为queue/stack map的新功能。  
> Queue/stack maps implement a FIFO/LIFO data storage for ebpf programs.These maps support peek, pop and push operations that are exposed to eBPFprograms through the new bpf_map[peek/pop/push] helpers. Those operationsare exposed to userspace applications through the already existingsyscalls in the following way:  
> BPF_MAP_LOOKUP_ELEM -> peek  
> BPF_MAP_LOOKUP_AND_DELETE_ELEM -> pop  
> BPF_MAP_UPDATE_ELEM -> push  
  
### 影响范围  
  
该漏洞影响Linux Kernel 4.20rc1-4.20rc4，主要Linux发行版并不受其影响。  
### 整数溢出  
  
这枚漏洞的根本成因是在创建queue_stack_map时发生的整数溢出导致申请出的对象偏小，函数调用链如下：  
```
```  
  
漏洞函数queue_stack_map_alloc如下：  
```
```  
  
上述函数在计算size时，使用了用户传入的参数attr->max_entries。由于size的类型是u32, 如果attr->max_entries=0xffffffff，那么attr->max_entries+1时就会发生整数溢出使得size=0。后续在bpf_map_area_alloc函数中会申请一块大小为queue_size的堆内存，queue_size的大小由以下表达式计算：  
```
```  
  
可以看出，由于size  
在之前的计算过程中发生整数溢出变成了0，分配的大小只有sizeof(*qs)  
。  
### 堆溢出  
  
之后，可以在另一个bpf系统调用update这块map过程中，向这块过小的queue stack区域拷入数据，导致内核堆溢出。调用链如下：  
```
```  
  
其中发生溢出的是queue_stack_map_hash_elem()函数中的memcpy调用。由源码可知，memcpy的dst就是上面申请的queue stack区域，src是由用户态拷入的大小为qs->map.value_size的buffer, 拷贝长度由创建queue_stack时用户提供的attr.value_size决定，因此拷贝长度用户可控。  
  
queue_stack_map_push_elem()函数如下：  
```
```  
  
可以看出memcpy(dst, value, qs->map.value_size); //堆溢出  
处是一个明显的堆溢出漏洞。由于dst  
堆块在之前计算堆块分配大小的过程中发生了整数溢出大小只有sizeof(struct bpf_queue_stack)  
也就是256个字节，如果value_size > 256 - (&qs->elements - &qs)  
，就会发生越界拷贝。  
  
**漏洞利用**  
  
利用之前，我们先来总结一下该漏洞提供的基本能力：现在我们有一个整数溢出导致的堆溢出漏洞，溢出的长度完全可控，溢出的内容也完全可控，发生溢出的堆块(struct bpf_queue_stack)大小是256个字节。  
  
漏洞关键数据结构struct bpf_queue_stack  
定义如下：  
```
```  
  
我们需要在溢出之前完成堆风水，将一个包含函数指针或写指针的敏感指针“受害者”对象放在发生溢出的堆块后面。  
  
Linux内核的堆分配机制在分配堆块时，倾向于为相近种类，相同大小的堆块申请一块大内存，在这篇内存里存放的都是相同大小和相近类型的堆块。  
  
对于这个漏洞来说，虽然不能使用常见的struct file_struct  
来充当受害者对象，但漏洞对象本身就可以充当受害者对象。这是因为struct bpf_queue_stack  
的第一个成员bpf_map_ops  
就是一个包含许多函数指针的虚表指针，我们只需要连续申请两个bpf_queue_stack  
，就可以让第一个bpf_queue_stack  
发生溢出，改写后一个bpf_queue_stack  
的虚表指针。  
  
在bpf_map_ops  
这个虚表里面有许多的函数指针：  
```
```  
  
如果我们能通过堆溢出将ops指向一块伪造的虚表，那么就可能通过dereference这些函数指针中的任何一个实现控制流劫持，获得rip的控制权。为了找到使用这些函数指针的方法，我们既可以去仔细阅读相关的代码手动编写漏洞利用，也可以使用[2]中提到的under-context fuzzing+symbolic execution的半自动技术，通过fuzzing找到dereference这些函数指针的系统调用，并辅助生成后续的利用。  
  
本次发布的利用代码[4]使用close()一个bpf map的方法来获得控制流劫持的机会：  
```
```  
  
在close()  
受害者BPF map时，会将bpf_map_free_deferred()  
添加到队列并随后执行，通过将map->ops指向用户态可控位置，并且将ops.map_free设为任意值，我们就可以在执行map->ops->map_free(map);  
语句时将rip设置为任意值。  
  
在获得控制流劫持的机会后，对于SMEP, SMAP, KASLR等内核漏洞缓解机制的绕过仍然是漏洞利用的巨大挑战。我们仅公布绕过SMEP的利用代码，并对其他缓解机制的绕过作一些讨论。  
  
在公布的利用代码中我们针对仅有SMEP的防御的情况，选择了一种最基础的利用流程[3]：  
1. 堆风水  
  
1. 触发堆溢出  
  
1. 控制流劫持  
  
1. stack pivoting到用户态  
  
1. commit_cred(prepare_kernel_cred(0))提权  
  
1. swapgs  
  
1. 修复页表(针对KPTI(Kernel Page Table Isolation)在kernel页表中移除了用户态可执行代码)(optional)  
  
1. iretq  
  
1. get_shell().  
  
利用效果如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb4AYflVRQJaiaEkeT1A94HMxnYbACWyQHM8rdDBWkW0B38CUq93tul6TSXAxIMZ537SeCzBAdeX7rg/640?wx_fmt=png "")  
### SMAP绕过讨论  
  
SMAP防止ring 0代码访问用户态数据，Linux下的传统的绕过SMAP提权的方法包括以下几种：  
1. 利用JOP改写CR4寄存器关闭SMAP防御  
  
1. 利用call_usermodehelper 以root身份执行binary  
  
1. 通过内存任意读写直接改写当前进程cred。  
  
关于利这一个单个漏洞SMAP, KPTI, KASLR等其他防御机制的绕过，将在后续文章中进行详解。  
### KASLR绕过讨论  
  
Linux下的传统的绕过KASLR提权的方法包括以下几种：  
1. 近年来，有许多通过硬件侧信道绕过KASLR的工作，如prefetch, meltdown等  
  
1. 利用漏洞构造信息泄露  
  
1. 配合一个信息泄露漏洞  
  
## 时间线  
  
2018-10-19 漏洞引入  
  
2018-11-21 漏洞发现  
  
2018-11-22 漏洞利用  
  
2018-11-22 漏洞修补  
  
总结  
  
本文对一个Linux内核4.20中新引入的BPF模块整数溢出-堆溢出漏洞进行了分析，并介绍了其利用方法，本漏洞利用代码发布在[4]。不得不说新功能/新feature的添加是漏洞的一大来源。如果没有大量针对新功能code review和fuzzing来提升新功能的安全性，那么新的代码的安全性无法保证。安全不是一朝一夕，而是需要整个社区的长期投入。  
  
对于这个漏洞的分析和利用过程如有其它问题，欢迎联系我。  
  
e-mail:   
wuwei@iie.ac.cn  
 QQ: 544536427  
  
参考文献  
1. https://www.kernel.org/doc/Documentation/networking/filter.txt  
  
1. FUZE: Towards Facilitating Exploit Generation for Kernel Use-After-Free Vulnerabilities.  
  
1. https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP—Ropping-your-way-to—(Part-1)/  
  
1. 漏洞利用代码与对应内核 (exploit code and kernel image)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6OLwHohYU7UjX5anusw3ZzxxUKM0Ert9iaakSvib40glppuwsWytjDfiaFx1T25gsIWL5c8c7kicamxw/640?wx_fmt=png "虚线阴影分割线")  
```
```  
