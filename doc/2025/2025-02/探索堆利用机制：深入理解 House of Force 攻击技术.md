#  探索堆利用机制：深入理解 House of Force 攻击技术   
darkrelay  securitainment   2025-02-13 22:01  
  
> 【翻译】Exploring Heap Exploitation Mechanisms Understanding the House of Force Technique  
  
## 堆利用技术简介  
### 预备知识  
  
在深入探讨堆利用技术之前，建议您具备以下基础知识：  
- 对计算机内存架构有基本了解，包括栈 (stack) 和堆 (heap) 的概念  
  
- 熟悉 C 编程语言  
  
- 掌握基本数据结构和指针知识  
  
- 具备 Linux 命令和调试工具（如 GDB）的基本使用能力  
  
即使您不是这些领域的专家，本文包含相关解释说明来帮助您理解核心概念。但具备这些基础知识将极大提升您对堆利用技术的理解深度。  
### 什么是堆？  
  
**堆是程序运行时动态分配内存的存储区域**  
。其内存地址通常从低到高增长，与栈不同（在大多数架构中栈从高地址向低地址增长）。**堆的关键优势在于允许在程序执行期间动态调整已分配内存的大小**  
。  
  
可以通过**malloc() 或 calloc() 等函数**  
在堆上分配内存。这些函数以请求的内存大小为参数，并返回指向分配空间的指针。当内存不再需要时，**应使用 free() 函数释放内存**  
以防止内存泄漏。  
  
下方代码（及配图）展示了使用 malloc 进行堆内存分配的示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0F13c013iaLVL5yvWHRfV6OXzVy4IIVZ4uvicLRqzdEmkbHToVbJenQCMQ/640?wx_fmt=png&from=appmsg "")  
  
使用 malloc 分配内存的 C 代码示例图  
```
#include <stdio.h>#include <stdlib.h> // For malloc and freeint main() {    int *ptr; // Pointer to allocated memory    // Allocate memory for 1 integer    ptr = (int *)malloc(sizeof(int));    // Check if malloc succeeded    if (ptr == NULL) {        printf("Memory allocation failed!\n"); // Exit with error        return1;     }    // Assign and display a value    *ptr = 42;     printf("Value: %d\n", *ptr);    // Free the allocated memory    free(ptr);    return0;}
```  
### 堆内存段  
  
堆 (heap) 和栈 (stack) 内存段应仅设置为可读和可写，而不应具有可执行权限。这是因为如果攻击者能够劫持程序控制流并操纵指令指针 (RIP/x64 位或 EIP/x32 位)，他们将能执行任意代码。  
- 要查看 Linux 中运行进程的内存区域和其他段，首先需要通过以下命令获取进程 ID(PID)：  
  
```
ps aux | grep <process_name>
```  
- 然后，使用以下命令查看内存映射：  
  
```
cat /proc/<pid>/maps
```  
  
在下图中，我们可以看到堆的起始和结束位置，以及栈的分布。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0Fd7xNkIYQTHOgmPiby32MibE9hfC9Q6Ut3rxrwLiaBGvXyia7P8yQicaCMRQ/640?wx_fmt=png&from=appmsg "")  
  
Linux 程序内存映射示意图  
  
如果聚焦观察堆内存区域，在第二列权限描述中可以看到读写权限被设置。然而在权限列的第三个条目中，其值为"-"，表明**该区域不可执行**  
。  
### 非堆内存区域  
  
了解堆之后，我们简要讨论哪些内存区域不属于堆内存：  
- **栈内存 (Stack Memory):**  
 存储局部变量并管理函数调用。与堆不同，栈不具备动态性且**具有固定大小**  
。  
  
- **全局/静态内存 (Global/Static Memory):**  
 存储程序执行期间使用的全局变量和静态变量。该内存区域在程序整个生命周期持续存在。  
  
## 动态内存分配器  
  
内存分配器对操作系统管理至关重要。它们负责程序执行期间的内存分配、释放和重新分配，允许程序根据需求动态申请内存，适应不同数据规模和使用模式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0F8nHqlbTwUdEuAicjiaBKxyxy3X5dmGsREU9sSQlZX03P9KRyJibPwMVEQ/640?wx_fmt=png&from=appmsg "")  
  
内存分配示意图  
  
内存分配  
  
我们在程序执行期间动态分配存储空间，但无法在程序运行时"即时"创建新变量。  
### glibc：C 标准库  
  
GNU C 库  
（glibc）是包括 Linux 在内的类 Unix 操作系统的标准 C 库。它提供了动态内存分配函数如 malloc()、realloc() 和 free() 的实现，为 C 编程和内存管理提供基础功能。  
  
glibc 还提供**通过系统调用与内核交互**  
的高级函数。  
#### glibc 中的 malloc()  
  
glibc 中的 malloc() 函数是其内存分配器的组成部分，旨在高效管理动态内存。该分配器负责程序执行期间内存块的分配和释放，允许按需申请内存。  
##### ptmalloc()  
- 大多数 Linux 操作系统使用 ptmalloc() 作为 libc 中的 malloc() 实现  
  
- ptmalloc() 是 dlmalloc（Doug Lea's malloc）的改进版本  
  
- 针对多线程进行优化，更适合现代操作系统  
  
##### 内存块 (Chunk)  
- 内存分配器将堆划分为称为"块"的单元  
  
- 每个块包含记录大小和使用状态的元数据  
  
- 根据大小将块分类到不同的容器中，优化分配/释放流程  
  
##### 内存容器 (Bins)  
- **小容器 (Smallbins):**  
 在 64 位系统中管理小于 1024 字节的块。采用**双向链表**  
结构，使用前向 (fd) 和后向 (bk) 指针管理。共包含**62 个小容器**  
，每个对应特定尺寸规格。  
  
- **快速容器 (Fastbins):**  
 专为管理**小于 128 字节**  
的块设计，支持**快速分配释放**  
且无需合并空闲块。释放的块存入快速容器以便快速复用。共**10 个快速容器**  
，在**64 位系统**  
中每个快速容器包含 10 个链表，最大**块尺寸为 160 字节**  
。  
  
- **大容器 (Largebins):**  
 管理 64 位系统中**大于 1024 字节**  
的块。采用更复杂的链表结构，支持高效遍历和管理大内存块。  
  
- **未排序容器 (Unsorted bins):**  
 作为临时存储区，容纳不符合其他分类的**不同尺寸**  
空闲块。分配器在需要时会检索该容器，实现**灵活的内存管理**  
。  
  
##### 容器类型总结  
###### 单线程容器总数  
<table><caption><section><span leaf=""><br/></span></section></caption><tfoot><tr><td></td></tr></tfoot><colgroup><col/><col/></colgroup></table><table><tbody><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">容器名称</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">容器数量</span></strong></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">小容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">六十二</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">大容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">六十三</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">未排序容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">一</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">快速容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">十</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">线程缓存容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">六十四</span></p></td></tr></tbody></table>###### 尺寸范围  
<table><caption><section><span leaf=""><br/></span></section></caption><tfoot><tr><td></td></tr></tfoot><colgroup><col/><col/></colgroup></table><table><tbody><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">容器类型</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">尺寸范围</span></strong></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">快速容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">小于 128 字节</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">小容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">小于 1024 字节</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">大容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">大于 1024 字节</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">未排序容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">多种尺寸</span></p></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><strong style="font-weight: bold;color: black;"><span leaf="">线程缓存容器</span></strong></p></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><p dir="auto" style="font-size: 16px;padding-top: 8px;padding-bottom: 8px;margin: 0;line-height: 26px;color: black;"><span leaf="">24 – 1032 字节</span></p></td></tr></tbody></table>#### 内存竞技场  
  
在 glibc 中，**内存竞技场**  
的设计目的是让多个线程能够访问独立的内存区域而互不干扰。这些被称为"竞技场"的区域，可以帮助在多线程应用中更高效地管理内存分配。**每个竞技场都是连续的内存区域**  
。  
  
**每个应用程序都可以有一个主竞技场**  
，通常称为"主竞技场"。malloc() 函数包含指向这个主竞技场的静态变量，必要时可以创建额外的竞技场。**每个线程可以使用一个或多个竞技场**  
，主竞技场在程序启动时初始化。如果现有堆内存耗尽，可以分配新的竞技场来实现内存池的动态扩展。  
#### 系统的竞技场数量  
  
对于 32 位系统：  
```
Number of Arenas = 2 * number of cores
```  
  
对于 64 位系统：  
```
Number of Arenas = 2 * number of cores
```  
#### 如何查看内存竞技场？  
  
为了本次演示，我们将使用托管在 GitHub 仓库  
Heap Overflow Labs  
中的二进制文件和源代码。  
  
请按顺序执行以下命令进行环境配置：  
```
git clone [https://github.com/DarkRelay-Security-Labs/Heap-Overflow-Labs.git](https://github.com/DarkRelay-Security-Labs/Heap-Overflow-Labs.git)cd Heap-Overflow-Labs
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FdwsnvZ4MJQMuVV4fKqv2lvAZqWYlfRExwVa4pOs90ic44kt9dvZf1Gw/640?wx_fmt=png&from=appmsg "")  
  
查看内存竞技场  
  
查看内存竞技场  
  
要查看上述详细信息，我们执行以下步骤（按照前文所述设置 Git 仓库后）：  
- 在 GDB 中加载二进制文件：  
  
```
gdb ./main
```  
- 运行二进制文件  
  
- 使用 run（或 r）命令启动二进制文件执行：  
  
```
r
```  
- 中断执行  
  
- 当二进制文件运行时，**按 Ctrl + C**  
 暂停执行。这将使程序暂停在当前状态，以便我们检查内存结构。  
  
- 查看竞技场 - 使用 pwndbg 提供的 arenas  
 命令来检查竞技场：  
  
```
pwndbg> arenas
```  
  
此处，  
- **竞技场类型（Arena Type）**  
：表示内存竞技场的类型。本例中的 main_arena 表示 glibc 用于内存分配的默认竞技场。除非通过 pthread_create 等方法显式创建额外竞技场，否则该竞技场将被所有线程共享。创建额外竞技场通常用于多线程应用中，通过减少主竞技场的竞争来提高性能。  
  
- **竞技场地址（Arena Address）**  
：这是竞技场结构的内存地址（如 0x7ffff7bafc20）。它指向内存中的 malloc_state 结构，该结构包含关于竞技场的元数据，包括用于管理竞技场内动态内存分配的 bins 信息、锁机制和其他状态数据。  
  
- **堆地址（Heap Address）**  
：显示该竞技场管理的堆区域起始地址（如 0x602000）。堆是动态内存分配发生的区域，这个地址表示与主竞技场或其他竞技场关联的堆基址。对于主竞技场，除非为次要竞技场显式分配独立堆，否则该堆在所有线程间共享。  
  
- **映射起始与结束（Map Start and Map End）**  
：这些字段指定为竞技场堆区域分配的内存地址范围。例如，若范围是 0x602000 到 0x623000，表示操作系统已为该堆映射了此地址范围内的内存页。这些映射由操作系统通过 mmap 或 sbrk 等系统调用管理，当需要更多内存时会动态映射额外区域。  
  
- **权限（perm）**  
：表示内存区域的访问权限。例如 rw-p 表示该区域可读（r）、可写（w）且私有映射（p）。私有映射意味着对此内存区域的修改不会与其他进程共享，仅对当前进程有效。权限可能因内存段的用途而异（例如可执行代码可能具有 r-x 权限）。  
  
- **大小（Size）**  
：为此堆/竞技场分配的内存总大小（如 21,000 字节）。该值表示操作系统当前为此竞技场内部分配映射的内存总量。注意该大小会根据 glibc 分配器使用的策略（brk 或 mmap）随着更多内存分配而动态增长。  
  
## 通过 House of Force 技术进行堆利用  
  
在了解堆及其内部机制的基础知识后，我们现在可以开始探索堆利用技术。目前有超过 30 种已记录的堆利用技术，其中部分在现代内存分配器中已被修复，但有些在特定环境下仍然有效。  
  
本文将重点介绍一个简单但具有代表性的技术——"House of Force"。虽然不可能在单篇文章中涵盖所有堆利用技术，但我会尽力使这个技术尽可能易于理解。  
### 什么是 House of Force  
#### 背景  
  
House of Force 是一种堆利用技术，**源自更广泛的"House of XXX"框架**  
，该框架包含**多种利用 glibc 内存分配的方法**  
。该技术的基本概念可追溯至 2004 年发表的《The Malloc Maleficarum》，该文献提出了多种利用 glibc 内存管理漏洞的策略。  
#### House of Force 的核心原理  
  
在 glibc 2.29 之前的版本中，top chunk 的 size 字段缺乏完整性检查。通过覆盖该字段，攻击者可以请求特定大小来操纵内存布局。  
  
**示例**  
：假设 top chunk 起始于 0x405000，攻击者的目标位于 0x404000。  
  
通过溢出并修改 top chunk 的 size 为 0xfffffffffffffff1，下一次内存分配请求将导致分配的 chunk 与目标数据区域重叠。  
  
这种操纵**使攻击者能够控制内存分配**  
，可能导致任意代码执行或内存破坏。  
#### 为何仍具研究价值？  
  
尽管这是相对古老的技术，但理解其底层机制至关重要。掌握 House of Force**为应对更高级的堆利用技术奠定基础**  
，因为许多现代方法都基于类似原理。  
#### 简化视角  
  
简而言之，在 House of Force 中，攻击者通过堆溢出劫持分配大小，进而控制程序流并可能执行任意代码。  
### House of Force 的执行条件  
  
要成功实施 House of Force 技术，必须满足以下条件：  
- 控制 Top Chunk 的 Size 字段：攻击者必须能够覆盖 top chunk 的 size 字段以操纵其值  
  
- 控制堆分配大小：攻击者必须能影响内存分配的大小，通过覆盖 top chunk 大小来操纵内存布局。这种控制通过覆盖 top chunk 大小并随后影响 malloc() 调用的行为来实现  
  
运行以下命令查看二进制文件"main"的 checksec 输出：  
```
checksec --file=main
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FsMHKHpbmiblYcc3vor6LbnllzdDE4T8EWHjO23MyyEcW5wfAyAiaN9Cg/640?wx_fmt=png&from=appmsg "")  
  
main 文件的 Checksec 输出  
  
main 文件的 Checksec 输出  
  
在本案例中，checksec**输出显示"No PIE"**  
，这意味着二进制文件每次执行时都会加载到固定的内存地址。  
### 实施 House Of Force 攻击  
  
现在让我们**在 pwndbg 中运行二进制文件**  
，这是一个强大的二进制漏洞利用 GDB 插件，它还可以**直接在其环境中禁用 ASLR**  
。  
  
加载二进制文件后，程序提供三个选项：  
- AllocHeap 选项：该选项调用 malloc 函数，允许我们最多分配四次内存。它接收大小和数据作为输入，将指定的内存大小分配到堆中。  
  
- SavedString 选项：显示目标变量的值，该变量初始设置为**WRITEME**  
。  
  
- Exit 选项：退出程序。  
  
这些选项在程序菜单中呈现，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FzAeLlaUNiciaugkm4TsFFaG9stuELGTBxHA2OOnmsYZsG0FkBQYQfgOw/640?wx_fmt=png&from=appmsg "")  
  
通过 gdb 加载的程序菜单  
  
gdb 中加载的"main"二进制文件程序菜单  
  
我们的**目标是通过操纵 top chunk 并向其区域写入数据，使用 House of Force 技术覆盖目标值**  
。  
  
要继续操作，请按 Ctrl+C 中断程序执行并**进入 pwndbg 提示符**  
。从这里我们可以可视化堆段并分析其当前状态。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0Fd7ymw7iclogy1RD8WJ4liaoQYELIryATq04XXva6fDicMMyJpRGrr4HgQ/640?wx_fmt=png&from=appmsg "")  
  
堆段及其当前状态  
  
堆段及其当前状态  
  
我们成功分配了**24 字节的 chunk**  
，并确认其中**包含我们的数据"iamhere"**  
。但您可能注意到**实际分配的大小是 32 字节而非 24 字节**  
，这种差异源于对齐和元数据开销：  
- **对齐**  
：请求的大小（24 字节）会向上取整到 8 字节的最近倍数以实现内存对齐，最终产生 32 字节的分配  
  
- **元数据开销**  
：每个堆 chunk 包含 8 字节的元数据头，用于存储 chunk 大小和标志位。本例中的 0x21 值表示：  
  
- chunk 总大小为 32 字节（十六进制 0x20 表示大小 + 1 字节标志位）  
  
- 前一个 chunk 标记为"正在使用"  
  
在上述输出中，**0x603020 处我们观察到 top chunk 的起始位置**  
，其**大小为 0x020fe1**  
。该值是动态的，会随着更多 chunk 的分配而改变。top chunk 作为空闲内存池，允许堆在需要更多内存时扩展。随着内存的分配和释放，top chunk 的大小会相应调整，为未来分配提供灵活性。  
  
在后续操作中，我们分配了另一个 chunk，但这次**写入数据超过 24 字节**  
，**导致缓冲区溢出**  
。结果我们成功覆盖了 top chunk 的大小。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0F7DRLtJROvVicXQypM1ghNTciccLokJVslOe9wIWCiaGb8h5nqeByFdb1w/640?wx_fmt=png&from=appmsg "")  
  
通过超出 24 字节溢出缓冲区  
  
缓冲区溢出过程  
  
**注意**  
：我们使用的是 glibc 2.29 之前的版本，这些版本不对 top chunk 的大小进行完整性检查。这种验证缺失构成了安全漏洞。在后来的版本中，该问题被修复，并在 glibc 中引入了 tcache 机制等额外保护措施来缓解此类漏洞利用。  
  
现在让我们再次检查堆以观察变化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FJcEejMByZY4O4auL3NtSK5z1YOn7XyMzbeuib5qmD8jqRtyiasGym01g/640?wx_fmt=png&from=appmsg "")  
  
溢出效果可视化  
  
溢出效果可视化  
  
当我们写入超过 24 字节的数据时，**结果覆盖了 top chunk 的大小**  
。通过将 top chunk 大小改为**最大可能值 0xffffffffffffffff**  
，我们可以造成内存重叠。此时**malloc 会认为整个内存区域都是 top chunk 的一部分**  
，允许我们申请比原本预期大得多的内存。  
  
在本案例中，**目标变量驻留**  
在程序的**数据段**  
。由于堆现在假定 top chunk 大小为 0xffffffffffffffff，它将会把数据段视为堆的一部分。为了利用这一点，**我们需要计算目标变量与堆起始地址之间的"环绕距离"**  
。这个距离将决定我们需要申请多少内存来覆盖目标变量。  
## 推进漏洞利用阶段  
  
在成功构造堆溢出条件后，我们使用**pwn 库**  
继续执行漏洞利用策略的后续步骤。我们创建了一个 pwn 库模板来方便向堆发送构造数据。利用过程聚焦于计算环绕距离和操作堆内存以实现目标。  
### 计算环绕距离  
  
我们定义了一个名为 delta 的函数来计算两个地址之间的环绕距离。这对于确定需要写入多少数据才能到达内存中的目标变量至关重要。  
  
使用的公式如下：  
```
def delta(x, y):    return (0xffffffffffffffff - x) + y  # Calculate the wraparound distance between x and y
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FLhhl55G8iajSQeFNxUtE1ks0E0iasrz3XJ3Rw4lBB8faUWkvogVf20Cg/640?wx_fmt=png&from=appmsg "")  
  
计算环绕距离的公式  
  
计算环绕距离的公式  
  
**参数说明：**  
- x 表示起始地址（例如堆地址偏移量）  
  
- y 表示我们想要操纵的目标地址  
  
### 内存泄漏与初始化  
  
在进行内存操作之前，我们需要收集程序当前状态的关键信息，包括泄漏内存地址和初始化必要变量。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FlbmvgYqKiaKL1dEpmA6422k6sujiaicibg9nnncI5ovINjtQOib3A8owOicQ/640?wx_fmt=png&from=appmsg "")  
  
内存操作示意图  
  
内存操作流程  
  
操作步骤：  
- **启动进程：**  
 首先与程序交互并**获取 puts() 函数的地址**  
。通过从泄漏地址中减去已知偏移量，我们可以得到 libc 的基地址，从而定位关键结构  
  
- **泄漏堆地址：**  
 随后获取堆的起始地址。这个信息对后续内存操作和目标定位的精确计算至关重要  
  
这些初始化步骤确保我们获得可靠执行漏洞利用所需的必要信息  
### 堆内存操控  
  
在获取堆地址和目标变量地址后，我们可以进行内存分配和溢出操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FsrnTQXJdTJEwsSAckj16sG9lwe3ib5ia0vNHn371BM5mx2nyxyianfoiag/640?wx_fmt=png&from=appmsg "")  
  
利用获取信息操控堆内存  
  
利用收集信息进行堆操控  
- **首次分配：**  
 分配**24 字节并覆写 top chunk 大小为 0xffffffffffffffff**  
。这会欺骗分配器将整个内存区域视为堆的一部分，从而绕过大小检查  
  
- **计算环绕距离：**  
 使用 delta 函数**精确计算到达目标变量所需的字节数**  
，确保对内存布局的精准控制并避免副作用  
  
- **二次分配：**  
 根据计算的距离分配内存，通过溢出直接写入目标变量的内存位置  
  
- **最终分配：**  
 **再次分配 24 字节并向目标变量位置写入 payload**  
（例如"0xrottenrabbit"）。该值将覆盖原始目标变量，实现对程序流的控制或达成其他利用目标  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0Fc755fDWlQU77FnFTKhELWYoSK3Nbhs4Cy0gzOPODic3Gvj3Df7ghjcQ/640?wx_fmt=png&from=appmsg "")  
  
堆内存操作执行过程  
## 获取系统 Shell 之路  
  
在完成前期准备工作后，我们现在进入堆利用最激动人心的阶段：弹出系统 shell！这正是我们精心设计的堆操控最终展现威力的时刻  
### 地址信息  
  
"main"二进制程序输出以下地址：  
- puts 函数地址泄漏 ---> 0x7d95dc26df10  
  
- 堆地址 ---> 0x3dd6000  
  
由于 PIE（地址无关可执行文件）被禁用，二进制文件及其关联库每次都会加载到相同地址。这使我们能够可靠地利用 libc 地址泄漏来执行系统命令  
### 利用 malloc 钩子  
  
在 glibc 中，核心内存管理函数如 malloc() 和 free() 使用 glibc 数据段中的可写函数指针作为钩子。攻击者可以利用这些钩子在内存分配/释放期间重定向函数调用并执行任意代码  
  
通过覆写这些钩子，我们的目标是劫持程序执行流并执行任意命令  
### 连接__malloc_hook 的间隙  
  
要操作__malloc_hook，我们需要填补 top chunk 与__malloc_hook 指针之间的间隙。这包括：  
- **使用 malloc() 填补间隙：**  
 通过下方 payload 分配内存来覆写 top chunk 的大小  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FBwKne2D5SotZpic3FM7pZ8DBPnhshCNRREQSbb577gD2WpFwTP27S0g/640?wx_fmt=png&from=appmsg "")  
  
使用 malloc 填补间隙示意图  
  
使用 malloc() 填补间隙  
- **调整距离计算：**  
 计算到__malloc_hook 的距离时，需要从__malloc_hook 地址中减去 0x20 以应对对齐和元数据问题  
  
通过仔细执行这些步骤，我们可以重定向程序流并通过覆写的__malloc_hook 执行预定命令  
  
在上述操作中，**我们减去 0x20 是为了应对堆块元数据**  
，这些元数据在堆中位于用户数据之前。这种调整确保我们的计算与分配块的有效使用区域对齐  
  
距离计算提供了填补 top chunk 与 malloc 钩子之间间隙所需的精确偏移量。使用公式 libc.sym.__malloc_hook - 0x20，我们可以定位__malloc_hook 可用区域的起始位置。通过从这个值中减去 (heap + 0x20)，我们可以准确定位到 top chunk 中 payload 区域的起始位置  
  
计算距离后，我们将该值传递给 malloc() 来填补 top chunk 与__malloc_hook 之间的间隙  
  
填补间隙后，我们用 payload 覆写 malloc 钩子。例如，我们再次**分配 24 字节后跟随机地址**  
（如 0xdeadbeef）来**展示对执行流的控制**  
。这将破坏程序流并中断执行。为确保内存地址可预测，请使用 GDB 在禁用 ASLR 的情况下运行程序。在 Vim 命令行模式中执行：  
```
`:!./% GDB NOASLR
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FC4yPAoKPTYhdyicLhic70nibZecTPVbEAyyfQOuImMlQ7iaPHNjgwA7HXQ/640?wx_fmt=png&from=appmsg "")  
  
running_no_aslr_1  
  
如果我们尝试调用 malloc 进行内存分配，程序将因"无效地址"错误而停止执行，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0Fa1F9uYNNVzpPuP9r9vYuh6bHoJNwzBn4L2sSA1fgML8wdoUuzTKJ5Q/640?wx_fmt=png&from=appmsg "")  
  
执行最终漏洞利用过程  
  
现在，我们将原本使用的 0xdeadbeef 地址替换为 libc 中的/bin/sh 地址。这使我们能够执行 system("/bin/sh") 命令，**成功弹出一个系统 shell**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0FXiaIMdY0NdbMeNqLMibCqPZa7ulhj4PrWJ1ADiaAXklMyiamEn6kwJMufQ/640?wx_fmt=png&from=appmsg "")  
  
在 libc 中搜索/bin/sh 字符串位置  
```
malloc(24, b"Y"*24 + p64(0xffffffffffffffff))  # Overwrite top chunk size to maximumdistance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)  # Calculate distance from current top chunk to __malloc_hookmalloc(distance, "/bin/sh\0")  # Allocate memory to overlap __malloc_hook and write "/bin/sh" stringmalloc(24, p64(libc.sym.system))  # Overwrite __malloc_hook with system() function addresscmd = next(libc.search(b"/bin/sh"))  # Find "/bin/sh" string in libcmalloc(cmd, "")  # Trigger system("/bin/sh") to pop a shell
```  
## 具体实现步骤  
1. 写入/bin/sh:  
  
1. 第 3 行的_malloc(distance, "/bin/sh\\0")  
将/bin/sh 字符串写入计算得到的内存地址 (与__malloc_hook 对齐)。这**为执行 shell 做好载荷准备**  
  
1. 覆写__malloc_hook:  
  
1. 第 4 行的_malloc(24, p64(libc.sym.system))  
用 system() 函数地址覆盖__malloc_hook 函数指针。这确保**下次调用 malloc() 时会触发 system()**  
  
1. 调用 Shell:  
  
1. 第 5 行的cmd = next(libc.search(b"/bin/sh"))  
在 libc 中搜索/bin/sh 字符串的精确地址  
  
1. 第 6 行的malloc(cmd, "")  
触发 system("/bin/sh") 命令，**成功启动系统 shell**  
  
通过执行最后这个步骤，我们成功获取了 shell 访问权限。这展示了精确的堆操作技术结合 libc 内部知识如何实现程序执行流的控制。**获得的 shell 赋予我们对系统的完全访问权**  
，充分体现了这种漏洞利用技术的强大威力  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPDpiarAyI4sLJ9HFf6Sza0Fa1xmvDKd4fq7DWkiaa0M8YFrYaQxfMcrwffUXDKribqZvVRClem4jEibA/640?wx_fmt=png&from=appmsg "")  
  
最终漏洞利用执行效果  
## 结论  
  
House of Force 等堆利用技术揭示了 glibc 等内存管理系统的复杂性和潜在风险。尽管现代系统已修复许多此类漏洞，理解其机制对防御和识别潜在攻击仍至关重要  
  
通过研究块元数据操作、环绕计算和 malloc 钩子利用等概念，我们阐明了堆利用的基本原理。虽然 House of Force 等技术在多数现代系统中已失效，但它们为理解更高级的利用方法奠定了基础  
### 防御措施  
  
为防范此类漏洞，组织机构应当：  
- 启用 PIE、栈保护金丝雀和地址空间随机化 (ASLR) 等现代防护机制  
  
- 严格验证并适当净化所有输入数据  
  
- 尽量避免手动内存管理，使用 C++ 智能指针或 Rust 等内存安全语言的高级抽象  
  
- 采用强化版内存分配器  
  
- 确保 glibc 等库更新至最新版本，启用 tcache 和完整性检查  
  
## 参考文献  
- https://heap-exploitation.dhavalkapil.com/attacks/house_of_force.html  
  
- https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/  
  
- http://phrack.org/issues/66/10.html  
  
- https://github.com/shellphish/how2heap  
  
- https://www.exploit-db.com/docs/english/28476-linux-glibc-hooks.pdf  
  
  
  
