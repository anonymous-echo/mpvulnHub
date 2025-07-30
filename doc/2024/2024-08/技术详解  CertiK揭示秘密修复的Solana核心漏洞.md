#  技术详解 | CertiK揭示秘密修复的Solana核心漏洞   
原创 CertiK  CertiK   2024-08-28 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjibXV1ay7qsd0iczhtT83ydPJolvRxiaC7uxe0p7ohia3nxpnLu594mFJ2A/640?wx_fmt=png&from=appmsg "")  
  
  
# 1. Solana漏洞起因  
  
  
8月9日，Solana验证者和客户端团队齐心协力解决了一个严重的安全漏洞。Solana验证者Laine表示，这一过程始于8月7日，当时Solana基金会通过私人渠道联系了知名网络运营商。此次联系是秘密修补漏洞策略的一部分，旨在防止漏洞被以任何方式利用。补丁通过Anza工程师的GitHub存储库提供，使运营商能够独立验证和应用更改。  
  
这次秘密修复的详情可以在GitHub存储库最近一次发布的**Mainnet-beta**  
（https://github.com/anza-xyz/agave/compare/v1.18.21...v1.18.22）中找到，唯一的改变是rbpf SVM虚拟机，从8月9日的rbpf SVM虚拟机唯一**pull**  
（https://github.com/solana-labs/rbpf/pull/583）可以定位到漏洞所在，虽然这一过程是秘密进行的，但是依然是通过开源存储库，Solana顺利地过渡了这次安全性危机。这个漏洞究竟有多大危害，以至于让Solana团队如此重视？  
  
CertiK团队对这一漏洞进行了深入分析。漏洞存在于rbpf SVM虚拟机中，SVM（Solana Virtual Machine）是Solana区块链生态系统的核心组件之一，负责执行智能合约和去中心化应用程序。其核心原理是利用即时编译技术实现高性能的智能合约执行。由于Solana的高吞吐量和低延迟特性，SVM在Solana中扮演着至关重要的角色，为开发者提供了一个高效的去中心化应用开发环境，并且对Solana的安全性起着重要作用。  
  
本文  
将会详细分析漏洞的核心原理与影响。  
  
  
# 2. SVM虚拟机存在严重的指令漏洞  
  
  
SVM是Solana区块链平台的关键组成部分，用于提供高效、安全的执行环境，用于运行智能合约和分布式应用程序。  
SVM的设计采用了rbpf字节码解释器（interpreter）和即时编译器（JIT），通过全局状态和智能合约接口实现与区块链网络的交互。  
  
关于SVM虚拟机如何加载运行elf智能合约可以参考[上一次CertiK对rbpf的漏洞分析章节](https://mp.weixin.qq.com/s?__biz=MzU5OTg4MTIxMw==&mid=2247502980&idx=1&sn=7ba7670d5f9b63dfeb6a09ea12e7105f&scene=21#wechat_redirect)  
中关于SVM运行模式介绍。  
  
这次漏洞的核心补丁是**commit**  
（https://github.com/solana-labs/rbpf/pull/583）对rbpf SVM虚拟机的修复。漏洞的根源在于精心构造的  
`callx regs`  
指令会导致rbpf SVM虚拟机崩溃。接下来，我们将分析  
`callx regs`  
指令如何引发如此严重的影响。  
  
首先，我们需要了解SVM虚拟机中  
`SBF`  
指令  
`callx regs`  
的运行模式和基础信息：  
  
**a.**  
 SBF指令基本的寻址  
  
`SBF`  
指令的基本结构如下图所示，其中  
`program_vm_addr`  
是SVM虚拟机中指令的起始地址。对于SBFV1版本的智能合约，  
`program_vm_addr`  
计算公式为  
`text_section.sh_addr.saturating_add(ebpf::MM_PROGRAM_START)`  
。  
`text_section.sh_addr`  
是ELF头部的  
`text address`  
。在SVM虚拟机中，每条  
`SBF`  
指令的大小为  
`ebpf::INSN_SIZE`  
，即8字节。下图中的   
`program.len`  
表示n+1条`SBF`指令的总大小。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjUandQUykXyiaN6zhE4Cv8df2fxIInI6s0jkFMF3tdtbaPhnIL6v8Wjg/640?wx_fmt=png&from=appmsg "")  
  
**b.**  
 Callx regs的运行模式  
  
在SVM虚拟机中，  
`callx regs`  
指令的运行模式如下：  
`target_pc`  
是传入   
`callx`  
指令的寄存器值，并作为SVM虚拟机中的程序计数器（PC）偏移量。在执行  
`callx regs`  
时，两个关键检查用于确保寄存器值不越界。  
1. **检查程序起始地址：**  
确保  
`target_pc`  
不小于程序的起始地址。  
`program_vm_addr`  
代表  
`SBF`  
程序的起始地址。检查条件是  
`program_vm_addr <= target_pc`  
，确保  
`target_pc`  
不低于程序的起始地址，从而避免程序跳转到非法地址。  
  
1. **检查程序结束地址：**  
确保  
`target_pc`  
不超过程序的最大地址。  
`program.MaxAddr`  
代表  
`SBF`  
指令在程序中的起始地址加上整个程序的指令大小。检查条件是  
`target_pc < program.MaxAddr`  
，确保  
`target_pc`  
在程序的有效范围内，避免越界访问。  
  
如果这两个条件都满足，则程序会安全地跳转到指定的PC地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjtxcfvOpLkeYSiaBgFL8pWiaH7McWwTRBfQYicy5qiaEIkLInWXhyicQL8zA/640?wx_fmt=png&from=appmsg "")  
  
  
**c.**  
 漏洞的root cause  
  
通过前文对  
`SBF`  
指令基本寻址和  
`callx regs`  
运行模式的了解，我们可以分析 JIT模式下  
`callx regs`  
存在漏洞的关键原因。  
  
首先先分析下在JIT模式中  
`SBF`  
指令寻址映射到x86机器码的过程，  
`JitProgram`  
结构体包含了两个重要成员：  
1. **`pc_section`**  
：存储每个  
`SBF`  
指令映射到x86机器码在  
`text_section`  
中的偏移地址。这个字段提供了从指令到机器码的映射，使得在执行  
`SBF`  
指令时可以快速找到对应的机器码位置。  
  
1. **`text_section`**  
：存储x86机器码的内存区域。它包含了即时编译生成的机器码，供处理器在运行时执行。  
  
即使在执行x86机器码时，也需要根据  
`SBF`  
 指令寻址到相应的机器码。例如，  
`callx target_pc`  
指令中，  
`target_pc`  
可以通过索引  
`pc_section`  
数组寻址到相应的x86机器码偏移。如果  
`target_pc`  
偏移的换算过程出现问题，导致从   
`pc_section`  
取得的偏移不正确，可能会导致获取的执行的x86机器码不一致。  
  
```
pub struct JitProgram {
    /// OS page size in bytes and the alignment of the sections
    page_size: usize,
    /// A `*const u8` pointer into the text_section for each BPF instruction
    pc_section: &'static mut [usize],
    /// The x86 machinecode
    text_section: &'static mut [u8],
}
Initialization：
pc_section: std::slice::from_raw_parts_mut(raw.cast::<usize>(), pc) ->SBF指令偏移对应x86机器码偏移
write:
self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;->每一次编译SBF指令，每一条SBF对应x86机器码地址
```  
  
  
在  
`JitProgram`  
中初始化  
`pc_section`  
和  
`text_section`  
的流程如下：  
1. **确定页面大小**：通过  
`get_system_page_size()`  
获取系统的页面大小，这通常是内存管理的基本单位。  
  
1. **`pc_loc_table_size`**：  
`pc_loc_table_size`  
是  
`PC * 8`  
的大小，其中  
`pc`  
是传入的指令数量。此大小四舍五入到页面大小的倍数，因为  
`pc_section`  
存储的是  
`text_section`  
中对于x86机器码地址偏移，  
`usize`  
类型的地址大小在64位系统中刚好是8字节。  
  
1. **`over_allocated_code_size`**  
：  
`over_allocated_code_size`  
是  
`code_size`  
四舍五入到页面大小的倍数。这样做是为了确保分配足够的内存来存放x86机器码。  
  
1. **分配内存**  
：通过  
`allocate_pages`  
分配的内存总大小是  
`pc_loc_table_size + over_allocated_code_size`  
。  
`allocate_pages`  
返回一个裸指针，指向分配的内存区域。  
  
1. **初始化`pc_section`**  
：  
`pc_section`  
是一个可变切片，指向内存的起始部分，用于存放  
`pc`  
个x86机器码地址。通过  
`std::slice::from_raw_parts_mut`  
创建，  
`raw.cast::<usize>()`  
将裸指针转换为  
`*mut usize`  
类型，切片的长度为   
`pc`  
，每个元素的大小为8字节。  
  
1. **初始化**  
**`text_section`**  
：  
`text_section`  
是另一个可变切片，指向分配内存区域的后半部分，用于存放x86机器码。它从  
`pc_loc_table_size`  
位置开始，到内存的末尾。这通过  
`raw.add(pc_loc_table_size)`  
确定起始地址（跳过  
`pc_section`  
存储大小），大小为  
`over_allocated_code_size`  
。  
  
`pc_section`  
用于存储指令计数器位置表，大小为  
`pc * 8`  
，而  
`text_section`  
用于存储x86机器码，大小为  
`code_size`  
，所有内存分配都以页面大小对齐。  
```
fn new(pc: usize, code_size: usize) -> Result<Self, EbpfError> {
        let page_size = get_system_page_size();  （1、确定页面大小）
        let pc_loc_table_size = round_to_page_size(pc * 8, page_size); 
        （2、获取pc_loc_table_size值，用于pc_section切片大小，round_to_page_size()函数确保四舍五入到页面大小的倍数，pc_loc_table_size的大小需要指令数和8字节对齐）
        let over_allocated_code_size = round_to_page_size(code_size, page_size); 
        （3、获取over_allocated_code_size值，用于text_section大小）
        unsafe {
            let raw = allocate_pages(pc_loc_table_size + over_allocated_code_size)?;
            （4、分配内存，返回裸指针raw）
            Ok(Self {
                page_size,
                pc_section: std::slice::from_raw_parts_mut(raw.cast::<usize>(), pc),
                （5、初始化pc_section）
                text_section: std::slice::from_raw_parts_mut(
                    raw.add(pc_loc_table_size),
                    over_allocated_code_size,
                ),
                （6、初始化text_section）
            })
        }
    }
```  
  
`JitProgram`  
的每一次  
`compile``SBF`  
指令时候都会将偏移的  
`text_section`  
地址存储到  
`pc_section`  
中，而  
`text_section`  
保存了x86机器码的偏移地址：  
```
let text_section_base = self.result.text_section.as_ptr();（text_section_base 是一个裸指针，指向 text_section 的起始位置。）
self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;
（目标指针（text_section_base.add(self.offset_in_text_section)）被转换为 usize 类型并存储在 pc_section 的相应位置。）
```  
  
在  
`callx regs`  
指令中，通过传入的  
`target_pc`  
计算出相对地址后跳转到存储在  
`pc_section`  
中的x86机器码地址。在JIT模式中，通过计算  
`target_pc - program_vm_addr`  
获取相对地址。JIT模式下通过获取的相对地址和  
`self.result.pc_section.as_ptr() as i64`  
数组指针地址相加可以获取  
`pc_section`  
数组中存储的  
`text_section`  
地址。其中  
`self.result.pc_section.as_ptr() as i64`  
获取的是  
`pc_section`  
裸指针的数组基地址，  
`pc_section`  
是一个  
`&[usize]`  
类型的切片，想要正确索引  
`pc_section`  
数组的值，获取的裸指针地址索引偏移必须是8字节的整数倍。  
  
在了解完callx regs的寻址方式，接着分析造成漏洞root cause的地方。  
  
漏洞的根本原因在于获取相对地址的过程。  
`callx regs`  
指令的处理流程如下：  
  
1. 获取  
`target_pc`  
的值作为绝对地址。  
  
2. 绝对地址按照8字节对齐。  
  
3. 判断绝对地址是否越界。  
  
4. 获取相对地址。  
  
5. 通过相对地址和  
`pc_section`  
数组指针地址计算最终跳转的x86机器码地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jj1S1H1JYAdcFicyV2LeWrI37sMTyds1iaibk3pWAbobQYG8vgTPtTicfaZg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞的关键点在于第4步，合约中  
`program_vm_addr`  
和  
`target_pc`  
的值传入可控，  
`target_pc`  
的值为  
`callx regs`  
的值，而  
`program_vm_addr`  
的值需要根据ELF格式经过精心构造并且绕过SVM虚拟机对ELF格式的安全检查，就可以控制  
`program_vm_addr`  
的值。  
  
这里起始地址  
`program_vm_addr`  
值的构造需要注意SVM虚拟机中的主要几个检查：  
  
1. 这个检查代码的目的是计算ELF文件中入口点（  
`Entrypoint`  
）相对于文本段（  
`text section`  
）的偏移量，并检查这个偏移量是否是指令大小  
`ebpf::INSN_SIZE`  
的整数倍，目的是确保入口点（  
`Entrypoint`  
）在ELF文件的文本段（  
`text section`  
）中对齐到正确的指令边界，由于  
`text_section.sh_addr`  
用作  
`program_vm_addr`  
的偏移，所以这里得和入口点（  
`Entrypoint`  
）的偏移对齐：  
```
// calculate entrypoint offset into the text section
let offset = header.e_entry.saturating_sub(text_section.sh_addr);
（这一行计算入口点 header.e_entry 和文本段基地址 text_section.sh_addr 之间的偏移量。saturating_sub 方法确保如果计算结果为负数，结果不会出现溢出，而是会返回 0。）
if offset.checked_rem(ebpf::INSN_SIZE as u64) != Some(0) {
        return Err(ElfError::InvalidEntrypoint);
}
（这一行检查偏移量 offset 是否是指令大小 ebpf::INSN_SIZE 的整数倍。checked_rem 方法用于计算偏移量对指令大小的模，并确保计算不会出现溢出。!= Some(0) 表示如果模结果不是 0（即偏移量不是指令大小的整数倍），则进入条件块。）
```  
  
2. 检查入口点  
`header.e_entry`  
是否在  
`.text`  
节的虚拟地址范围内。如果入口点不在该范围内，返回  
`ElfError::EntrypointOutOfBounds`  
错误。  
```
let text_section = get_section(elf, b".text")?;
if !text_section.vm_range().contains(&header.e_entry) {
    return Err(ElfError::EntrypointOutOfBounds);
}
```  
  
`target_pc`  
作为绝对地址在第二步中按照8字节对齐，是8的整数倍，  
`  
target_pc  
`个位数只要小于8，执行对齐操作后将为0，大于等于8将为8，传入正常的  
`program_vm_addr`  
与8字节对齐的值将不会造成越界，只要获取到的  
`program_vm_addr`  
为并不与8字节对齐且小于8，  
`target_pc`  
减去  
`program_vm_addr`  
，可以获取到不与8字节对齐的相对地址，这里获取到的可控的相对地址范围为（  
`relative address < number_of_instructions * INSN_SIZE`  
），相对地址将会用作索引  
`pc_section`  
数组，这里计算方式是直接获取  
`self.result.pc_section.as_ptr() as i64`  
裸指针进行切片地址索引，未与8字节对齐的相对地址将会导致  
`pc_section`  
数组基指针引用错误，将会获取到一个越界地址，而越界的范围需要小于  
`number_of_instructions * INSN_SIZE`  
，这个非法地址将会导致后续call跳转到一个不一致的地址，假如访问到非法地址程序系统将会抛出段错误  
`Segmentation fault`  
，这将导致SVM虚拟机直接崩溃，如果通过精心构造的内存数据，可能会获取到一个能控制的任意跳转地址，  
后续甚至执行任意命令  
！  
  
**d.**  
 漏洞修复  
  
漏洞修复后的补丁对比如下：  
  
1. **绝对地址**：获取  
`target_pc`  
的值作为绝对地址。  
  
2. **计算相对地址**：首先通过减去  
`program_vm_addr`  
来获取相对地址。这一步确保了后续操作能够正确处理内存对齐问题。  
  
3. **内存对齐**：将相对地址按照8字节进行内存对齐。  
  
4. **越界检查**：判断对齐后的相对地址是否越界。  
  
5. **获取跳转地址**：最终计算出  
`PC`  
跳转的地址。  
  
修复漏洞的关键在于第一步，通过首先获取相对地址并确保其正确对齐，从而避免了之前未对齐带来的问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jj8kxGXgNU4MiaS0GfYHQD5zXNkYA5wmiaBWicF5D5qICT3ia6Q8OmhETvwQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
# 3. SVM漏洞x86代码调试与复现  
  
  
在这一章节，我们  
将通过分析代码和漏洞调试来复现问题。  
存在漏洞的合约POC构造如下：  
  
**a.**  
 SBF指令构造  
  
假设  
`rax = target_pc`  
且  
`target_pc = 0x100000129`  
，以下是相关指令的构造，这里的r1在SVM中为rax：  
```
rsh64 r1, 2        ; 将 r1 寄存器的值右移 2 位
or64 r1, 0x129     ; 将 r1 寄存器的值与 0x129 进行按位或运算
callx r1           ; 调用 r1 寄存器指定的地址
```  
  
这些包含的  
`SBF`  
指令被编译成ELF合约，版本为SBFV1。  
`text_section.sh_addr`  
通过以下计算得出：  
```
let text_section_info = SectionInfo {
            .............
            vaddr: if sbpf_version.enable_elf_vaddr()
                && text_section.sh_addr >= ebpf::MM_PROGRAM_START
            {
                text_section.sh_addr (SBFV2)
            } else {
                text_section.sh_addr.saturating_add(ebpf::MM_PROGRAM_START) (SBFV1)
            },
            offset_range: text_section.file_range().unwrap_or_default(),
        };
```  
  
通过  
`readelf`  
工具，可以查看编译出的包含上述  
`SBF`  
指令的执行合约ELF文件的头部信息，其中  
`.text`  
段的地址为  
`0x121`  
，这里通过正常的合约编译出来的ELF结构并不能完全控制  
`.text`  
部分，需要精心修改  
`.text`  
段的  
`address`  
和  
`Entrypoint`  
的偏移，然后修复相应的ELF结构，才能得到能正确执行的合约。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjRVMhBLG23wicxBudZbve6CXXEb5gSluYJ6894XKaEDuaZME5weWZlpQ/640?wx_fmt=png&from=appmsg "")  
  
最终的  
`program_vm_addr`  
计算如下：  
```
text_section.sh_addr = text_section.sh_addr.saturating_add(ebpf::MM_PROGRAM_START);
```  
  
在上述代码中，  
`program_vm_addr`  
的最终值为  
`0x100000121`  
。  
  
**b.**  
 SBF指令构造  
  
在JIT模式下，将  
`SBF`  
指令翻译为x86_64汇编指令如下：  
```
shr    rsi,0x2
mov    r10,0x33fe958d
add    r10,0xffffffffcc016b9c
or     rsi,r10
```  
  
在调试器中，  
`rsi`  
计算出的  
`target_pc`  
值为  
`0x100000129`  
，这里的  
`target_pc`  
只需要小于  
`number_of_instructions * INSN_SIZE`  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jj3RO1II30cSqvCUfoib4Tq1euHXnfO7rEnWvLYE8LsVgafSAiccrLMPwA/640?wx_fmt=png&from=appmsg "")  
  
  
获取  
`target_pc`  
后，进入  
`call`  
地址检查流程，最终得到  
`call_address`  
：  
```
and       rax,0xfffffffffffffff8 (absolute address &= - ebpf::INSN_SIZE(8) ) （绝对地址对齐）
movabs    rbp,0x100000139
cmp       rax,rbp             （判断target_pc是否小于地址加指令总数边界）
jae       0x7ffff7e9b0da       CALL_OUTSIDE_TEXT_SEGMENT
movabs    rbp,0x100000121
cmp       rax,rbp              （判断target_pc是否大于等于起始地址边界）
jb        0x7ffff7e9b0da       CALL_OUTSIDE_TEXT_SEGMENT
sub       rax,rbp     （获取相对地址，因为program_vm_addr没有保证8字节内存对齐，这里相对地址为7，而存储指令的内存地址是按照8字节来索引的)
mov       r11,rax
shr       r11,0x3     （这里r11 = rax / 8，用作后续的CU计算，不影响漏洞触发）
movabs    rbp,0x7ffff7e9a000   （获取pc_section数组的基地址这里是：0x7ffff7e9a000，0x7ffff7e9a000作为pc_section数组基地，这个地址数据连续保存了3个SBF指令映射到x86机器码的地址）
add       rax,rbp         （pc_section.address + 7，0x7ffff7e9a007）
mov       rax,QWORD PTR [rax+0x0] （这里将会获取越界数据，地址0x7ffff7e9a007对应的8字节数据作为后续的call地址，而这个call地址是无效数据，是个非法地址）
```  
  
在调试器中获取到相对地址，  
`relative address = absolute address - program_vm_addr`  
如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jj0dkRWLWL66Zj1oI367UJzm6XHIkbPMcCQYnTWejoeWURL1r2e4EjZw/640?wx_fmt=png&from=appmsg "")  
  
获取  
`pc_section`  
数组的基地址：  
`0x7ffff7e9a000`  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjJqO5QSWLgtwMh34nnIPAClSb2mtmIOmAsd9m1ElC1X1JALJGTz0ibmg/640?wx_fmt=png&from=appmsg "")  
  
`pc_section`  
数组的基地址  
`0x7ffff7e9a000`  
中连续保存了3个  
`SBF`  
指令映射到x86机器码的地址分别是：  
`0x7ffff7e9b6d0`  
、  
`0x7ffff7e9b6d4`  
、  
`0x7ffff7e9b6e5`  
，但是引用地址  
`0x7ffff7e9a007`  
获取的值是  
`0x7ffff7e9b6d400`  
，这是个无效的非法地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjbR70ZiaklsndT0K0NRicibynxoMWAzVjqwia8KtrAPKVoibd5zYDXHxiaVVw/640?wx_fmt=png&from=appmsg "")  
  
最后直接  
`call`  
越界的非法内存地址，造成段错误  
`Segmentation fault`  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjicFwqHrmlibao1pYEYTl7Px9A741VFDLyIq74dd7CO4Gy1K9RbajJnrA/640?wx_fmt=png&from=appmsg "")  
  
**c.**  
 补丁commit  
  
存在漏洞的  
`commit`  
补丁如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjPRpasHurficpjhk9lxfY9ias7UYEuibFYCHIWdDwbSp4cVvYTsibdac3oQ/640?wx_fmt=png&from=appmsg "")  
  
  
# 4. SVM虚拟机指令漏洞影响  
  
  
Callx指令在智能合约中至关重要。内存越界常常成为底层漏洞的根源，而在SVM虚拟机中，尤其是在Solana链上，这种漏洞可能导致SVM崩溃，使运行恶意合约的Solana节点无法正常使用，如果通过恶意攻击者进行精心构造的内存布局甚至会导致任意代码执行，篡改合约执行数据。此外，这个漏洞的生命周期可能长达2年以上。Solana对这一漏洞的秘密处理非常有效，成功保护了链上资产和用户利益。随着类似SVM虚拟机漏洞的减少，Solana也将变得更加稳定。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnC4GJiaB5Hib0852qEb077jjYZB9CHib9MSyhw06hIkwo63ByVFmaXKWWibN56lm3xQ5BSnOJljGnyxg/640?wx_fmt=png&from=appmsg "")  
  
