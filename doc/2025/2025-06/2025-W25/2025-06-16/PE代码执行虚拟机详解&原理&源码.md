> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyOTc0NDY2Nw==&mid=2247485188&idx=1&sn=48ce12178a70e5b8f3ea47e79dd57e64

#  PE代码执行虚拟机详解&原理&源码  
原创 为了安全鸭  冲鸭安全   2025-06-16 06:30  
  
## 前言  
  
粉丝要求,安排!  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWKRp2d9CxB9Ums7dzyB9HBOczic9dYNG0kZBU47rgL9LlZlQicpibEF9WEBwzh9FQw6Iz3qubOJn0Rng/640?wx_fmt=png&from=appmsg "")  
  
不过我不知道是**PE代码虚拟执行**  
还是指**虚拟化壳**  
的. 而且还问不了!  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWKRp2d9CxB9Ums7dzyB9HBOoEdbjkXbUbgOt0aGUIm1f2LedA9gZWRKbsnrwwwQbT6dfHdD6wCEPw/640?wx_fmt=png&from=appmsg "")  
  
所以先写一篇关于PE代码虚拟机的，下一篇再写一个关于虚拟化壳的,全都要。  
源码先丢这里,可以看着源码对着学习  
https://git.key08.com/huoji/awesome_anti_virus_engine  
## 环境初始化  
  
这边我用的模拟执行框架是unicorn-engine,为了实现一个代码执行,我们需要先初始化模拟环境,包括SharedUserDataBase,Segment  
### 段寄存器 (Segment Registers)  
  
在Windows环境下，虽然现代操作系统主要使用平坦内存模型，但段寄存器（CS, DS, SS, ES, GS, FS）仍然在某些特定场景下扮演着重要角色，特别是FS和GS寄存器，它们常用于指向TEB和KPCR（Kernel Processor Control Region）等关键结构。这里我们为它们设置了默认的段选择子。  

```
// SetupVirtualMachine 函数片段
SegmentSelector cs = { 0 };
cs.fields.index = 1;
uc_reg_write(m_ucEngine, UC_X86_REG_CS, &cs.all);
// ... 其他段寄存器 (DS, SS, ES, GS) 类似设置

```

### SharedUserData  
  
这是一个位于 0x7FFE0000 的只读内存区域，包含了系统时间、系统版本等常用信息，许多Windows API会从这里读取数据。我们将其映射并写入真实系统的数据。  

```
// SetupVirtualMachine 函数片段
m_KSharedUserDataBase = 0x7FFE0000;
// ... 计算大小并映射
uc_mem_map(m_ucEngine, m_KSharedUserDataBase, m_KSharedUserDataSize, UC_PROT_READ);
uc_mem_write(m_ucEngine, m_KSharedUserDataBase, (void*)m_KSharedUserDataBase, m_KSharedUserDataSize);

```

### PEB  
  
PEB (Process Environment Block) 和 TEB (Thread Environment Block): 这两个结构体是Windows进程和线程的核心数据结构，包含了大量关于进程、模块、堆、环境参数、线程本地存储 (TLS) 等信息。模拟器需要分配内存并初始化这些结构，以便被模拟的程序能够正确查询其运行环境。特别是TEB中的NtTib.Self字段，它是一个指向TEB自身的指针，对于32位程序，FS段寄存器的基址通常指向TEB。  

```
// SetupVirtualMachine 函数片段 (以64位为例)
m_tebBase = TEB_BASE; // 进程TEB地址
m_pebBase = PEB_BASE; // 进程PEB地址
// ...
m_peb64.ImageBaseAddress = m_peInfo->RecImageBase;
m_teb64.ProcessEnvironmentBlock = reinterpret_cast<X64PEB*>(m_pebBase);
m_teb64.NtTib.StackBase = (DWORD64)m_stackBase;
m_teb64.NtTib.StackLimit = (DWORD64)m_stackSize;
// ... 映射并写入PEB和TEB
uc_mem_map(m_ucEngine, m_pebBase, m_pebEnd - m_pebBase, UC_PROT_READ | UC_PROT_WRITE);
uc_mem_write(m_ucEngine, m_pebBase, &m_peb64, sizeof(X64PEB));
// ...
// 对于64位，设置GS基址MSR
uc_x86_msr msr;
msr.rid = static_cast<uint32_t>(Msr::kIa32GsBase);
msr.value = m_gsBase;
uc_reg_write(m_ucEngine, UC_X86_REG_MSR, &msr);
// 对于32位，设置FS基址MSR
// msr.rid = static_cast<uint32_t>(Msr::kIa32FsBase);
// msr.value = m_tebBase;
// uc_reg_write(m_ucEngine, UC_X86_REG_MSR, &msr);

```

### 进程环境变量  
  
RTL_USER_PROCESS_PARAMETERS 结构体是PEB中的一个重要字段，它包含了进程的命令行、当前目录、映像路径、DLL搜索路径以及环境变量等信息。BuildPebParameter 函数负责填充这些信息，并在模拟器内存中分配相应的字符串缓冲区。GetEnvString 则提供了默认的环境变量列表。  

```
// BuildPebParameter 函数片段
RTL_USER_PROCESS_PARAMETERS processParams = {};
// ... 映射内存
// 设置映像路径、命令行、当前目录、DLL路径等
std::wstring imagePath = L&#34;C:\\Path\\To\\EmulatedImage.exe&#34;;
// ... 写入字符串到模拟内存
processParams.ImagePathName = imagePathUnicode;
// ... 设置其他参数
processParams.Environment = reinterpret_cast<WCHAR*>(m_envBlockBase); // 指向环境变量块
uc_mem_write(m_ucEngine, m_processParamsBase, &processParams, sizeof(RTL_USER_PROCESS_PARAMETERS));

```

  
至此我们完成了环境初始化  
## 导入表  
  
PE文件通常会依赖大量的动态链接库（DLL）。为了模拟执行，我们需要将主程序及其依赖的DLL加载到模拟器内存中，并正确处理它们的导入表和导出表。（无论是模拟的API还是真实DLL的导出函数）。  
  
ResoveImport: 这个函数负责解析主程序的导入表。它使用 peconv::process_import_table 结合 cListImportNames 回调来提取所有导入函数的名称及其所在的DLL。然后，对于每个导入的DLL，它会尝试使用 mapSystemModuleToVmByName 将其加载到模拟器中。  

```
// ResoveImport 函数片段
// 处理延迟导入
peconv::load_delayed_imports(static_cast<BYTE*>(m_peInfo->peBuffer), 0);
// 解析导入表
cListImportNames importCallback(static_cast<BYTE*>(m_peInfo->peBuffer),
                                m_peInfo->peSize, m_impFuncDict,
                                m_impFuncOrdinalDict);
if (!peconv::process_import_table(static_cast<BYTE*>(m_peInfo->peBuffer),
                                  m_peInfo->peSize, &importCallback)) {
    throw std::runtime_error(&#34;Failed to process import table&#34;);
}
// 处理每个导入模块，将其加载到VM中
for (const auto& importModule : m_impFuncDict) {
    processImportModule(importModule.get());
}

```

## API Hooking 与系统调用  
  
为了在模拟执行过程中处理API调用和系统调用，我们需要在Unicorn Engine中设置钩子 (Hooks)。  
  
API Hooking: 对于已修复的导入函数，我们可以在其在模拟器中的地址上设置 UC_HOOK_CODE 钩子。当模拟器执行到这些地址时，钩子回调函数 sandboxCallbacks::handleApiCall 会被触发，我们可以在这里实现对API的模拟或重定向到宿主机上的真实API。  
  
我们给导入表挂钩子:  

```
    // 挂导入表钩子
    for (const auto& module : this->GetModuleList()) {
        // 遍历导出函数查找对应名称
        for (const auto& exp : module->export_function) {
            auto inMemAddr = module->base + exp->function_address;
            uc_hook_add(m_ucEngine, &exp->sys_ook, UC_HOOK_CODE, sandboxCallbacks::handleApiCall,(void*)this, inMemAddr, inMemAddr + 5, 0);
        }
    }

```

  
执行导入表的时候,会触发我们的钩子:  

```

void handleApiCall(uc_engine* uc, uint64_t address, uint32_t size, void* userData)
{
    uint64_t currentRip = 0;
    auto* sandbox = static_cast<Sandbox*>(userData);
    if (!sandbox) return;

    uc_reg_read(uc,
        sandbox->GetPeInfo()->isX64 ? UC_X86_REG_RIP : UC_X86_REG_EIP,
        ¤tRip);

    auto [lastReadImpAddr, lastImp] = sandbox->GetLastImpRead();

    if (lastImp != nullptr && currentRip == lastReadImpAddr) {
        printf(
            &#34;direct call function [%s]%s at file address: %llx lastRip: &#34;
            &#34;%llx\n&#34;,
            lastImp->dll_name,
            lastImp->name, address, lastRip);
        sandbox->EmulateApi(uc, lastReadImpAddr, currentRip, lastImp->name);
        sandbox->SetLastImpRead(0, nullptr);
    }
    else {
        for (auto module : sandbox->GetModuleList()) {
            for (auto item : module->export_function) {
                const auto vmAddress = module->base + item->function_address;
                if (vmAddress == currentRip) {
                    printf(&#34;[!!!]detect no correct call, currentRip: 0x%llx\n&#34;,
                        currentRip);
                    sandbox->SetLastImpRead(0, nullptr);

                    sandbox->EmulateApi(uc, vmAddress, currentRip, item->name);
                }
            }
        }
    }
}

```

  
然后就模拟各种API了:  
> 为什么我们不能模拟syscall? 因为这样模拟,就跟某h*系统一样,搞所谓的兼容层了,而代价是,我们需要重写整个NT内核!! 因为很多API是不可控的.某系统能成功写兼容层的原因是linux是开源的! 意味着直接把内核编译好,只要内核初始化成功,把ssdt接过去就行,但是windows是闭源的,做的最好的是wine也有各种bug.所以不要做兼容层的操作了.对于个人来说浪费时间  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWKRp2d9CxB9Ums7dzyB9HBOV5XoxbD7DibpNvlO4gNoqZ8bzJEEh86ZXdgzq9kn1RxxzmoQ8V6NlUQ/640?wx_fmt=png&from=appmsg "")  
  
比如URL download  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWKRp2d9CxB9Ums7dzyB9HBOVuJESGib0svGG0fErOM9Erq60pULS0YyNCAnlBlV8t5d484EQJvQhRQ/640?wx_fmt=png&from=appmsg "")  
  
  
createprocess  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWKRp2d9CxB9Ums7dzyB9HBO6GwWJUrFy9d79JMykiahc42j7tOOJs9vC62EbiarYLbsYl3FCzccUIVw/640?wx_fmt=png&from=appmsg "")  
  
  
只要模拟的够多,基本上什么病毒都能跑:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWKRp2d9CxB9Ums7dzyB9HBOXHQFsibu4ec8Px8AmsHcCccZWnCONUJZk9icZl4xFRMYkzUC7qwhHdIg/640?wx_fmt=png&from=appmsg "")  
  
## 自动脱壳机  
  
我们还能做一个自动的脱壳机器,脱掉常见的UPX,ASP什么壳,原理是,壳会释放原始PE到text段并且执行,我们只需要记录跨区段执行,执行的时候立刻dump即可  

```
    // 如果找到区段，并且与上次执行的区段不同，记录跨区段行为
    if (currentSectionIndex >= 0 &&
        sandbox->GetLastExecuteSectionIndex() != currentSectionIndex &&
        sandbox->GetLastExecuteSectionIndex() != 0) {
        printf(
            &#34;[!!!]detect cross section excute, from %d to %d,address: 0x%llx\n&#34;,
            sandbox->GetLastExecuteSectionIndex(), currentSectionIndex,
            address);
        sandbox->SetMalwareAnalysisType(MalwareAnalysisType::kSuspicious);

        // 记录跨区段执行地址
        sandbox->SetCrossSectionExecution(address);
    }

```

  
然后dump,标准的PE dump  

```
#include &#34;sandbox.h&#34;

auto Sandbox::DumpPE() -> std::pair<std::unique_ptr<BYTE[]>, size_t> {
    // 查找目标模块 - 这里我们使用主模块(通常是被分析的可执行文件)
    std::shared_ptr<struct_moudle> targetModule = nullptr;
    for (const auto& module : m_moduleList) {
        if ((*module).name == &#34;HUOJI.EXE&#34;) {
            targetModule = module;
            break;
        }
    }

    if (!targetModule) {
        throw std::runtime_error(&#34;No modules found to dump&#34;);
    }

    // 计算虚拟内存大小
    auto virtualMemorySize = getVirtualMemorySize(m_peInfo->peBuffer);

    // 创建用于存储转储数据的缓冲区
    auto resultBuffer = std::make_unique<BYTE[]>(virtualMemorySize);

    // 从虚拟机内存中读取PE文件
    uc_err err = uc_mem_read(m_ucEngine, m_peInfo->RecImageBase,
        resultBuffer.get(), virtualMemorySize);
    if (err != UC_ERR_OK) {
        throw std::runtime_error(&#34;Failed to read memory during PE dump: &#34; +
            std::string(uc_strerror(err)));
    }

    // 确保PE头部的签名有效
    auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(resultBuffer.get());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error(&#34;Invalid DOS signature in dumped PE&#34;);
    }

    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(resultBuffer.get() +
        dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error(&#34;Invalid NT signature in dumped PE&#34;);
    }

    // 获取当前RIP/EIP作为新的入口点
    uint64_t currentEntryPoint = 0;
    if (this->GetCrossSectionExecution().size() > 0) {
        currentEntryPoint = this->GetCrossSectionExecution()
            [this->GetCrossSectionExecution().size() - 1] -
            m_peInfo->RecImageBase;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = nullptr;
    WORD numberOfSections = 0;

    // 处理32位或64位PE文件
    if (m_peInfo->isX64) {
        auto* optHeader64 =
            &reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders)->OptionalHeader;
        optHeader64->ImageBase = m_peInfo->RecImageBase;
        if (currentEntryPoint != 0) {
            // 修改入口点为当前执行位置
            optHeader64->AddressOfEntryPoint =
                static_cast<DWORD>(currentEntryPoint);
        }

        // 修改SizeOfImage
        optHeader64->SizeOfImage = static_cast<DWORD>(AlignToSectionAlignment(
            virtualMemorySize, optHeader64->SectionAlignment));

        // 修改DllCharacteristics以移除ASLR标记
        optHeader64->DllCharacteristics &=
            ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

        // 获取区段头信息
        sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<ULONG_PTR>(ntHeaders) +
            sizeof(ntHeaders->Signature) + sizeof(ntHeaders->FileHeader) +
            ntHeaders->FileHeader.SizeOfOptionalHeader);
        numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    }
    else {
        auto* optHeader32 =
            &reinterpret_cast<PIMAGE_NT_HEADERS32>(ntHeaders)->OptionalHeader;
        optHeader32->ImageBase = static_cast<DWORD>(m_peInfo->RecImageBase);

        if (currentEntryPoint != 0) {
            // 修改入口点为当前执行位置
            optHeader32->AddressOfEntryPoint =
                static_cast<DWORD>(currentEntryPoint);
        }

        // 修改SizeOfImage
        optHeader32->SizeOfImage = static_cast<DWORD>(AlignToSectionAlignment(
            virtualMemorySize, optHeader32->SectionAlignment));

        // 修改DllCharacteristics以移除ASLR标记
        optHeader32->DllCharacteristics &=
            ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

        // 获取区段头信息
        sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<ULONG_PTR>(ntHeaders) +
            sizeof(ntHeaders->Signature) + sizeof(ntHeaders->FileHeader) +
            ntHeaders->FileHeader.SizeOfOptionalHeader);
        numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    }

    // 更新代码基址和大小
    UpdateBaseOfCode(sectionHeaders, ntHeaders, numberOfSections,
        static_cast<DWORD>(currentEntryPoint));

    // 修复区段
    FixSections(sectionHeaders, numberOfSections, virtualMemorySize);

    // 创建一个ExportsMapper对象用于导入表修复
    peconv::ExportsMapper exportsMap;

    // 添加所有已加载模块到导出表映射中
    for (const auto& module : m_moduleList) {
        if (module->base == 0 || module->size == 0) {
            continue;
        }

        // 创建临时缓冲区以存储模块内容
        std::unique_ptr<BYTE[]> moduleBuffer =
            std::make_unique<BYTE[]>(module->size);

        // 从虚拟机内存读取模块内容
        uc_err readErr = uc_mem_read(m_ucEngine, module->base,
            moduleBuffer.get(), module->size);
        if (readErr != UC_ERR_OK) {
            printf(
                &#34;Warning: Could not read module %s for exports mapping: %s\n&#34;,
                module->name, uc_strerror(readErr));
            continue;
        }

        // 添加模块到导出表映射
        exportsMap.add_to_lookup(module->name,
            reinterpret_cast<HMODULE>(moduleBuffer.get()),
            module->base);
    }
    // 这里有一个严重的问题,就懒得处理了:
    // 壳里面吐出来的代码的导入表和壳的导入表不是同样一个.
    // 这个修的是壳的 导入表,所以导入表 修 不 全
    // 有个很简单的办法,需要搜索IAT结构,然后修改脱壳后的IAT的字段到壳的字段里面,然后再执行一次fix_imports
    // 懒得写了,家庭作业.自己完成
    bool importsFixed = peconv::fix_imports(
        resultBuffer.get(), virtualMemorySize, exportsMap, nullptr);
    if (importsFixed) {
        printf(&#34;PE file imports fixed successfully\n&#34;);
    }
    else {
        printf(&#34;Warning: Failed to fix PE file imports\n&#34;);
    }

    size_t out_size = 0;

    // 重新计算校验和
    if (m_peInfo->isX64) {
        auto* optHeader64 =
            &reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders)->OptionalHeader;
        optHeader64->CheckSum =
            CalculateChecksum(resultBuffer.get(), virtualMemorySize);
    }
    else {
        auto* optHeader32 =
            &reinterpret_cast<PIMAGE_NT_HEADERS32>(ntHeaders)->OptionalHeader;
        optHeader32->CheckSum =
            CalculateChecksum(resultBuffer.get(), virtualMemorySize);
    }

    printf(
        &#34;PE file dumped successfully from address: 0x%llx, size: %zu bytes\n&#34;,
        m_peInfo->RecImageBase, virtualMemorySize);
    printf(&#34;Entry point set to: 0x%llx (RVA: 0x%llx)\n&#34;,
        m_peInfo->RecImageBase + currentEntryPoint, currentEntryPoint);

    return { std::move(resultBuffer), virtualMemorySize };
}

// 修复区段信息
void Sandbox::FixSections(PIMAGE_SECTION_HEADER sectionHeaders,
    WORD numberOfSections, size_t virtualMemorySize) {
    if (numberOfSections == 0 || sectionHeaders == nullptr) {
        return;
    }

    // 修复每个区段的信息
    for (WORD i = 0; i < numberOfSections - 1; i++) {
        auto& currentSection = sectionHeaders[i];
        auto& nextSection = sectionHeaders[i + 1];

        // 修复大小，使之与下一个区段的起始地址对齐
        currentSection.SizeOfRawData =
            nextSection.VirtualAddress - currentSection.VirtualAddress;
        currentSection.PointerToRawData = currentSection.VirtualAddress;
        currentSection.Misc.VirtualSize = currentSection.SizeOfRawData;
    }

    // 修复最后一个区段
    auto& lastSection = sectionHeaders[numberOfSections - 1];
    lastSection.SizeOfRawData =
        static_cast<DWORD>(virtualMemorySize) - lastSection.VirtualAddress;
    lastSection.PointerToRawData = lastSection.VirtualAddress;
    lastSection.Misc.VirtualSize = lastSection.SizeOfRawData;
}

// 计算校验和
DWORD Sandbox::CalculateChecksum(const BYTE* peBuffer, size_t size) {
    DWORD sum = 0;
    const DWORD* ptr = reinterpret_cast<const DWORD*>(peBuffer);
    const DWORD count = static_cast<DWORD>(size / sizeof(DWORD));

    // 获取校验和字段的偏移
    const auto dosHeader = (PIMAGE_DOS_HEADER)(peBuffer);
    const auto ntHeaders = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
    DWORD checksumOffset = dosHeader->e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        FIELD_OFFSET(IMAGE_OPTIONAL_HEADER, CheckSum);

    // 计算总和，跳过校验和字段本身
    for (DWORD i = 0; i < count; i++) {
        // 跳过校验和字段
        if ((i * sizeof(DWORD)) == checksumOffset ||
            (i * sizeof(DWORD)) == checksumOffset + sizeof(DWORD) - 1) {
            continue;
        }
        sum += ptr[i];
        // 处理溢出
        if (sum < ptr[i]) {
            sum++;
        }
    }

    // 完成计算
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = sum + static_cast<DWORD>(size);

    return sum;
}

// 按区段对齐大小进行对齐
DWORD Sandbox::AlignToSectionAlignment(size_t size, DWORD alignment) {
    return static_cast<DWORD>(((size + alignment - 1) / alignment) * alignment);
}

// 更新代码基址和代码大小
void Sandbox::UpdateBaseOfCode(PIMAGE_SECTION_HEADER sectionHeader,
    PIMAGE_NT_HEADERS ntHeaders,
    WORD numberOfSections, DWORD entryPoint) {
    if (sectionHeader == nullptr || ntHeaders == nullptr ||
        numberOfSections == 0) {
        return;
    }

    DWORD baseOfCode = 0;
    DWORD sizeOfCode = 0;
    bool foundSection = false;

    // 寻找包含入口点的区段
    for (WORD i = 0; i < numberOfSections; i++) {
        auto& section = sectionHeader[i];
        if (entryPoint >= section.VirtualAddress &&
            entryPoint < (section.VirtualAddress + section.Misc.VirtualSize)) {
            baseOfCode = section.VirtualAddress;
            sizeOfCode = section.Misc.VirtualSize;
            foundSection = true;
            break;
        }
    }

    // 如果没有找到包含入口点的区段，使用第一个可执行区段
    if (!foundSection) {
        for (WORD i = 0; i < numberOfSections; i++) {
            auto& section = sectionHeader[i];
            if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                baseOfCode = section.VirtualAddress;
                sizeOfCode = section.Misc.VirtualSize;
                foundSection = true;
                break;
            }
        }
    }

    // 更新NT头部信息
    if (foundSection) {
        if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            // 64位PE
            auto* optHeader64 =
                &reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders)
                ->OptionalHeader;
            optHeader64->BaseOfCode = baseOfCode;
        }
        else {
            // 32位PE
            auto* optHeader32 =
                &reinterpret_cast<PIMAGE_NT_HEADERS32>(ntHeaders)
                ->OptionalHeader;
            optHeader32->BaseOfCode = baseOfCode;
            optHeader32->SizeOfCode = sizeOfCode;
        }
    }
}

```

  
这样我们的PE虚拟机同时也实现了一个 自动脱壳机的功能了.  
### 不足  
  
当然,这也有很多不足,其中需要改进的是,API模拟的不够多,我们没模拟 win32k的api,也没模拟其他DLL的API,导致很多时候很多样本用冷门API就拉闸了,只能看到一个加一个  
还有一个是线程轮转和异常处理我们并没有模拟,异常处理64的还好,32位的真的癌症所以懒得浪费时间了  
线程轮转非常简单,这边就不说了  
最后我们还有STL INIT函数没模拟,也就是_initterm,导致PE的行为可能会不一样  

```
// 非空函数指针才“调用”
            if (function_ptr != 0) {
                printf(&#34;[*] _initterm: Simulating call to initializer function at 0x%llx\n&#34;,
                    function_ptr);
                // 在沙箱环境中，通常我们不会真正地跳转到并执行这些初始化函数，
                // 而是记录它们的调用。
                // 如果需要更深度的模拟，可以在这里使用 uc_emu_start
                // 来模拟执行这些函数，然后跳回当前位置。
                // 但对于多数初始化例程，简单的记录就足够了。
                // 例如：
                // uc_emu_start(uc, function_ptr, function_ptr + some_size, 0, 0);
                // 或
                // context->EmulateApi(uc, function_ptr, some_return_address, &#34;CustomInitializer&#34;);
            }

```

  
这些都是可以改进的点,欢迎提PR  
https://git.key08.com/huoji/awesome_anti_virus_engine  
  
  
