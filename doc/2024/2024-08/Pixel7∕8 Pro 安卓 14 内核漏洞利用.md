#  Pixel7/8 Pro 安卓 14 内核漏洞利用   
原创 骨哥说事  骨哥说事   2024-08-05 13:56  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
# 博客新域名：https://gugesay.com  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
****  
目录  
  
背景介绍漏洞详情gpu_pixel_handle_buffer_liveness_update_ioctl() 中缓冲区溢出谷歌在此提交中修复了时间线流消息缓冲区中内核指针的泄漏EXP关于 buffer_count 和 live_ranges_count 值的说明选择合适的覆盖对象将 pipe_buffer 和 buff 对象放置相邻获取struct page地址要写入 pipeline_buffer 的内容选择下溢的最佳偏移值修改pipe_buffer→page字段修改pipe_buffer→len/offset字段获取 root 权限禁用 SELinuxPoC汇编Demo演示  
# 背景介绍  
  
本文将深入分析了两个存在于 Mali GPU 内核中的漏洞，这些漏洞可从默认应用程序沙盒访问，漏洞由   
安全研究人员独立发现并向谷歌报告。EXP包括一个内核利用程序，可实现任意内核读写能力。  
  
漏洞可以在运行 Android 14 版本的 Google Pixel 7 和 8 Pro 型号上禁用 SELinux 并提升到 ROOT 权限：  
- Pixel 8 Pro: google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys  
  
- Pixel 7 Pro: google/cheetah/cheetah:14/UP1A.231105.003/11010452:user/release-keys  
  
- Pixel 7 Pro: google/cheetah/cheetah:14/UP1A.231005.007/10754064:user/release-keys  
  
- Pixel 7: google/panther/panther:14/UP1A.231105.003/11010452:user/release-keys  
  
# 漏洞详情  
  
   
漏洞利用了两个漏洞：gpu_pixel_handle_buffer_liveness_update_ioctl ioctl 命令中的补丁不完整导致的整数溢出，以及时间线流消息缓冲区内的信息泄漏。  
## gpu_pixel_handle_buffer_liveness_update_ioctl() 缓冲区溢出  
  
Google 在此提交中（https://android.googlesource.com/kernel/google-modules/gpu/+/68073dce197709c025a520359b66ed12c5430914%5E%21/#F0） 解决了 gpu_pixel_handle_buffer_liveness_update_ioctl ioctl 命令中的整数溢出问题。起初，当研究人员报告此问题时，认为该错误是由前面描述的补丁中的问题引起的，但在查看了该报告后，研究人员意识到对漏洞的分析并不准确。  
  
尽管最初的假设是补丁不完整，但它有效地解决并防止了计算中的下溢，这让研究人员怀疑该更改并未应用于生产版本。  
  
然而，尽管可以导致计算下溢，但无法导致计算上溢。这表明 ioctl 命令已被部分修复，尽管不是上面所示的补丁。  
  
通过 IDA 查看，生产版本中又发布了一个不完整的补丁，而这个补丁不存在于任何 Mali GPU 内核模块的 git 分支中。  
  
此漏洞最早在最新版 Android 中被发现，并于 2023 年 11 月 19 日报告。谷歌后来告知研究人员，他们已内部识别出该漏洞，并在 12 月份的 Android   
安全公告中将其编号为 CVE-2023-48409，同时将其标记为重复问题。  
  
奇怪的是最近设备的 10 月和 11 月的安全补丁级别（SPL）仍然受到该漏洞的影响。  
  
因此，研究人员无法最终确定这是否属于一个真正重复的问题，以及研究人员之前提交的申请时，是否确实计划在 12 月发布相应的补丁，又或者是否存在处理该漏洞的疏忽。  
  
无论怎样，这个漏洞强大在于：  
- 缓冲信息 info.live_ranges 完全由用户控制  
  
- 溢出值由用户控制输入，因此可以溢出计算，使 info.live_ranges 指针位于 buff 内核地址开始之前的任意偏移处  
  
- 分配大小也是用户可控的，这使得能够从任何通用的slab分配器请求内存分配  
  
此漏洞与研究人员在 2022 年发现并利用的 iOS 15 内核中的 DeCxt::RasterizeScaleBiasData()缓冲区溢出漏洞非常相似（https://github.com/0x36/weightBufs）。  
## 时间线流消息缓冲区中内核指针的泄漏  
  
GPU Mali 实现了一个自定义时间线流，用于收集信息和序列化，然后按照特定格式将其写入环形缓冲区。用户可以通过 kbase_api_tlstream_acquire ioctl 命令获取文件描述符，从而能够从该环形缓冲区读取数据。消息的格式如下：  
- packet header （数据包头）  
  
- message id （消息 ID）  
  
序列化消息缓冲区，其中特定内容取决于消息 ID。例如，__kbase_tlstream_tl_kbase_kcpuqueue_enqueue_fence_wait函数将kbase_kcpu_command_queue和dma_fence内核指针序列化到消息缓冲区中，导致内核指针泄漏到用户空间进程。  
```
void __kbase_tlstream_tl_kbase_kcpuqueue_enqueue_fence_wait(
    struct kbase_tlstream *stream,
    const void *kcpu_queue,
    const void *fence
)
{
    const u32 msg_id = KBASE_TL_KBASE_KCPUQUEUE_ENQUEUE_FENCE_WAIT;
    const size_t msg_size = sizeof(msg_id) + sizeof(u64)
        + sizeof(kcpu_queue)
        + sizeof(fence)
        ;
    char *buffer;
    unsigned long acq_flags;
    size_t pos = 0;

    buffer = kbase_tlstream_msgbuf_acquire(stream, msg_size, &acq_flags);

    pos = kbasep_serialize_bytes(buffer, pos, &msg_id, sizeof(msg_id));
    pos = kbasep_serialize_timestamp(buffer, pos);
    pos = kbasep_serialize_bytes(buffer,
        pos, &kcpu_queue, sizeof(kcpu_queue));
    pos = kbasep_serialize_bytes(buffer,
        pos, &fence, sizeof(fence));

    kbase_tlstream_msgbuf_release(stream, acq_flags);
}
```  
  
概念验证漏洞通过监视消息 ID KBASE_TL_KBASE_NEW_KCPUQUEUE 来泄漏 kbase_kcpu_command_queue 对象地址，每当分配新的 kcpu 队列对象时，该消息 ID 都会由 kbasep_kcpu_queue_new 函数调度。  
  
谷歌告诉研究人员该漏洞于 2023 年 3 月被报告，并在其   
安全公告中被分配 CVE-2023-26083。尽管如此，研究人员能够在最新款 Pixel 设备上复现该漏洞，这些设备配备了 10 月和 11 月的安全补丁级别 (SPL)，这表明修复程序没有正确应用或根本未应用。  
  
随后，谷歌在 12 月安全更新公告中快速解决了该问题，但没有给予任何认可，后来告知研究人员该问题被认为是重复的，然而，将此问题标记为重复的理由仍值得商榷。  
# EXP  
  
以上两个有趣的漏洞，第一个漏洞提供了一个强大的能力，可以修改任何 16 字节对齐的内核地址，这些地址位于分配的缓冲区地址之前，第二个漏洞提供了有关内核内存中对象的潜在位置的提示。  
## 关于 buffer_count 和 live_ranges_count 值的说明  
  
通过对 buffer_count 和 live_ranges_count 字段的完全控制，研究人员可以灵活地选择目标 slab 以及打算写入的确切偏移量。然而，由于一些约束限制，选择 buffer_count 和 live_ranges_count 的值需要仔细考虑：  
- 两个值都是相关的，只有绕过所有新引入的检查才会发生溢出  
  
- 负偏移量必须 16 字节对齐的要求限制了写入任何选定位置的能力。然而，这通常不是一个太大的障碍  
  
- 选择较大的偏移量会导致大量数据被写入可能不是预期目标的内存区域。例如，如果分配大小溢出到 0x3004，则 live_ranges 指针将被设置为 buff 对象分配空间的 -0x4000 字节。然后，copy_from_user 函数将根据 update->live_ranges_count乘以 4 的计算写入 0x7004 字节。因此，此操作将导致用户控制的数据覆盖 live_ranges 指针和 buff 分配之间的内存区域。因此，必须仔细确保该范围内的关键系统对象不会被意外覆盖。鉴于该操作涉及 copy_from_user 调用，人们可能会考虑通过故意取消映射用户源缓冲区后面不需要的内存区域来触发 EFAULT，以防止数据写入敏感位置。然而，这种方法是无效的，因为如果 raw_copy_from_user 函数失败，它会将目标内核缓冲区中的剩余字节清零。实现此行为是为了确保在由于错误而进行部分复制的情况下，内核缓冲区的其余部分不包含未初始化的数据。  
  
```
static inline __must_check unsigned long
_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res = n;
    might_fault();
    if (!should_fail_usercopy() && likely(access_ok(from, n))) {
        instrument_copy_from_user(to, from, n);
        res = raw_copy_from_user(to, from, n);
    }
    if (unlikely(res))
        memset(to + (n - res), 0, res);
    return res;
}
```  
  
考虑到这一点，需要仔细选择覆盖对象和写入数据。  
## 选择合适的覆盖对象  
  
由于陷入了这个不幸的检查，所以研究人员的策略是识别一个对象，如果将其清零，则不会产生任何不良结果。但是在开始之前，还有另一个问题需要处理。  
  
还记得在上一部分中说过，由于可以选择任何分配大小，从而选择任何通用的slab缓存分配器来为我们的分配缓冲区提供服务吗？这是不正确的，因为又是因为copy_from_user！这是由于 CONFIG_HARDENED_USERCOPY 缓解措施所致。  
  
它禁止指定不符合slab缓存大小的大小，其中内核目标缓冲区对应于堆对象（在本例中）。它确定缓冲区的页面是否是slab页面，如果是，则检索匹配的kmem_cache->size并确定用户提供的大小是否会超过它；否则，内核会因大小不匹配而崩溃。  
  
所以，换句话说，虽然无法定位属于通用分配器（general purpose allocator）的对象，但仍可以定位大尺寸的对象（即那些直接由页分配器（page allocator）提供服务的对象）。  
  
研究人员想第一个想法是使用 pipeline_buffer 技术，这是一种非常优雅的技术来获取任意读/写原语。  
  
本文不会详细介绍该技术，但鼓励读者阅读 Interrupt Labs 的（https://www.interruptlabs.co.uk/articles/pipe-buffer） 博客。构造管道对象时，pipe_buffer对象最初是在一个包含16个元素的数组中创建的；但是，可以使用 fcntl(F_SETPIPE_SZ) 调整数组大小。  
  
因此，可以调整 pipeline_buffer 数组分配，以便可以从页面分配器提供服务，使其成为完美的攻击目标对象。  
  
选择 pipeline_buffer 对象作为目标候选者后，实现内核读写的下一步是使用下溢漏洞覆盖其内容，这将允许从其页面覆盖 pipeline_buffer 的任何内存位置读取/写入 – >页面字段。  
  
因为该漏洞允许写入任意数据，所以可以控制“pipe_buffer”的全部内容，包括其页面字段，为此，需要在易受攻击的 kbuff 对象之前分配 pipeline_buffer 数组，并且它们必须相邻。  
## 将 pipe_buffer 和 buff 对象放置相邻  
  
通过用大量的 kbase_kcpu_command_queue 对象喷射了内核内存，然后是一堆 pipeline_buffer 数组。由于 pipeline_max_size 的限制，研究人员不能仅仅使用 pipeline_buffer 数组作为喷射的主要来源。  
  
因此，研究人员决定开始使用 kbase_kcpu_command_queue 对象进行喷射。选择 kbase_kcpu_command_queue 对象有两个原因：它的分配大小为 0x38C8，由页面分配器处理，并且可以使用信息内核泄漏 bug 确定性地获取其内核地址，使其成为一个很好的喷射对象以及一个很好的对象目标。  
  
如前所述，使用 fcntl(F_SETPIPE_SZ) 来增加 pipeline_buffer 数组分配的大小，以便页面分配器可以为其提供服务。更具体地说，选择分配大小为 ==0x4000 字节 (4 * PAGE_SIZE)== 以便与 kbase_kcpu_command_queue 分配保持一致。  
## 获取struct page地址  
  
为了正确使用pipe_buffer，需要一个页面地址。能够识别可以有意创建和销毁的 kbase_kcpu_command_queue 对象的内核地址，使其成为一个很好的使用候选者，并且可以使用 virt_to_page 找到其匹配的 struct page。  
## 要写入 pipeline_buffer 的内容  
  
pipe_buffer 对象如下：  
```
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};
```  
  
如前所述，页面字段必须包含有效的页面地址。offset和len字段不能超过PAGE_SIZE，否则管道将增加头/尾计数器，导致使用新的pipe_buffer对象并失去对假管道缓冲区的控制。  
  
另外，标志必须是 PIPE_BUF_FLAG_CAN_MERGE，因此接下来的 pipeline_write 调用不是盲目地增加头计数器并使用下一个管道缓冲区，而是首先检查当前的 pipeline_buffer 中是否有适合写入请求的空间，如果有的话，它会简单地将数据附加到从 len 字段存储的值开始的同一管道缓冲区中。  
  
为了避免在由pipe_write和pipe_read’调用的pipe_buf_confirm处崩溃设备，ops指针也必须是有效的内核地址，并且ops->confirm字段设置为NULL。可以简单地使用泄漏的 kbase_kcpu_command_queue 对象中的偏移量，该偏移量为 NULL 并且在任何情况下都不会改变。  
## 选择下溢的最佳偏移值  
  
虽然 buff、kbase_kcpu_command_queue 和 pipe_buffer 的分配大小为 0x4000 字节，但研究人员选择以 0x8000 字节溢出缓冲区。为什么？  
  
简单看一下pipe_buffers在读写操作过程中是如何更新的，假设我们可以将 pipeline_buffer 调整为如下所示：  
```
struct pipe_buffer {
    .page = virt_to_page(addr),
    .offset =  0,
    .len = 0x40,
    .ops = kcpu_addr + 0x50,
    .flags = PIPE_BUF_FLAG_CAN_MERGE,
    unsigned long private = 0
};
```  
  
虽然该漏洞提供了任意控制该对象内容的能力，但它只执行一次，因为下溢的对象在 ioctl 调用完成后立即被释放，这实际上带来了一个问题，因为需要手动更新 pipeline_buffer 对象以使其在每次管道读/写操作后再次可用：  
- .page 字段未更新；保持不变，当缓冲区为空时，它被释放，研究人员不希望发生这种情况，因为 .ops 字段未正确设置  
  
- 由于 pipeline_buffer 在读取操作时更新 .offset 字段，因此无法再次读取同一内存区域  
  
- 写入 pipeline_buffer 的数据将从 .len 值开始附加到缓冲区（假设设置了 PIPE_BUF_FLAG_CAN_MERGE 标志），并且 .len 相应更新。也就是说，我们不能将数据两次写入确切的地址  
  
因此，除非在每次读取或写入操作后正确更新 pipeline_buffer，否则无法同时从同一管道读取和写入。这就是为什么使用 0x8000 字节下溢更加实用，因为将覆盖两个不同管道对象的两个不同的 pipeline_buffer 实例，而不是覆盖单个 pipeline_buffer ：一个将被考虑用于读取，另一个将被考虑用于写入操作。  
```
#define PIPE_BUF_FLAG_CAN_MERGE 0x10    /* can merge buffers */

pipe_read = (struct pipe_buffer *)( ptr);
pipe_read->page = virt_to_page(ta->kcpu_kaddr);
pipe_read->offset = 0;
pipe_read->len = 0xfff;
pipe_read->ops = (const void *)(ta->kcpu_kaddr + 0x50);
pipe_read->flags = PIPE_BUF_FLAG_CAN_MERGE;
pipe_read->private = 0;

pipe_write = (struct pipe_buffer *)( ptr + 0x4000);
pipe_write->page = virt_to_page(ta->kcpu_kaddr);
pipe_write->offset = 0;
pipe_write->len = 0;             /* This is the starting position of the pipe_write */
pipe_write->ops = (const void *)(ta->kcpu_kaddr + 0x50);
pipe_write->flags = PIPE_BUF_FLAG_CAN_MERGE;
pipe_write->private = 0;
```  
  
pipe_read 是一个伪管道缓冲区，将用于从目标页面读取数据，起始位置为 .offset = 0，最多读取 0xfff 字节；而 pipe_write 同样是一个伪管道缓冲区，将用于写入数据，起始位置为 .len = 0，最多写入 0xfff 字节。  
  
再次强调，写入超过 PAGE_SIZE 字节将推动管道增加头计数器，因此使用新分配的 pipeline_buffer 并失去对伪 pipeline_write 的控制。另一方面，清空（从中读取 0xfff 数据）fake_read 缓冲区告诉内核通过调用 ops→release 释放实际页面，导致内核崩溃，因为我们仍然没有内核文本地址。  
  
尽管成功地将管道读写操作分离，使得在一个管道端进行写入不会干扰另一个管道缓冲区，反之也是如此，但仍然没有解决核心问题：如何可靠地更新管道缓冲区？  
  
能够想到的答案是在每次管道读取或写入调用后一次又一次地重复喷射过程，但这是没有意义的，因为它会对利用的可靠性产生重大影响，接下来是 .len/.offset 字段。  
## 修改pipe_buffer→page字段  
  
令研究人员惊讶的是，根本不需要更新.page，这是因为可以覆盖pipe_buffer | page以指向泄露的kbase_kpu_命令_queue的页面地址。  
  
因此，** 我们需要做的就是释放kbase_kpu_命令_queue对象，并将其与新的pipe_buffer对象重叠。是的！现在就有了一个指向合法管道_buffer对象的pipe_buffer页面！用pipe_buffer替换kbase_kpu_命令_queue使我们能够操纵合法的管道缓冲区，而无需定期更新.page字段。然而仍需要处理.len和. oft字段。  
# 修改pipe_buffer→len/offset字段  
  
正如之前提到的，执行管道读/写会更新 .len 和 .offset 字段，从而使同一页面上的后续读/写操作不可用，即使在两个不同的管道上执行也是如此。  
  
这是另一个技巧：有一种技术可以在不触及 .len/.offset 字段的情况下读取/写入数据！并且可以通过对 pipe_read/write 的 copy_page_from_iter 和 copy_page_to_iter 调用进行错误来实现这一目标！是的，就像 copy_to/from_user 一样，copy_page_to/from_iter 从/向通过iov_iter结构传递的用户空间复制数据，这可能会出错。  
  
为了继续前面的示例，如果我们希望将 8 个字节的数据写入一个地址，则提供的用户空间缓冲区大小必须为 8，然后是未映射或不可读的内存区域，然后将 9 作为大小参数传递给写入系统调用，指示我们想要写入的数据量。  
  
此操作将写入 8 个字节，并在第 9 个字节失败，因为它遇到未映射/未读的内存位置。因此，数据已有效地写入目标内核缓冲区，并且未修改 .len 字段。pipe_write 内核函数将返回而不更新 buf->len 字段。  
```
        if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
            offset + chars <= PAGE_SIZE) {
            ret = pipe_buf_confirm(pipe, buf);
            if (ret)
                goto out;

            ret = copy_page_from_iter(buf->page, offset, chars, from);
            if (unlikely(ret < chars)) {
                ret = -EFAULT;
                goto out;
            }

            buf->len += ret;
            if (!iov_iter_count(from))
                goto out;
        }
```  
  
读取操作也是如此;如果我们希望读取 8 个字节，则使缓冲区的第 9 个字节不可读，然后仅声明我们想要读取 9 个字节，数据将被复制到用户缓冲区，而不更改 .offset 字段。因此，我们能够在任何内核内存地址上执行无限制的读/写操作，而无需重复进行喷射过程。  
# 获取 root 权限  
  
现在有了一个强大的任意读/写原语，只需查看 VMEMMAP_START 数组中的所有结构页，即可使用 Interrupt Labs 博客文章中提到的技术来确定内核文本起始地址。  
  
然而 init_task 在 Android 11 月   
安全更新中被取消，所以只需使用 kthreadd_task 代替。有了 kthreadd_task 内核地址，就可以遍历任务->任务列表并获取当前任务内核地址，然后将 cred 结构清零来获取 root 权限。  
  
不久之后，研究人员意识到扫描所有页面地址是不必要的，因为已经从 pipeline_buffer 对象中获得了 anon_pipe_buf_ops 内核文本地址。有了这些信息，就可以推断出内核文本基地址，从而有效地绕过 KASLR。  
# 禁用 SELinux  
  
该漏洞还禁用了 SELinux，使用内核文本基址，只需要找到selinux_state全局结构位置，然后将 .enforcing 值归零即可。  
# PoC  
  
PoC在运行 Android 14 的 Pixel 7 和 8 Pro 设备上进行了测试，并参加了 10 月和 11 月的 ASB，成功率接近 100%。  
  
同样值得一提的是，由于使用了一些硬编码偏移量，该   
漏洞利用在其他设备中无法开箱即用。为了添加对新设备的支持，必须提供以下内容：  
- kthreadd_task 与内核基址的偏移量  
  
- selinux_state与内核基址的偏移量  
  
- task_struct->cred、task_struct->pid 和 task_struct->tasks 结构偏移  
  
- anon_pipe_buf_ops 与内核基址的偏移量  
  
## 汇编  
  
要将漏洞编译为独立的二进制文件，请使用以下命令，然后使用 adb shell 运行它  
```
$ aarch64-linux-androidXX-clang++ -static-libstdc++ -w -Wno-c++11-narrowing -DUSE_STANDALONE -o poc poc.cpp -llog
$ adb push poc /data/local/tmp/
$ adb shell /data/local/tmp/poc
```  
  
Copy  
  
还可以通过 Android Studio 应用程序将此目录嵌入其中来运行该漏洞，并确保通过向 cmake 文件添加 -w -Wno-c++11-narrowing 来禁用无用的 C++ 警告。  
# Demo演示  
```
$ adb logcat  |grep -i EXPLOIT
11-28 16:04:12.500  7989  7989 E EXPLOIT : [+] Target device: 'google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys' 0xa9027bfdd10203ff 0xa90467faa9036ffc
11-28 16:04:15.563  7989  7989 E EXPLOIT : [+] Got the kcpu_id (0) kernel address = 0xffffff8901390000  from context (0x0)
11-28 16:04:18.441  7989  7989 E EXPLOIT : [+] Got the kcpu_id (255) kernel address = 0xffffff89b0bf8000  from context (0xff)
11-28 16:04:18.442  7989  7989 E EXPLOIT : [+] Found corrupted pipe with size 0xfff
11-28 16:04:18.442  7989  7989 E EXPLOIT : [+] SUCCESS! we have a fake pipe_buffer (0)!
11-28 16:04:18.444  7989  7989 E EXPLOIT : 10 00 39 01 89 FF FF FF  10 00 39 01 89 FF FF FF  | ..9.......9.....
11-28 16:04:18.444  7989  7989 E EXPLOIT : 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ................
11-28 16:04:18.444  7989  7989 E EXPLOIT : 00 B0 CD 12 C0 FF FF FF  00 00 00 00 00 00 00 00  | ................
11-28 16:04:18.444  7989  7989 E EXPLOIT : 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ................
11-28 16:04:18.445  7989  7989 E EXPLOIT : [+] Freeing kcpu_id = 0 (0xffffff8901390000)
11-28 16:04:18.446  7989  7989 E EXPLOIT : [+] Allocating 61 pipes with 256 slots
11-28 16:04:18.462  7989  7989 E EXPLOIT : [+] Successfully overlapped the kcpuqueue object with a pipe buffer
11-28 16:04:18.463  7989  7989 E EXPLOIT : 40 AB BA 26 FE FF FF FF  00 00 00 00 30 00 00 00  | @..&........0...
11-28 16:04:18.463  7989  7989 E EXPLOIT : 70 37 8D F1 DA FF FF FF  10 00 00 00 00 00 00 00  | p7..............
11-28 16:04:18.463  7989  7989 E EXPLOIT : 00 00 00 00 00 00 00 00                           | ........
11-28 16:04:18.463  7989  7989 E EXPLOIT : [+] pipe_buffer {.page = 0xfffffffe26baab40, .offset = 0x0, .len = 0x30, ops = 0xffffffdaf18d3770}
11-28 16:04:18.463  7989  7989 E EXPLOIT : [+] kernel base = 0xffffffdaf0010000, kthreadd_task = 0xffffff8002da3780 selinux_state = 0xffffffdaf28a3168
11-28 16:04:20.097  7989  7989 E EXPLOIT : [+] Found our own task struct 0xffffff88416c5c80
11-28 16:04:20.097  7989  7989 E EXPLOIT : [+] Successfully got root: getuid() = 0 getgid() = 0
11-28 16:04:20.097  7989  7989 E EXPLOIT : [+] Successfully disabled SELinux
11-28 16:04:20.102  7989  7989 E EXPLOIT : [+] Cleanup  ... OK
```  
  
以上内容由骨哥翻译并整理。  
  
原文及Exp：https://github.com/0x36/Pixel_GPU_Exploit#start-of-content  
  
**加入星球，随时交流：**  
  
****  
**（前50位成员）：99元/年****（前100位成员）：128元/年****（****100位+成员）：199元/年**![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～****====正文结束====**  
  
  
