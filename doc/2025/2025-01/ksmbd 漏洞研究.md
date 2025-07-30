#  ksmbd 漏洞研究   
Norbert Szetei  securitainment   2025-01-09 09:17  
  
## ksmbd vulnerability research  
## 引言  
  
在 Doyensec，我们决定对 Linux 内核的一个组件——SMB3 内核服务器 (ksmbd) 进行漏洞研究。最初，它作为一个实验性功能被启用，但在内核版本 6.6 中，实验性标志被  
移除  
，并保持稳定。  
  
Ksmbd 为了优化性能而分割任务，在内核空间处理关键的文件操作，而通过ksmbd.mountd  
在用户空间处理非性能相关的任务，如 DCE/RPC 和用户账户管理。该服务器采用多线程架构，通过内核工作线程实现并行处理 SMB 请求的高效性，并利用用户空间集成来处理配置和 RPC。  
  
Ksmbd 默认并未启用，但它是学习 SMB 协议的绝佳目标，同时也可以探索 Linux 内部机制，如网络、内存管理和线程处理。  
  
ksmbd 内核组件直接绑定到 445 端口以处理 SMB 流量。内核与用户空间进程ksmbd.mountd  
之间的通信通过  
Netlink  
接口进行，这是 Linux 中用于内核与用户空间通信的基于套接字的机制。尽管ksmbd.mountd  
以 root 权限运行，但由于内核的直接可达性，我们选择直接针对内核进行研究。  
  
架构的示意图可以在邮件列表中  
找到  
，如下所示：  
```
               |--- ...
       --------|--- ksmbd/3 - Client 3
       |-------|--- ksmbd/2 - Client 2
       |       |         ____________________________________________________
       |       |        |- Client 1                                          |
<--- Socket ---|--- ksmbd/1   <<= Authentication : NTLM/NTLM2, Kerberos      |
       |       |      | |     <<= SMB engine : SMB2, SMB2.1, SMB3, SMB3.0.2, |
       |       |      | |                SMB3.1.1                            |
       |       |      | |____________________________________________________|
       |       |      |
       |       |      |--- VFS --- Local Filesystem
       |       |
KERNEL |--- ksmbd/0(forker kthread)
---------------||---------------------------------------------------------------
USER           ||
               || communication using NETLINK
               ||  ______________________________________________
               || |                                              |
        ksmbd.mountd <<= DCE/RPC(srvsvc, wkssvc, samr, lsarpc)   |
               ^  |  <<= configure shares setting, user accounts |
               |  |______________________________________________|
               |
               |------ smb.conf(config file)
               |
               |------ ksmbdpwd.db(user account/password file)
                            ^
  ksmbd.adduser ------------|

```  
  
关于这个主题已经发表了多项研究，包括  
Thalium  
和  
pwning.tech  
的研究。后者详细解释了如何使用  
syzkaller  
从零开始进行模糊测试。尽管文章的语法相当简单，但它为我们后续改进提供了一个很好的起点。  
  
我们首先使用标准 SMB 客户端拦截和分析合法通信。这使我们能够扩展 syzkaller 语法，以包含  
smb2pdu.c  
中实现的其他命令。  
  
在模糊测试过程中，我们遇到了几个挑战，其中之一在 pwning.tech 文章中得到了解决。最初，我们需要标记数据包以识别 syzkaller 实例（procid）。这种标记仅需要在第一个数据包中使用，因为后续数据包共享相同的套接字连接。为了解决这个问题，我们修改了第一个（协商）请求，添加了 8 字节来表示 syzkaller 实例号。之后，我们发送后续数据包时不再进行标记。  
  
syzkaller 的另一个限制是它  
无法  
使用malloc()  
进行动态内存分配，这使得在  
伪系统调用  
中实现身份验证变得复杂。为了解决这个问题，我们修补了相关的身份验证（NTLMv2）和数据包签名验证检查，使我们能够在没有有效签名的情况下绕过协商和会话设置。这使我们能够调用其他命令，如 ioctl 处理逻辑。  
  
为了创建更多样化和有效的测试用例，我们最初使用strace  
提取通信，或手动制作数据包。为此，我们使用了 Kaitai Struct，通过其  
网页界面  
或  
可视化工具  
。当数据包被内核拒绝时，Kaitai 使我们能够快速识别和解决问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMVRNNKN2JrZ4XuicZ5WnXVuG1PsxL3l1zIfibjia2RzGHgQLaszW3fny9Bu9KLwRgdUTK6klVPLJcew/640?wx_fmt=png&from=appmsg "")  
  
使用 SMB 语法的 Kaitai  
  
在我们的研究过程中，我们发现了多个安全问题，本文描述了其中的三个。这些漏洞有一个共同特点——它们可以在会话设置阶段无需身份验证就能被利用。利用它们需要对通信过程有基本的了解。  
## 通信  
  
在 KSMBD 初始化期间（无论是内置于内核还是作为外部模块），都会调用启动函数create_socket()  
来监听传入流量：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/transport_tcp.c#L484
 ret = kernel_listen(ksmbd_socket, KSMBD_SOCKET_BACKLOG);
 if (ret) {
  pr_err("Port listen() error: %d\n", ret);
  goto out_error;
 }
```  
  
实际的数据处理发生在ksmbd_tcp_new_connection()  
函数和每个连接生成的线程（ksmbd:%u  
）中。该函数还会分配表示连接的struct ksmbd_conn  
结构体：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/transport_tcp.c#L203
static int ksmbd_tcp_new_connection(struct socket *client_sk)
{
 // ..
 handler = kthread_run(ksmbd_conn_handler_loop,
         KSMBD_TRANS(t)->conn,
         "ksmbd:%u",
         ksmbd_tcp_get_port(csin));
 // ..
}
```  
  
ksmbd_conn_handler_loop  
函数至关重要，因为它负责读取、验证和处理 SMB 协议消息（PDU）。在没有错误发生的情况下，它会调用一个更具体的处理函数：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/connection.c#L395
  if (default_conn_ops.process_fn(conn)) {
   pr_err("Cannot handle request\n");
   break;
  }
```  
  
处理函数将 SMB 请求添加到工作线程队列中：  
```
// ksmbd_server_process_request
static int ksmbd_server_process_request(struct ksmbd_conn *conn)
{
 return queue_ksmbd_work(conn);
}
```  
  
这些操作发生在queue_ksmbd_work  
函数内部，该函数分配了一个ksmbd_work  
结构体来封装会话、连接和所有 SMB 相关数据，同时还执行早期初始化。  
  
在 Linux 内核中，要将工作项添加到工作队列中，需要使用INIT_WORK()  
宏进行初始化，该宏将工作项与处理时要执行的回调函数关联起来。在这里，具体实现如下：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/server.c#L312
 INIT_WORK(&work->work, handle_ksmbd_work);
 ksmbd_queue_work(work);
```  
  
现在我们已经接近处理 SMB PDU 操作的阶段。最后一步是由handle_ksmbd_work  
从请求中提取命令编号  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/server.c#L213
rc = __process_request(work, conn, &command);
```  
  
并执行相关的命令处理函数。  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/server.c#L108
static int __process_request(struct ksmbd_work *work, struct ksmbd_conn *conn,
        u16 *cmd)
{
 // ..
 command = conn->ops->get_cmd_val(work);
 *cmd = command;
 // ..

 cmds = &conn->cmds[command];
 // ..
 ret = cmds->proc(work);
```  
  
以下是被调用的处理函数列表：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/smb2ops.c#L171
 [SMB2_NEGOTIATE_HE] = { .proc = smb2_negotiate_request, },
 [SMB2_SESSION_SETUP_HE] = { .proc = smb2_sess_setup, },
 [SMB2_TREE_CONNECT_HE]  = { .proc = smb2_tree_connect,},
 [SMB2_TREE_DISCONNECT_HE]  = { .proc = smb2_tree_disconnect,},
 [SMB2_LOGOFF_HE] = { .proc = smb2_session_logoff,},
 [SMB2_CREATE_HE] = { .proc = smb2_open},
 [SMB2_QUERY_INFO_HE] = { .proc = smb2_query_info},
 [SMB2_QUERY_DIRECTORY_HE] = { .proc = smb2_query_dir},
 [SMB2_CLOSE_HE]  = { .proc = smb2_close},
 [SMB2_ECHO_HE]  = { .proc = smb2_echo},
 [SMB2_SET_INFO_HE]      =       { .proc = smb2_set_info},
 [SMB2_READ_HE]  = { .proc = smb2_read},
 [SMB2_WRITE_HE]  = { .proc = smb2_write},
 [SMB2_FLUSH_HE]  = { .proc = smb2_flush},
 [SMB2_CANCEL_HE] = { .proc = smb2_cancel},
 [SMB2_LOCK_HE]  = { .proc = smb2_lock},
 [SMB2_IOCTL_HE]  = { .proc = smb2_ioctl},
 [SMB2_OPLOCK_BREAK_HE] = { .proc = smb2_oplock_break},
 [SMB2_CHANGE_NOTIFY_HE] = { .proc = smb2_notify},
```  
  
在解释了 PDU 函数是如何被调用的之后，我们可以开始讨论由此产生的漏洞。  
## CVE-2024-50286  
  
该漏洞源于 ksmbd 中sessions_table  
管理的不当同步。具体来说，代码在**会话过期**  
和**会话注册**  
期间都缺乏sessions_table_lock  
来保护并发访问。这个问题引入了一个竞态条件，多个线程可以同时访问和修改sessions_table  
，导致在kmalloc-512  
缓存中出现 Use-After-Free（UAF）漏洞。  
  
sessions_table  
被实现为一个哈希表，它存储了一个连接的所有活动 SMB 会话，使用会话标识符（sess->id  
）作为键。  
  
在会话注册过程中，会发生以下流程：  
- 为连接创建一个新会话。  
  
- 在注册会话之前，工作线程调用ksmbd_expire_session  
来移除过期会话，以避免过期会话消耗资源。  
  
- 一旦清理完成，新会话就会被添加到连接的会话列表中。  
  
对这个表的操作，如添加（hash_add  
）和移除会话（hash_del  
），缺乏适当的同步机制，从而产生了竞态条件。  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/smb2pdu.c#L1663
int smb2_sess_setup(struct ksmbd_work *work)
{
 // .. 
 ksmbd_conn_lock(conn);
 if (!req->hdr.SessionId) {
  sess = ksmbd_smb2_session_create(); // [1]
  if (!sess) {
   rc = -ENOMEM;
   goto out_err;
  }
  rsp->hdr.SessionId = cpu_to_le64(sess->id);
  rc = ksmbd_session_register(conn, sess); // [2]
  if (rc)
   goto out_err;

  conn->binding = false;
```  
  
在[1]  
处，通过分配sess  
对象来创建会话：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/mgmt/user_session.c#L381
 sess = kzalloc(sizeof(struct ksmbd_session), GFP_KERNEL);
 if (!sess)
  return NULL;
```  
  
在这一点上，当存在大量并发连接时，一些会话可能会过期。当在[2]  
处调用ksmbd_session_register  
时，它会调用ksmbd_expire_session  
 [3]  
：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/mgmt/user_session.c#L192
int ksmbd_session_register(struct ksmbd_conn *conn,
      struct ksmbd_session *sess)
{
 sess->dialect = conn->dialect;
 memcpy(sess->ClientGUID, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);
 ksmbd_expire_session(conn); // [3]
 return xa_err(xa_store(&conn->sessions, sess->id, sess, GFP_KERNEL));
}
```  
  
由于没有实现表锁定机制，过期的sess  
对象可能会从表中移除（[4]  
）并被释放（[5]  
）：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/mgmt/user_session.c#L173
static void ksmbd_expire_session(struct ksmbd_conn *conn)
{
 unsigned long id;
 struct ksmbd_session *sess;

 down_write(&conn->session_lock);
 xa_for_each(&conn->sessions, id, sess) {
  if (atomic_read(&sess->refcnt) == 0 &&
      (sess->state != SMB2_SESSION_VALID ||
       time_after(jiffies,
          sess->last_active + SMB2_SESSION_TIMEOUT))) {
   xa_erase(&conn->sessions, sess->id);
   hash_del(&sess->hlist); // [4]
   ksmbd_session_destroy(sess); // [5]
   continue;
  }
 }
 up_write(&conn->session_lock);
}
```  
  
然而，在另一个线程中，当连接在ksmbd_server_terminate_conn  
中终止时，清理操作可能会通过调用ksmbd_sessions_deregister  
被触发，该函数在操作相同的表时没有使用适当的锁（[6]  
）：  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/mgmt/user_session.c#L213
void ksmbd_sessions_deregister(struct ksmbd_conn *conn)
{
 struct ksmbd_session *sess;
 unsigned long id;

 down_write(&sessions_table_lock);
 // .. ignored, since the connection is not binding
 up_write(&sessions_table_lock);

 down_write(&conn->session_lock);
 xa_for_each(&conn->sessions, id, sess) {
  unsigned long chann_id;
  struct channel *chann;

  xa_for_each(&sess->ksmbd_chann_list, chann_id, chann) {
   if (chann->conn != conn)
    ksmbd_conn_set_exiting(chann->conn);
  }

  ksmbd_chann_del(conn, sess);
  if (xa_empty(&sess->ksmbd_chann_list)) {
   xa_erase(&conn->sessions, sess->id);
   hash_del(&sess->hlist); // [6] 
   ksmbd_session_destroy(sess);
  }
 }
 up_write(&conn->session_lock);
}
```  
  
这里概述了一种可能的执行流程：  
```
Thread A                         | Thread B
---------------------------------|-----------------------------
ksmbd_session_register           | 
ksmbd_expire_session             |  
                                 | ksmbd_server_terminate_conn
                                 | ksmbd_sessions_deregister
ksmbd_session_destroy(sess)      |   |
    |                            |   |
    hash_del(&sess->hlist);      |   |
    kfree(sess);                 |   |
                                 |   hash_del(&sess->hlist);
```  
  
启用 KASAN 后，该问题表现为以下崩溃：  
```
BUG: KASAN: slab-use-after-free in __hlist_del include/linux/list.h:990 [inline]
BUG: KASAN: slab-use-after-free in hlist_del_init include/linux/list.h:1016 [inline]
BUG: KASAN: slab-use-after-free in hash_del include/linux/hashtable.h:107 [inline]
BUG: KASAN: slab-use-after-free in ksmbd_sessions_deregister+0x569/0x5f0 fs/smb/server/mgmt/user_session.c:247
Write of size 8 at addr ffff888126050c70 by task ksmbd:51780/39072

BUG: KASAN: slab-use-after-free in hlist_add_head include/linux/list.h:1034 [inline]
BUG: KASAN: slab-use-after-free in __session_create fs/smb/server/mgmt/user_session.c:420 [inline]
BUG: KASAN: slab-use-after-free in ksmbd_smb2_session_create+0x74a/0x750 fs/smb/server/mgmt/user_session.c:432
Write of size 8 at addr ffff88816df5d070 by task kworker/5:2/139
```  
  
这两个问题都导致在偏移量 112 处发生越界 (OOB) 写入。  
## CVE-2024-50283: ksmbd：修复 smb3_preauth_hash_rsp 中的释放后使用 (UAF) 漏洞  
  
该漏洞在提交  
7aa8804c0b  
时被引入，当时为了避免 UAF 而实现了会话的引用计数：  
```

// https://github.com/torvalds/linux/blob/7aa8804c0b67b3cb263a472d17f2cb50d7f1a930/fs/smb/server/server.c
send:
 if (work->sess)
  ksmbd_user_session_put(work->sess);
 if (work->tcon)
  ksmbd_tree_connect_put(work->tcon);
 smb3_preauth_hash_rsp(work); // [8]
 if (work->sess && work->sess->enc && work->encrypted &&
     conn->ops->encrypt_resp) {
  rc = conn->ops->encrypt_resp(work);
  if (rc < 0)
   conn->ops->set_rsp_status(work, STATUS_DATA_ERROR);
 }

 ksmbd_conn_write(work);

```  
  
在这里，ksmbd_user_session_put  
 会递减 sess->refcnt  
，如果该值降至零，内核就被允许释放 sess  
 对象（[7]  
）：  
```
// https://github.com/torvalds/linux/blob/7aa8804c0b67b3cb263a472d17f2cb50d7f1a930/fs/smb/server/mgmt/user_session.c#L296
void ksmbd_user_session_put(struct ksmbd_session *sess)
{
 if (!sess)
  return;

 if (atomic_read(&sess->refcnt) <= 0)
  WARN_ON(1);
 else
  atomic_dec(&sess->refcnt); // [7]
}
```  
  
随后的 smb3_preauth_hash_rsp  
 函数 ([8]  
) 在访问 sess  
 对象时没有验证该对象是否已被释放 ([9]  
):  
```
// https://github.com/torvalds/linux/blob/7aa8804c0b67b3cb263a472d17f2cb50d7f1a930/fs/smb/server/smb2pdu.c#L8859
 if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE && sess) {
  __u8 *hash_value;

  if (conn->binding) {
   struct preauth_session *preauth_sess;

   preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);
   if (!preauth_sess)
    return;
   hash_value = preauth_sess->Preauth_HashValue;
  } else {
   hash_value = sess->Preauth_HashValue; // [9]
   if (!hash_value)
    return;
  }
  ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,
       hash_value);
 }
```  
  
这可能导致在访问已释放对象时产生使用后释放（UAF）漏洞，该问题被 KASAN 检测到：  
```
BUG: KASAN: slab-use-after-free in smb3_preauth_hash_rsp (fs/smb/server/smb2pdu.c:8875) 
Read of size 8 at addr ffff88812f5c8c38 by task kworker/0:9/308
```  
## CVE-2024-50285: ksmbd：检查未完成的并发 SMB 操作  
  
在报告漏洞并确认修复后，我们在发送大量数据包时发现了另一个问题。每次在套接字连接期间调用queue_ksmbd_work  
时，它都会通过ksmbd_alloc_work_struct  
分配数据  
```
// https://elixir.bootlin.com/linux/v6.11/source/fs/smb/server/ksmbd_work.c#L21
struct ksmbd_work *ksmbd_alloc_work_struct(void)
{
 struct ksmbd_work *work = kmem_cache_zalloc(work_cache, GFP_KERNEL);
    // ..
}
```  
  
在 SMB 协议中，信用点（credits）机制被设计用来控制客户端可以发送的请求数量。然而，受影响的代码在执行信用点限制之前就已经执行了。  
  
在通过远程套接字发送这些数据包大约两分钟后，系统持续遇到内核崩溃并重启：  
```
[  287.957806] Out of memory and no killable processes...
[  287.957813] Kernel panic - not syncing: System is deadlocked on memory
[  287.957824] CPU: 2 UID: 0 PID: 2214 Comm: ksmbd:52086 Tainted: G    B              6.12.0-rc5-00181-g6c52d4da1c74-dirty #26
[  287.957848] Tainted: [B]=BAD_PAGE
[  287.957854] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[  287.957863] Call Trace:
[  287.957869]  <TASK>
[  287.957876] dump_stack_lvl (lib/dump_stack.c:124 (discriminator 1)) 
[  287.957895] panic (kernel/panic.c:354) 
[  287.957913] ? __pfx_panic (kernel/panic.c:288) 
[  287.957932] ? out_of_memory (mm/oom_kill.c:1170) 
[  287.957964] ? out_of_memory (mm/oom_kill.c:1169) 
[  287.957989] out_of_memory (mm/oom_kill.c:74 mm/oom_kill.c:1169) 
[  287.958014] ? mutex_trylock (./arch/x86/include/asm/atomic64_64.h:101 ./include/linux/atomic/atomic-arch-fallback.h:4296 ./include/linux/atomic/atomic-long.h:1482 ./include/linux/atomic/atomic-instrumented.h:4458 kernel/locking/mutex.c:129 kernel/locking/mutex.c:152 kernel/locking/mutex.c:1092) 
```  
  
原因是 ksmbd 不断创建线程，在创建超过 2000 个线程后，ksmbd_work_cache  
耗尽了可用内存。  
  
这可以通过使用slabstat  
或检查/proc/slabinfo  
来确认。活动对象的数量稳步增加，最终耗尽内核内存并导致系统重启：  
```
# ps auxww | grep -i ksmbd | wc -l
2069

# head -2 /proc/slabinfo; grep ksmbd_work_cache /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
ksmbd_work_cache  16999731 16999731    384   21    2 : tunables    0    0    0 : slabdata 809511 809511      0
```  
  
这个问题并非由 syzkaller 发现，而是通过手动测试触发代码时被发现的。  
## 结论  
  
尽管 syzkaller 识别并触发了两个漏洞，但它未能生成重现程序，需要手动分析崩溃报告。这些问题无需身份验证即可访问，通过模糊测试的进一步改进可能会发现更多的漏洞，这些漏洞可能来自难以正确实现的复杂锁定机制或其他因素。由于时间限制，我们没有尝试为 UAF 漏洞创建完整的可用漏洞利用程序。  
## 参考资料  
- https://lore.kernel.org/linux-cve-announce/2024111944-CVE-2024-50283-3aad@gregkh/  
  
- https://lore.kernel.org/linux-cve-announce/2024111948-CVE-2024-50286-85e9@gregkh/  
  
- https://lore.kernel.org/linux-cve-announce/2024111946-CVE-2024-50285-6013@gregkh/  
  
- https://ubuntu.com/security/CVE-2024-50283  
  
- https://ubuntu.com/security/CVE-2024-50286  
  
- https://ubuntu.com/security/CVE-2024-50285  
  
  
  
