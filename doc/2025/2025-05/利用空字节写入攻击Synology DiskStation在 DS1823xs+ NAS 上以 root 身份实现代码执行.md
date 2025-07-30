#  利用空字节写入攻击Synology DiskStation在 DS1823xs+ NAS 上以 root 身份实现代码执行   
 Ots安全   2025-05-06 12:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
10月，我们参加了2024年Pwn2Own爱尔兰站，并成功利用Synology DiskStation DS1823xs+以root身份远程执行代码。此漏洞已修复，编号为CVE-2024-10442。  
  
DiskStation 是 Synology 旗下广受欢迎的 NAS（网络附加存储）产品线。它曾在过去的 Pwn2Own 大赛中被成功利用过几次，但在前一年的大赛（2023 年多伦多 Pwn2Own 大赛）中却毫发无损。之后，在 2024 年爱尔兰大赛中，又有三台 DiskStation 成功参赛，它们都使用了独特的漏洞。  
  
这篇文章将详细介绍我们研究 Synology DiskStation 以及为该事件编写漏洞利用程序的经验。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadibXd1zjP4OqYagU8JzasTM5b6ocYTALciaEFJWqcNLRibkH3G6iazmLuBJSokrqEibFibzBLCOV8OMuvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
准备在 Pwn2Own Ireland 2024 上利用 Synology DiskStation 漏洞  
  
查看 Synology 套件  
  
如上所述，过去一两年的 Pwn2Own 大赛中，没有出现任何与 Synology DiskStation 竞争的案例。2024 年，ZDI 选择将一些非默认但由 Synology 编写的第一方软件包纳入比赛范围：  
  
对于 Synology DiskStation 目标，将安装以下软件包并纳入竞赛范围：  
- MailPlus  
  
- Drive  
  
- Virtual Machine Manager  
  
- Snapshot Replication  
  
- Surveillance Station  
  
- Photos  
  
“  
Packages”是可选的附加应用程序/服务（等），可以通过 DiskStation 管理器中的 Synology 套件中心轻松安装在设备上。  
  
对我们来说，这意味着更多的攻击面，而且由于这些软件包是第一年纳入范围的，我们认为这是一个很好的机会来发现一些相对较浅的漏洞，因为这些软件包可能还没有经过太多的安全审查。事实证明，这完全是事实。  
  
我们查看的第一个软件包是虚拟机管理器，它是直接从物理 DiskStation 上的内置软件包中心安装的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadibXd1zjP4OqYagU8JzasTMLj23s9vBvg5YFPc3VKjRXQsmehvh3QorWotaphcRzHYsfUbHq61OrA/640?wx_fmt=png&from=appmsg "")  
  
然后，我们可以通过测试设备上的 SSH shell 枚举所有新的网络监听器netstat。这揭示了一些仅在本地主机上运行的服务，除了一个绑定到所有接口的服务，运行以下命令（以 root 身份）：  
  
```
/var/packages/ReplicationService/target/sbin/synobtrfsreplicad --port 5566
```  
  
  
这个监听器实际上是复制服务的一部分，而复制服务是一个独立的包，依赖虚拟机管理器（同时也依赖快照复制）。由于该服务拥有较高的权限级别，并且易于通信，我们对此很感兴趣。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadibXd1zjP4OqYagU8JzasTMiajicKdLqvlSq9YfWy8CZSdME805HjoZ8QCjaBVqUMNun3bYhiaLuZ84A/640?wx_fmt=png&from=appmsg "")  
  
下一步是检查二进制文件。由于我们已经在真实设备上安装了该服务，因此我们能够通过 SSH 提取文件。  
  
或者，您也可以直接从 Synology 下载 DSM（核心操作系统）和软件包。然后可以使用提取工具解析自定义 Synology 存档，并提取软件包、固件映像或更新的内容。请注意，此特定工具是针对原生第一方 Synology 共享库的 FFI 包装器，可以从真实设备中拉取，也可以使用单独的工具从 DSM 存档中提取。  
  
查找 Bug  
  
有了相关的二进制文件，我们就可以开始查看监听端口 5566 的 TCP 服务的代码。主二进制文件synobtrfsreplicad只是一个驱动程序垫片，用于调用中的功能libsynobtrfsreplicacore.so.7，从而启动 TCP 监听器。  
  
该服务是一个基于 Linux 的极简派生服务器，主进程不断调用accept()并派生出一个子进程来处理每个新的远程客户端。反过来，子进程会运行一个基本的命令循环来解析发送到该服务的传入消息。  
  
每个命令都有一个简单的二进制格式，带有一个操作码（可选），后面跟着一个大小可变的数据有效载荷：  
  
```
unsigned cmd // command opcodeunsigned seq // sequence numberunsigned lenchar data[len]
```  
  
  
为了方便解析这些命令消息，定义了两个全局变量。一个用于命令本身，另一个是一个环形缓冲区结构，用于保存最多 3 个大小可变的命令有效载荷。  
  
```
struct{    unsigned char sector; // ring buffer index    char bufs[3][65536]; // ring buffer of 3 payloads    unsigned buf_lens[3]; // populated lengths of 3 payloads} g_recvbuf;struct{    ReplicaCmdHeader header; // opcode, seq, len    char *data; // will point into one of the 3 g_recvbuf bufs} g_cmd;
```  
  
读取消息的命令循环如下所示：  
  
```
voidrunCmdLoop(){    while(1) {        g_cmd.data = g_recvbuf.bufs[g_recvbuf.sector];        int err = recvCmd(&g_cmd);        if (err)            bail;        g_cmd.data[g_cmd.header.len] = 0;        // ... handle cmd ...    }}// function to read both the header and payload of a messageintrecvCmd(ReplicaCmd* cmd){    int err = raw_tcp_recv(cmd->header, 12);    if (err)        return err;    if (cmd->header.len > 0x10000)        return err;    // read actual payload data    err = raw_tcp_recv(cmd->data, cmd->header.len);    // ...}
```  
  
如果攻击者提供的长度过大，recvCmd则跳过不读取任何有效载荷的环节。然而，它的返回值为零，表示没有错误，考虑到标头长度无效，这有点奇怪……回到调用方，它并不知道有任何错误，一切正常进行，命令有效载荷以空值终止，并使用任意大的标头长度。  
  
这个漏洞很简单，对于我们最初的 POC，我们可以使用 netcat 以经典的可破解方式发送仅由 A（至少 12 个）组成的消息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadibXd1zjP4OqYagU8JzasTMfib176Lx3ydick0cdckpzs9GCcttiawicTicD38AQrLibXUVBYAakfXUk2LA/640?wx_fmt=png&from=appmsg "")  
  
除非您使用 gdb 连接到该服务，否则设备上没有任何迹象表明出现了任何问题。该故障似乎没有记录到 syslog 或任何其他 DSM 日志记录工具中，而且由于分叉服务器的特性，它不会立即导致功能丧失。  
  
此漏洞提供的原语允许我们将空字节重复写入共享库 BSS（数据段）的任意偏移量。非常类似 CTF 题。虽然漏洞本身相当简单，但利用起来却更加有趣。  
  
无论如何，由于所有缓解措施都已启用，我们首先必须以某种方式将其转变为信息泄露。  
  
分叉服务器  
  
在继续之前，请记住，我们正在处理一个 fork 服务器，这对于破坏 ASLR 非常有用。每个 fork 出来的子进程都将拥有与父进程完全相同的地址空间，因此即使它们崩溃也不会造成任何后果：我们只需重新连接到该服务，即可获得一个新的子进程，重新开始。这有点像时间循环，每次连接都是一个以累积方式收集有关地址空间新信息的机会。  
  
从高层次来看，每次迭代都具有以下结构：  
1. 猜一些事情（例如地址）  
  
1. 让二进制文件使用猜测的值，这样它的行为就会有所不同，无论它是否正确（例如，错误的地址将崩溃）  
  
1. 观察二进制的行为以确定值是否正确  
  
1. 如果正确，则我们找到了正确的值。否则，重复下一个猜测  
  
接下来，我们将看到如何将其应用于这个特定的二进制文件。  
  
功能概述  
  
由于所讨论的错误发生在输入解析期间，我们尚未探索该程序的大部分功能，稍后我们需要利用这些功能来构建漏洞。  
  
从网络读取命令后，命令循环会对提供的操作码进行 switch-case 处理。需要输入的操作码会从可变长度的命令有效负载中解析出来。我们查看了所有可用的操作码，以大致了解它们的功能：  
- CMD_DSM_VER：无输入  
  
- 返回 DSM 版本号  
  
- CMD_SSL：初始化 SSL 连接  
  
- CMD_TEST_CONNECT  
  
- CMD_NOP  
  
- CMD_VERSION：输入整数  
  
- 设置连接的“版本”以适应兼容性差异  
  
- CMD_TOKEN：输入字符串“token” ，它必须作为键存在于磁盘上的 JSON 文件中  
  
- 执行初始化并设置全局std::string g_token  
  
- CMD_NAME：输入字符串“name”  
  
- 可以执行与 btrfs 相关的操作，和/或用于g_token修改 JSON 文件  
  
- CMD_SEND：输入原始数据  
  
- 代理输入到文件描述符，似乎在其他地方设置为btrfs命令的管道  
  
- CMD_UPDATE  
  
- CMD_STOP：输入标记字符串  
  
- 从 JSON 中删除令牌  
  
- CMD_COUNT  
  
- CMD_CLR_BKP  
  
- CMD_SYNCSIZE  
  
- CMD_END  
  
很快我们就发现，许多代码路径都依赖于提供有效的“token”，而这个“token”应该已经存在于一个 JSON 文件中/usr/syno/etc/synobtrfsreplica/btrfs_snap_replica_recv_token。JSON 被用作属性的简单键值存储，其中 token 就是键：  
  
```
{    "<token>": {"<attribute>":value, ... other attributes ...},    ... other tokens ...}
```  
  
  
据推测，一些外部服务分发了这些令牌并写入文件，但我们不清楚这是在哪里发生的。  
  
但是，有一条代码路径允许以非预期的方式向 JSON 文件添加标记。该CMD_NAME操作码使用当前的g_token，并将属性写入文件，但有两个重要的细微差别：  
- 它不检查是否g_token曾经初始化（即使用CMD_TOKEN）  
  
- 如果令牌尚未作为 JSON 对象中的键存在，则设置属性将其添加  
  
通常情况下，未初始化的g_token只是一个空字符串，但由于内存损坏，所有的猜测都将被取消，我们将在稍后看到这如何证明是有用的。  
  
ASLR Oracle #1：释放伪堆块  
  
我们的原语是写入空字节，即向命令有效载荷缓冲区中提供任意偏移量。该偏移量是无符号的，因此我们只能将空值写入有效载荷缓冲区后面的内存。  
  
这就带来了一个问题：有效载荷缓冲区之后是什么？有效载荷缓冲区是共享库 BSS 中全局变量中三个 0x10000 大小的缓冲区之一。除了少数几个具有以下结构的实例外，g_recvbuf全局变量并不多：std::string  
  
```
structstd::string {    char* ptr; // for short strings, points into inline_buffer    unsignedlong length;    char inline_buffer[16];}
```  
  
  
默认构造函数将长度设置为 0，并指向char*内联缓冲区。换句话说，我们将std::string在 BSS 中拥有一堆实例，其指针指向它们自己的 BSS 地址，加上偏移量 16。  
  
现在，考虑一下如果我们使用空写入将其中一个指针的最低两个字节清零。它前面的有效载荷缓冲区大小为 0x10000 字节，这个大小足以保证部分为空的 BSS 指针指向该缓冲区内的某个位置，尽管我们不知道确切的偏移量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadibXd1zjP4OqYagU8JzasTMD1mBGHj8b1UWhRZo3SNQnibefmhjXhmanFgkQpiciaQItR9bDokOyaqFg/640?wx_fmt=png&from=appmsg "")  
  
由于 ASLR 具有页面粒度（12 位），因此该偏移量中会有 4 位（一个半字节）的熵（即它可以是 0、0x1000、0x2000、... 0xf000）。  
  
我们可以破坏的全局字符串之一是_gSnapRecvPath，它可以被重新分配为命令执行的操作之一CMD_NAME。  
  
重新赋值时std::string，如果char*未指向内联缓冲区，delete则会在赋值新值之前对旧值（现已损坏）调用 。 这让我们可以 free 在有效载荷缓冲区中调用一个伪块。我们自然可以使用命令有效载荷来控制此缓冲区的内容。  
  
当free被调用时，如果伪造的块足够小，它将被放入 glibc tcache 中。相反，如果大小无效（例如零），free则会调用abort，导致进程崩溃。这将创建我们的第一个 oracle，我们可以将它与 forking-server 的行为结合起来，以确定伪造的块位于 16 个可能的偏移量（0、0x1000、…、0xf000）中的哪一个。  
  
对于 16 个可能的偏移量中的每一个：  
1. 将有效载荷缓冲区填充到猜测的偏移量，然后是假块的元数据（这只是一个假的大小值）  
  
1. 触发漏洞两次，将char*for的两个低字节清零_gSnapRecvPath  
  
1. 用于CMD_NAME释放损坏的char*，它可能指向也可能不指向放置在猜测偏移量的假块  
  
- 如果套接字保持连接并且发送了响应，则猜测的偏移量是正确的  
  
- 如果套接字已关闭（即被abort调用），则猜测不正确；请使用下一个偏移量重试  
  
现在，我们已经解决了 ASLR 熵的一小部分，并且可以可靠地释放有效载荷缓冲区中的假块，该假块将被放入 tcache 中。  
  
ASLR 预言机 #2：泄露令牌  
  
tcache 是一个由空闲块组成的单链表，每个空闲块都有一个 next 指针。由于 glibc 中的一些强化措施，next 指针的填充方式如下：  
  
```
chunk->next = (&chunk->next>> 12) ^ next
```  
  
  
在我们的例子中，tcache 列表之前为空（next = 0），因此写入的值将是&chunk->next >> 12。换句话说，我们将一个移位后的 BSS 指针放入了有效载荷缓冲区。现在我们需要找到某种方法来泄露这个值。  
  
一旦伪造的块被释放，并且移位后的 BSS 指针被写入，我们就会将char*第二个全局变量的低 2 个字节置空std::string。g_token这种破坏会导致g_token指向与 完全相同的位置_gSnapRecvPath，也就是移位后的 BSS 指针。  
  
回想一下我们之前讨论的功能CMD_NAME，它可以将一个未初始化的值添加g_token到磁盘上的 JSON 文件中。这正是这个功能非常有用的地方，因为它不再g_token指向空字符串，而是指向移位后的 BSS 指针。触发此代码路径后，JSON 文件现在包含了我们想要泄漏的值。  
  
另请注意，在写入g_token磁盘之前，我们可以额外触发一次空字节写入，以截断移位后的 BSS 指针。这样，我们就可以写出指针的每个部分。例如，如果移位后的指针为0x766554433，我们可以写出从33、3344、…… 到完整的 的每个部分3344556607。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadibXd1zjP4OqYagU8JzasTMrRvwyV9Wm7Iv9ibuiamR4JzAvEp9FnrSq6ZaeXV5icfqZSGuMxyZRNEVQ/640?wx_fmt=png&from=appmsg "")  
  
一旦 JSON 文件包含泄漏信息，我们就可以CMD_TOKEN按预期使用，它需要一个字符串参数来指示要使用的令牌。该令牌将在 JSON 文件中查找，并根据是否找到返回不同的错误代码。这将创建我们的第二个 oracle，我们可以使用它来实现逐字节的暴力破解：  
  
b对移位后的 BSS 指针的 5 个字节中的每一个字节从 0 循环到 4：  
1. 将指针截断为 length b+1，然后将截断的段写入 JSON 文件  
  
1. 循环遍历可能的字节0 - 0xff：  
  
- 发送CMD_TOKEN猜测的字节（前面加上前几次迭代中已知的字节，长度为b）  
  
- 返回的错误代码将指示提供的字节是否正确  
  
- b如果正确，我们就找到了移位指针索引处的字节  
  
- 否则，继续尝试下一个可能的字节  
  
一旦逐字节暴力破解完成，我们就泄露了移位后的 BSS 指针，从而得到了共享库的基址。由于mmap映射在虚拟内存中是连续的，因此这也给了我们所有共享库的地址，尤其是 libc 的地址。  
  
劫持控制流  
  
有了泄漏，我们就可以准备制作最终的有效载荷来劫持控制流。  
  
我们已经有能力在有效载荷缓冲区中释放一个伪块，并且通过发送其他命令，我们可以任意破坏这个空闲的块。此时，我们可以以标准方式滥用 tcache 链表：  
1. 使用任意地址破坏伪块的下一个指针  
  
1. 分配与假块大小相同的内容  
  
1. malloc将返回假块，然后将 tcache 列表的新头部设置为任意地址  
  
1. 再次分配相同的大小以malloc返回任意地址  
  
我们只需要找到一些符合这种连续两次分配模式的代码。幸运的是，CMD_TOKEN处理程序符合这种模式，并且在执行两次分配之后，std::string临时包含我们输入参数的函数会被析构，并调用delete一个char*带有我们输入的函数。  
  
这给我们带来了以下策略：  
1. 破坏伪 tcache 块的下一个指针，使其指向共享库的 GOT 条目附近delete  
  
1. 发送CMD_TOKEN命令  
  
1. 处理程序将从损坏的 tcache 中分配两次，并delete用以下方式覆盖 GOT 条目：system  
  
1. 后续的析构函数调用delete，而是system使用受控的输入字符串调用  
  
从这里开始，游戏就结束了。我们可以简单地执行/bin/sh并将 stdio 重定向到已经连接的客户端套接字（避免了回连）。  
  
  
我们提交的完整漏洞代码已在此处提供-  
https://github.com/ret2/Pwn2Own-Ireland2024-DiskStation。  
  
修复  
  
该漏洞的编号为 CVE-2024-10442。Synology 于 2024 年 11 月 5 日（Pwn2Own Ireland 于 10 月 22 日举行）相对较快地发布了针对复制服务的补丁，您可以在此处找到该补丁的公告。ZDI 的公告可在此处找到。该补丁修改了函数recvCmd，如果提供的标头长度过长，则返回错误而不是零。  
  
```
if (cmd->header.len > 0x10000)    return1; // instead of previous return 0
```  
  
  
然后，调用者检测到此错误并放弃，而不是继续处理无效命令。  
  
结论  
  
虽然很容易找到，但这个漏洞的利用过程却非常有趣，因为空字节写入的攻击原语相对较弱。它感觉就像你在 CTF 挑战中会遇到的那种漏洞，而且 tcache 操作和暴力破解预言机也符合 CTF 的风格。  
  
更严重的是，尽管它不在默认包中，但在远程可访问服务（以 root 身份运行）中存在如此简单的漏洞还是有点令人担忧，尤其是考虑到 Synology 是一款相当流行的面向消费者和企业的 NAS，这些设备暴露在互联网上的情况并不少见。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
