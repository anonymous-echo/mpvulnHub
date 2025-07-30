> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1MDA1MjcxMw==&mid=2649908515&idx=1&sn=9dd45778d480828d43ccc3465239a217

#  如何调试Microsoft Defender for Endpoint (MDE) 发现 CVE 漏洞  
 先进攻防   2025-07-05 03:11  
  
说明： 本文是翻译自 FalconForce 团队的技术博客原文  
  
原文地址： https://falconforce.nl/debugging-the-undebuggable-and-finding-a-cve-in-microsoft-defender-for-endpoint/  
  
在 FalconForce，我们热衷于深入理解我们日常使用的工具。在蓝队工作中，我们最常使用的工具之一就是 MDE（Microsoft Defender for Endpoint，前身为 Microsoft Defender ATP）。在一次探究 MDE 如何将日志发送到 M365 云环境的过程中，我们不仅发现了一个调试受保护进程的巧妙技巧，还意外发现了一个 MDE 的漏洞。该漏洞已于 2021 年 8 月报告给微软，并被分配了编号 CVE-2022–23278。  
  
这篇博客将分为三个部分：  
1. 首先，分享一些调试受保护进程（Protected Processes）的技巧和窍门。  
  
1. 然后，在我们成功调试 MDE 进程后，深入探讨我们发现的具体漏洞。  
  
1. 最后，快速看一下微软为修复此漏洞所做的更新。  
  
**长话短说 (TL;DR)**  
> 你可以通过运行 
```
dbgsrv.exe
```

  
 并将其 PPL (Protected Process Light) 保护级别提升至 
```
WinTcb
```

  
，来调试在终端上运行的 MDE 进程。利用这种方法，我们可以嗅探到 MDE 传输到云端的数据。我们发现了一个与 MDE 终端发送到 M365 云的数据缺少授权检查相关的漏洞，该漏洞允许任何人向任意 M365 租户发送欺骗性数据。  
  
## 第一部分：调试受保护进程  
  
为了实现我们观察 MDE 进程发送到 M365 云流量的目标，我们需要能够调试 MDE 进程，其核心进程是 
```
MsSense.exe
```

  
。  
  
我们可以使用强大的 Process Hacker 工具来检查一个程序的保护状态。  
  
  
如果我们尝试将调试器附加到该进程，操作将会失败，即使我们使用具备 
```
TrustedInstaller
```

  
 权限的 
```
SYSTEM
```

  
 账户运行调试器也无济于事。  
  
  
有多种工具可以用来修改 
```
MsSense.exe
```

  
 程序的保护属性，例如 PPLKiller。它可以通过一个易受攻击的驱动程序来操纵内核内存，从而移除正在运行进程的 PPL 保护标志。  
  
使用 PPLKiller 降低保护级别是我们最初的尝试，但不幸的是，WinDbg 仍然报出相同的权限拒绝错误。我们过去有过一些 Windows 内核模式调试的经验，这种方法确实可以调试这些受保护的进程，但非常不方便，因为只要调试器触发断点，整个机器就会冻结。  
  
幸运的是，我们找到了一个更好的方法：**与其降低 MsSense.exe 的保护级别，不如提升我们调试器的保护级别。**  
### 提升调试器的保护级别  
  
默认情况下，PPLKiller 只允许移除 PPL 权限，但相同的机制也可以用来为一个现有进程添加这些权限。我们为 PPLKiller 贡献了一个补丁，增加了一个 
```
/enablePPL
```

  
 选项来提升现有进程的保护级别。要让这个技巧稳定生效，关键不是直接对 WinDbg 进程操作，而是对调试服务器 
```
dbgsrv.exe
```

  
 进程进行操作。  
  
首先，我们以 
```
SYSTEM
```

  
 账户启动 
```
dbgsrv.exe
```

  
 进程，并让它在本地 
```
1234
```

  
 端口（任何端口都可以）上监听。  

```
&#34;C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2111.9001.0_neutral__8wekyb3d8bbwe\amd64\dbgsrv.exe&#34; -t tcp:server=127.0.0.1,port=1234


```

  
现在，使用打过补丁的 PPLKiller 版本来提升这个调试服务器的保护级别：  

```
> tasklist | findstr dbgsrv
dbgsrv.exe                   4024

> .\PPLKiller.exe /enablePPL 4024
PPLKiller version 0.3 by @aceb0nd
[+] Windows Version 2009 Found
[*] Device object handle has been obtained
[*] Ntoskrnl base address: FFFFF80720800000
[*] PsInitialSystemProcess address: FFFF90032906D080
[*] Current process address: FFFF900330580080
[*] Enabling PPL protection for process.


```

  
  
在 
```
dbgsrv.exe
```

  
 的保护级别被提升后，它就可以用来调试 
```
MsSense.exe
```

  
 了。一旦 
```
dbgsrv.exe
```

  
 运行起来，我们就可以用 WinDbg 连接到它。  
  
  
通过这个以 
```
SYSTEM
```

  
 身份运行且提升了 PPL 保护级别的 
```
dbgsrv.exe
```

  
 进程，我们成功附加到了 
```
MsSense.exe
```

  
。  
###   
### 观察 TLS 加密流量的明文  
  

```
MsSense.exe
```

  
 与 M365 云环境之间的所有通信都通过 TLS 进行，并使用了证书固定（Certificate Pinning）。这样做是为了确保即使设备上安装了流氓 CA 证书，像 Burp 这样的中间人攻击工具也无法奏效。  
  
既然我们已经将调试器附加到进程上，我们就可以在流量被加密前进行拦截。为此，我们可以在 
```
SspiCli!EncryptMessage
```

  
 函数上下一个断点。这个函数是 TLS 协议中负责加密的部分。  
  
可以使用以下命令设置断点：  

```
> bu SspiCli!EncryptMessage


```

  
然后我们用 
```
g
```

  
 命令恢复进程。一旦进程执行到 
```
EncryptMessage
```

  
 函数，调试器就会中断程序：  

```
Breakpoint 0 hit
SspiCli!EncryptMessage:
00007ff8`53a91be0 4053            push    rbx
```EncryptMessage` 的参数在[微软的官方文档](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage)中有详细说明。我们关心的是第三个参数 `pMessage`，因为它包含了消息内容。根据 Windows 的[调用约定](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)，第三个参数通过 `r8` 寄存器传递。`r8` 寄存器包含一个指向 `SecBufferDesc` 结构的指针。

`pBuffers` 元素是我们要找的，它位于偏移量 8 的位置。我们可以用以下 WinDbg 命令来查看 `pBuffers` 元素，它包含了多个 `SecBuffer`。注意，`poi` 函数在 WinDbg 中用于解引用指针。

```c
0:039> dq(poi(@r8+8))
00000054`c4bff070  00000007`0000000d 00000235`ea69c040
00000054`c4bff080  00000001`000003f9 00000235`ea69c04d
00000054`c4bff090  00000006`00000010 00000235`ea69c446
...


```

  
经过一番摸索，我们发现第二个 
```
SecBuffer
```

  
（类型为 
```
00000001
```

  
）实际上包含了明文数据。我们可以这样提取它（注意，
```
0n16*1
```

  
 可以修改为 
```
0n16*0
```

  
、
```
0n16*2
```

  
 等来转储其他缓冲区）：  

```
> db poi(poi(@r8+8)+8+0n16*1) L0n192
50 4f 53 54 20 2f 4f 6e-65 43 6f 6c 6c 65 63 74  POST /OneCollect
6f 72 2f 31 2e 30 20 48-54 54 50 2f 31 2e 31 0d  or/1.0 HTTP/1.1.
0a 43 61 63 68 65 2d 43-6f 6e 74 72 6f 6c 3a 20  .Cache-Control: 
6e 6f 2d 63 61 63 68 65-0d 0a 43 6f 6e 6e 65 63  no-cache..Connec
74 69 6f 6e 3a 20 4b 65-65 70 2d 41 6c 69 76 65  tion: Keep-Alive
...


```

  
POST 的请求头和请求体是通过对 
```
EncryptMessage
```

  
 的不同调用来加密的。因此，这里只显示了请求头。如果我们想观察 POST 请求体，我们需要继续执行直到下一个断点被命中。  
  
当我们查看 POST 请求体时，它看起来很奇怪：  

```
> db poi(poi(@r8+8)+8+0n16*1)
b5 5b 59 6f ea 4a 97 7d-6f a9 ff c3 55 9e ba 95  .[Yo.J.}o...U...
9b 73 3c 60 02 47 ea 07-1b 0f 31 49 99 18 3c 60  .s<`.G....1I..<`
...


```

  
这看起来不像一个正常的 POST 请求体，直到我们意识到请求头中有一行 
```
Content-Encoding: deflate
```

  
，表明 POST 请求体被压缩了。  
  
我们可以将压缩数据写入文件：  

```
> .writemem c:\temp\request.raw  poi(poi(@r8+8)+8+0n16*1) l1c42
Writing 1c42 bytes....


```

  
这个文件可以用多种方式解压，例如，使用一个简单的 Python 脚本：  

```
import zlib
import sys

with open(sys.argv[1], 'rb') as f_in, open(sys.argv[1] + '.out', 'wb') as f_out:
    decompressed_data = zlib.decompress(f_in.read(), -15)
    f_out.write(decompressed_data)


```

  
对 
```
request.raw
```

  
 文件运行此脚本后，我们得到的 
```
request.raw.out
```

  
 文件终于包含了解密后的负载。事实证明，这实际上是一个 JSON 格式的数据。  
  
  
实际的事件数据在 JSON 中经过了 base64 编码：  

```
&#34;data&#34;: {
   &#34;events&#34;: &#34;rQkLAQ9HZ...snip&#34;
}


```

  
对这串 base64 字符串进行解码，可以得到二进制格式的事件。它们似乎是使用 Microsoft Bond 序列化框架进行序列化的，这与更常用的 Protobuf 框架类似。  
  
  
这些就是被采集并发送到 M365 云端的真实事件。  
## 第二部分：漏洞详情  
  
现在我们知道了数据是如何从我们设备上的 MDE 发送到 M365 云的，我们终于可以审视这个漏洞了。  
  
要理解这个漏洞，我们必须查看所发送 JSON 的 
```
id
```

  
 部分：  
  
  
原来，关于被发送事件的元数据位于 JSON 数据的 
```
id
```

  
 部分。这其中包含了 
```
OrgId
```

  
（一个代表日志将被投递到的目标组织的 GUID）、
```
MachineId
```

  
 和 
```
ComputerDnsName
```

  
，这些信息最终会作为事件的来源出现在 M365 门户中。  
  
我们再来看看 POST 请求的头部：  

```
POST /OneCollector/1.0 HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Content-Type: application/x-json-stream; charset=utf-8
Content-Encoding: deflate
Accept: application/json
User-Agent: MSDW
ApiKey: <removed>
AuthMsaDeviceTicket: <removed>
...
Host: eu-v20.events.data.microsoft.com


```

  
身份验证基于一个 
```
ApiKey
```

  
——事实证明它对所有 MDE 客户端都是静态和共享的——以及一个 
```
AuthMsaDeviceTicket
```

  
。然而，这个 
```
ticket
```

  
 竟然是可选的，可以被替换为一个 
```
Client-Id: NO_AUTH
```

  
 的请求头，从而完全绕过身份验证。  
  
**漏洞的核心在于：系统没有进行适当的授权检查，来证明发送者有权代表特定的设备和组织发送数据。**  
 这意味着任何人只要篡改 
```
MachineId
```

  
、
```
OrgId
```

  
 和 
```
ComputerDnsName
```

  
 字段，就可以代表任何组织和机器发送数据。这甚至可以跨租户工作，如果知道了目标租户的 GUID，就可以向另一个租户发送日志。这个 GUID 可以由组织中的任何用户或任何已注册到 MDE 的机器获取。  
  
作为概念验证（PoC），我们从自己的租户捕获了一些事件，并将这些事件重放了 20 次到另一个我们拥有的租户，同时伪造了 
```
MachineId
```

  
 和 
```
ComputerDnsName
```

  
 字段。结果发现，如果一个 
```
MachineId
```

  
 尚不存在，MDE 会使用提供的信息添加一个新的
```
设备
```

  
。  
  
### 潜在影响  
  
利用这个漏洞，攻击者在知道 
```
OrgId
```

  
 的情况下，可以向任何 M365 环境发送任意数量的欺骗性事件。这些事件可能包括伪造的警报，从而触发虚假事件，让 SOC（安全运营中心）团队去调查，导致他们对哪些事件是真实的、哪些是被操纵的产生巨大困惑。  
## 第三部分：漏洞修复  
  
2022 年 3 月 8 日，微软在“补丁星期二”发布了针对该漏洞的补丁，并在 MSRC 博客上提供了一些额外的指导。  
  
该补丁要求更新 MDE 客户端，增加了反欺骗措施。可以使用 Microsoft Defender for Endpoint 客户端分析器工具来检查特定机器是否已更新并启用了反欺骗措施。  
  
  
除了补丁，微软还在 Microsoft 365 Defender 门户中将此漏洞添加为一个威胁，提供了一个仪表盘，显示环境中易受攻击设备的数量。  
  
  
还增加了一个新的警报，当针对目标环境发生此漏洞的利用尝试时会触发。该警报标题为“可疑的客户端通信”（Suspicious client communication）。我们通过运行原始的 PoC 代码成功在测试环境中触发了此警报，但它仅在我们针对一台已完全打补丁的机器的 
```
DeviceId
```

  
 时才会触发。  
  
### 修复的技术细节  
  
此修复增加了一个新的机制来验证发送日志的设备。它使用一个类似 JWT 的签名令牌，该令牌通过一个新增的名为 
```
Custom-Request-Field
```

  
 的 HTTP 头传递。  
  
下图是一个从已完全打补丁的 MDE 版本的设备 
```
Custom-Request-Field
```

  
 头中提取并解码的 JWT 令牌示例。  
  
  
截图显示，
```
machineId
```

  
 和 
```
orgId
```

  
 是这个 JWT 令牌的一部分。当它们与实际请求中的 
```
orgId
```

  
 和 
```
machineId
```

  
 不匹配时，这些值可用于识别欺骗行为。  
  
看起来微软还实施了额外的措施，限制了代表不存在的 
```
MachineId
```

  
 发送数据的能力。这些事件似乎被丢弃了，不再出现在 MDE 门户的日志中。  
## 时间线  
- **2021年8月17日**  
 - 通过微软 MSRC 门户报告漏洞。  
  
- **2021年8月20日**  
 - 向微软提供包括 Python PoC 代码在内的附加信息。  
  
- **2021年9月15日**  
 - 微软确认漏洞。  
  
- **2021年11月4日**  
 - 微软团队请求在问题修复前需要更多时间，并希望推迟任何公开披露。  
  
- **2021年11月20日**  
 - 微软团队通知我们修复工作复杂，需要更多时间。  
  
- **2022年2月7日**  
 - 收到通知，CVE-2022–23278 将被分配，漏洞将在三月的“补丁星期二”进行修复。  
  
- **2022年3月8日**  
 - 微软发布补丁。  
  
- **2022年4月1日**  
 - FalconForce 发布包含完整细节的博客文章；有意延迟发布，以便各组织有足够的时间来修补漏洞。  
  
  
  
  
