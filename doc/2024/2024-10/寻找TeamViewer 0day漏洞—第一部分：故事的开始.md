#  寻找TeamViewer 0day漏洞—第一部分：故事的开始   
原创 一个不正经的黑客  一个不正经的黑客   2024-10-05 15:28  
  
## 寻找TeamViewer 0day漏洞—第一部分：故事的开始  
  
这一系列博客文章将探讨关于TeamViewer（TV）与其SYSTEM服务之间的IPC通信的一些发现。我原本是在尝试寻找TeamViewer客户端中的一些漏洞，最后却深入研究了它与辅助服务的通信机制。  
  
在能够伪造（我们稍后会看到，只是一些简单的身份验证）一个有效的TeamViewer客户端并与SYSTEM服务的IPC通信连接后，我发现可以触发任意驱动程序的安装。  
  
TeamViewer并未验证所安装驱动程序的签名，它将任意的inf文件传递给了UpdateDriverForPlugAndPlayDevices。  
  
因此，通过TeamViewer可以实现从用户权限到内核权限的提升。  
  
正如我们将看到的，其中一种最有效的方法是使用著名的BYOD技术（Bring Your Own Vulnerable Driver，带上你自己的易受攻击的驱动程序），将一个有效签名的驱动程序加载到Windows内核中，然后加以利用，从而在用户级别执行特权操作，例如将任意进程的令牌替换为一个拥有高级权限的令牌。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLdBUM0Rkibfq8oHmSFLRHxlpdryJBLIpTpe9raQqB3HInQhK0m2hKF6g/640?wx_fmt=other&from=appmsg "")  
### 背景  
  
首先，提供一些背景知识，以便理解后续内容。这个漏洞在TeamViewer仅在系统上运行时是无法利用的，必须安装TeamViewer才能触发。  
  
当TeamViewer安装在系统上时，它会创建一个以SYSTEM权限运行的服务，名为TeamViewer_service.exe。  
  
这个服务的作用是为客户端执行某些任务。因此，客户端并不会以提升的权限运行，而是将部分任务委托给该服务。  
  
与服务的通信（IPC）是通过套接字实现的（使用重叠I/O和IoCompletionPort）。默认情况下，TeamViewer的SYSTEM服务在本地主机上的5939/tcp端口监听。  
```
C:\Windows\system32>netstat -ano | findstr /i 15792  
  TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       15792  
  TCP    127.0.0.1:5939         127.0.0.1:64668        ESTABLISHED     15792  
  [...]  
```  
  
我测试了以下TeamViewer版本，该漏洞在这些版本中有效：  
  
15.53.7
15.54.6  
  
在测试TeamViewer的过程中，有一项功能引起了我的注意。那就是只需点击一下，就能安装其VPN和打印机驱动。  
  
我用一个未授权用户进行了测试，结果发现该功能也可以正常工作。  
  
好奇心害死猫。  
  
那么问题来了，这个功能是如何实现的呢？于是，研究之旅由此开始。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLzfzDB71fXic1OwrI4ubIC8XFAtXkX2jzj09kbezMAIicPBzxZice82CPA/640?wx_fmt=png&from=appmsg "")  
  
在我第一次尝试时，我使用的是具有管理员权限的用户运行TeamViewer，尽管是以中等完整性级别运行的。  
  
于是，我尝试使用一个未授权用户启动驱动程序安装，结果同样成功了。  
  
TeamViewer记录了整个安装过程。第四列表示哪个实体进行了日志记录，S0表示SYSTEM进程日志。S0后面的符号表示日志的类型，"+"似乎表示详细程度，"+"越多，日志越详细。当发生错误时，会使用"!"来表示  
```
2024/05/26 20:36:39.130  2036      10604 S0+  GetSimpleDisplayCertNameFromFile: Found cert name: 'TeamViewer Germany GmbH'.
2024/05/26 20:36:39.130  2036      10604 S0+  VerifyTeamViewerCertificate: File for loading certificate is C:\Program Files\TeamViewer\tv_x64.exe
2024/05/26 20:36:39.130  2036      10604 S0+  VerifyTeamViewerCertificate: SHA256 code path.
2024/05/26 20:36:39.130  2036      10604 S0+  SHA256 certificate check.
2024/05/26 20:36:39.130  2036      10604 S0+  VerifyCertHash(): Certificate check succeded.
2024/05/26 20:36:39.130  2036      10604 S0+  tvnetwork::IpcLoaderProcessHandlerWin::Received_StartLoaderProcess: Starting Loader Process C:\Program Files\TeamViewer\tv_x64.exe (type 2) for ID 1500170772 in session 2 with args --action install --verbose --log C:\Program Files\TeamViewer\TeamViewer15_Logfile.log  --event Local\DriverInstallFinishEvent_VPN --inf C:\Program Files\TeamViewer\x64\TeamViewerVPN.inf --id TEAMVIEWERVPN
2024/05/26 20:36:39.130  2036      10604 S0   CToken::GetSystemToken() set session 2
2024/05/26 20:36:39.130  2036      10604 S0+  ProcessWin::CreateProcessInternal: CreateProcess C:\Program Files\TeamViewer\tv_x64.exe AsUser
2024/05/26 20:36:39.130  2036      10604 S0   tvnetwork::IpcLoaderProcessHandlerWin::Received_StartLoaderProcess: Loader process started, pid = 13920
2024/05/26 20:36:39.146 13920 14904 L64  Loader started with: "C:\Program Files\TeamViewer\tv_x64.exe" --action install --verbose --log C:\Program Files\TeamViewer\TeamViewer15_Logfile.log  --event Local\DriverInstallFinishEvent_VPN --inf C:\Program Files\TeamViewer\x64\TeamViewerVPN.inf --id TEAMVIEWERVPN
```  
  
请注意最后一行，你可以看到一个辅助二进制文件以SYSTEM权限被启动了。  
```
2024/05/26 20:36:39.146 13920 14904 L64  Loader started with: "C:\Program Files\TeamViewer\tv_x64.exe" --action install --verbose --log C:\Program Files\TeamViewer\TeamViewer15_Logfile.log  --event Local\DriverInstallFinishEvent_VPN --inf C:\Program Files\TeamViewer\x64\TeamViewerVPN.inf --id TEAMVIEWERVPN
```  
  
有趣的是，一个以SYSTEM权限运行的进程正在被创建，它根据提供的INF文件安装驱动程序。该进程最终调用了UpdateDriverForPlugAndPlayDevicesA，而没有对签名（Catalog File）进行验证。  
> https://learn.microsoft.com/en-us/windows/win32/api/newdev/nf-newdev-updatedriverforplugandplaydevicesa  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLM2DMV6Frq0eEzibTLj4oDTMrhicMfTJl6ax9a6VALxbggrnExNib6324g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLsWIYtweA9uEdILCIc9Av9NhQJ2LqRxKW22AAbCc87ZoeKs2SDnicPZg/640?wx_fmt=png&from=appmsg "")  
  
那些参数是从哪里来的呢？  
  
于是我开始调查IPC通信。经过几个小时使用API Monitor（真是个超棒的工具）进行监控。我不会让你无聊于各种过滤器的尝试与错误以及研究IPC通信的时间。我们现在知道它使用的是5939/tcp端口，所以接下来让我们分析网络相关的API。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLCNhY2kOvgvkgCBUO9g9icnUD3ZIGozLIrR2SGHCh5PyAkCic6t4Oqj8g/640?wx_fmt=png&from=appmsg "")  
  
启动TeamViewer时，可以看到它使用了一种专有协议。起初，人们可能会认为它是加密的或其他类似的东西。但实际上，TeamViewer并没有对其通信进行加密。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLbjwm6PFYggsYZziaaO66tGpv9VCvBmC0O4kTXC5ziafGiaOcCUZu3Nz0g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLkzyfw16icYOdYwerjx9xbIusQldVzYXIUytf9ShYcLAjKgtIp3gz5dg/640?wx_fmt=png&from=appmsg "")  
  
有趣的是，当点击“安装VPN驱动程序”按钮时会发生什么？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGL946LoeNsoQScORGuaO4B7NibLHeE0Xy3qjyfvYoibpof9a0T3eibZ9DbQ/640?wx_fmt=png&from=appmsg "")  
  
哦，哦，休斯顿……  
  
客户端将INF参数发送给SYSTEM服务，而SYSTEM服务则使用该参数调用tv_x64.exe。  
  
因此，想法很明确，如果我们向SYSTEM服务发送一条IPC消息，指明一个任意的INF参数，是否就能安装一个任意的驱动程序呢？  
  
这是Wireshark的另一种视图。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLrj0NqdzyiaIKTR2yRcQAKicWIiccu1FD9XhsavoXTtovxlcaDSgPJApag/640?wx_fmt=png&from=appmsg "")  
  
（不仅仅是INF参数被发送，但我省略了其他部分，因为最相关的就是INF参数。请注意事件消息Local\DriverInstallFinishEvent。）  
### IPC通信协议  
  
这一部分是所有反向工程和TeamViewer冒险研究的结果。按时间顺序，这部分应该放在最后，但我认为如果我们首先研究IPC通信协议，接下来的章节会更容易理解。  
  
TeamViewer的IPC消息非常简单。它们都有以下结构：  
```
HEADER
BODY
TAIL
```  
  
我们有一个Header，其中包含一些消息自身的元数据，如长度、消息类型、自身长度等。  
  
然后是Body，包含了该消息的实际数据。  
  
最后是一个Tail，始终包含相同的签名和一些标识符。  
#### HEADER  
  
头部长度为8字节，但我将其视为16字节，因为在Body之前还有另一个8字节的子头部。因此，从我们的理解来看，在Body之前有一个16字节的Header。它包含以下字段，其中IDK表示我不知道。  
```
| 0 || 1 || 2 || 3 || 4 || 5 || 6 || 7 || 8 || 9 || 10 || 11 || 12 || 13 || 14 || 15 || 16 |

| Header长度 || IDK || IDK || IDK || 4字节消息长度 || 3字节消息长度 || 2字节消息长度 || 1字节消息长度 || IDK || 消息类型 || IDK || 方向（客户端或服务器消息） || IDK || IDK || IDK || IDK |
```  
  
我总是看到Header为8字节，因此消息的第一个字节始终为0x08。  
#### BODY  
  
该部分包含非加密数据，比如INF参数 :）。  
#### TAIL  
  
我发现IPC消息的最后部分可能会有所不同，但它始终以0xfe 0x01 0x00 0x00开头。  
  
我没有深入研究这一部分，始终保留从捕获的消息中复制的相同字节。  
  
最后的4字节似乎是一个标识符。  
  
以下是与本研究最相关的确切消息。  
#### 认证消息  
  
我将在专门的部分（第二部分）中详细介绍认证过程。该小节将描述消息本身。  
  
认证过程有两种类型的消息。  
  
一种是客户端使用的消息，另一种是服务器使用的消息。  
  
这两者的区别在于，客户端到服务器的消息在Body中包含8字节，而服务器到客户端的消息在Body中包含16字节。  
  
我们稍后会看到原因。  
  
**客户端到服务器的消息**  
  
在这里，我们可以看到一条来自客户端到服务器的消息，我们将对此进行分析。  
```
0000   08 00 01 00 1d 00 00 00 2d 02 09 10 00 00 00 b7   ........-.......
0010   48 77 26 8a 72 b8 f0 fe 57 04 03 fc 64 2e b0 fe   Hw&.r...W...d...
0020   01 00 00 00 01                                    .....
```  
  
首先，我们有头部  
- 08 00 01 00 1d 00 00 00 可以看到，它是8字节长（如第一个字节所示）。接下来的三个字节似乎始终相同，我不确定它们的具体作用。然后是下一个4字节，表示消息的长度。接下来是子头部  
  
- 2d 02 09 10 00 00 00  
  
  
这个子头部指示消息的类型。2d 02 09表示客户端到服务器的认证消息，而如我们将看到的，2d 03 09则表示服务器到客户端的认证消息。我不知道10 00 00 00代表什么，这在消息的两个方向上是相同的。  
  
然后是客户端发送给服务器的16字节挑战值  
  
  
- b7 48 77 26 8a 72 b8 f0 fe 57 04 03 fc 64 2e b0  
  
  
最后是尾部。我不确切知道这些字节表示什么，但它们始终是相同的。  
  
  
- fe 01 00 00 00 01  
  
**服务器到客户端的消息**  
  
在这里，我们可以看到一条来自服务器到客户端的消息，我们也将对此进行分析。  
```
0000   08 00 01 00 32 00 00 00 2d 03 09 10 00 00 00 29
0010   7e d4 88 48 ed 9e 18 5c 3a 4a 12 ce 6e ab 22 0a
0020   10 00 00 00 4b 85 07 8b 3f 21 76 0d a5 fa 62 9b
0030   a7 5e d1 4a fe 01 00 00 00 01
```  
  
在这种情况下，我们几乎看到相同的内容，但这条消息的大小更大，因为Body中有两个16字节的消息。第一个16字节是服务器发送的挑战值，接下来的16字节是对我们发送的挑战值的响应。  
  
首先，我们有头部  
- 08 00 01 00 1d 00 00 00 可以看到，它是8字节长（如第一个字节所示）。接下来的三个字节似乎始终相同，我不确定它们的具体作用。然后是下一个4字节，表示消息的长度。接下来是子头部  
  
- 2d 03 09 10 00 00 00 这个子头部指示消息的类型，即2d 03 09。请注意，之前我们提到的是2d 02 09。我不知道10 00 00 00代表什么，这在消息的两个方向上是相同的。然后是服务器发送给客户端的16字节挑战值  
  
- 29 7e d4 88 48 ed 9e 18 5c 3a 4a 12 ce 6e ab 22  
  
- 接下来是分隔符 0a 10 00 00 00 然后是服务器对我们挑战的响应4b 85 07 8b 3f 21 76 0d a5 fa 62 9b a7 5e d1 4a  
  
  
最后是尾部。我不确切知道这些字节表示什么，但它们始终是相同的。fe 01 00 00 00 01  
  
  
### 控制IPC消息  
  
一旦身份验证成功完成，客户端会向服务器发送一条消息，其中包含连接进程的PID、标识符以及需要与TeamViewer服务版本匹配的版本号。  
  
还有更多数据，但我没有对此进行研究，似乎不太相关，因此在利用时我只是保留了连接时相同的字节。  
  
以下是一个示例消息。  
```
0000   08 00 01 00 ac 00 00 00 01 12 01 04 00 00 00 78   ...............x
0010   22 00 00 02 04 00 00 00 02 00 00 00 03 01 00 00   "...............
0020   00 00 04 12 00 00 00 31 00 35 00 2e 00 35 00 33   .......1.5...5.3
0030   00 2e 00 37 00 20 00 00 00 05 04 00 00 00 01 00   ...7. ..........
0040   00 00 06 06 00 00 00 65 00 6e 00 00 00 07 01 00   .......e.n......
0050   00 00 00 09 06 00 00 00 31 00 35 00 00 00 0a 06   ........1.5.....
0060   00 00 00 35 00 33 00 00 00 0b 04 00 00 00 37 00   ...5.3........7.
0070   00 00 0d 01 00 00 00 01 0e 04 00 00 00 dd 7b a7   ..............{.
0080   37 0f 04 00 00 00 1d bf 52 39 11 04 00 00 00 01   7.......R9......
0090   00 00 00 f3 04 00 00 00 02 00 00 00 fd 04 00 00   ................
00a0   00 fd cf ff 02 fe 01 00 00 00 01 ff 04 00 00 00   ................
00b0   8c 83 14 3b                                       ...;
```  
  
首先，我们有一个类似的头部  
```
08 00 01 00 ac 00 00 00  
```  
  
如前所述，它是8字节长（由第一个字节表明）。接下来的三个字节似乎总是相同的，我不确定它们的具体作用。接着是下一个4字节，表示消息的长度。  
  
接下来是子头部  
```
01 12 01 04 00 00 00
```  
  
这表示消息的类型。  
  
然后是4字节，表示正在连接的PID。  
```
78 22 00 00
```  
  
在这个例子中，PID是8824。  
  
然后，在0x27到0x34字节中，我们有TeamViewer的版本号。在此示例中，版本号为15.53.7。这个版本号需要与TeamViewer服务匹配。如果客户端指示的版本与15.53.7不同，由于版本不匹配，服务会终止IPC连接。  
```
31 00 35 00 2e 00 35 00 33 00 2e 00 37
```  
  
消息中稍后也有版本号的再次出现，不过每个数字之间有分隔符。  
  
在0x58到0x5b字节中，我们有版本的主版本号，此处为15。在0x63到0x66字节中，我们有版本的次版本号。在0x6e到0x6f字节中，我们有版本的最后一位数字。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoWoBJamKDP3lADPJibzNdGLIqJKicKMjia2v6mXM89JXFemKeDK2XGjj2nKnb21NlicicPrvxoEYmK48w/640?wx_fmt=png&from=appmsg "")  
  
消息的其余部分我不确定它的作用，仅需写入正确的PID。  
  
在这个例子中，尾部有些不同，因为它在常见字节之后包含了以下字节：  
```
ff 04 00 00 00 95 d4 04 31
```  
  
最后有一个生成的标识符，用于后续消息中。  
```
8c 83 14 3b
```  
  
我还看到该消息中指示了语言。在这个例子中是英文 ( en)。  
#### 请求安装驱动消息  
  
在成功完成身份验证并发送了包含正确PID的控制IPC消息后，我们就能够发送驱动安装请求消息。  
  
这意味着，非特权用户可以通过提供 –inf 参数，让SYSTEM进程使用该参数安装任意的内核驱动程序。  
  
该消息中，最关键的部分是 –inf 参数，它将被SYSTEM进程用于安装所指定的驱动程序。  
  
以下是一个具体的示例消息：  
```
0000   08 00 01 00 35 01 00 00 33 0c 01 01 00 00 00 01   ....5...3.......
0010   02 04 00 00 00 02 00 00 00 03 96 00 00 00 2d 00   ..............-.
0020   2d 00 69 00 6e 00 66 00 20 00 43 00 3a 00 5c 00   -.i.n.f. .C.:.\.
0030   4e 00 6f 00 74 00 20 00 50 00 72 00 6f 00 67 00   N.o.t. .P.r.o.g.
0040   72 00 61 00 6d 00 20 00 46 00 5c 00 61 00 61 00   r.a.m. .F.\.a.a.
0050   61 00 61 00 61 00 61 00 61 00 61 00 61 00 61 00   a.a.a.a.a.a.a.a.
0060   5c 00 62 00 62 00 62 00 5c 00 41 00 6e 00 6f 00   \.b.b.b.\.A.n.o.
0070   74 00 68 00 65 00 72 00 54 00 68 00 69 00 6e 00   t.h.e.r.T.h.i.n.
0080   67 00 67 00 2e 00 69 00 6e 00 66 00 20 00 2d 00   g.g...i.n.f. .-.
0090   2d 00 69 00 64 00 20 00 54 00 45 00 41 00 4d 00   -.i.d. .T.E.A.M.
00a0   56 00 49 00 45 00 57 00 45 00 52 00 56 00 50 00   V.I.E.W.E.R.V.P.
00b0   4e 00 00 00 05 02 00 00 00 00 00 06 02 00 00 00   N...............
00c0   00 00 07 01 00 00 00 00 08 46 00 00 00 4c 00 6f   .........F...L.o
00d0   00 63 00 61 00 6c 00 5c 00 44 00 72 00 69 00 76   .c.a.l.\.D.r.i.v
00e0   00 65 00 72 00 49 00 6e 00 73 00 74 00 61 00 6c   .e.r.I.n.s.t.a.l
00f0   00 6c 00 46 00 69 00 6e 00 69 00 73 00 68 00 45   .l.F.i.n.i.s.h.E
0100   00 76 00 65 00 6e 00 74 00 5f 00 56 00 50 00 4e   .v.e.n.t._.V.P.N
0110   00 00 00 09 04 00 00 00 00 00 00 00 f3 04 00 00   ................
0120   00 02 00 00 00 fd 04 00 00 00 01 00 00 00 fe 01   ................
0130   00 00 00 01 ff 04 00 00 00 95 d4 04 31            ............1
```  
  
首先，我们从消息的头部开始进行解析：  
- **头部** ( Header): 0800010035010000  
  
- 头部的第一字节（ 08）表明消息的长度是8个字节。  
  
- 接下来的三个字节（ 000100）始终相同，我不确定它们的具体作用。  
  
- 最后4个字节（ 35010000）表示消息的总长度。  
  
- **子头部** ( Subheader): 330c0101000000 该子头部表示消息的类型，具体意义为：  
  
- 330c01 似乎是用于区分不同类型消息的标识符，表明这是驱动安装请求的消息。  
  
- 01000000 我不确定它的具体作用，但在每次消息中似乎保持一致。  
  
- **未知的22字节**：  
  
```
```  
  
这22个字节在每次消息中都保持不变，但其具体作用尚不清楚。  
  
  
- 02 04 00 00 00 02 00 00 00 03 96 00 00 00 2d 00 2d 00 69 00 6e 00  
  
- **-inf 参数**：  
  
```
```  
  
这是 -inf 参数的具体路径，表示要由SYSTEM进程执行的驱动安装的INF文件路径。  
  
  
- 2d 00 69 00 6e 00 66 00 20 00 43 00 3a 00 5c 00 4e 00 6f 00 74 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 5c 00 61 00 61 00  
  
- **尾部** ( Tail): ff0400000095d40431 尾部通常表示消息的结束部分，这些字节在不同消息中可能有所不同。在这种情况下，特定的字节组合似乎代表了某种标识符或校验值，但其确切含义并不明确。  
  
这一消息的重要部分在于 -inf 参数的传递，通过该参数可以让SYSTEM进程执行驱动安装，涉及到的路径和其他参数指示了要安装的驱动程序的详细信息。  
  
**第一次失败：需要认证**  
  
在第一次尝试发送驱动安装请求时，直接发送消息并没有成功。这是因为目标服务期望的是另一种类型的消息，即认证消息，而不是我们发送的安装请求消息。  
  
通过查看日志，发现IPC结构解析器产生了错误，明确指出期望的是不同类型的消息。这时我开始捕捉合法的流量并尝试找出模式。在分析过程中，注意到服务器最初发送的16字节消息，并且当发送相同的第一条消息时，服务器会回应相同的16字节。  
  
在对这些数据进行分析时，借助ChatGPT帮助分析各种输入后，得出的结论是TeamViewer（TV）使用了某种加密或哈希算法，而不是简单的二进制操作。  
  
虽然消息格式正确，但TV的日志显示如下错误：  
```
2024/05/26 19:03:04.770  3268       3660 S0!! InterProcessNetwork::Received_IPCAuth() invalid response
```  
  
显然，必须先通过正确的身份验证。正如我们将进一步研究的那样，认证算法并不是特别复杂或强壮。  
  
**第二次失败：重新回到逆向分析**  
  
在决定进行逆向分析之前，我尝试寻找是否有可能走捷径，看看是否能让TeamViewer（TV）更明确地显示认证失败的原因。  
  
通过尝试，发现了一种开启详细日志和调试输出的方法。虽然TV并没有记录IPC认证失败的具体原因，但值得记录和文档化的是TV服务查询的所有注册表项，尤其是其中的一些关键项。  
  
下面是一些注册表键的发现：  
1. **IPCPortService**：可以用于修改SYSTEM服务监听IPC的端口。  
  
1. **Log_Level**：允许修改日志类型。我尝试了许多值，但没有全部记录，只记下了调试用的0x40。  
  
1. **LogLevelVerboseStarted**：虽然我没有看到明显变化，但它似乎可以开启详细日志记录。  
  
1. **IPCPassword**：虽然未测试，但应该可以改变IPC的密钥。  
  
1. **HooksLogVerbose**：启用后，TV的钩子记录会写入文件 TeamViewer15_Hooks.log。  
  
虽然这个方向未能成功解决问题，但探索TV的其他部分还是有趣的，比如如何在日志中启用调试输出。因此，我认为这段时间的投入是值得的。  
  
最终，我还是回到了逆向工程，深入研究了认证机制的工作原理。我们将在第二部分中详细探讨这一点。  
  
接下来，在第三部分中，我们将深入探讨漏洞利用的具体细节，以及各个部分如何协同工作，最终实现从用户到内核的权限提升。  
  
**后续部分会继续在公众号发布，请保持关注公众号，第一时间获取更新！**  
## Thanks  
  
thanks for https://pgj11.com/posts/Finding-TeamViewer-0days-Part-1/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7mYNibgIry73PaOOvZMtx3j0HKkjnhoMSynVaJVict8XuLgbe9MibOKdd6jcIw8qnWMic8Vw3ylviaxOLlvauFht3Gw/640?from=appmsg&wx_fmt=png "")  
  
点个在看你最好看  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Sqw1rjQVlNe3KSKWQNwSSqLjjLwoZ8JhQaVY6eeemfbjnoeebEkic8Sb3amcz7PwHAbuoic2TeZcRRcVln88gvWA/640?wx_fmt=png "")  
  
盛世华诞 举国同庆 往期推荐  
  
[至暗时刻！Linux 史诗级核弹0day EXP公开](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505954&idx=1&sn=afb463f7f9cb6593e20a1f8aa6902fc1&chksm=c0ce235bf7b9aa4debd63e160ff78c2f165e3d8f701a63ca5c45e2c84f12097eb75a51aebb08&scene=21#wechat_redirect)  
  
  
[Android活动（Activities）Exploiting 技术](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505943&idx=1&sn=7c0f15870782a61558fbb2add2e482cd&chksm=c0ce236ef7b9aa78fd2c14358e7051d3d63753b15c7406030b871971d64af28545e44e5b6c63&scene=21#wechat_redirect)  
  
  
[寻找IDOR漏洞：Key Endpoints and Resources](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505935&idx=1&sn=69ea4216b3d472df4bc011e01a477e21&chksm=c0ce2376f7b9aa606100604b65ad87b35aea2d08ee6e0081774c79160ecd65bb4c557e1fe137&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505910&idx=1&sn=9c06e8e5e9b8ffcf6f83c1c1c3bdba7b&chksm=c0ce2c8ff7b9a599072651a23001282343f9861bf32ed9fcdf197af6f7283b4b15bf13f3e741&scene=21#wechat_redirect)  
  
[打破 BurpSuite Chromium 的限制重写JS文件](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505910&idx=1&sn=9c06e8e5e9b8ffcf6f83c1c1c3bdba7b&chksm=c0ce2c8ff7b9a599072651a23001282343f9861bf32ed9fcdf197af6f7283b4b15bf13f3e741&scene=21#wechat_redirect)  
  
  
