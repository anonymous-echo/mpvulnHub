#  Pwn2Own：WAN 到 LAN 的漏洞利用   
3bytes  3072   2024-07-13 11:28  
  
## 执行摘要  
- Claroty Team82在去年秋天参加了Pwn2Own 2023多伦多物联网黑客大赛，并成功利用了TP-Link ER605路由器和Synology BC500 IP摄像机的漏洞  
  
- 我们通过这项研究展示了一个攻击者如何破坏连接到广域网的设备，然后移动到局域网以破坏连接的物联网设备。  
  
- 在本系列的第一部分中，我们解释了我们对TP-Link ER605路由器的研究和攻击。第二部分将介绍我们如何从路由器移动到局域网以破坏Synology BC500 IP摄像机。  
  
- TP-Link已在我们报告的漏洞中通过固件版本ER605 (UN) V2 2.4 Build 20240119进行了修复  
  
- CVE-2024-5242  
  
- CVE-2024-5243  
  
- CVE-2024-5244  
  
- Synology在其固件版本1.0.7-0298中修复了我们报告的漏洞，并发布了安全公告。  
  
- ZDI-24-833  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp25iaIW4qQzNuyPgG0ALlHrXMDMFlibjDCAxL2uKOwlEXy8Fly26aYpBDg/640?wx_fmt=webp&from=appmsg "")  
  
Pwn2Own Toronto 2023：物联网版 | SOHO混合利用  
## 引言  
  
几乎所有通过小型办公室/家庭办公室（SOHO）网络连接到互联网的人都是从一个类似的网络布局进行连接的。在本地网络和互联网之间架起桥梁的最关键的设备是路由器。路由器不仅有助于路由网络流量，还充当保护屏障，分隔内部局域网（LAN）和外部互联网，即广域网（WAN），防止不需要的外部访问内部设备。因此，从WAN利用路由器并绕过网络地址转换（NAT）是危险的，并对局域网构成重大风险。  
  
在2023年Pwn2Own多伦多比赛中，我们展示了我们的WAN到LAN的枢轴攻击，利用了WAN上的TP-Link路由器。在我们的研究中，我们研究了攻击者如何从WAN渗透到LAN，发现了TP-Link路由器中的漏洞，允许攻击者绕过NAT保护。在路由器上获得远程代码执行（RCE）后，我们枢轴转到LAN，并开发了一个针对Synology IP摄像机的利用，通过在网络内部进行横向移动。  
  
在这篇博客中，我们将展示我们的研究成果，包括高级嵌入式利用技术，以及我们发现新的NAT绕过和物联网设备漏洞的方法和方法论。  
  
在本系列的第一部分，我们将介绍我们利用路由器的技术；在第二部分，我们将解释我们如何使用路由器从WAN移动到LAN。  
  
那么，系好安全带，我们有很长的路要走！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2gxVesNqbusmX3Xymmq0LLAZMMWMicFhYuIIAJk9IBYBborOQaicQibdibw/640?wx_fmt=webp&from=appmsg "")  
## WAN利用：TP-Link ER605路由器  
  
TP-Link ER605路由器被列为针对消费者和小型企业使用的VPN路由器。  
  
该设备被描述为具有安全措施，例如防火墙策略和拒绝服务（DoS）防御。此路由器还具有基于云的管理接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2w5ibMRzCTyDt4gyyGMMCjn8LT7pj5oOOkQib4hibYB3FV7rDQyoDTWlvQ/640?wx_fmt=webp&from=appmsg "")  
## 技术细节  
  
由于我们想要实现WAN利用，我们寻找了与WAN相关的攻击面。路由器支持的一个功能是动态DNS（DDNS）服务。DDNS使具有动态IP的设备能够持有一个当其IP变化时动态变化的域名记录。TP-Link选择支持的DDNS提供商之一是Comexe，它使用自定义DDNS协议与提供商的服务器通信。为了与服务提供商进行交互，设备使用位于/usr/sbin/cmxddnsd的二进制文件。在研究cmxddnsd二进制文件时，我们发现了三个漏洞，当它们串联在一起时，允许我们从WAN侧实现远程代码执行。  
### 漏洞 #1：不正确的服务器真实性验证（CVE-2024-5242）  
  
我们首先查看了二进制文件cmxddnsd。在启动时和之后定期，该二进制文件尝试访问其DDNS服务器以启动DDNS连接并更新其外部IP地址。默认情况下，路由器配置有两个Comexe DDNS服务器Dns1.comexe.net，Dns1.comexe.cn。  
  
为了获取服务器的IP地址，cmxddnsd尝试通过查询路由器的DNS解析器来解析DDNS服务器的DNS名称。获取IP地址后，该二进制文件通过UDP/9994启动到DDNS服务器的UDP连接。与DDNS服务器通信使用的协议是专有的，因此我们必须研究二进制文件以更好地理解协议。  
  
经过一些研究，我们发现用于DDNS通信的协议如下：每个消息由两个部分组成：  
1. 一个加密的Data部分  
  
1. 一个称为‘C’的消息段（例如C=1），表示消息方向（服务器到客户端或客户端到服务器）。为了分隔不同的消息部分，Comexe使用一个字节的\x01来分隔不同的部分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2clTgvwZdh6KKgArWFiaibiaJZrDlXxxcP4UoqibDGvXBqfP4WKCLg3v9UA/640?wx_fmt=webp&from=appmsg "")  
  
包含请求的加密Data部分的DDNS请求和响应。  
  
为了对消息中的数据段进行加密/解密，Comexe 使用了对称加密的3DES方案，并使用了一个硬编码的8字节密钥：\x53\x76********* [已审查]。加密过程之后，数据使用带有自定义base64字符映射的Base64进行编码。解密过程完成后，解密后的内容存储在数据段中。解密后的内容由消息的多个部分组成，例如消息类型（认证请求、认证响应等）、基于ASCII的参数（如用户名/密码对、IP地址等）以及请求的错误代码。  
  
通过研究cmxddnsd二进制文件，我们发现Comexe DDNS协议中实际上并没有进行主机验证。在这个DDNS协议中，冒充客户端/服务器所需的唯一事项是了解加密程序和各方使用的硬编码密钥。这意味着我们可以冒充提供商服务器，接收和发送请求到客户端设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2LKibucyyS0GgSeNTy9gRh8fAibrjQLh9E95aVdUneB3mY8v84qkR3NiaQ/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2UUhO5VOr3xAShjwaUOCgZoxr2HQ9SibQQUCREYPT97Vazuk7q707P7Q/640?wx_fmt=webp&from=appmsg "")  
  
在我们的脚本中使用的加密/解密常量。  
  
为了让客户端在连接期间验证服务器的身份，大多数协议使用SSL或非对称加密算法来验证每一方的真实身份。然而，由于Comexe使用对称加密算法，任何知道加密密钥（嵌入在设备内部）的人都能够冒充每一方。  
### 漏洞 #2：由于基于栈的溢出导致远程代码执行（CVE-2024-5243）  
  
在获得冒充DDNS提供商的能力后，我们开始调查cmxddnsd中的解析流程和DDNS功能。不久我们确定了二进制文件内部处理DDNS数据包处理的函数：_chkPkt。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp263ZXhz2M4g96PWsrbBzmMwbwzaMQwJnEHia4rkegxC54VFiaVXD0aMLw/640?wx_fmt=webp&from=appmsg "")  
  
处理数据解密的_chkPkt函数的一部分。  
  
作为通信协议的一部分，服务器发送一个由多个部分组成的基于ASCII的有效载荷，每个部分与特定消息类型和参数相关。例如，DDNS服务器可以发送一个errorCode参数，指示发生的具体错误，或者一个updateSvr参数，告诉客户端更新其提供商服务器域的版本，例如从Dns1.comexe.cn更新到mynewdomain.com。  
  
我们发现，在解析特定消息部分的解析程序中，服务器复制接收到的参数缓冲区时没有界限检查，也没有进行安全性验证。例如，涉及errorCode参数时，服务器使用strncpy将缓冲区复制到4字节大小的栈变量中。然而，复制使用的是接收到的参数的长度，而不是目标缓冲区的长度，后者可能更小。这意味着如果路由器接收到大于4个字符大小的errorCode数据，就会发生缓冲区溢出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2ObYoBkZZ5e6ibiaibLUqgvtCQicrgUwORbpqQkN1lFT4p0CpLUEIGljEGA/640?wx_fmt=webp&from=appmsg "")  
  
我们利用的导致溢出错误的代码，在_chkPkt函数内部。  
  
由于攻击者完全控制有效载荷，他们可以在errorCode参数中发送大尺寸的内容，仅受限于最大数据包大小0x800。这将触发基于栈的缓冲区溢出，并可能影响应用程序的代码执行流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2dyIbmXQ5Cqf3FdoicshjEiafYKIALsRu8t6PPcfQDK7Dk1K6Jq24G4wQ/640?wx_fmt=webp&from=appmsg "")  
  
我们在_chkPkt的errorCode解析流程中溢出之前的栈状态。我们可以看到在当前栈指针之前保存了一个有效的应用程序地址，并且在$ra寄存器内部。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2msvplFIGOCp59tQLXYlKZ5Tp22b2SSsIQSfxKJYFUDzfHe14IIoxWg/640?wx_fmt=webp&from=appmsg "")  
  
我们在_chkPkt的errorCode解析流程中溢出之后的栈状态。我们可以看到我们设法用我们控制的值（0x77fa62f0）溢出了返回地址寄存器，这意味着我们接管了执行流程。  
  
DDNS协议内部存在类似的缓冲区溢出漏洞。例如，在处理UpdateSvr1和UpdateSvr2参数时，用户控制的缓冲区被复制到全局部分中的一个小缓冲区，其长度恒定为0x80字节，用用户控制的新Comexe DNS服务器域覆盖全局部分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2b0Hia9QRXptdp2VN3cf4YpSgSqZcqLTx6BHsibf0FLAWHCOF99BWiaewg/640?wx_fmt=webp&from=appmsg "")  
  
滥用UpdateSvr1，攻击者可以发送大于0x80的负载，以溢出全局内存部分，并覆盖其他结构。  
  
在验证了不同的基于栈的缓冲区溢出后，我们选择专注于溢出errorCode参数（cmxddnsd ! 0x2d8a），同时覆盖整个栈在_checkPkt框架内的栈。由于没有堆栈金丝雀保护它，我们现在有能力控制执行流程并跳转到我们控制的$pc（程序计数器）。  
  
我们成功利用和远程代码执行的计划是创建一个ROP链（返回导向编程），导致system (COMMAND)。我们面临的问题是非堆栈布局随机化（ASLR）；我们无法猜测栈/堆/库的基本地址，需要找到一种泄露它们的方法，以击败ASLR，这是许多操作系统中针对基于内存的代码执行攻击的一种缓解措施。  
### 漏洞 #3: 由于OOB读取绕过ASLR (CVE-2024-5244)  
  
在成功控制程序的执行流程后，我们可以为程序提供跳转地址，并从这些地址继续执行。然而，在现代操作系统中，ASLR通过随机化程序地址布局来减轻此类攻击，每次执行时将库、堆和栈等不同部分加载到随机位置。为了成功利用上述漏洞并执行任意代码，我们必须绕过ASLR，以便为我们的ROP链提供有效的地址。  
  
为了绕过ASLR保护，我们需要从程序内存中泄露指向随机化内存部分的有效地址。这样我们才能从这些泄露的指针计算出库的基地址。为了实现这一目标，我们寻找了一种方式来泄露包含有效地址指针的越界内存。  
  
我们首先检查了程序中向远程服务器发送数据的代码部分。很快我们发现cmxddnsd二进制文件只使用两种协议通信：DDNS（Comexe专有的UDP/9994）和DNS（UDP/53）。为了在这些协议中找到内存泄露，我们开始查看处理这些请求的函数和过程。  
  
在检查sndDnsQuery函数时，我们注意到它容易受到基于栈的缓冲区溢出的影响。这个函数中的溢出发生在程序从内存的全局部分读取DNS名称，并逐个字符地将其复制到栈上时。  
  
通常DNS名称的大小限制为0x80，由于我们使用UpdateSvr1和UpdateSvr2更新成功溢出了全局部分变量，我们能够提供一个更大的DNS名称。  
  
在执行期间，函数将逐字节地从我们溢出的全局变量复制到栈上，这可能导致基于栈的缓冲区溢出。函数复制每个字节的唯一中断是在遇到正斜杠（/）字符或空字节（\x00）时。由于我们控制DNS名称及其大小，我们可以在sndDnsQuery框架中溢出任何栈上的内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2P3QBviajhqkFGE4cOsMgWYUzGIPib9aMggKt4WCs277micMyIOwPibqMDw/640?wx_fmt=webp&from=appmsg "")  
  
_sndDnsQuery()函数，通过将DNS服务器名称复制到栈变量而容易受到栈溢出的影响  
  
我们利用这个基于栈的缓冲区溢出来溢出并重写一个特定的栈变量sendSize。然后程序使用这个变量来指示程序在DNS查询中将发送多少字节。通过修改这个变量的低两个字节，我们能够覆盖一个非常大的数字，远大于实际域和DNS负载。  
  
因此，每当程序尝试发送DNS查询时，由于sendSize整数较大，它将继续从栈上发送数据；发送sendSize内的数字那么多的字节。这种方法导致越界内存读取，并使用DNS从栈上泄露指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2iaz4rFMoFadRibrXZben7QtvCM7pdUzzl7fXQT4jLbvDVNqiaywuuS1jg/640?wx_fmt=webp&from=appmsg "")  
  
_sndDnsQuery函数的栈布局。我们在domain_name变量开始我们的溢出，并溢出send_size的低两个字节。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZEkT0Rn34yG4er3MibS7r9alPYM31NWp2LVj3Mpd81SCu5YibNY0wKXLT3Gibz5U1cxSH3a0eaheTypRKOMK3XvUA/640?wx_fmt=webp&from=appmsg "")  
  
_sndDnsQuery函数的栈布局的另一个视图，包括我们特定的溢出以控制泄露大小  
  
使用越界读取，我们设法泄露了许多位于栈上的指针。这些指针指向许多不同的内存区域，包括栈本身、堆甚至不同的库，如libc。使用这些指针，我们设法计算了这些内存区域的当前基地址，允许我们绕过ASLR特性。  
## 完整的WAN利用链  
  
为了完全利用上述显示的漏洞链，攻击者首先需要在路由器和Comexe DDNS服务器之间（使用问题#1中的漏洞）进行中间人攻击（MiTM）。  
  
然后，攻击者将提供恶意的UpdateSvr1值给服务器，这个值的大小超过了这个变量的最大大小。这将在sndDnsQuery过程中引起缓冲区溢出，溢出sendSize变量，触发我们的越界读取漏洞（问题#3）。  
  
最后，使用攻击者设法利用问题#3泄露的基地址，攻击者将发送一个恶意的DDNS响应，具有特殊制作的errorCode参数，触发问题#2中显示的基于栈的缓冲区溢出。这将导致程序执行攻击者制作的ROP链，将执行流程交给攻击者，并触发攻击者控制下的操作系统命令。这意味着攻击者现在完全控制了被攻击的路由器，允许他们以根用户权限执行任意操作系统命令。  
  
**WAN利用摘要**  
1. 坐在路由器WAN后面 - MITM  
  
1. 使用UpdateSvr1，UpdateSvr2使用溢出的域名初始化DDNS域名更新  
  
1. 在不使应用程序崩溃的情况下溢出sndDnsQuery的栈并从栈中泄露指针  
  
1. 计算栈和libc的基地址  
  
1. 发送带有恶意errorCode的DDNS请求，以在_checkPkt框架中溢出栈  
  
1. 溢出栈并启动ROP链  
  
1. 使用我们的负载调用System  
  
## 准备转向LAN攻击  
  
现在我们已经获得了对路由器的完全远程root访问权限。我们需要确立优势，因此我们完全打开了它的防火墙规则（清除iptables）并配置了一个反向shell，以防连接关闭时尝试联系我们。  
  
接下来，我们需要找出哪些设备位于路由器后面的LAN上，所以我们嗅探并执行了arp -an命令，发现了我们正在寻找的物联网设备，即Synology BC500 IP摄像机。一旦检测到，我们在路由器上创建了一个“代理”，使用SOCAT（监听-连接）将摄像机的Web端口暴露给我们，并继续进入第二阶段，转向LAN。  
  
  
  
  
  
