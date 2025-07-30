#  Microsoft Windows KDC 代理中的 RCE   
 Ots安全   2025-03-08 12:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在趋势科技漏洞研究服务漏洞报告的摘录中， 趋势科技研究团队的 Simon Humbert 和 Guy Lederfein 详细介绍了 Microsoft Windows 密钥分发中心 (KDC) 代理中最近修补的代码执行漏洞。该漏洞最初由 Cyber KunLun 的昆仑实验室的 k0shl 和 Wei 发现。成功利用该漏洞可能导致在目标服务的安全上下文中执行任意代码。以下是他们撰写的有关 CVE-2024-43639 的部分内容，并做了一些微小的修改。  
  
已报告 Microsoft Windows KDC Proxy 存在整数溢出。该漏洞是由于缺少对 Kerberos 响应长度的检查而导致的。  
  
远程、未经身份验证的攻击者可以指示 KDC 代理将 Kerberos 请求转发到他们控制的服务器，然后该服务器将发回精心设计的 Kerberos 响应。成功利用此漏洞可能导致在目标服务的安全上下文中执行任意代码。  
  
漏洞  
  
Microsoft Windows 操作系统实施了一组默认身份验证协议，包括 Kerberos、NTLM、传输层安全性/安全套接字层 (TLS/SSL) 和 Digest，作为可扩展架构的一部分。对于 Active Directory 域内的身份验证，Windows 使用 Kerberos。  
  
Kerberos是一种计算机网络身份验证协议，它基于票据工作，允许通过非安全网络进行通信的节点以安全的方式相互证明其身份。Kerberos 建立在对称密钥加密的基础上，需要一个受信任的第三方，即密钥分发中心 (KDC)，该第三方与身份验证领域中的所有其他方共享密钥。客户端和服务与 KDC 交换 Kerberos 消息。Kerberos 消息可以通过端口 88 上的 UDP 或 TCP 传输。但是，当通过 TCP 发送时，每个请求和响应前面都会显示消息的长度，即按网络字节顺序的 4 个八位字节。  
  
Microsoft Windows Server 操作系统实施 Kerberos 版本 5 身份验证协议。每个 Active Directory 域控制器都运行 Kerberos KDC 的一个实例，该实例使用域的目录服务数据库作为其安全帐户数据库。要进行身份验证，客户端必须具有与域控制器的网络连接。  
  
虽然对于位于组织网络内的计算机来说，情况通常如此，但对于使用远程连接的客户端来说，情况可能并非如此。要启用远程工作负载，尤其是 RDP 网关和 DirectAccess 等服务，可以使用 KDC 代理通过 HTTPS 代理 Kerberos 流量。  
  
KDC 代理是一个基于 HTTP 的服务器，它实现了 Kerberos KDC 代理协议 ( KKDCP )。客户端将其 Kerberos 请求包装在 KDC 代理消息中，并将其发送到 HTTPS POST 请求的正文中，其中请求 URI 设置为/KdcProxy。KDC 代理消息使用抽象语法表示法一 (ASN.1) 定义。ASN.1 是一种标准接口描述语言 (IDL)，用于定义可以跨平台序列化和反序列化的数据结构。ASN.1 的完整规范，包括其词汇单元、分隔符、递归定义、本机数据类型、空格、生成规则等，可在此处找到。  
  
以下是KDC代理消息的结构：  
  
```
KDC-PROXY-MESSAGE::= SEQUENCE {
    kerb-message [0] OCTET STRING,
    target-domain [1] KERB-REALM OPTIONAL,
    dclocator-hint [2] INTEGER OPTIONAL
}
```  
  
在哪里：  
  
· kerb-message是一条 Kerberos 消息，包括 4 个八位字节的消息长度前缀。  
  
· target-domain是一个 DNS 或 NetBIOS 域名，代表必须向其发送 Kerberos 消息的领域（target-domain对于 KDC 代理请求是必需的，但不用于 KDC 代理响应）。  
  
· dclocator-hin  
t是一个可选字段，其中包含用于查找域控制器的附加数据。  
  
KDC 代理消息使用可区分编码规则 ( DER ) 进行编码。DER 是一种类型长度值编码系统，每个 DER 编码字段具有以下结构：  
  
```
Name                              Description
--------------------      --------------------
Identifier Octets         Type of structure
Length Octets             Length of Contents
Contents Octets          Data
End-of-Contents         Octets (optional)
```  
  
标识符八位字节对内容八位字节的类型进行编码。通常，它由具有以下结构的单个八位字节组成：  
  
```
Bits          8    7     6     5     4     3     2     1
       +-----------+-----+--------------------------+
       | Class | P/C | Tag Number |
       +-----------+-----+--------------------------+
```  
  
  
Class字段可以是 Universal（位：00）、Application Specific（位：01）、Context-specific（位：10）或 Private（位：11）。P/C 字段指定该字段是原始数据类型（位：0），例如 INTEGER，还是构造数据类型（位：1），即其内容八位字节包含其他原始或构造数据类型。如果Class字段是 Universal，则规范定义了几个标准标签号，例如 BOOLEAN  
  
（\x1）、INTEGER（\x2）、OCTET STRING（\x4）、UTF8STRING（\x0C）、SEQUENCE（\x10）、IA5STRING（\x16）、GeneralString（\x1B）等。非通用类的情况下，对大于30的标签号的编码有规则。  
  
在 DER 中，有两种方式对长度八位字节进行编码。在短格式中，使用单个长度八位字节，其最高有效位设置为 0，其余 7 位表示内容八位字节的数量。在长格式中，第一个长度八位字节的最高有效位设置为 1，其余 7 位对后续长度八位字节的数量进行编码，这些后续长度八位字节本身包含内容八位字节的数量。长格式通常仅在必要时使用。所有多字节整数都采用大端格式。  
  
举例来说，KDC 代理请求经过编码后如下所示：  
  
```
30820107 # SEQUENCE tag and length
   a0 81 f4 # EXPLICIT tag 0 and length
      0481 f1 000000 ed 6a 81 ea 3081 e7 a1 03020105 a2 0302010a a3 15
      30133011 a1 0402020080 a2 0904073005 a0 030101 ff a4 81 c3 30
      81 c0 a0 0703050040810010 a1 1d301b a0 03020101 a1 1430121b
      104445534b 544f502d5155383950515124 a2 0e 1b 0c 4b 444350
      524f58592e 434f4d a3 21301f a0 03020102 a1 1830161b 066b 72
      627467741b 0c 4b 444350524f58592e 434f4d a5 11180f323033
      37303931333032343830355a a6 11180f323033373039313330
      32343830355a a7 06020410 d3 7a 0f a8 16301402011202011702
      02 ff 7b 0201800201180202 ff 79 a9 1d301b 3019 a0 03020114 a1
      1204104445534b 544f502d5155383950515120 # OCTET STRING tag, length, and value (kerb-message)
   a1 0e # EXPLICIT tag 1 and length
      1b 0c 4b 444350524f58592e 434f4d # GeneralString tag, length, and value (target-domain)
```  
  
  
缩进显示了构造数据类型和原始数据类型之间的关系。请注意，SEQUENCE 的标签编号为\x10，但是，SEQUENCE 字段是构造数据类型，其P/C字段设置为 1。因此，SEQUENCE 的标识符八位字节为0x30。SEQUENCE 项被分配了从 0 到 2 的显式标签，并且在编码时，它们被封装在 EXPLICIT 标签数据类型中。在 EXPLICIT 标签的标识符八位字节中，类字段设置为上下文特定（位：10），P/C 字段设置为 1。最后，Kerberos 领域被编码为 KerberosString，它是 GeneralString 的别名。  
  
收到 KDC 代理请求后，KDC 代理会提取目标域并定位该领域的域控制器。首先，KDC 代理查询名称_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.<target_domain>的 DNS SRV 记录，并根据需要解析匹配的 A 记录。然后，KDC 代理向结果集发送LDAP ping。LDAP ping 是一种无连接 LDAP (CLDAP) rootDSE 搜索Netlogon属性，用于验证域控制器的活动性，并检查它是否符合一组特定的要求。域控制器返回一个对 NETLOGON_SAM_LOGON_RESPONSE_EX结构进行编码的小端字节字符串。  
  
最后，KDC 代理从 KDC 代理请求中提取kerb-message并将其转发到域控制器。请注意，KDC 代理仅通过 TCP 转发 Kerberos 请求。还请注意，虽然它只能在加入域的计算机上运行，但 KDC 代理将代理任意域的 Kerberos 请求。当 KDC 代理从域控制器收到 Kerberos 响应时，它会将其包装在 KDC 代理消息中（仅包含kerb-message字段），并将其在 HTTPS 200 OK 响应的正文中返回给客户端。  
  
已报告 Microsoft Windows KDC Proxy 存在整数溢出问题。该漏洞是由于缺少对 Kerberos 响应长度的检查而导致的。  
  
将 Kerberos 请求发送到域控制器后，KDC 代理从网络套接字读取 4 个字节以获取 Kerberos 响应长度。然后，它尝试读取尽可能多的字节以获取完整响应。读取 Kerberos 响应涉及许多函数，所有函数都传递指向_KPS_IO结构的指针作为参数。_KPS_IO结构的大小为0x120字节，下面是部分定义（本节中的所有结构定义都是通过逆向工程确定的；大多数结构和字段名称都是我们选择的）：  
  
```
Offset Length Name Description
(bytes) (bytes)
------- ------- ----------- -------------
[... truncated fields ...]
0x100 0x8 recvbuf pointer tobuffer holding bytes read from the socket
0x108 0x4 bytesread number of bytes readso far
0x10C 0x4 bytestoread number of bytes toread from the socket
[... truncated fields ...]
```  
  
  
每当从套接字读取后续字节时，都会调用DLL 文件kpssvc.dll中的KpsSocketRecvDataIoCompletion()函数。它会检查是否读取了足够的字节来获取完整响应，如果是，则调用KpsPackProxyResponse()函数，并将指向_KPS_IO结构的指针作为参数传递。KpsPackProxyResponse()首先调用KpsCheckKerbResponse()函数来验证 Kerberos 响应。值得注意的是，如果紧跟在消息长度前缀后面的字节设置为“0x7E”或“0x6B”，则KpsCheckKerbResponse()会验证响应是否是正确构造的 Kerberos 消息。如果不是，则它不会执行任何验证并返回无错误。  
  
KpsPackProxyResponse()局部变量包含一个ASN1_KDC_PROXY_MSG类型的结构。ASN1_KDC_PROXY_MSG结构的大小为 `0x28` 字节，下面是部分定义：  
  
```
Offset  LengthName         Description
(bytes) (bytes)
---------------------------------------
[... truncated fields ...]
0x8     0x4     len          lengthoftheKerberosresponse
[... truncated fields ...]
0x10    0x8     buf          pointertobufferholdingtheKerberosresponse
[... truncated fields ...]
```  
  
  
调用KpsCheckKerbResponse()后，KpsPackProxyResponse()会按如下方式初始化结构：将ASN1_KDC_PROXY_MSG.buf设置为_KPS_IO.recvbuf，将ASN1_KDC_PROXY_MSG.len设置为_KPS_IO.bytesread。然后，为了将 Kerberos 响应包装在 KDC 代理响应中，它会调用函数KpsDerPack() ，并将ASN1_KDC_PROXY_MSG结构的地址作为参数传递。从此刻开始，代码流在实现 KDC 代理服务器的 DLL 文件kpssvc.dll中的函数和 Microsoft ASN.1 库msasn1.dll中的函数之间交替。后者随后被称为“MSASN.1”函数。  
  
KpsDerPack()调用 MSASN.1 函数ASN1_CreateEncoder() ，该函数分配一个ASN1_encoder类型的结构。ASN1_encoder结构的大小为 0x50 字节，部分定义如下：  
  
```
Offset Length Name Description
(bytes) (bytes)
------- ------- ------------ -------------
[... truncated fields ...]
0x10 0x8 buf pointer to buffer holding DER-encoded data
0x18 0x4 len length of DER-encoded data
[... truncated fields ...]
0x28 0x8 current pointer to the current writing position in buf
[... truncated fields ...]
```  
  
  
然后， KpsDerPack()调用 MSASN.1 函数ASN1_Encode() ，将指向ASN1_encoder和ASN1_KDC_PROXY_MSG结构的指针作为参数传递。ASN1_Encode ()调用函数ASN1Enc_KDC_PROXY_MESSAGE()。ASN1Enc_KDC_PROXY_MESSAGE ()调用 MSASN.1 函数ASN1BEREncExplicitTag()，将指向 ASN1_encoder 结构的指针作为参数传递。ASN1BEREncExplicitTag ()被调用两次，以对 SEQUENCE 和 EXPLICIT 字段进行编码。  
  
编码数据被附加到ASN1_encoder.buf，并分配缓冲区，然后在对字段进行编码时重新分配。为此，MSASN.1 函数调用ASN1EncCheck()，并将所需大小作为参数传递。对于初始分配，ASN1EncCheck()通过调用 Windows API 函数LocalAlloc()在堆中分配空间。初始分配的大小至少为 1,024 字节。在后续调用期间，如果缓冲区无法容纳所需大小， ASN1EncCheck()会重新分配缓冲区。在这种情况下，它会将缓冲区的当前大小和所需大小相加，然后将结果作为参数传递给 Windows API 函数LocalReAlloc()。  
  
ASN1BEREncExplicitTag()调用 MSASN.1 函数ASN1BEREncTag()。ASN1BEREncTag()对标识符八位字节进行编码，首先调用ASN1EncCheck()以确保ASN1_encoder.buf有足够的空间，然后将标识符八位字节写入地址ASN1_encoder.current，最后增加ASN1_encoder.current。此时  
  
阶段，构造字段的长度未知，因为它取决于尚未编码的其他构造字段和原始字段的长度。因此，ASN1BEREncExplicitTag()通过调用大小为 1 的ASN1EncCheck()并将ASN1_encoder.current增加 1，为ASN1_encoder.buf中的 Length Octets 保留一个字节。  
  
ASN1Enc_KDC_PROXY_MESSAGE()然后调用 MSASN.1 函数ASN1DEREncOctetString()对kerb-message OCTET STRING 字段进行编码，并将指向ASN1_encoder结构的指针以及ASN1_KDC_PROXY_MSG.buf和ASN1_KDC_PROXY_MSG.len作为参数传递。ASN1DEREncOctetString()是函数ASN1BEREncCharString()的别名。ASN1BEREncCharString()首先调用ASN1BEREncTag()对标识符八位字节进行编码，然后调用ASN1BEREncLength()，并将ASN1_KDC_PROXY_MSG.len作为参数传递。  
  
ASN1BEREncLength()首先计算编码 Length Octets 所需的字节数，添加ASN1_KDC_PROXY_MSG.len，然后将结果值作为参数传递给ASN1EncCheck()。这确保ASN1_encoder.buf有足够的空间容纳 Length Octets 和 Contents Octets。然后ASN1BEREncLength()将 Length Octets 写入地址ASN1_encoder.current，最后将ASN1_encoder.current增加Length Octets 的大小。最后，ASN1BEREncCharString()调用 Windows API 函数memcpy()将ASN1_KDC_PROXY_MSG.len从地址ASN1_KDC_PROXY_MSG.buf复制到地址ASN1_encoder.current。  
  
但是，MSASN.1 函数并不总是能正确处理意外输入，特别是，它们在处理较大长度值时不会检查可能的整数溢出。此外，KpsSocketRecvDataIoCompletion()在调用KpsPackProxyResponse()之前不会检查 Kerberos 响应的长度。最后，可以通过将消息长度前缀后面的字节设置为除或之外的任何值来绕过KpsCheckKerbResponse()中的 Kerberos 响应验证。因此，恶意域控制器可能会发送较大的 Kerberos 响应，从而导致内存损坏错误。0x7E0x6B  
  
对kerb-message OCTET STRING 字段进行编码时，会发生整数溢出和内存损坏错误。此时，SEQUENCE 和 EXPLICIT 字段都已编码，ASN1_encoder.buf指向大小为 1,024 的缓冲区，ASN1 _encoder.current指向地址ASN1_encoder.buf + 4。KDC Proxy 接受的 Kerberos 响应的最大大小为 4,294,967,295。如果发送长度从 4,294,967,291 到 4,294,967,295（含）的 Kerberos 响应，ASN1BEREncLength()将发现需要 5 个字节来编码 Length Octets，然后添加 Kerberos 响应的长度。但是，加法结果存储在溢出的 4 字节无符号变量中。因此，传递给ASN1EncCheck() 的参数大小非常小。ASN1EncCheck ()不会重新分配ASN1_encoder.buf缓冲区，之后，当ASN1BEREncCharString()调用memcpy()时，会发生堆缓冲区溢出。  
  
或者，当发送长度从 4,294,966,267 到 4,294,967,290（含）的 Kerberos 响应时，ASN1BEREncLength()会调用ASN1EncCheck()。由于当前ASN1_encoder.buf缓冲区太小，ASN1EncCheck()会继续重新分配它。它将缓冲区的当前大小（1,024）添加到 Kerberos 响应的长度。但是，加法结果存储在溢出的 4 字节无符号变量中。因此，  
  
LocalReAlloc()实际上会减小缓冲区的大小。稍后，当ASN1BEREncCharString()调用memcpy()时，会发生越界写入或堆缓冲区溢出。作为一个有趣的极端情况，可以将 0 作为新大小传递给LocalReAlloc()。LocalReAlloc()返回一个内存地址，而不是错误，但是，内存实际上并未分配，尝试写入该地址时会发生访问冲突。  
  
远程、未经身份验证的攻击者可以指示 KDC 代理将 Kerberos 请求转发到他们控制的服务器，然后该服务器将发回精心设计的 Kerberos 响应。成功利用此漏洞可能导致在目标服务的安全上下文中执行任意代码。  
  
注意：要到达存在漏洞的代码，仅发送一个前四个字节中包含较大消息长度前缀值的短 Kerberos 响应是不够的。Kerberos 响应长度必须与前缀值实际匹配。  
  
检测指导  
  
为了检测利用此漏洞的攻击，检测设备必须监视和解析 UDP 端口 389 和 TCP 端口 88 上的流量。Kerberos 消息可以通过端口 88 上的 UDP 或 TCP 传输。但是，当通过 TCP 发送时，每个请求和响应前面都会显示消息的长度，按网络字节顺序为 4 个八位字节。  
  
检测设备必须检查 Kerberos 响应。请注意，KDC Proxy 仅使用 TCP 端口 88 进行 Kerberos 流量（而不是 UDP）。因此，设备不需要完全解析 Kerberos 响应。它只需要解析 4 字节消息长度前缀，并能够隔离 TCP 流内的响应。如果 Kerberos 响应为 0x80000000（2,147,483,648）字节或更长，则应将流量视为可疑，利用此漏洞的攻击可能正在进行中。  
  
注意：上述检测指南基于 Kerberos V5 RFC 的第 7.2.2 节。其中提到，在 4 个八位字节的消息长度前缀中，高位必须设置为 0。因此，根据 RFC，通过 TCP 传输的 Kerberos 消息的最大长度为 0x7FFFFFFF。  
  
关于补丁的问题  
  
我们的研究表明，漏洞存在于 ASN.1 库中，但 Microsoft 公告中提到了 KDC 代理服务器。此外，通过在 KDC 代理KpsSocketRecvDataIoCompletion()函数中添加长度检查来解决该漏洞。目前尚不清楚 Microsoft 选择这种方法的原因。ASN.1 库可能已知存在错误，这对于调用软件检查其输入是意料之中的。目前还不清楚是否可以使用任何其他软件组件来触发 ASN.1 库中的漏洞。因此，本报告重点介绍 KDC 代理服务器。  
  
结论  
  
供应商已于11 月修补了此漏洞。到目前为止，尚未发现任何实际攻击。Microsoft 未针对此漏洞提供任何缓解措施，但他们确实指出，只有配置为 KDC 服务器的服务器才会受到影响。域控制器不受此问题影响。他们还指出，由于此漏洞存在于 KDC 代理服务器服务 (KDCSVC) 中，因此只有当您已经在环境中使用 KPSSVC 时，您才会受到攻击。如果您的环境中没有配置它，则此漏洞不可利用。我们建议立即修补所有 KPSSVC 服务器实例。  
  
特别感谢趋势科技研究团队的 Simon Humbert 和 Guy Lederfein 对此漏洞进行了如此详尽的分析。如需了解趋势科技研究服务的概况，请访问http://go.trendmicro.com/tis/。  
  
威胁研究团队将来会带着其他出色的漏洞分析报告回来。在此之前，请在Twitter、Mastodon、LinkedIn或Bluesky上关注该团队 ，了解最新的漏洞利用技术和安全补丁。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
