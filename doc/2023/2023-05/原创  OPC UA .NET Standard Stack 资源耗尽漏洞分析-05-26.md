#  原创 | OPC UA .NET Standard Stack 资源耗尽漏洞分析-05-26   
原创 启明星辰ADLab  网络安全应急技术国家工程中心   2023-05-29 14:35  
  
# 作者 | 启明星辰ADLab  
# 漏洞概述  
#   
  
OPC UA .NET Standard Stack是OPC Foundation（OPC基金会）官方维护的OPC UA协议栈的参考实现。该协议栈以.NET语言开发，包含了可移植的OPC UA协议栈和核心库（包含客户端、服务端、配置、复杂类型支持库等），服务端和客户端的参考实现以及客户端和服务端的X.509证书认证等实现。  
  
OPC UA协议是工业控制领域中的一种十分流行的通讯协议。启明星辰ADLab研究员在工控漏洞情报跟踪中发现了OPC UA .NET Standard Reference Server中存在内存资源耗尽漏洞（编号为CVE-2023-27321），并对该漏洞进行了深入分析和验证。  
# 漏洞分析  
#   
  
该漏洞存在于OPC UA .NET Standard Server Stack代码库中。根据官方漏洞公告，远程攻击者可通过发送恶意的请求来耗尽服务器所有可用内存。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176mOxsPyCchqXZdPgmia3cwx3JluhAG8FlWKPbyQnVo9Cicxmfx9YVh9boJia5h7WSFjZ82IrOC0ZxUHw/640?wx_fmt=jpeg "")  
  
图 1、OPC Foundation Security Bulletin关于CVE-2023-27321概述  
【1】  
  
  
由官方漏洞公告的描述可以看出，该漏洞存在于OPC UA .NET Standard Reference Server对OPC UA Client请求的处理代码中。OPC UA .NET Standard处理客户端请求的关键代码类位于协议栈代码Stack\Opc.Ua.Core\Stack\Tcp目录下。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3ldQLZecZ6a8t3hnwI8lv6RlgFo8HGZ7zLNFhzbao4XtT3QWNe39Gmw/640?wx_fmt=png "")  
  
图 2、OPC UA .NET Standard处理TCP连接核心代码文件  
  
其中创建OPC UA Server Service的核心入口位于TCPServiceHost类函数CreateServiceHost中。  
  
该函数首先通过Create函数创建一个TCPTransportListener，随后调用ServerBase类函数CreateServiceHostEndpoint启动该监听器：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3rJ1h2rb7ZmJyvZtB1VAeURYnBB2t5Kh3dIAFKApAbMiaVv9Z99pT91w/640?wx_fmt=png "")  
  
图 3、TcpServiceHost类成员函数CreateServiceHost调用Create方法创建Tcp监听器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3WicWGZjUmdRHXOu3bse67kuoZOsF097j6mvRuhSOF4oia103HbEJvKQg/640?wx_fmt=png "")  
  
图 4、ServerBase类函数CreateServiceHostEndpoint调用Open方法启动Tcp监听器  
  
CreateServiceHostEndpoint函数调用TCPTransportListener的Open方法启动监听器。在Open函数中，首先通过ChannelQuotas类对OPC UA连接的通道参数进行了一些列的配置，例如MaxBufferSize、MaxMessageSize等。并且实例化了一个用于管理Socket buffer的BufferManager类。然后调用Start函数运行Listener。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3DUZ42Tl8hrdAeKibict5KkicDsXZgqLgDMjJly3ZlV14poBOa2gzgZdgg/640?wx_fmt=png "")  
  
图 5、TcpTransportListener类Open函数主要代码  
  
在Start函数中，完成Server Socket的创建工作，同时指定了OnAccept函数来处理OPC UA Client连接：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3hBncUQP3Dm6s9SvjnYGHsSA3z2DodW5cTB2fIjD5HGkgzRNicXhftqQ/640?wx_fmt=png "")  
  
图 6、TcpServerListener类函数Start创建Server socket  
  
OnAccept函数则建立了一个TcpServerChannel来管理客户端连接。同时设置该channel的各种消息处理回调函数。并调用Attach函数将该TcpServerChannel与Client socket进行关联。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3BAeiadgEoEUc1OJYbyjTTibA7WRyQDic5T9ozcHhkAGpEmbianuL96e9Xg/640?wx_fmt=png "")  
  
图 7、TcpTransportListener类OnAccept函数创建TcpServerChannel关联Client socket  
  
随后在Attach函数中创建了TcpMessageSocket实例来处理客户端请求数据，使用TcpMessageSocket类的ReadNextMessage方法来处理客户端请求数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3RdRTxryffM0TUK7SVhEzjMvenbhAFnicVQ2VnbndlTuiavuSAJVGWTqg/640?wx_fmt=png "")  
  
图 8、TcpServerChannel类函数Attach创建TcpMessageSocket实例处理客户端请求数据  
  
以上便是OPC UA .NET Standard创建Server，接受Client连接和处理Client请求的过程。下面我们着重分析ReadNextMessage(  
)函数，该函数负责处理客户端的请求数据。该函数的实现代码如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3StLVE7FWVD0mg0ALajRItM7YQEABXAyheUnqCibwyicsqab9vtL4UvbA/640?wx_fmt=png "")  
  
  
图 9、ReadNextMessage函数代码  
  
该函数是一个双重循环，第一重循环首先通过BufferManager申请一块内存，然后设置m_bytesToReceive为TcpMessageLimits.MessageTypeAndSize（值为8）大小，然后调用ReadNextBlock读取Message数据。  
  
在ReadNextBlock函数中，使用ReceiveAsync函数异步方式接受客户端的请求数据，在ReceiveAsync的接收回调函数OnReadComplete中，通过调用DoReadComplete函数，完整读取一个Message消息的所有内容。然后通过ReadNext函数重新进入ReadNextMessage循环，不断的处理客户端的请求消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3icvic921XLmt94icrtNyGw7drNO5Rv6nDpNnko5odLTkUibLes6O8lPGlA/640?wx_fmt=png "")  
  
图 10、ReadNextBlock调用ReceiveAsync异步接收客户端数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3lian3sAI25x0MUxoCYDo1OOLBdQ4e1m56Q2eseZYDUAmz7PmLMyrJRQ/640?wx_fmt=png "")  
  
图 11、OnReadComplete通过readState状态确定客户端一个Message是否读取完毕  
  
  
DoReadComplete函数中首先确保读取到了8字节的Message头部，其中包含了4字节的MessageSize，然后通过该MessageSize大小读取剩余Message消息数据。如果完成一个Message的读取，再通过触发OnMessageReceived函数来处理消息的内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3Koee5RbsmnQWum6wrz0RX6J4rsdLtA4SVycn485cko3LoUrXw8cXGA/640?wx_fmt=png "")  
  
图 12、DoReadComplete读取Messsage消息过程  
  
OnMessageReceive函数最终是通过HandleInComingMessage来具体处客户端请求消息内容。在HandleInComingMessage函数中通过判断MessageType来确定不同的Message处理函数（包括ProcessRequestMessage、ProcessHelloMessage、ProcessOpenSecureChannelRequest等）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx37Q3lu3hdCs1WTNJVESYwsicRP24YtnibcR5Mdp0XD1HnSKKHZ4f0Ivlw/640?wx_fmt=png "")  
  
图 13、HandleInComingMessage函数处理流程  
  
在消息的具体处理函数ProcessXXX中解析和处理完消息数据后，便会释放存储消息的内存。如下是ProcessRequestMessage函数中释放Message内存的代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3QrrGtudFrFyO2ibtw16c6XlsLHqBsVww32SFK7p8WA2iaibqib9QbFndEg/640?wx_fmt=png "")  
  
图 14、ProcessRequestMessage函数释放内存代码  
  
在Server端收到客户端消息时，会根据创建TcpServerChannel时设置的回调函数（参见图7），对客户端进行回复。例如处理客户端request的回调函数是TcpTransportListener类中的OnRequestReceived函数。该函数设置了消息处理完毕的回调函数OnProcessRequestComplete函数，并在此函数中调用SendReponse对客户端消息进行回复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3W1v67mv7hNpR4fia0jNdhVsAGTIfyK9y0Yf96DVkaANRsiaeuNZSibxkw/640?wx_fmt=png "")  
  
图 15、客户端Request消息处理的回调函数设置  
  
SendResponse函数则通过WriteSymmetricMessage函数生成Response消息并调用BeginWriteMessage发送给OPC UA Client。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3HEKQTjicAU55G6UKlEsXfyq7r9BIial1ROn3xsWZicIRPAcGiaU7sKXZibw/640?wx_fmt=png "")  
  
图 16、SendResponse函数关键代码  
  
这里WriteSymmetricMessage函数中依然会通过BufferManager来申请一块内存来存储回复消息数据。申请的内存大小为SendBufferSize。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3KCujyicsU8fzfI2RcTHceSZ6xicxcyPMmxXAnd2AdAoayL3wTQm3KYHA/640?wx_fmt=png "")  
  
图 17、WriteSymmetricMessage内存分配关键代码  
  
从上述OPC UA .NET Standard Server处理Client请求的过程可以看出，无论是在接收Client Message消息阶段还是发送Response消息阶段，Server都会申请一块内存来临时存储数据。对于接收阶段，在ReadNextMessage函数中为每个Message申请的内存的大小为m_receiveBufferSize，该变量在TcpServerChannel类中初始化TcpMessageSocket时指定为Quotas.MaxBufferSize（参见图8）。而Quotas.MaxBufferSize是在TcpTransportListener类的Open函数中赋值的（参见图5）,其最终来源为ServerBase类函数CreateServiceHostEndpoint中的参数ApplicationConfiguration。对于OPC UA Reference Server应用来说，就是其配置文件（Quickstarts.ReferenceServer.Config.xml）的MaxBufferSize参数，默认值为65535。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3BLzrpErDKqfEzJGChpwBGEHCh8SZ2PYaxA7wubaq6iaEIMUlibLBficXQ/640?wx_fmt=png "")  
  
图 18、Reference Server配置文件中关于TransportQuotas的参数配置  
  
同样回溯WriteSymmetricMessage函数中SendBufferSize的赋值过程发现，其初始大小也是MaxBufferSize。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3L82OFbRiafWBcjbWWAmV12RWznXVf9r0ibTfeUdhH7Kg5eOVibseYuO3g/640?wx_fmt=png "")  
  
图 19、UaSCBinaryChannel类构造函数中对sendBufferSize的初始化  
  
也就是说，对于客户端发送的每个TCP请求，OPC UA Reference Server都会通过BufferManager申请64K的内存来存放Request数据，然后处理完毕后再申请64KB的内存来存放Response数据。  
  
根据BufferManager的实现可知，该类是通过ArrayPool来进行动态内存管理的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3eTlAdEOruErsicuh4ZviblK7YP6S2weVocXiaMStZOs7GHauuHRIfNdwA/640?wx_fmt=png "")  
  
图 20、BufferManager构造函数代码  
  
ArrayPool是.NET框架中的一个类，用于管理和重用数组内存缓冲区。它旨在帮助减少在高性能应用程序中频繁分配和释放大量相同大小的数组时产生的垃圾回收压力。在传统的.NET内存管理中，每次使用new关键字创建数组时，都会在堆上分配一块内存。当这些数组不再使用时，垃圾回收器会负责回收这些内存。这种频繁的内存分配和垃圾回收操作可能会对性能产生负面影响。ArrayPool通过维护一个内部的缓冲区池来解决这个问题。当需要分配一个数组时，可以从池中获取一个可用的数组，而不是每次都分配新的内存。使用完毕后，可以将数组返回到池中以供重用，而不是立即释放内存。  
  
ArrayPool的使用虽然提高了系统进行内存分配和释放的性能，但是对ArrayPool不加限制的不当使用，会导致系统资源被耗尽。  
# 漏洞复现  
#   
## 复现环境  
  
lOPC UA Vulnerable Server  
  
OPC UA .NET Standard Reference Server（Version: UA-.NETStandard-1.4.371.60）  
## 复现过程  
  
首先按照默认配置编译OPC UA .NET Standard Reference Server。然后启动该OPC UA Server。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx38vMTbSJTeehgNB9g1OubWAmNS7APK79abCZNmiaNiaZ06y24lU8rxZVg/640?wx_fmt=png "")  
  
图 21、OPC UA .NET Standard Reference Server启动界面  
  
运行PoC脚本，脚本中OPC Client连接Reference Server之后将发送大量请求，最终可消耗Reference Server所在主机的所有可用内存。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx32yGbVk3J2p4QwmAOzFDCYANV22aHpkw9JkfboBmy1Pr2elxfb9QPJw/640?wx_fmt=png "")  
  
图 22、OPC UA .NET Standard Reference Server消耗大量内存  
  
下图展示了在调试环境中通过插桩内存分析代码得到的ArrayPool内存占用情况和程序实际内存占用的情况。  
# 补丁分析  
#   
  
根据OPC UA的官方漏洞公告，该漏洞在OPC UA .NET Standard 1.4.371.86版本【2】  
中修复。  
通过对该版本代码的分析，我们发现实际上该漏洞在Github库UA-.NET Standard的Commit 67fd91ca993c01c38712a61f0342dfdf3c02f4c5中【3】  
已被修复。  
  
  
主要修复的方式如下：  
  
1.限制了服务端RequestQueue队列的大小。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx321eebibJ4RCCAFGKCEEEO9vsANgLia3Yibak4k55lYfkMYjbhOLfD09tQ/640?wx_fmt=png "")  
  
图 23、漏洞补丁（部分）-限制Server端RequestQueue大小  
  
2.增加了判断Client和Server通信的通道是否已满的函数ChannelFull，该函数限制了在一个Channel会话中能保持活跃的最大WriteRequest数量为100。当客户端不再从Server读取数据后，关闭当前Client连接的channel。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176mOxsPyCchqXZdPgmia3cwx3zjdQZ6DTqePqPn6KJ3CFGc3LLQpCOxm4bYCY6icMwiaeNiazZdwyuHO1g/640?wx_fmt=png "")  
  
图 24、漏洞补丁（部分）-判断Server端Channel WriteRequest数量  
  
上述修复方式的核心是：限制OPC UA Server所能占用的托管内存大小，避免在ArrayPool中分配过多的内存资源。  
# 安全建议  
#   
  
鉴于该漏洞无需认证便可从网络侧发动针对OPC UA服务器的拒绝服务攻击，我们建议使用了OPC UA .NET Standard代码的相关OPC UA产品及时更新OPC UA .NET Standard代码到版本1.4.371.86, 或者将引用的代码版本更新到修复了该漏洞的commit版本【3】  
。  
  
# 参考：  
  
[1].https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2023-27321.pdf  
  
[2].https://github.com/OPCFoundation/UA-.NETStandard/releases/tag/1.4.371.86  
  
[3].https://github.com/OPCFoundation/UA-.NETStandard/commit/67fd91ca993c01c38712a61f0342dfdf3c02f4c5  
  
  
  
转载请注明  
来源：CNCERT国家工程研究中心  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176njVOPvfib4X3jQ6GIHLtX8SSDvbpmcpr4uu3X7ELG7PDjdaLVeq4Er02ZoicTPvxrC6KCVH3bssUVw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
