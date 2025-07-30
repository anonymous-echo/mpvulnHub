#  AirPlay 协议中易受蠕虫攻击的零点击远程代码执行 (RCE) 漏洞使 Apple 和 IoT 设备面临风险   
 Ots安全   2025-05-01 04:17  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
Oligo Security Research 发现 Apple 的 AirPlay 协议和 AirPlay 软件开发工具包 (SDK) 中存在一组新的漏洞，第三方供应商使用该工具包将 AirPlay 集成到第三方设备中。  
  
这些漏洞会导致一系列攻击媒介和结果，包括：  
- 零点击远程代码执行  
  
- 一键远程代码执行  
  
- 访问控制列表 (ACL) 和用户交互绕过  
  
- 本地任意文件读取  
  
- 敏感信息泄露  
  
- 中间人 (MITM) 攻击  
  
- 拒绝服务（DoS）  
  
攻击者可以利用这些漏洞来控制支持 AirPlay 的设备 - 包括 Apple 设备和利用 AirPlay SDK 的第三方设备。  
  
Oligo Security 研究人员将这些漏洞及其引发的攻击媒介命名为“AirBorne”，因为它们引发的攻击通过无线网络或点对点连接传输，并允许攻击者完全接管设备，并将该访问用作进一步利用的启动板。  
  
Oligo 已证明，其中两个漏洞（CVE-2025-24252 和 CVE-2025-24132）允许攻击者利用可蠕虫的零点击远程代码执行漏洞进行攻击。这意味着攻击者可以控制某些支持 AirPlay 的设备，并执行诸如部署恶意软件之类的操作，这些恶意软件会传播到受感染设备所连接的任何本地网络上的设备。这可能导致与间谍活动、勒索软件、供应链攻击等相关的其他复杂攻击。   
  
由于 AirPlay 是 Apple 设备（Mac、iPhone、iPad、AppleTV 等）以及利用 AirPlay SDK 的第三方设备的基本软件，因此此类漏洞可能会产生深远的影响。  
  
从角度来看：  
- 虽然并非全球所有 Apple 设备都容易受到通过 AirBorne 进行的 RCE 攻击，但 Apple 在 2025 年 1 月表示，全球共有 23.5 亿台活跃的 Apple 设备。   
  
- 2018 年，苹果表示全球有超过 1 亿活跃的 MacOs 用户。      
  
- 其他 Apple 设备，例如 iPhone、Apple TV 和 Vision Pro，也受到不同 AirBorne 漏洞的影响。iPhone 等设备需要用户在手机设置中启用 AirPlay 接收器。  
  
- 此外，支持 AirPlay 的第三方音频设备数量估计达数千万。  
  
- 虽然尚不清楚支持 CarPlay 的设备的具体数量，但它已被广泛使用并可用于 800 多种车型。  
  
Apple 和 Oligo 携手合作，彻底识别并解决了这些漏洞，旨在保护最终用户。Apple 已发布最新版本的软件来修复这些漏洞，并预留了时间让这些设备进行更新。在整个负责任的漏洞披露过程中，Oligo 向 Apple 提供了与这些漏洞相关的文档、流程和代码。  
  
Oligo 共向 Apple 披露了 23 个漏洞，并因此发布了 17 个 CVE。以下是这些 CVE 的完整列表和说明，以及它们可能引发的具体攻击场景。  
  
攻击类型  
  
Oligo 发现的漏洞（独立或组合）可导致多种可能的攻击媒介，包括远程代码执行 (RCE)、访问控制列表 (ACL) 和用户交互绕过、本地任意文件读取、敏感信息泄露、中间人 (MITM) 攻击和拒绝服务 (DoS) 攻击。  
  
在本文档中，我们重点关注针对使用 MacOS、AirPlay SDK 和 CarPlay 的设备进行的 RCE 攻击。在后续的文章中，我们可能会探讨其他类型的攻击以及与 AirPlay 相关的其他设备。    
  
远程代码执行（RCE）攻击  
  
利用 AirBorne，攻击者可以根据某些因素（例如 Apple 和第三方设备设置以及用户偏好）在易受攻击的设备上实现 RCE。  
  
为了提供示例，下面列出了针对配置了不同设置的设备可能发生的一些不同的 RCE 攻击。  
  
MacOS - 零点击 RCE  
  
CVE-2025-24252是一个释放后使用 (UAF) 漏洞，可用作 UAF 或操纵为“任意释放”操作，使攻击者能够在 MacOS 设备上远程执行代码。   
  
当 CVE-2025-24252 与 CVE-2025-24206（用户交互绕过）漏洞组合使用时，攻击者可利用该漏洞在连接到攻击者所在网络且 AirPlay 接收器已开启且设置为“同一网络上的任何人”或“所有人”配置的 MacOS 设备上进行零点击远程代码执行 (RCE)。由于该漏洞允许攻击者在无需人工交互的情况下，从一台设备传播到另一台设备，因此在这种情况下，该漏洞可导致蠕虫式攻击。  
  
一种潜在情况是：受害设备在使用公共 WiFi 时受到攻击，然后连接到其雇主的网络 - 为攻击者提供了接管该网络上其他设备的途径。   
  
下面的视频演示了我们的“write-what-where”原语的实际操作，实时覆盖了音乐应用。为了方便您清晰地看到效果，我们特意添加了一次点击来启动应用。由于我们的原语可以定位到任何内存地址，因此有很多方法可以无需打开应用即可利用这种“UAF”漏洞。  
  
  
MacOS - 一键 RCE  
  
CVE-2025-24271是一个访问控制列表 (ACL) 漏洞，攻击者可利用该漏洞在未配对的情况下发送 AirPlay 命令。当 CVE-2025-24271 与 CVE-2025-24137 漏洞叠加使用时，攻击者可利用该漏洞在连接到与攻击者同一网络、AirPlay 接收器已打开且设置为“当前用户”配置的 MacOS 设备上进行一键式 RCE 攻击。  
  
注意： Apple 已于 2025 年 1 月 27 日在 macOS Sequoia 15.3 中修补了 CVE-2025-24137：    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibD5cSRDjkBH9ic1k3u6QZMVUJZjJhZuQgtO9oX65atcC4mCiansegeZIicg/640?wx_fmt=png&from=appmsg "")  
  
AirPlay SDK - 扬声器和接收器 - 零点击 RCE  
  
CVE-2025-24132是一个基于堆栈的缓冲区溢出漏洞。此漏洞允许对利用 AirPlay SDK 的扬声器和接收器进行零点击远程代码执行 (RCE)。这些设备在所有配置下都容易受到零点击远程代码执行攻击。由于该漏洞允许在无需人工交互的情况下从一台设备传播到另一台设备，因此在这些情况下，该漏洞允许蠕虫病毒利用。  
  
成功攻击结果的例子包括更有趣的行为，例如在设备上显示图像或播放音乐，以及更严重的行为，例如使用设备的麦克风监听附近的对话，例如通过高调会议室中的设备进行窃听。  
  
  
Car-Play 设备 - 零点击和一键 RCE  
  
CVE-2025-24132是一个基于堆栈的缓冲区溢出漏洞，也适用于 CarPlay 设备。此漏洞在特定条件下允许零点击远程代码执行 (RCE)。攻击结果包括通过显示图像和播放音频来分散驾驶员注意力，或者可能窃听对话和跟踪车辆位置等操作。  
- WiFi 条件：攻击者可以利用 CarPlay 设备中的 WiFi 热点，在距离 CarPlay 设备较近的情况下执行 RCE 攻击。如果设备具有默认、可预测或已知的 WiFi 热点密码，则有可能获得访问权限并执行 RCE。    
  
- 蓝牙条件：一些 CarPlay 设备供应商通过 IAP2 协议通过蓝牙交换 WiFi 凭证，需要 PIN 码才能配对设备。攻击者可以执行 RCE 攻击，前提是：1）攻击者距离 CarPlay 设备很近；2）攻击者能够看到并输入 AirPlay 设备上显示的 PIN 码。在某些情况下，这是一种一键式 RCE，因为受害者可能需要点击一下。    
  
- USB 条件：非无线 CarPlay 设备通过物理连接（USB）容易受到攻击。  
  
攻击结果的例子包括通过显示图像和播放音频来分散驾驶员的注意力，以及窃听谈话和跟踪车辆位置等更邪恶的行为。  
  
  
其他攻击  
  
由于 RCE 漏洞的潜在影响，本文档主要侧重于提供有关其的详细信息。  
  
然而，如上所述，除了 RCE 之外，利用这组漏洞还可能实现其他攻击媒介和漏洞利用。这些攻击媒介和漏洞包括远程代码执行 (RCE)、访问控制列表 (ACL) 和用户交互绕过、本地任意文件读取、敏感信息泄露、中间人 (MITM) 攻击以及拒绝服务 (DoS) 攻击。    
  
我们可能会在未来的博客和演示中提供有关这些其他攻击媒介和漏洞的更多信息和见解。  
  
我们为什么关注 AirPlay   
  
我们在研究0.0.0.0 漏洞后开始了这项研究。在扫描0.0.0.0可能访问的开放端口时，我们注意到内部网络上的大多数设备都开放了 AirPlay 端口 7000。出于对协议的好奇，我们开始研究 AirPlay 服务器处理的基本命令。令我们惊讶的是，许多协议命令在默认设置下完全可以访问。在初步研究协议的过程中，我们注意到命令中存在一些处理流的模式，这些流实际上就是“代码异味”。这些可疑的流促使我们进一步深入研究，并开展了这项广泛的研究。  
  
技术概述  
  
攻击向量的工作原理  
  
AirPlay使用专有API通过7000端口进行通信，该 API 融合了HTTP和RTSP协议的某些特性。在该系统中，许多命令（尤其是需要附加参数的命令）会以plist格式编码的HTTP数据有效负载形式发送。  
  
属性列表 ( plist ) 是一种结构化数据格式，在 Apple 生态系统中被广泛用于序列化和存储数据。plist 将数据表示为键值对的分层集合，从而可以组织复杂的信息。它们支持各种数据类型，包括字符串、数字、日期、布尔值、数组和字典，并且可以序列化为XML或二进制格式。  
  
Apple 的核心基础 API 在处理plist文件方面发挥着至关重要的作用。这些 API 提供了读取、写入和序列化plist 的全面功能。  
  
由于plist 文件是向 AirPlay 接收器发送参数的主要方式，因此理解 plist 文件及其结构对于理解该协议至关重要。此外，许多漏洞与 plist 参数解析流程直接相关。  
  
CVE-2025-24129 就是一个因plist参数处理不当而导致类型混淆漏洞的例子。由于该漏洞已于一月份公布，我们很乐意分享一些技术细节。其余漏洞（包括今天公布的漏洞）的技术细节，将在我们确定大多数用户已更新到最新版本且不再受影响后，稍后发布。  
  
使用 CVE-2025-24129 演示的类型混淆  
  
URI：/getProperty  
  
方法：POST  
  
AirPlay 中的getProperty命令用于从接收器检索特定属性或设置，例如当前音量级别或设备名称。  
  
CFPropertyCreateWithData 方法根据客户端发送的HTTP数据创建一个属性列表。该方法可以根据用户提供的数据（CFArray/CFString 等）返回不同的 CFType 值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibDbibohAS0yictwCI1WCaPkDAtHWE1KXggfIcibTlyuMJ95wiau6fNC4wI8Q/640?wx_fmt=png&from=appmsg "")  
  
在 mcProcessor_requestProcessSetProxiedProperty 中格式化HTTP数据 plist服务器期望/setProperty plist负载中包含一个值键值变量用于创建响应，而不检查它是否为空：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibDttEvZm8sFjyGpGjaXdpg5MtoqH0rMFyDu23qGuV7oU5tfzFVBhXjbg/640?wx_fmt=png&from=appmsg "")  
  
如果用户未在请求中发送 value 键，则该键将保持为 null。使用 null  
  
调用CFDictionarySetValue会导致未处理的异常，从而导致ControlCenter进程崩溃。  
  
使用 WindowServer Crash  
  
URI：rtsp://<ip>/stream  
  
方法：SETUP  
  
配置：同一网络上的任何人  
  
配置：所有人  
  
用户交互：0 次点击使用 CVE-2025-24206  
  
AirPlay 中的 SETUP 方法使用 RTSP（实时流协议），是从 AirPlay 发送方（如 iPhone/iPad）到接收方（如 Apple TV）发起媒体流的过程的一部分。  
  
发送多个 SETUP 命令会创建多个视频流。由于视频流的数量不受限制，我们可以在 while 循环中创建视频流。发送过多的视频流会增加 WindowServer 服务的内存消耗和响应时间。发送 SETUP 命令几秒钟后，看门狗会终止 WindowServer 服务，并注销用户。  
  
该漏洞允许网络攻击者远程注销同一网络或附近的用户。  
  
  
空中漏洞  
  
AirBorne 漏洞会使设备面临多种攻击风险，每个漏洞都构成独特的安全风险。下文我们将分析每类漏洞的危害及其潜在影响。  
  
ACL 和用户交互绕过  
  
AirPlay 使用两个主要功能来处理权限：  
  
ACL——根据 AirPlay 接收器配置限制访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibD2rhRL3IC7aF1dkGV6rACnGUknWJ10nvzb50FmYd8uNXRCelyoa2d1Q/640?wx_fmt=png&from=appmsg "")  
  
点击接受——某些操作需要用户点击“接受”并批准 AirPlay 连接  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibDDs7mkHdXllCCicGJNEQ1GrU3ZT8QmIS7QoVWOCNCvqkEp5vu2Lc3wUA/640?wx_fmt=png&from=appmsg "")  
  
我们发现了多个 ACL 绕过漏洞和问题以及一个用户交互绕过问题，当 macOS 设备配置为 AirPlay 接收器的默认设置并设置为“当前用户”时，这些问题使得利用 AirBorne 漏洞进行许多攻击成为可能。   
  
CVE-2025-24206 还通过绕过“接受”点击要求使许多攻击实现零点击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibDgnZfKVHQpyTEB9UpxegWdMwcOYOic2avcVObT53XlbHXAdP9cQXjMug/640?wx_fmt=png&from=appmsg "")  
  
远程代码执行（RCE）  
  
该软件包中最严重的漏洞允许远程执行代码，使攻击者能够完全控制易受攻击的设备。这些漏洞使得 AirBorne 易于感染蠕虫。在攻陷一台设备后，攻击者可以利用同一漏洞传播到其他设备和网络，进一步扩大其影响和破坏。  
  
以下是可用于接管设备（RCE）的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibD2Kaia0vnjWsm3ZW9jibD90cichwdIwzQ0MCj94A6JUMl9Uxx7dFaVOxmQ/640?wx_fmt=png&from=appmsg "")  
  
本地任意文件读取  
  
另一个漏洞允许本地用户读取其他用户的文件。利用此漏洞，攻击者可以读取敏感数据、提取凭证，甚至可能控制以更高权限运行的进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibD14OxNian2DyrcZKnz52gmAQdwzeG3CXjpoSr5ELe2t7SgMsoAf8PdqQ/640?wx_fmt=png&from=appmsg "")  
  
敏感信息披露  
  
另一个严重漏洞可能导致敏感数据在网络上泄露。该漏洞会将敏感日志数据暴露给网络上的任何用户，从而使攻击者能够获取设备指纹并获取有关用户和设备的敏感信息。  
  
可用于获取敏感数据的漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibD4POia2xyXXw7xhSfAQkRcVJibnh683khAkPHcYsG1qXsxdF0vZrdJO1Q/640?wx_fmt=png&from=appmsg "")  
  
其他漏洞  
  
以下漏洞可使攻击者执行各种不同的操作，例如拒绝服务 (DoS)。鉴于与 AirBorne 相关的 CVE 数量众多，我们无法对其潜在的可利用性进行广泛的研究。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafvPEJvb6gJkIFb9luSmiaibD54kWtCdrbHsicU0GtD1S4xvmhHLMY8UfVOQJ9kxuzKGRV2a4D9QtcPA/640?wx_fmt=png&from=appmsg "")  
  
虽然上述漏洞可能造成各种影响，但 AirPlay 服务器崩溃会为中间人攻击创造机会。例如，假设有一场刚刚开始的董事会会议。CEO 想通过 AirPlay 将会议内容播放到办公室的电视上。攻击者可以利用以下任一 DOS 漏洞来：  
- 利用其中一个 DOS 漏洞导致电视的 AirPlay 接收器崩溃  
  
- 使用 mDNS 在网络上欺骗电视的身份  
  
- 等待 CEO 开始向虚假 AirPlay 服务器进行流式传输  
  
- 将 CEO 的直播从假服务器转发回真正的电视  
  
- 从截取的流中捕获并记录整个会议的内容  
  
如何保护自己  
  
对于组织而言，所有支持 AirPlay 的企业 Apple 设备和其他机器都必须立即更新到最新软件版本。安全主管还需要向员工明确告知，所有支持 AirPlay 的个人设备也需要立即更新。  
  
我们建议的补救措施  
  
建议用户更新其设备以减轻潜在的安全风险。‍  
  
禁用 AirPlay 接收器：如果不使用 AirPlay 接收器，我们建议完全禁用它。‍  
  
限制 AirPlay 访问：创建防火墙规则以将 AirPlay 通信（Apple 设备上的端口7000）限制到仅受信任的设备，从而增强网络安全性并减少暴露。  
  
限制 AirPlay 设置：将“允许 AirPlay 的用户”更改为“当前用户”。虽然这并不能完全杜绝报告中提到的所有问题，但确实可以减少该协议的攻击  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
