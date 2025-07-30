#  Apple及物联网设备面临风险 | 空中传播：AirPlay 协议中的零点击蠕虫式远程代码执行漏洞   
白帽子左一  白帽子左一   2025-05-07 04:00  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 概要  
  
Oligo 安全研究团队发现了 Apple 的 AirPlay 协议及其软件开发工具包（SDK）中的一组新漏洞，后者被第三方厂商用于将 AirPlay 集成进自家设备中。  
  
这些漏洞可被利用实现多种攻击方式和结果，包括：  
- • 零点击远程代码执行（Zero-Click RCE）  
  
- • 单点击远程代码执行（One-Click RCE）  
  
- • 绕过访问控制列表（ACL）和用户交互  
  
- • 本地任意文件读取  
  
- • 敏感信息泄露  
  
- • 中间人攻击（MITM）  
  
- • 拒绝服务攻击（DoS）  
  
攻击者可以将这些漏洞进行组合利用，从而可能控制支持 AirPlay 的设备，包括 Apple 自家设备以及使用 AirPlay SDK 的第三方设备。  
  
Oligo 将这些漏洞及其所启用的攻击方式命名为 “AirBorne”，因为相关攻击可通过无线网络或点对点连接传播，并允许攻击者完全控制设备，并将该访问权限作为进一步攻击的跳板。  
  
Oligo 证明其中两个漏洞（CVE-2025-24252 和 CVE-2025-24132）可被**武器化为可蠕虫式的零点击 RCE 漏洞**  
。这意味着攻击者可以接管启用 AirPlay 的设备，部署会传播的恶意软件，并感染任何该设备连接的本地网络中的其他设备。这可能导致间谍活动、勒索软件、供应链攻击等高级攻击的投递。  
  
由于 AirPlay 是 Apple 设备（如 Mac、iPhone、iPad、Apple TV 等）和部分第三方设备的关键组件，这类漏洞的影响范围可能非常广泛。  
  
一些数据参考：  
- • 虽然并非所有 Apple 设备都易受 AirBorne 攻击，但 Apple 于 2025 年 1 月表示其全球活跃设备已达 23.5 亿台。  
  
- • 2018 年 Apple 表示其 macOS 活跃用户已超 1 亿。  
  
- • iPhone、Apple TV、Vision Pro 等设备也受不同 AirBorne 漏洞影响，其中 iPhone 需在设置中手动开启 AirPlay 接收器功能。  
  
- • 支持 AirPlay 的第三方音频设备数量估计达数千万。  
  
- • 虽然支持 CarPlay 的具体设备数不详，但其已在 800 多款车型中广泛使用。  
  
Apple 与 Oligo 已合作识别并修复这些漏洞，目标是保护终端用户。Apple 已发布最新软件版本修复漏洞，并留出时间供用户更新。在负责任的漏洞披露过程中，Oligo 向 Apple 提供了漏洞相关的文档、流程与代码。  
  
Oligo 共向 Apple 披露了 23 个漏洞，最终发布了 17 个 CVE 编号。完整的 CVE 列表及其所启用的攻击场景详见下文。  
## 攻击类型  
  
Oligo 发现的这些漏洞，无论是单独使用还是组合利用，都可以实现多种攻击向量，包括远程代码执行（RCE）、访问控制列表绕过、用户交互绕过、本地任意文件读取、敏感信息泄露、中间人攻击（MITM）、拒绝服务（DoS）攻击。  
  
本文重点分析基于 MacOS、AirPlay SDK 和 CarPlay 设备的 RCE 攻击。在未来的文章中，Oligo 可能还会分析其他设备及攻击类型。  
### 远程代码执行（RCE）攻击  
  
利用 AirBorne，攻击者可以在特定条件下对易受攻击的设备实现远程代码执行，这些条件包括 Apple 或第三方设备的设置，以及用户偏好。  
  
以下是根据不同配置下可能实现的 RCE 攻击示例：  
#### MacOS – 零点击 RCE  
  
**CVE-2025-24252**  
 是一个使用后释放（Use-After-Free, UAF）漏洞，可被利用为标准 UAF 攻击，也可以被操控为“任意释放”，使攻击者能在 macOS 设备上远程执行代码。  
  
当该漏洞与 **CVE-2025-24206**  
（用户交互绕过）组合使用时，攻击者可对与其处于同一网络中的 macOS 设备实现零点击 RCE，只要该设备开启了 AirPlay 接收器并设置为“同一网络中的任何人”或“所有人”。  
  
在该配置下，漏洞具备可蠕虫化特性，即攻击路径可以从一台设备自动传播到另一台设备，无需人工干预。  
  
一种潜在场景：受害设备在公共 WiFi 下被入侵，之后连接到公司网络，从而为攻击者提供横向移动的路径，接管更多设备。  
  
以下视频展示了我们“写入任意地址”的原语，实时覆盖音乐应用。我们刻意增加了一个点击动作来启动应用，以便更清楚地展示效果。由于我们的原语可以覆盖任意内存地址，因此无需打开应用即可实现多种利用方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcyQhIC9jelnNicGTsHIoXAlzhPEqG85zKhibu7sLAxAYmKXPD7PmH0SbA/640?wx_fmt=png&from=appmsg "")  
  
利用过程，漏洞利用视频链接：https://www.youtube.com/embed/ZmOvRLBL3Ys?si=6F6wvPcPcLeDx9pb  
#### MacOS – 单点击 RCE  
  
**CVE-2025-24271**  
 是一个访问控制列表（ACL）漏洞，允许攻击者在未配对的情况下向目标设备发送 AirPlay 命令。当该漏洞与 **CVE-2025-24137**  
 组合使用时，可对配置为“当前用户”的 macOS 设备实现单点击 RCE，前提是设备与攻击者处于同一网络，并开启了 AirPlay 接收器。  
  
注意：CVE-2025-24137 已由 Apple 于 2025 年 1 月 27 日在 macOS Sequoia 15.3 中修复：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcmXA7wOJibxzh3917MCpaJrSeefDRy7bQECvmoJwW5MRfSicqf5BMTBNw/640?wx_fmt=png&from=appmsg "")  
  
**AirPlay SDK - 扬声器与接收器 - 零点击远程代码执行（Zero-Click RCE）**  
  
**CVE-2025-24132**  
 是一个基于堆栈的缓冲区溢出漏洞。该漏洞允许攻击者在使用 AirPlay SDK 的扬声器和接收器设备上实现零点击远程代码执行（RCE）。无论设备处于何种配置状态，该漏洞都可被利用，从而在完全无需用户交互的情况下发动攻击。  
  
在这种情况下，漏洞可被用于构造“蠕虫式”攻击路径，使攻击从一个设备自动传播至另一个设备。  
  
成功攻击的结果可能包括一些“轻松”的操作，例如在设备上显示图像或播放音乐，也可能包括更为严重的行为，例如利用设备的麦克风监听附近的对话——比如在一个高规格会议室中窃听。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmckic2rOzVgJwP14ibXialVwydfR16ibs3GN23Cz8USicn5ur9uicCB9hGLibiaQ/640?wx_fmt=png&from=appmsg "")  
  
利用过程，youtube上的视频演示链接：https://www.youtube.com/embed/vcs5G4JWab8?si=kgz3r_sZrbiiJ07e  
  
**CarPlay 设备 - 零点击与单点击远程代码执行（RCE）**  
  
**CVE-2025-24132**  
 是一个基于堆栈的缓冲区溢出漏洞，同样适用于 CarPlay 设备。在特定条件下，该漏洞可实现零点击 RCE。攻击可能带来的结果包括：通过图像显示或播放音频分散驾驶员注意力，甚至执行更恶意的行为，如窃听车内对话或跟踪车辆位置。  
  
具体攻击条件包括：  
- • **WiFi 条件**  
：若攻击者靠近 CarPlay 单元，并利用 CarPlay 设备的 WiFi 热点功能，在默认、可预测或已知的热点密码条件下，攻击者可获取访问权限并执行远程代码。  
  
- • **蓝牙条件**  
：某些 CarPlay 设备厂商会通过 IAP2 协议利用蓝牙传输 WiFi 凭据，配对过程中需输入 PIN 码。若攻击者 1）靠近 CarPlay 单元，2）能看到并输入 AirPlay 设备上显示的 PIN 码，则可实施 RCE 攻击。在某些情况下，这是一次单点击 RCE，因为可能需要受害者点击确认。  
  
- • **USB 条件**  
：非无线版本的 CarPlay 设备可通过物理连接（USB）受到攻击。  
  
攻击效果示例如下：通过显示图像或播放音频干扰驾驶员注意力，或者进行更具隐蔽性的操作，例如窃听谈话或追踪车辆位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcZ7xvPtuIG5ay23MEd7mYtIT40pM2CyRCaetmQUobZcmSQRQuRt6Gtg/640?wx_fmt=png&from=appmsg "")  
  
利用过程，youtube上的视频演示链接：https://www.youtube.com/embed/eq8bUwFuSUM?si=dEfz6cfkdUTkfmCX  
### 其他攻击方式  
  
由于远程代码执行（RCE）漏洞的潜在影响巨大，本文档主要聚焦于该类漏洞的细节。  
  
然而，正如前文所述，除了 RCE 外，这组漏洞还可能带来其他攻击路径和利用方式，包括：访问控制列表（ACL）和用户交互绕过、本地任意文件读取、敏感信息泄露、中间人攻击（MITM）以及拒绝服务攻击（DoS），这些可能会在未来的博客中进一步提供这些攻击路径与利用方式的详细信息和分析。  
### 为何研究 AirPlay  
  
本次研究起源于对 0.0.0.0 day 漏洞：https://www.oligo.security/blog/0-0-0-0-day-exploiting-localhost-apis-from-the-browser的调查。在扫描可能通过   
0.0.0.0  
 被访问的开放端口时，我们注意到内部网络中的大多数设备都开放了 AirPlay 的 7000 端口。出于对该协议的好奇，我们开始研究 AirPlay 服务器所处理的基础命令。  
  
令人惊讶的是，许多协议命令在默认设置下即可完全访问。在初步分析协议时，我们注意到某些处理流程中的命令存在明显的“代码异味（code smell）”，这些可疑流程促使我们深入挖掘，最终开展了这项广泛的研究工作。  
## 技术概览  
### 攻击向量的工作原理  
  
AirPlay 通过端口   
7000  
 通信，使用的是一种专有的   
API  
 协议，结合了   
HTTP  
 和   
RTSP  
 协议的特点。在该协议中，许多命令（尤其是需要附加参数的）通过   
HTTP  
 的数据负载发送，并采用   
plist  
（属性列表）格式编码。  
  
属性列表（  
plist  
）是一种在 Apple 生态中广泛使用的结构化数据格式，用于序列化和存储数据。plist 使用键值对的分层结构表示数据，支持多种数据类型，如字符串、数字、日期、布尔值、数组和字典，并可序列化为   
XML  
 或二进制格式。  
  
Apple 的 Core Foundation API 在处理 plist 文件方面起着关键作用，这些 API 提供了读写与序列化 plist 的完整功能。  
  
由于 plist 是向 AirPlay 接收端传递参数的主要方式，理解 plist 的结构对于掌握整个协议至关重要。更重要的是，许多漏洞都直接与 plist 参数解析流程相关。  
  
举例来说，CVE-2025-24129 就是一个由于 plist 参数处理不当而引发的类型混淆（Type Confusion）漏洞。由于该漏洞已于 1 月公开，因此我们可以分享一些技术细节。至于其他漏洞（包括本次披露的新漏洞），我们将在确保大多数用户已更新至最新版本、不再受影响之后再行公开技术细节。  
### 利用 CVE-2025-24129 演示的类型混淆漏洞  
- • **URI**  
：/getProperty  
  
- • **方法**  
：POST  
  
AirPlay 中的   
getProperty  
 命令用于从接收端获取特定属性或设置，例如当前的音量级别或设备名称。  
  
方法 CFPropertyCreateWithData  
 会将客户端通过 HTTP 发送的数据构造成一个   
propertylist  
。该方法根据用户提供的数据内容不同，可能返回不同的 CFType 类型（如 CFArray、CFString 等）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmc9oZgo5z9qRk3vAAfqEniaNTIycgptgaianJ61ZecbndwtwznIZvrSSdQ/640?wx_fmt=png&from=appmsg "")  
  
  
如上图所示，使用 CFPropertyListCreateWithData  
 创建了一个属性列表（  
property list  
），但返回结果的类型（  
CFType  
）并未进行校验，程序默认其为字典类型（  
CFDictionary  
）。  
  
如果实际创建的 plist 不是一个   
CFDictionary  
，那么在调用如 CFDictionaryGetValue  
 这类函数时，程序将会崩溃。  
  
**可利用性分析**  
：  
CFDictionaryGetValue  
 属于 CoreFoundation 库的一部分，因此该问题的可利用性取决于具体的 CoreFoundation 版本。我们发现，大多数类型混淆漏洞在不同版本的 CoreFoundation 中，其可利用性也存在差异。  
### 未获得 CVE 编号的漏洞  
  
Oligo Security 研究团队向 Apple 报告了共计 23 个漏洞。这些漏洞均已被修复，但并非所有漏洞都获得了 CVE 编号。  
  
在某些情况下，Apple 会根据修复方式和修复时间将多个漏洞归类为同一个 CVE，而非按漏洞类型、影响范围或在 AirPlay 协议代码中的位置进行区分。  
  
以下是两个未获得 CVE 编号的漏洞示例：  
#### /setProperty 路由崩溃漏洞  
- • **URI**  
：/setProperty  
  
- • **方法**  
：PUT  
  
- • **适用配置**  
：全部设备  
  
- • **用户交互**  
：需要用户点击一次以接受连接  
  
AirPlay 中的   
setProperty  
 命令允许发送端配置接收端的某些属性或设置，如调节音量、播放选项或设备特定功能。  
  
大多数 AirPlay 的   
POST  
/  
PUT  
 命令都要求 HTTP 请求中的数据以 plist 格式提供。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmc8a9LOtqyYh0lZCw60ibLMActJibicYEhicnHzOkymJyWf5TpsMJiaian9TUQ/640?wx_fmt=png&from=appmsg "")  
  
  
在 mcProcessor_requestProcessSetProxiedProperty  
 中对   
HTTP  
 数据 plist 的格式化处理：  
  
服务器期望在   
/setProperty  
 的   
plist  
 载荷中包含一个 value  
 键。  
  
value  
 变量在未检查是否为 null 的情况下被用于构造响应：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcHKkBr89bjJfFpibjgOq7Ob19FvNaN0qd9EFXmV4shia00NuvQTZD92Tg/640?wx_fmt=png&from=appmsg "")  
  
  
如果用户在请求中未发送 value  
 键，它将保持为 null。  
  
在此情况下调用   
CFDictionarySetValue  
 会因传入 null 而触发未处理异常，导致   
ControlCenter  
 进程崩溃。  
#### 通过 WindowServer 崩溃实现远程用户注销  
- • **URI**  
：rtsp://<ip>/stream  
  
- • **方法**  
：SETUP  
  
- • **适用配置**  
：同一网络中的任意用户 / 所有人  
  
- • **用户交互**  
：使用 CVE-2025-24206 实现 0 点击攻击  
  
AirPlay 中的 SETUP 方法基于 RTSP（实时流传输协议），用于从发送端（如 iPhone/iPad）向接收端（如 Apple TV）发起媒体流。  
  
发送多个 SETUP 命令会创建多个视频流。由于系统未限制流数量，我们可以通过 while  
 循环持续创建流。  
  
持续发送大量流会增加 WindowServer 服务的内存占用和响应时间。几秒钟后，**看门狗（watchdog）会终止 WindowServer 服务，导致用户被强制注销。**  
  
该漏洞允许网络内或附近的攻击者远程强制注销用户。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcibW2gjnuIqC21z9wfva0BKXOPm6s0HVoiaWGrEC2WVKia9e6mk0kVeAwQ/640?wx_fmt=png&from=appmsg "")  
  
利用过程，youtube上的视频演示链接：https://www.youtube.com/embed/RODsw_eXB5g?si=6-0QL0-HZmynZmsS  
## AirBorne 漏洞  
  
AirBorne 漏洞使设备暴露于多种攻击之下，每类漏洞都带来了独特的安全风险。以下是对各类漏洞功能与潜在影响的分析。  
### ACL 和用户交互绕过  
  
AirPlay 使用两项主要功能来处理访问权限控制：  
- • **ACL（访问控制列表）**  
：根据 AirPlay 接收端的配置限制访问权限。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcKSbpUeWGpQuicKwnho8WnZ4ZE8dXLQAapf6UlvzvQsd0M9cqkflsn3A/640?wx_fmt=png&from=appmsg "")  
  
- • 点击接受 – 某些操作要求用户点击“接受”并批准 AirPlay 连接。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcQQhibYSA6yibCUFTKj0apTvOggQDzNBI1cYMZT9r96qyfYNBy8r1osiaA/640?wx_fmt=png&from=appmsg "")  
  
  
我们发现了多个 ACL 绕过漏洞和问题，以及一个用户交互绕过问题，这使得在 macOS 设备配置为 AirPlay 接收器默认设置并设置为“当前用户”时，AirBorne 漏洞可以实现许多攻击。  
  
CVE-2025-24206 还**通过绕过“Accept”点击要求**  
使许多攻击成为零点击攻击。  
  
**用户交互绕过**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmc4zCxRYMYutMkicWanYdAleSc4HrzcOiaQgdO1CJtGVDIsKwV7ndicJJKQ/640?wx_fmt=png&from=appmsg "")  
  
**ACL 问题和绕过**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcSZuaJLN6AfBiaD0wnXMNapz8tzrz8Q1iacMejthefNZVcxWkicUDQdutw/640?wx_fmt=png&from=appmsg "")  
  
**远程代码执行 (RCE)**  
  
该套件中最严重的漏洞允许远程代码执行，使攻击者能够完全接管易受攻击的设备。这些漏洞使得 AirBorne 可以被蠕虫化。在攻陷一个设备后，攻击者可以利用相同的漏洞传播到其他设备和网络，进一步扩大影响和破坏。  
  
以下是可以用于接管设备（RCE）的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcicibXgj462I7hPksoVskt2I5Q5yj8mXUEMiaqmvNHMalrjmmIE3Am9nAA/640?wx_fmt=png&from=appmsg "")  
  
**本地任意文件读取**  
  
另一个漏洞允许本地用户读取属于其他用户的文件。利用此漏洞，攻击者可以读取敏感数据、提取凭据，或者潜在地控制具有更高权限的进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmchSbMIJOJfb5UYklNZQQeUdefwUy2Hqc1WJB9lzUj73VA2Oat7iaqx1w/640?wx_fmt=png&from=appmsg "")  
  
**敏感信息泄露**  
  
另一个关键漏洞可能导致敏感数据在网络上暴露。该漏洞将敏感的日志数据暴露给网络上的任何用户，使攻击者能够识别设备并获取关于用户和设备的敏感信息。  
  
**可用于获取敏感数据的漏洞：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcznzq2UH0DMkjXSKUNyY6CEyffDsicCsNonB4wtqJKay7ibiayG4J46njQ/640?wx_fmt=png&from=appmsg "")  
  
### 其他漏洞  
  
以下漏洞使攻击者能够执行多种不同的操作，例如拒绝服务（DoS）。由于与AirBorne相关的CVE数量较多，因此未能对潜在的可利用性进行深入研究。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmcW9GxwibtFckMjdz2Aj0xTpLb0pbpzmITxuvBKGvyZBl41xnOWa8IGqg/640?wx_fmt=png&from=appmsg "")  
  
虽然上述漏洞可能会产生各种影响，但崩溃AirPlay服务器为中间人攻击提供了机会。例如，考虑一下即将开始的董事会议。首席执行官希望将会议通过AirPlay投射到办公室的电视上。攻击者可以利用其中一个DoS漏洞：  
- • 利用其中一个DoS漏洞使电视的AirPlay接收器崩溃  
  
- • 使用mDNS伪造电视在网络上的身份  
  
- • 等待首席执行官开始将内容流式传输到伪造的AirPlay服务器  
  
- • 将首席执行官的流从伪造的服务器中转发到真实的电视  
  
- • 捕获并记录整个会议内容，从被拦截的流中获取  
  
### 漏洞缓解  
  
对于组织来说，确保所有公司Apple设备和其他支持AirPlay的设备立即更新到最新的软件版本至关重要。安全领导者还需要向员工明确传达，所有支持AirPlay的个人设备也需要立即更新。  
## 建议修复步骤  
  
- • **建议用户更新设备**  
，以减轻潜在的安全风险。**‍**  
  
- • **禁用AirPlay接收器**  
：如果不使用AirPlay接收器，建议彻底禁用。**‍**  
  
- • **限制AirPlay访问**  
：创建防火墙规则，仅允许受信任设备访问AirPlay通信（Apple设备上的端口  
7000  
），增强网络安全性并减少暴露风险。  
  
- • **限制AirPlay设置**  
：将“允许AirPlay的设备”更改为“当前用户”。虽然这**不能防止**  
报告中提到的所有问题，但确实减少了该协议的攻击面。  
  
- • 利用其中一个DoS漏洞使电视的AirPlay接收器崩溃  
  
- • 使用mDNS伪造电视在网络上的身份  
  
- • 等待首席执行官开始将内容流式传输到伪造的AirPlay服务器  
  
- • 将首席执行官的流从伪造的服务器中转发到真实的电视  
  
- • 捕获并记录整个会议内容，从被拦截的流中获取  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFfcM9ydR3KPfzarJPtzpmc4uScZdDEF2Ec2qJ47CsqfeM9Ztc0FJ9e8E38US9RL8JscVldiaf31Zw/640?wx_fmt=png&from=appmsg "")  
  
  
**AirPlay接收器可以在系统设置中关闭。**  
  
参考：https://www.oligo.security/blog/airborne  
  
   
  
获取更多精彩内容，尽在Track安全社区~：  
https://bbs.zkaq.cn  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
