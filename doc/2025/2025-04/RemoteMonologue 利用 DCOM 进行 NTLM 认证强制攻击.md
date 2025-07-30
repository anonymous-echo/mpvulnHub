#  RemoteMonologue: 利用 DCOM 进行 NTLM 认证强制攻击   
Andrew Oliveau  securitainment   2025-04-11 09:37  
  
> 【翻译】RemoteMonologue Weaponizing DCOM for NTLM authentication coercions  
  
  
随着微软加强针对凭证窃取的防御措施以及端点检测与响应 (EDR) 解决方案的不断进步，使用   
Mimikatz  
 轻松获取凭证的日子即将结束。传统的红队技术，如横向移动、载荷执行和直接访问本地安全认证子系统服务 (LSASS) 正面临越来越严格的审查。因此，红队社区被迫探索在 Windows 系统上获取凭证的替代方法。  
  
想象一下，无需"高级"载荷或访问 LSASS，仅通过"就地取材"和利用未充分利用的组件对象模型 (COM) 对象就能获得类似的结果。如果这让你感到兴奋，请继续阅读，因为本博客将介绍一些可以在下次任务中使用的有趣技巧。  
  
我们将简要介绍 COM 及其分布式版本分布式组件对象模型 (DCOM) 的基础知识，深入探讨 RunAs 设置以及为什么认证强制攻击具有影响力，并介绍一个新的凭证收集工具 - **RemoteMonologue**  
。  
## 关于 COM 和 DCOM 需要了解的内容  
  
组件对象模型 (COM)  
是 Windows 中最古老且最普遍的技术之一，默默地在日常应用程序和服务背后运行。尽管历史悠久，COM 仍然是攻击者的宝贵资源，提供了实现横向移动、权限提升和持久化的替代方法。然而，其固有的复杂性使得其攻击面在很大程度上未被充分探索。  
  
对于本博客，需要理解的关键概念是：  
- COM  
：一种核心 Windows 技术，使软件组件能够跨进程边界进行交互。COM 允许程序重用其他程序的功能，而无需重复实现这些功能。例如，程序可以使用 COM 对象读取系统日志或向 Excel 文件添加新条目，而无需自己实现这些功能。  
  
- **分布式组件对象模型 (DCOM)**  
：COM 的扩展，支持基于网络的通信。通过 DCOM，一台机器上的进程可以调用位于另一台机器上的 COM 对象的函数。这种基于网络的能力使 DCOM 成为横向移动的宝贵工具。访问 DCOM 对象通常需要远程系统上的本地管理员权限。  
  
从高层次来看，可以将 COM 对象视为具有两个主要组件的自包含单元：  
- 属性  
：表示对象的状态或配置。  
  
- 方法  
：表示对象可以执行的操作。例如，COM 对象可能具有启动进程、创建文件或发起认证请求的方法。  
  
攻击者可以滥用这些方法来促进横向移动，并强制远程 NTLM 认证以进行密码破解和重放攻击。  
## 以交互用户身份运行  
  
在深入探讨有趣的内容之前，需要更详细地讨论 COM 的一个重要组件。COM 中的应用程序标识符 (  
AppID  
) 是管理 COM 应用程序安全性、身份和运行时行为的关键机制，特别是在涉及 DCOM 或需要特定安全上下文的应用程序场景中。当 COM 类使用 AppID 注册时，它会继承为该 AppID 定义的安全设置。  
  
特别感兴趣的安全设置是   
RunAs  
 键，它指定在实例化时将使用哪个用户账户来执行 DCOM 对象。RunAs 键可以在注册表的以下位置找到：  
- HKEY_CLASSES_ROOT\AppID{AppID_GUID}  
  
在审查微软关于 DCOM 和 RunAs 键的文档时，一个特定的值引起了注意：Interactive User  
。此值将 DCOM 对象配置为在系统控制台会话中当前登录用户的安全上下文中执行。从攻击的角度来看，这很有趣，因为它可能允许我们利用 DCOM 对象作为另一个用户操作，而无需知道受影响用户的凭证。  
  
并非所有具有 AppID 的 DCOM 对象都将 RunAs 值设置为 Interactive User  
。事实上，大约一半的 AppID 根本没有设置 RunAs 值。但是，如果 RunAs 值可以被添加或修改以满足我们的目的呢？  
  
默认情况下，注册表中的 AppID 受自由访问控制列表 (DACL) 保护，授予 TrustedInstaller  
 所有权权限，并将本地管理员限制为只读访问，如图 1 所示。  
  
![AppID 默认 DACL 设置的截图](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6jgZoDcqGAMxJpqBTY17iaAL0ttyCfOsNDgyg2BsWMed6nkR1qkghkxg/640?wx_fmt=png&from=appmsg "")  
  
AppID 默认 DACL 设置的截图  
  
然而，本地管理员被授予   
SeTakeOwnershipPrivilege  
 权限，这允许他们获取系统对象的所有权，包括注册表键。此权限与此攻击相关，因为它使我们能够更改 AppID 的所有权。一旦所有权被更改，我们就可以授予自己对 AppID 的 完全控制  
 权限，并随后修改其设置以添加或更改 RunAs 值。  
  
一旦 RunAs 值被修改为 Interactive User  
，攻击就变得简单明了。这使我们能够强制 DCOM 对象在另一个活动会话的上下文中运行。然而，此攻击的成功最终取决于目标 DCOM 对象暴露的属性和方法。  
## NTLM 认证强制攻击  
  
现在我们知道可以将 DCOM 对象转换为会话劫持工具，下一步是确定可以利用哪些方法和属性来完成劫持。在这项研究中，我探索了是否可以在不运行载荷的情况下实现用户入侵 - 这与大多数  
公开的 DCOM 横向移动技术  
采取了不同的方法。  
  
我专注于以"无文件"格式实现类似的结果，这意味着无需在目标系统上传输或执行载荷。这种区别很重要，因为在目标系统上传输和运行载荷通常被认为是红队操作中的"昂贵"行为。通过避免这一步，触发常见安全控制的风险显著降低。因此，我旨在通过 DCOM 强制远程用户账户进行 NTLM 认证。  
  
与传统横向移动技术相比，强制 NTLM 认证有几个关键优势：  
- 捕获 NTLMv1/NTLMv2 哈希并尝试离线破解  
  
- 将 NTLMv1 或 WebDAV NTLMv2 哈希中继到其他网络服务，如 LDAP 或 SMB，以受影响用户的身份执行操作  
  
- 避免在目标系统上传输和运行载荷，这通常会引发安全工具的更多审查  
  
- 避免接触 LSASS 进程，从而降低检测风险  
  
截至本文撰写时，LDAP 签名和通道绑定在大多数域控制器上不是默认要求和强制执行的。这些安全功能仅在 Windows Server 2025 上是强制性的。这意味着如果我们能够从目标系统强制进行 NTLMv1 或 WebDAV 认证，我们就可以将其中继到 LDAP 并以受影响用户的身份执行操作。同样，SMB 签名在 Windows 服务器上默认不是必需的，域控制器除外。  
  
另一个重要的考虑是，NTLMv1 哈希可以使用彩虹表轻松破解，截至 2024 年 12 月，Nic Losby 已经  
公开分享了这些表  
。这些表大大减少了从 NTLMv1 哈希中恢复 NTLM 凭证所需的时间和精力。为了获得 NTLMv1 哈希而不是 NTLMv2 哈希，我们在目标系统上修改以下注册表键：  
- HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel  
  
将 LmCompatibilityLevel 设置为 2 或更低的值会强制系统回退到 NTLMv1 进行认证。此修改需要本地管理员权限，通常被称为"NetNTLMv1 降级攻击"。  
  
或者，我们可以捕获 WebDAV 认证并将其中继到 LDAP，因为基于 HTTP 的认证可以转发到此服务。如果 WebClient 服务尚未以特权访问运行，我们可以在目标系统上远程启用它。一旦启用，我们可以通过指定 UNC 路径中的机器 NetBIOS 名称来强制 WebDAV NTLM 认证到我们的监听器。例如：  
- \MYHACKERBOX@80\giveme\creds.txt  
  
有关 NTLM 中继攻击以及可以中继到不同端点的协议的更多信息，请参阅以下资源  
这里  
。  
## ServerDataCollectorSet DCOM 对象  
  
在研究过程中，我分析了 CLSID 为 {03837546-098B-11D8-9414-505054503030}  
 的 ServerDataCollectorSet  
 DCOM 对象，以识别可用于认证强制的 Methods 和 Properties。其中，DataManager  
 属性引起了我的注意，幸运的是，这个 COM 对象包含一个 Type Library，它更详细地定义了其 Methods 和 Properties。  
  
![枚举 ServerDataCollector 属性和方法](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6wdqIRzPq5tCerHXWOFJmIibbLpYyFPnuLkJSeg73BxNtbTAtn8VneRA/640?wx_fmt=png&from=appmsg "")  
  
枚举 ServerDataCollector 属性和方法  
  
使用   
OleView.NET  
，我审查了 ServerDataCollectorSet  
 的 Type Library，发现 DataManager  
 属性有一个 Extract  
 方法，它需要两个参数：  
1. CabFilename  
 - 要提取的 CAB 文件名  
  
1. DestinationPath  
 - 提取 CAB 文件内容的目标路径  
  
CabFilename  
 参数的存在特别有趣，因为它暗示了提供 UNC 路径的可能性，这可能导致网络认证行为。  
  
![使用 OleView.NET 分析 Type Library](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6WiaUARp7lNVAbQRV1pBwptALf8xObvicrO0CkeBSGUz9lwl4MQvDcCMQ/640?wx_fmt=png&from=appmsg "")  
  
使用 OleView.NET 分析 Type Library  
  
为了验证这个理论，我为 CabFilename  
 参数提供了一个指向我系统 (172.22.164.58  
) 的 UNC 路径，该系统运行着   
Responder  
，如图 4 所示。结果？成功了！我们能够捕获 NTLMv2 哈希，如图 5 所示。  
  
![使用 Extract 方法强制认证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6hD2UwnjWabWmk1bAWK0mlZc7fSn375IQ35uH9xhbnNVzdEWzTwSRlw/640?wx_fmt=png&from=appmsg "")  
  
使用 Extract 方法强制认证  
  
![捕获 NTLMv2 凭证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6nVRddHiaqpHppc6OhEbudIdh48cHERRfpbVqMrGMxPVmpdyhibXjpn8g/640?wx_fmt=png&from=appmsg "")  
  
捕获 NTLMv2 凭证  
  
接下来，我测试了是否可以通过修改 ServerDataCollectorSet  
 的 RunAs 键来捕获远程系统 (172.22.166.170  
) 上不同用户的凭证。为此，我使用   
Remote Registry  
 服务为 AppID {03837503-098B-11D8-9414-505054503030}  
 添加了 Interactive User  
 值。  
  
当目标系统上登录了不同用户（本例中为 GALAXY\yoda  
）时，我以 GALAXY\Administrator  
 身份访问 ServerDataCollectorSet  
 DCOM 对象，并执行了与图 6 相同的 Extract  
 方法。再次成功捕获了认证，但这次是来自 GALAXY\yoda  
 的，如图 7 所示。这表明将 RunAs 键修改为 Interactive User  
 使我们能够利用 DCOM 对象劫持其他用户的会话。  
  
![远程使用 Extract 方法强制认证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6H9SbBOMrTLm5vOEQr5ic5ibiaooxdBOd1sReGEQVAO6M3FcoBS7weYGHA/640?wx_fmt=png&from=appmsg "")  
  
远程使用 Extract 方法强制认证  
  
![捕获其他用户的 NTLMv2 凭证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6qdt7jgXVBkR7RliaeoykhoaeEzNwRjvGZps4GX3c7ZW1hWuQs66QJ9A/640?wx_fmt=png&from=appmsg "")  
  
捕获其他用户的 NTLMv2 凭证  
  
此攻击流程如下图所示。  
  
![展示 RemoteMonologue 攻击的图表](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6FJh4tLeKhlze6OM6pxalX4W7awp7qiaY0GibYia5U5byIcEPic1zsOpJuA/640?wx_fmt=png&from=appmsg "")  
  
展示 RemoteMonologue 攻击的图表  
## FileSystemImage DCOM 对象  
  
另一个容易受到认证强制攻击的有趣 DCOM 对象是 FileSystemImage  
，其 CLSID 为 {2C941FC5-975B-59BE-A960-9A2A262853A5}  
。这个对象特别独特，因为强制攻击是通过修改 Property 而不是调用 Method 来触发的 - 这在基于 DCOM 的攻击中是一种不太常见的技术。  
  
相关属性是 WorkingDirectory  
，它默认指向交互用户的 %TEMP%  
 文件夹。然而，通过将 WorkingDirectory  
 值更改为指向我们监听器的 UNC 路径，就有可能捕获 NTLMv2 认证，如图 9 和 10 所示。  
  
![修改 WorkingDirectory 属性以强制认证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6nl96hrMcuvLiaPIQc93mBNFwq4OQ51RXsWmV6x9ckeCSk0BTKHPrN4g/640?wx_fmt=png&from=appmsg "")  
  
修改 WorkingDirectory 属性以强制认证  
  
![捕获 NTLMv2 凭证的演示](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6icsBkiaJ9ibTjHTvhOhDhEJ2LibDejPp7ibTxAQRbvraAUe9IsfTXqnqcuQ/640?wx_fmt=png&from=appmsg "")  
  
捕获 NTLMv2 凭证的演示  
  
为了验证其会话劫持能力，我通过将 AppID {2C941FD1-975B-59BE-A960-9A2A262853A5}  
 的 RunAs 键设置为 Interactive User  
 来远程测试这一点。此配置触发了 FileSystemImage  
 DCOM 对象在目标系统上以活动用户的安全上下文执行。正如预期的那样，我能够捕获该用户的 NTLMv2 哈希。  
  
该技术表明，认证强制不仅可以通过调用 Methods 实现，还可以通过修改 Properties 实现，从而扩大了 DCOM 对象的潜在攻击面。  
## UpdateSession DCOM 对象  
  
最后一个值得分享的 DCOM 对象是 UpdateSession  
，其 CLSID 为 {4CB43D7F-7EEE-4906-8698-60DA1C38F2FE}  
。在审查其 Type Library 时，AddScanPackageService  
 方法引起了我们的注意，因为它需要一个 serviceName  
 参数，更重要的是，还需要一个 scanFileLocation  
 参数。scanFileLocation  
 的存在暗示它可能接受 UNC 路径。  
  
![使用 OleView.NET 分析 UpdateSession 的 Type Library](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6UVx2h3hlLdZKoWTC8vhniaLo9t5WjZsRQIC4EpyVwhIB2YSvfBiaZOzQ/640?wx_fmt=png&from=appmsg "")  
  
使用 OleView.NET 分析 UpdateSession 的 Type Library  
  
在测试这个理论时，我们成功捕获了 NTLMv2 认证，但接收到的不是用户账户的凭证，而是机器账户的凭证，如下图所示。  
  
![使用 UpdateSession 方法强制认证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6U2xbC544OGCMxyWBt88aPl5t7MTF08kVvVxrSscZdiaNf34ZOqdxIlA/640?wx_fmt=png&from=appmsg "")  
  
使用 UpdateSession 方法强制认证  
  
![捕获机器账户认证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6ozU4B6mMQy0GcIR9H0rBqb45vpiaKoOdGIvcS82U8ErqPTHGpNUwGXQ/640?wx_fmt=png&from=appmsg "")  
  
捕获机器账户认证  
  
这个发现特别有趣，因为即使在添加了 RunAs 键并将其设置为 Interactive User  
 之后，UpdateSession  
 DCOM 对象仍然以机器账户的身份执行网络操作。为什么会这样？简单来说，虽然 DCOM 对象本身在实例化或交互用户的安全上下文中运行，但网络操作是由一个单独的进程执行的：svchost.exe  
。UNC 路径被传递给 svchost.exe  
，而该进程始终默认使用 SYSTEM  
 账户执行这些操作。因此，RunAs 键的设置不会影响这种行为。  
  
尽管 RunAs 键不会影响用于网络操作的账户，但捕获机器账户凭证在以下几种攻击场景中仍然很有价值：  
1. 访问 Active Directory 中有趣的 DACL 权限  
：  
  
机器账户（例如 DOMAIN\MACHINE$  
）可能对 Active Directory 中的特定对象拥有权限，这些权限可能有助于横向移动或权限提升。  
  
1. 伪造白银票据以增强隐蔽性  
：  
  
我们可以使用机器账户的 NTLM 哈希来伪造白银票据，从而冒充系统中的任何用户并以较低的检测风险执行操作。  
  
## RemoteMonologue  
  
这种攻击被命名为   
RemoteMonologue  
，因为它与   
InternalMonologue  
 功能类似，关键区别在于它是远程执行攻击。该工具使用 Python 开发，基于   
Impacket  
 库，并自动化了攻击过程。  
  
RemoteMonologue 提供了针对上述三种 DCOM 对象（-dcom  
）的能力，可以对指定的监听器（-auth-to  
）执行认证强制。此外，它还具有喷洒模块（-spray  
），用于验证多个系统的凭证，并附带捕获凭证的功能。该工具还支持 NetNTLMv1 降级攻击（-downgrade  
），并有一个选项可以启用 WebClient 服务以促进 HTTP 认证（-webclient  
）。最后，该工具包含一个查询模块（-query  
），用于枚举目标系统上具有活动会话的用户。  
  
下面是一个使用 NetNTLMv1 降级攻击运行 RemoteMonologue 的示例，同时使用 Responder 作为监听器。默认情况下，如果未指定 DCOM 选项，该工具会使用 ServerDataCollectorSet  
 DCOM 对象。  
  
![运行 RemoteMonologue 捕获凭证](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6bgn9Uzx9Sv5BJwn4K9nMC7f5TxsZHLGrjLicPf5CdFNPFTdeJZYkxCw/640?wx_fmt=png&from=appmsg "")  
  
运行 RemoteMonologue 捕获凭证  
  
下面是另一个示例。这次攻击使用 FileSystemImage  
 DCOM 对象执行，并启用 WebClient 服务以获取 HTTP 认证，然后使用   
ntlmrelayx  
 将其中继到 LDAP。  
  
![强制 HTTP 认证并中继到 LDAP](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6icc4S7enU6Iw2JGDl6g0hKn8B8vT0j16w9Ly6GUcTxaDyZ41MBUwvWA/640?wx_fmt=png&from=appmsg "")  
  
强制 HTTP 认证并中继到 LDAP  
## 防御建议  
  
为了防范和检测本文中描述的技术，可以实施以下几种预防和检测措施。  
  
预防措施：  
1. 启用 LDAP 签名和通道绑定  
：在域控制器上配置 LDAP 签名强制和通道绑定，以保护 LDAP 端点免受中继攻击。注意：从 Windows Server 2025 开始，这些设置将默认强制执行。  
  
1. 升级到最新的 Windows 版本  
：将服务器升级到 Windows Server 2025，工作站升级到 Windows 11 24H2 版本，以缓解 NetNTLM 降级攻击，因为这些版本中已移除 NTLMv1。  
  
1. 强制执行 SMB 签名  
：在 Windows 服务器上启用并强制执行 SMB 签名，以防止 SMB 中继攻击。  
  
1. 实施强密码策略  
：强制执行强密码要求，使密码破解攻击更具挑战性。  
  
检测机会：  
1. 监控对 DCOM 对象的远程访问  
：跟踪对受影响的 DCOM 对象及其特定属性和方法的访问，以识别异常活动。  
  
1. 监控注册表修改  
：监控 RunAs 和 LmCompatibilityLevel 注册表键的更改。  
  
1. 跟踪 WebClient 服务活动  
：监控 WebClient 服务被远程启用的实例，因为该服务用于促进基于 HTTP 的 NTLM 认证。  
  
## 结论  
  
RemoteMonologue 攻击展示了如何利用未被充分利用的 DCOM 对象来执行隐蔽的、无文件的认证强制攻击。通过修改特定属性并利用 NetNTLMv1 降级等技术，攻击者可以在不部署有效载荷或直接访问 LSASS 等敏感进程的情况下，破坏用户账户并提升权限。  
  
通过专注于强化关键系统，例如强制执行 LDAP 签名、SMB 签名和禁用 NTLMv1 等遗留协议，防御者可以显著减少攻击面。此外，对注册表修改、DCOM 活动和远程服务更改的稳健监控可以帮助在早期阶段检测这些技术并减轻其影响。  
## 参考资料  
  
[1]   
Mimikatz: https://github.com/gentilkiwi/mimikatz  
  
[2]   
**RemoteMonologue**  
: https://github.com/xforcered/RemoteMonologue  
  
[3]   
组件对象模型 (COM): https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal  
  
[4]   
**分布式组件对象模型 (DCOM)**  
: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/86b9cf84-df2e-4f0b-ac22-1b957627e1ca  
  
[5]   
AppID: https://learn.microsoft.com/en-us/windows/win32/com/appid-key  
  
[6]   
RunAs: https://learn.microsoft.com/en-us/windows/win32/com/runas  
  
[7]   
SeTakeOwnershipPrivilege: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672  
  
[8]   
公开的 DCOM 横向移动技术: https://www.cybereason.com/blog/dcom-lateral-movement-techniques  
  
[9]   
公开分享了这些表: https://console.cloud.google.com/storage/browser/net-ntlmv1-tables  
  
[10]   
这里: https://en.hackndo.com/ntlm-relay/  
  
[11]   
OleView.NET: https://github.com/tyranid/oleviewdotnet  
  
[12]   
Responder: https://github.com/lgandx/Responder  
  
[13]   
Remote Registry: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78  
  
[14]   
RemoteMonologue: https://github.com/xforcered/RemoteMonologue  
  
[15]   
InternalMonologue: https://github.com/eladshamir/Internal-Monologue  
  
[16]   
Impacket: https://github.com/fortra/impacket  
  
[17]   
ntlmrelayx: https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py  
  
  
  
