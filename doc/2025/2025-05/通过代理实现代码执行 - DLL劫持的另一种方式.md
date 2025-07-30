#  通过代理实现代码执行 - DLL劫持的另一种方式   
 Khan安全团队   2025-05-08 07:42  
  
在不断发展的网络安全格局中，攻击者不断设计出新的方法来利用终端中的漏洞执行恶意代码。DLL 劫持是最近越来越流行的一种方法。虽然 DLL 劫持攻击有多种形式，但本文将探讨一种称为 DLL 代理的特定攻击类型，深入分析其工作原理、潜在风险，并简要介绍发现这些易受攻击的 DLL 的方法。这种方法导致发现了几个存在零日漏洞的 DLL，微软已承认这些漏洞，但目前选择不予修复。在讨论该方法的同时，我们还将研究如何轻松地利用这些 DLL 进行隐蔽攻击。首先，我们来简单讨论一下什么是 DLL 劫持。    
  
什么是 DLL 劫持？   
  
DLL 劫持包含多种不同的技术，包括 DLL 侧劫持和侧加载，但从总体上讲，DLL 劫持利用了 Windows 应用程序搜索和加载 DLL 的方式。进程执行时，为了正常运行，它会尝试加载一系列 DLL。有时，进程会在终端上的多个位置查找才能找到正确的 DLL；而在其他情况下，该 DLL 可能根本不存在。通过将恶意 DLL 放置在进程首先查找的位置，攻击者可以诱骗进程加载恶意 DLL 而不是合法 DLL，从而使攻击者能够以与正在运行的应用程序相同的权限执行任意代码。这种技术在规避应用程序允许列表等安全控制措施，甚至终端安全控制措施方面非常有效，因为合法（审查较少）的应用程序会将这些 DLL 加载到应用程序的标准运行时程序中。此外，通过利用易受此漏洞攻击的 DLL，攻击者可以避免使用任何 Living off the Land 二进制文件 (LOLbins) 来执行其恶意 DLL，而这些恶意 DLL 已成为许多基于检测的产品的关注重点。   
  
虽然这种技术非常有效，但也存在一些缺陷。通过劫持所需的 DLL，攻击者可以使进程不稳定，或者在大多数情况下导致应用程序缺少功能，从而中断运行。这可能会引起用户或系统管理员的注意，尤其是在攻击者试图隐蔽行动时。另一个问题是，大多数进程检查 DLL 的文件夹都需要提升权限才能写入。因此，我开始寻找实现此类攻击的其他方法。这让我陷入了巨大的研究困境，最终发现了我称之为“DLL 代理攻击”的东西。   
  
什么是 DLL 代理攻击？   
  
DLL 代理采用的方法与传统的 DLL 劫持不同。DLL 代理并非利用进程的搜索顺序，而是依赖于两个因素。首先，DLL 所在文件夹的访问控制配置错误，导致任何用户都可以写入该文件夹的内容。这使得攻击者可以将 DLL 放入存在漏洞的 DLL 所在的文件夹中。    
  
现在，您不能在同一个文件夹中拥有两个同名的 DLL，因此，有了此写入权限，我们可以将 DLL 重命名为任何我们想要的名称。这对于第二部分（代理方面）至关重要。此技术背后的想法是仍然允许访问我们目标 DLL 中的函数。为此，我们需要将所有来自恶意 DLL 的流量转发到合法 DLL；这确保我们不会中断应用程序的运行。当应用程序尝试加载 DLL 时，它将加载恶意 DLL，从而有效地允许我们的恶意代码运行，并将任何函数请求转发到合法 DLL，而不会中断或崩溃。这将我们的恶意 DLL 变成应用程序和合法 DLL 之间的代理。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiangNCn5koghBuMickmwoqic1xk6ZOBOQfPia1v5OrsXpyfHMfUlGic0wUwQ/640?wx_fmt=png&from=appmsg "")  
  
DLL 代理攻击非常有效，因为它们不需要提升权限即可执行。通常，当程序安装 DLL 时，这些文件会被放置在具有严格安全权限的目录中。这些权限确保只有具有管理员权限的用户才能写入或重命名这些目录中的文件。这种保护机制至关重要，因为它可以防止低权限用户将恶意 DLL 引入存储合法 DLL 的文件夹中，从而保护系统免受潜在的劫持攻击。   
  
发现它们   
  
识别易受 DLL 代理攻击的 DLL 与查找可劫持的 DLL 类似。我们需要查找进程首次执行时加载的所有 DLL。然而，我们不会忽略缺失的 DLL 或位于其他路径的 DLL，而是查找在运行时加载的 DLL，并检查文件夹权限。为此，我们会过滤掉所有已知默认受保护的位置，以防止低权限用户对其进行写入，例如 System32 和任何程序文件文件夹。    
  
一个有效的工具是进程监视器 (Process Monitor)，这是一款适用于 Windows 的免费工具，可以监视并显示实时文件系统、注册表以及进程/线程活动。进程监视器可用于观察应用程序的“加载映像”事件，该事件发生在应用程序加载 DLL 时。通过过滤特定的文件位置，可以识别可能被代理的 DLL。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaukibueY6S57rWql2SbvtNT4cWN0xVYTRnQ3LlKldKr1Btd8UEztZFAg/640?wx_fmt=png&from=appmsg "")  
  
要开始搜寻，我们首先要启动应用程序。Microsoft Office 产品与其他应用程序之间存在大量的交叉兼容性和支持，尤其是 Outlook 和 Teams。通过监控这些应用程序，我注意到 Outlook 会从 AppData 加载多个 DLL。深入研究这些事件后，我发现 Microsoft Teams 版本 2（又名 Microsoft Teams for Work and School）和 Microsoft Teams Classic 中都存在易受攻击的 DLL（用于代理）。当使用用户的配置文件配置 Microsoft Teams v2 时，它会在 Outlook 中安装一个名为 TeamsMeetingAddin 的包（如果已安装 Outlook）。低权限用户可以修改包含此加载项关联 DLL 的文件夹，从而重命名合法 DLL 并添加恶意 DLL。这意味着下次启动 Outlook 时，恶意 DLL 会被 Outlook 加载，从而导致 Outlook 进程中的代码执行。低权限用户可以修改此目录中的所有文件。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBia2gPCp1RQXY4yaE3uk1QJbXSPv4hAGBQ7rc8liaLkZSHz3tDv1ya5lbQ/640?wx_fmt=png&from=appmsg "")  
  
Windows 中的 AppData 文件夹是一个隐藏的系统目录，用于存储特定于应用程序的数据和各个用户帐户的设置。Windows 系统上的每个用户帐户都有自己的 AppData 文件夹，这确保了每个用户的应用程序数据都独立且安全。由于该文件夹专注于用户数据，因此用户本身拥有写入 AppData 中任何内容的权限。这使得它成为托管恶意代码的理想场所，也成为托管进程使用的合法 DLL 的极不安全的地方。如下所示，低权限用户可以写入包含“TeamsMeetingAddin”的文件夹。    
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiad3OfdXEAG4biceyaAeicTBthF8ZWM6qIQJSftV9IulINdMI3USia9EtkQ/640?wx_fmt=png&from=appmsg "")  
  
现在，我们已知一个 DLL 会在执行时加载，文件夹权限允许我们向其中写入新的 DLL，并且我们可以重命名该文件夹中的任何 DLL。下一步是创建代理功能。这时，定义文件 (.def) 就派上用场了。定义文件是包含一个或多个模块语句的文本文件，这些语句描述了 DLL 的各种属性。使用 .def 文件，我们可以定义所有导出函数，并将它们映射到包含所请求函数的合法 DLL。因此，我们可以将合法 DLL 重命名为任何我们想要的名称（在下面的示例中，我们在名称后附加 -legitimate），并将我们的 DLL 放在同一文件夹中，这样，当进程加载它时，它会将对下述函数的任何请求代理到对合法 DLL 的请求。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaNoCa8b12IGt9AZHibFicEzGsgzniadCDJnSfwva0ibicm2wYDIfHV94Cu2g/640?wx_fmt=png&from=appmsg "")  
  
只有一个 DLL 会被加载（不是 OneAuth.dll 和 OneAuth-legitimate/dll），但当我们查看 DLL 的导出函数时，我们可以看到每个代理函数都回调到了 OneAuth-legitmate.dll。在下面的示例中，我们的 OneAuth.dll 只会弹出一个简单的 hello world 语句，显示我们的 DLL 已加载。深入研究后，我们可以看到导出函数中引用了合法的 DLL。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiahwxlBLcpia9BmDgH5sVJOTlibPtU2kdOMkF4Wd12PNHLZWTda3sziagTw/640?wx_fmt=png&from=appmsg "")  
  
观察到以下 DLL 容易受到这种攻击。   
  
Microsoft Teams V2 或 Microsoft Teams for Work 或 School   
  
```
C:\Users\{用户名}\AppData\Local\Microsoft\TeamsMeetingAddin\{版本}\x64\OneAuth.dll
```  
  
  
注意：在查看此插件的多个不同版本时，我发现根据版本的不同，文件夹名称可能会从 TeamsMeetingAddin 更改为 TeamsMeetingAdd-in。我无法直接找到原因，但这似乎是微软开发人员的偏好设置。（我们将在第二部分中详细讨论这个问题）   
  
Microsoft Teams V1 或 Microsoft Teams Classic   
```
C:\Users\{用户名}\AppData\Local\Microsoft\Teams\current\ffmpeg.dll
C:\Users\{用户名}\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\slimcore\bin\SlimCV.dll
```  
  
武器化   
  
将 DLL 加载到进程后，我们需要一些东西来触发代码。由于我们将函数代理到合法 DLL，因此运行恶意代码的唯一方法是将其放入 DLLMain 函数中。遗憾的是，直接从 DLLMain 运行 Shellcode 可能会引发 DLLhijack 攻击，特别是进程死锁。Microsoft 提供了有关 DLL 最佳实践的文档（如果您有兴趣进一步了解，可以在此处找到）。他们的建议之一是“推迟 DllMain 中可以稍后执行的任何调用”。这句话让我想到创建一个单独的线程，然后将其休眠 10 秒。这确保我们的恶意代码仅在其他所有内容加载到进程中后才运行。通过这样做，我们可以避免被检测到，因为从用户的角度来看，服务或功能不会中断。    
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBia3nEv6dXJz3vicFLCoSPursbicoT7CZwoC2icEZcrwMGuWb4UbOhhka1Yg/640?wx_fmt=png&from=appmsg "")  
  
DLL 代理攻击的影响   
  
DLL 代理攻击的影响可能非常巨大，因为它们允许攻击者绕过各种安全控制。其中一个关键影响是能够绕过应用程序允许列表。应用程序允许列表是一种安全措施，只允许预先批准的应用程序在系统上运行。由于 DLL 代理攻击中的恶意代码是由合法允许的应用程序加载的，因此它通常可以逃避检测。此外，这些攻击不需要任何特殊权限，使其成为初始访问的理想方法。    
  
微软的回应   
  
截至目前，微软尚无修复或补救这些问题的计划，但承认它们是有效的漏洞。他们的官方回应：   
  
我们认为您的发现有效，但不符合我们立即提供服务的标准，因为即使与此插件相关的DLL也只带来低/中等风险。不过，我们已将您的发现标记为待审核，以便改进我们的产品。目前尚无审核时间表。由于目前无需采取进一步行动，我将结案。   
  
继续这项研究  
  
虽然微软的消息并不理想，但在查阅了一些文档后，我发现 Microsoft Outlook 和 Microsoft Teams Classic 已被其新版本 olk.exe 和 ms-teams.exe（又名 Microsoft Teams V2）取代。经过一番调查，我发现新版本包含多项安全控制措施，可防止中等完整性级别和高级用户访问这些产品的安装路径，从而保护其免受 DLL 侧载和劫持攻击。虽然这些控制措施已经到位，但仍有可能绕过这些控制措施，并让这些应用程序利用注册表从终端上的任何位置加载恶意 DLL。    
  
首先，我们可以看到这些应用程序的安装目录与之前的安装目录不同。“C:\Program Files\WindowsApps\”这个路径似乎被严格锁定。当我们尝试访问该文件夹查看内容时，即使以管理员身份运行，也遭到拒绝。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiazUSeIvtXib34Jibeqrrad8qwNdkpQMgxDFXfIb1M36EaPIsyqXwphicRQ/640?wx_fmt=png&from=appmsg "")  
  
由于这些应用程序没有任何驻留在用户控制区域（例如 Appdata）的第三方或外部插件，因此无法以传统方式进行任何 DLL 劫持攻击。即使提升了权限，也无法访问或写入这些文件夹。这降低了使用传统方法利用这些应用程序的可能性。但是，如果我们使用Process Monitor监控这些应用程序的启动情况，我们可以看到它们使用 COM 加载了多个系统 DLL。    
  
COM 对象（组件对象模型对象）是 Microsoft 框架的重要组成部分，该框架使软件组件能够相互通信，无论它们使用何种语言编写。COM 对象支持进程间通信、版本控制和动态对象创建等功能，这些功能对于在 Windows 操作环境中构建复杂的分布式系统和应用程序至关重要。在本例中，这些 COM 查询用于查找某些系统 DLL 的路径，然后进行加载。这些请求的有趣之处在于，它们首先检查注册表的当前用户 (HKCU) 部分；然而，它们无法找到正确的注册表值，因此会转到注册表中存在这些条目的其他部分。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaL60dqeUW3RprXL2kFVzFZlRFWLKMzcAF0ianrlFW18LUBCMSv8kSMsg/640?wx_fmt=png&from=appmsg "")  
  
Windows 中的 HKEY_CURRENT_USER (HKCU) 注册表配置单元是一个至关重要的组件，用于存储特定于当前登录用户的配置设置和首选项。它包含用户特定的软件设置、用户界面配置和网络连接等信息，从而为系统上的每位用户提供个性化体验。通过将这些设置与 HKEY_LOCAL_MACHINE (HKLM) 中更广泛的系统范围配置隔离，HKCU 可确保一个用户所做的更改不会影响其他用户。这意味着当前运行的用户即使以低权限用户身份也可以读取和写入注册表项。因此，通过在 HKCU\SOFTWARE\Classes\CLSID\ 中添加一个包含进程正在查找的 DLL 的 COM ID 的注册表项，就可以让此进程从 WindowsApps 或 System32 文件夹之外加载 DLL。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBia3nuwhoIfJhW0m1C7BDmtcbFicm6zSuGFcKMXKK5vd6HI39JdfuUA4Eg/640?wx_fmt=png&from=appmsg "")  
  
每当应用程序运行时，进程都会加载我们的 DLL，而不是C:\Windows\System32\中的系统版本。虽然这只是一个例子，但许多应用程序和 DLL 都容易受到这种影响，因为应用程序首先会查找注册表的 HKCU 部分。    
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaD6Q0SYL3J5CEicKrjicEje73GFogeRgI8lfzLjP7n1BtgibicWA6mfDbMw/640?wx_fmt=png&from=appmsg "")  
  
从下图可以看出，这种方法有效，我们能够强制新版 Outlook 加载我们的 DLL。虽然我们只披露了存储在锁定的 WindowsApp 文件夹中的这些新应用程序，但这个问题实际上更为普遍，影响了许多其他应用程序。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaU2CX9Sn60LUGAKnNugeUr17tRJzY4piaCuWZOxCaGEZMPRMC0BRTMcQ/640?wx_fmt=png&from=appmsg "")  
  
为了扩大搜索范围，我们可以再次使用进程监视器，筛选出以“HKCU”开头的 RegOpenKey 操作，结果为“未找到名称”。通过监控，我们可以发现还有哪些应用程序在 HKCU 中查找 COM 对象，以便我们可以劫持它们。经过几个小时的监控，我们发现许多 Windows 系统原生应用程序都依赖于查询这些 COM 对象来加载 DLL。    
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaA3mapicVOTB1p1q0ib1icibvnh9AiaS4Rv9JPE8276OX2HLQ0bDJwbKWhicw/640?wx_fmt=png&from=appmsg "")  
  
有了这份详尽的 COM 对象 UUID 列表以及上述步骤，我们可以创建许多不同的 POC DLL，并映射到不同的 DLL。通过在企业中通常包含大量应用程序的终端的注册表 HKCU\SOFTWARE\Classes\CLSID\ 部分中部署这些 DLL 和注册表项，我们可以观察到哪些其他应用程序加载了这些 DLL。结果发现，原生 Windows 和其他应用程序的数量甚至更多。我们可以通过监控包含 POC DLL 的文件夹中的任何“加载映像”操作来查看这一点。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaSjoUbyfeKycb4296vM3QNEClviaK7ZTwrNW4pjhkyibibxjLpvQBkpficQ/640?wx_fmt=png&from=appmsg "")  
  
付诸行动   
  
编译和设置这些 DLL 的过程可能有点繁琐，所以我创建了一个名为 FaceDancer 的工具来帮助自动化这个过程。在下面的示例中，我将选择仅针对进程 msedge。我可以使用任意 DLL Payload（在本例中，我使用的是 Cobalt Strike 生成的原生 DLL，没有规避机制），将其输入到这个工具中，它将生成以下内容：   
- 我需要更新的注册表项设置。   
  
- 将代理使用 COM 执行 DLL msedge 加载的 DLL。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaYqzIzYRvlzYboAy1Aou4KFgPBNa1a6WlYa1iceywG7gANlubRQeeSmw/640?wx_fmt=png&from=appmsg "")  
  
一旦设置了注册表项，执行新的 msedge.exe 实例只是时间问题：   
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaSqficUBFksictheia4nXib0nWOpAFz6JXwnBibmFNV0LFDIjmp5FhcDTqpg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1EhmujG2uFQoxDS4ExIUBiaZIUibJXxSJBib1GHvgNPC6GAzcSWMRmTxaITvVPgVdiaC0dYLFF8qlGYw/640?wx_fmt=png&from=appmsg "")  
  
  
  
