#  通过代理实现代码执行——DLL 劫持的另一种方式   
 Ots安全   2024-10-01 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taemwJKicjCw53NuR5L6eRPZeibnsbVm74SjOBMLO5x4a1J9cYop4ytouRQ0Wlich0XlbtbndTJ6N3HoA/640?wx_fmt=jpeg&from=appmsg "")  
  
在不断发展的网络安全领域，攻击者不断设计新方法来利用端点中的漏洞来执行恶意代码。最近越来越流行的一种方法是 DLL 劫持。虽然 DLL 劫持攻击可以采取多种不同的形式，但这篇博文将探讨一种称为 DLL 代理的特定类型的攻击，深入了解其工作原理、它带来的潜在风险，并简要介绍发现这些易受攻击的 DLL 的方法，这导致发现了几个零日漏洞 DLL，微软已经承认但选择暂时不修复。在讨论方法时，我们还将研究如何轻松地将这些 DLL 武器化以进行隐蔽攻击。首先，让我们先简单讨论一下什么是 DLL 劫持。    
  
**什么是 DLL 劫持？**  
  
DLL 劫持包含多种不同的技术，包括 DLL 侧劫持和侧加载，但从高层次上讲，DLL 劫持利用了 Windows 应用程序搜索和加载 DLL 的方式。当进程执行时，它会尝试加载一系列 DLL 才能正常运行。有时，进程会在端点上的多个位置查找，然后才能找到正确的 DLL，而在其他情况下，DLL 可能根本不存在。通过将恶意 DLL 放置在进程首先查找的位置，攻击者可以诱使进程加载他们的 DLL 而不是合法的 DLL，从而允许攻击者以与正在运行的应用程序相同的权限执行任意代码。这种技术在规避安全控制（例如应用程序允许列表）甚至端点安全控制方面非常有效，因为有效的（审查较少的）应用程序会将这些 DLL 加载为应用程序标准运行时过程的一部分。此外，通过利用易受此攻击的 DLL，攻击者可以避免使用任何 Living off the Land 二进制文件 (LOLbins) 来执行其恶意 DLL，而这已成为许多基于检测的产品的关注重点。   
  
虽然这种技术非常有效，但也有其缺陷。通过劫持所需的 DLL，攻击者可以使进程不稳定，或者在大多数情况下导致应用程序缺少功能，从而中断操作。这可能会引起用户或系统管理员的不必要注意，尤其是当攻击者试图隐蔽时。另一个问题是，大多数进程检查 DLL 的文件夹都需要提升权限才能写入。因此，我开始寻找实现此类攻击的其他方法。这让我陷入了巨大的研究困境，并发现了我喜欢称之为 DLL 代理攻击的东西。   
  
**什么是 DLL 代理攻击？**  
  
DLL 代理采用的方法与传统的 DLL 劫持不同。DLL 代理不是利用进程的搜索顺序，而是依靠两件事。第一，DLL 所在文件夹的访问控制配置错误，允许任何用户写入该文件夹中的内容。这允许攻击者将 DLL 放入与易受攻击的 DLL 相同的文件夹中。    
  
现在，您不能在同一个文件夹中拥有两个同名的 DLL，因此有了这个写入权限，我们可以将 DLL 重命名为我们想要的任何名称。这对于第二部分，即代理方面很重要。这种技术背后的想法是仍然允许访问我们针对的 DLL 中的函数。为此，我们需要将所有流量从我们的恶意 DLL 转发到合法 DLL；这确保我们不会破坏应用程序的运行。当应用程序尝试加载 DLL 时，它将加载恶意 DLL，从而有效地允许我们的恶意代码运行，并将任何函数请求转发到合法 DLL，而不会中断或崩溃。这会将我们的恶意 DLL 变成应用程序和合法 DLL 之间的代理。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taemwJKicjCw53NuR5L6eRPZeErGE5PO4XpusccFqico95RPDqPSZQY66NJygjh7dQ750CulXxJEgeXA/640?wx_fmt=jpeg&from=appmsg "")  
  
图 1 – DLL 代理攻击   
  
DLL 代理攻击非常有效，因为它们不需要提升权限即可执行。通常，当程序安装 DLL 时，这些文件会被放置在具有严格安全权限的目录中。这些权限确保只有具有管理权限的用户才能写入或重命名这些目录中的文件。这种保护机制至关重要，因为它可以防止低权限用户将恶意 DLL 引入存储合法 DLL 的文件夹中，从而保护系统免受潜在的劫持尝试。   
  
**发现它们**  
  
识别易受 DLL 代理攻击的 DLL 与查找可劫持的 DLL 类似。我们需要查找进程首次执行时加载的任何 DLL。但是，我们不会查找丢失的 DLL 或位于不同路径的 DLL，而是查找在运行时加载的 DLL 并检查文件夹权限。我们通过过滤掉所有我们知道默认受保护的位置来防止低权限用户写入这些位置，例如 System32 和任何程序文件文件夹。    
  
一个有效的工具是Process Monitor，这是一个免费的 Windows 工具，可以监控和显示实时文件系统、注册表和进程/线程活动。Process Monitor 可用于观察应用程序的“加载图像”事件，该事件发生在应用程序加载 DLL 时。通过过滤特定的文件位置，可以识别可能被代理的 DLL。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeiaQPn8ibbdSGoL2GvTpINibwTufHQnm2PSiayHhItMmPgolGOtiaVrVLypg/640?wx_fmt=png&from=appmsg "")  
  
图 2 – 搜索过滤器   
  
要开始搜寻，我们首先要启动应用程序。对于 Microsoft Office 产品，与其他应用程序（特别是 Outlook 和 Teams）之间存在很多交叉兼容性和支持。通过监视这些应用程序，我注意到 Outlook 会从 AppData 加载多个 DLL。深入研究这些事件后，我发现 Microsoft Teams 版本 2（又名 Microsoft Teams for Work and School）和 Microsoft Teams Classic 中都存在易受攻击的 DLL（用于代理）。当使用用户的配置文件配置 Microsoft Teams v2 时，它会将一个名为 TeamsMeetingAddin 的包安装到 Outlook 中（如果安装了 Outlook）。低权限用户可以修改包含此加载项的关联 DLL 的文件夹，以重命名合法 DLL 并添加恶意 DLL。这意味着下次启动 Outlook 时，Outlook 会加载恶意 DLL，从而导致在 Outlook 进程中执行代码。低权限用户可以修改此目录中的所有文件。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZebnQowOMvw4g4iaP91Cfksy1UgZicT7rdPgrmFnlnfQuY1AgU0dCv2nRA/640?wx_fmt=png&from=appmsg "")  
  
图 3 – 进程监视器结果 – Outlook.exe   
  
Windows 中的 AppData 文件夹是一个隐藏的系统目录，用于存储特定于应用程序的数据和各个用户帐户的设置。Windows 系统上的每个用户帐户都有自己的 AppData 文件夹，这可确保每个用户的应用程序数据都是分开且安全的。由于它专注于用户的数据，因此用户本身有权写入 AppData 中的任何内容。这使得它成为托管恶意代码的理想场所，也是托管进程使用的合法 DLL 的非常糟糕的场所。如下所示，我们的低权限用户可以写入“TeamsMeetingAddin”所在的文件夹。    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeP0YkvFOHoGoSXrTLefKnd2ECDkuRVHmeYQ30r2ttcs6otm9rUtrkvQ/640?wx_fmt=png&from=appmsg "")  
  
图 4 – OneAuth.dll 的安全权限   
  
现在，我们知道了在执行时会加载的 DLL，文件夹权限允许我们将新 DLL 写入其中，并且我们可以重命名该文件夹中的任何 DLL。下一步是创建代理功能。这是定义文件 (.def) 发挥作用的地方。定义文件是包含一个或多个模块语句的文本文件，这些语句描述了 DLL 的各种属性。使用 .def 文件，我们可以定义所有导出的函数并将它们映射到包含请求函数的合法 DLL。因此，我们可以将合法 DLL 重命名为我们想要的任何名称（在下面的示例中，我们在名称后附加 -legitimate），将我们的 DLL 放在同一个文件夹中，当进程加载它时，它会将对下面列出的函数的任何请求代理到对合法函数的请求。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeqzibykKmictLAdwdWdRicXEv0ovrxoKCZrQb1IYdD4LfPJ5s8o5wjN8Xg/640?wx_fmt=png&from=appmsg "")  
  
图 5 – 示例 – Def 文件   
  
因此，只会加载一个 DLL（不是 OneAuth.dll 和 OneAuth-legitimate/dll），但当我们查看 DLL 的导出函数时，我们可以看到每个代理函数都会回调 OneAuth-legitmate.dll。在下面的示例中，我们的 OneAuth.dll 将弹出一个简单的 hello world 语句，显示我们的 DLL 已加载。当我们深入研究时，我们可以看到在导出中引用了合法的 DLL。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeWTrH2sXDKuPLZBPibgWtibticwKjYfNfuBgibN7fN42vyibUU37XicQUcicjw/640?wx_fmt=png&from=appmsg "")  
  
图 6 – 概念验证 – Outlook 弹出“Hello World”消息   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeEqV6iaAWoOf3epWJiaxxm7oZdicRrTH7RVgic7woodPCUj1tL87Z68jAAA/640?wx_fmt=png&from=appmsg "")  
  
图 7 – 我们的恶意 OneAuth.dll 将函数代理给合法的 OneAuth.dll   
  
我观察到以下 DLL 容易受到此类攻击。   
  
Microsoft Teams V2 或 Microsoft Teams for Work 或 School   
  
```
C:\Users\{username}\AppData\Local\Microsoft\TeamsMeetingAddin\{version}\x64\OneAuth.dll
```  
  
  
注意：在查看此插件的多个不同版本时，我发现根据版本的不同，文件夹名称可能会从 TeamsMeetingAddin 更改为 TeamsMeetingAdd-in。我无法直接回答为什么会发生这种情况，但这似乎是 Microsoft 开发人员的偏好。（我们将在第二部分中进一步讨论这方面的问题）   
  
Microsoft Teams V1 或 Microsoft Teams Classic   
  
```
C:\Users\{username}\AppData\Local\Microsoft\Teams\current\ffmpeg.dll
```  
  
  
**武器化它们**  
  
一旦我们将 DLL 加载到进程中，我们就需要一些东西来触发代码。由于我们将函数代理到合法的 DLL，因此运行恶意代码的唯一方法是将其放入 DLLMain 函数中。不幸的是，直接从 DLLMain 运行 shellcode 可能会引发 DLLhijack 攻击，特别是进程死锁。Microsoft 提供了有关 DLL 最佳实践的文档（如果您有兴趣进一步了解这方面的内容，请在此处找到）。他们的建议之一是“推迟 DllMain 中可以稍后再调用的任何调用”。这句话让我想到创建一个单独的线程，然后让它休眠 10 秒。这可确保我们的恶意代码仅在其他所有内容加载到进程中后才运行。通过这样做，我们可以帮助保持低调，因为从用户的角度来看，服务或功能不会中断。    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZepiaCcNia6WYvUuFuCGCwc1Q6yA8ofnia9OICOgd3qTW72fcK4zUeScC9g/640?wx_fmt=png&from=appmsg "")  
  
图 8 – 睡眠延迟代码   
  
**DLL 代理攻击的影响**  
  
DLL 代理攻击的影响可能非常大，因为它们允许攻击者绕过各种安全控制。其中一个关键影响是能够绕过应用程序允许列表。应用程序允许列表是一种安全做法，其中只有预先批准的应用程序才允许在系统上运行。由于 DLL 代理攻击中的恶意代码是由合法的允许应用程序加载的，因此它通常可以逃避检测。此外，这些攻击不需要任何特殊权限，使其成为初始访问的完美方法。    
  
**微软的回应**  
  
截至目前，微软还没有修复或补救这些问题的计划，但承认它们是有效的漏洞。他们的官方回应：   
  
我们认为您的发现是有效的，但不符合我们立即提供服务的标准，因为即使与此加载项关联的 DLL 也只提供低/中等风险。但是，我们已将您的发现标记为将来审查，作为改进我们产品的机会。我没有这次审查的时间表。由于目前不需要采取进一步行动，我将结束此案例。   
  
**继续这项研究**  
  
虽然微软的消息并不理想，但在查看了一些文档后，我发现 Microsoft Outlook 和 Microsoft Teams Classic 已被其新版本 olk.exe 和 ms-teams.exe（又名 Microsoft Teams V2）取代。经过一番调查，我发现新版本包含几个安全控制措施，可防止中等完整性和高级用户访问这些产品的安装路径，从而保护其免受 DLL 侧载和劫持攻击。虽然这些控制措施已经到位，但可以绕过这些控制措施，并且仍然让这些应用程序使用注册表从端点上的任何位置加载恶意 DLL。    
  
首先，我们可以看到这些应用程序安装在与之前安装不同的目录中。这个路径“C:\Program Files\WindowsApps\”似乎被严格锁定。当我们尝试访问该文件夹以查看内容时，即使以管理员身份运行，我们也被拒绝访问。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeqVky25SMAZftkQ01oA0RExBNMI1nL2gDuuvJlAJ9icRvibGkzP8sDUCg/640?wx_fmt=png&from=appmsg "")  
  
图 9 – Outlook OLK.exe 文件路径   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeW0LzJAJEG1Yuma0UzTvDF1vO6kIQ7iciaicK7QLLs7hkdhVkx9MxsqhJA/640?wx_fmt=png&from=appmsg "")  
  
图 10 – 管理员无法查看文件夹的内容   
  
由于这些应用程序没有任何位于用户控制区域（即 Appdata）的第三方或外部插件，因此不可能以传统方式进行任何 DLL 劫持攻击。即使提升了权限，也不可能访问或写入这些文件夹。这降低了使用传统方法利用这些应用程序的可能性。但是，如果我们使用Process Monitor监视这些应用程序的启动情况，我们可以看到这些应用程序使用 COM 加载了多个系统 DLL。    
  
COM 对象（组件对象模型对象）是 Microsoft 框架的一个关键部分，该框架使软件组件能够相互通信，而不管它们是用什么语言编写的。COM 对象支持进程间通信、版本控制和动态对象创建等功能，这些功能对于在 Windows 操作环境中构建复杂的分布式系统和应用程序至关重要。在这种情况下，这些 COM 查询用于查找某些系统 DLL 的路径，然后加载。这些请求之所以有趣，是因为它们首先检查注册表的当前用户 (HKCU) 部分；但是，它们无法找到正确的注册表值，然后转到注册表中存在条目的另一个部分。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeYF3k7cJJhSK1LFT4W8nWnNY697vTfefnmvFlgjIXcvTBYzmT5IRmhg/640?wx_fmt=png&from=appmsg "")  
  
图 11 – 跟踪 OLK.exe 的 RegOpenKey 操作   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZel7SSd6V59EYyJEknpicdsA6QOwicpyDwxKCwrWM2ut43kf5ibZkCS3qXg/640?wx_fmt=png&from=appmsg "")  
  
图 12 – 包含 DLL 信息的注册表项   
  
Windows 中的 HKEY_CURRENT_USER (HKCU) 注册表配置单元是一个关键组件，用于存储特定于当前登录用户的配置设置和首选项。它包括用户特定的软件设置、用户界面配置和网络连接等信息，从而为系统上的每个用户提供个性化体验。通过将这些设置与 HKEY_LOCAL_MACHINE (HKLM) 中更广泛的系统范围配置隔离开来，HKCU 可确保一个用户所做的更改不会影响其他用户。这意味着当前运行的用户可以读取和写入注册表项，即使是低权限用户也可以。因此，通过在 HKCU\SOFTWARE\Classes\CLSID\ 中添加包含进程正在寻找的 DLL 的 COM ID 的注册表项，可以让此进程从此 WindowsApps 或 System32 文件夹之外加载 DLL。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeiab3sapwh3IibFZgGViatULQueialPIicU4YAtJs6MVF8NpFiciaqdUSYWAvg/640?wx_fmt=png&from=appmsg "")  
  
图 13 – CLSID 文件夹的权限 – 允许低权限用户访问   
  
因此，每次应用程序运行时，进程都会加载我们的 DLL，而不是“C:\Windows\System32\”中的系统版本。虽然这只是一个例子，但许多应用程序和 DLL 都容易受到此影响，因为应用程序首先会查看注册表的 HKCU 部分。    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeUKWCUvSOyOUZXxWcP6OXIBqwPYDDF5gN9Ficia1moP7sZ7N9aN3rL08w/640?wx_fmt=png&from=appmsg "")  
  
图 14 – OLK.exe 成功查询 HKCU COM 对象   
  
从下图可以看出，这种方法有效，我们可以强制新版本的 Outlook 加载我们的 DLL。虽然我们只披露了存储在锁定的 WindowsApp 文件夹中的这些新应用程序，但这个问题实际上更为普遍，影响了许多其他应用程序。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZemJUROAWPV1KtGKMHiaVKgESNHV0sfuApgpd1MTk3ZYsmibGTQbrSF4Jw/640?wx_fmt=png&from=appmsg "")  
  
图 15 – 加载我们的 DLL，弹出一个消息窗口   
  
为了扩大范围，我们可以再次使用进程监视器，过滤以仅查找以“HKCU”开头的任何 RegOpenKey 操作，结果是“未找到名称”。通过监视这一点，我们可以看到哪些其他应用程序在 HKCU 中寻找我们可以劫持的 COM 对象。在几个小时的监视过程中，我们发现许多 Windows 系统原生的应用程序依赖于查询这些 COM 对象来加载 DLL。    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZe3F29Lb0FX8t7eVoyS0m2TuoGPNg0vOy87hVAmYqVzBiauOXiaqC2P7ZQ/640?wx_fmt=png&from=appmsg "")  
  
图 16 – 进程监视器显示其他进程执行相同行为    
  
借助此详尽的 COM 对象 UUID 列表和上述步骤，我们可以创建许多不同的 POC DLL，这些 POC DLL 映射到不同的 DLL。通过在企业中通常包含大量应用程序的端点注册表的 HKCU\SOFTWARE\Classes\CLSID\ 部分中部署这些 DLL 和注册表项，我们可以观察到哪些其他应用程序加载了这些 DLL。结果是本机 Windows 和其他应用程序的数量甚至更多。我们可以通过监视包含我们的 POC DLL 的文件夹中的任何加载图像操作来查看这一点。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZeAN7Ussg0TxrLHtafhtYOk8QUQzib7t8VkTnib9ggycupVRoMg2XFc5fQ/640?wx_fmt=png&from=appmsg "")  
  
图 17 – 加载我们的 POC DLL 的进程   
  
**付诸行动**  
  
现在，编译和设置这些 DLL 的过程可能有点艰巨，因此我创建了一个名为 FaceDancer 的工具来帮助自动化此过程。在下面的示例中，我将选择仅针对进程 msedge。使用我选择的任何 DLL 有效负载（在本例中，我使用的是 Cobalt Strike 生成的 vanilla DLL - 没有规避），我都可以将其输入到此工具中，它将为我生成以下内容：   
- 我需要更新的注册表项设置。   
  
- 将代理使用 COM 加载的 DLL 的执行的 DLL。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZenjGY25AbzuiaplIavdUpAFDhRaPzq6TXQibNdiaNRsHAs9YLnH1yyvDkw/640?wx_fmt=png&from=appmsg "")  
  
图 18 – FaceDancer 生成 DLL   
  
一旦设置了注册表项，执行新的 msedge.exe 实例只是时间问题：   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZebLqW64xE6HibuKS8sHmDw5oQ1pYqhicxibJiac8RVDv3onu4kb8tMXyPJA/640?wx_fmt=png&from=appmsg "")  
  
图 19 – Msedge 加载我们的 DLL   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taemwJKicjCw53NuR5L6eRPZehvcDtfq4blnibFv8hzoIKJrD7kMQM40icRKpS9yuknXnovsOsWXKG9Qw/640?wx_fmt=png&from=appmsg "")  
  
图 20 – 我们的 DLL 使用 Cobalt Strike 进行调用   
  
**微软的第二次回应**  
  
我们再次联系微软，强调这些问题的重要性。微软的回应如下：   
  
“经审查，此漏洞不符合 MSRC 服务的任何 DLL 植入问题类别。攻击者若要利用此漏洞在计算机上执行代码，他们必须已在计算机上执行代码”   
  
这是什么意思？微软不承认这些问题符合他们认为的 DLL 劫持的要求。微软有自己的术语，称为 DLL 植入，涵盖植入/劫持/预加载 DLL 攻击。他们主要在以下情况下将其视为 DLL 植入：   
- 应用程序从不安全的位置搜索并加载 DLL。   
  
- DLL 不在应用程序所需的目录中，导致 Windows 搜索其他目录。   
  
- 攻击者可以将恶意 DLL 放置在合法 DLL 之前搜索的目录中。   
  
截至目前，微软不会采取补救措施或措施来缓解此问题。这对企业意味着什么？不幸的是，这些漏洞将永远存在，直到微软改变主意，不再认为这些漏洞值得修复。由于这些进程是 Windows 和其他应用程序（如 Outlook 和 Teams）的原生进程，而这些应用程序是日常业务的关键部分，因此防御者无法阻止这些应用程序。由于所有这些原因，唯一可以部署的防御措施是基于检测的。    
  
**披露时间表**  
  
4 月 17日– 向微软披露第一个发现。   
  
4 月 25日——收到微软的以下回复，称这是一个有效的零日漏洞，但不会修复它。   
  
4 月 26日——要求审查他们的立场并提供更多信息。   
  
4 月 26日——收到消息称不会采取进一步行动，也不会发生 CVE 认可。    
  
7 月 24日-向微软披露第二个发现。   
  
8 月 1 日——案件结案。   
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
