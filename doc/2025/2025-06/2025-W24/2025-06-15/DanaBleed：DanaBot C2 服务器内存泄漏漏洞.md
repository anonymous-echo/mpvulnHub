> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247530905&idx=3&sn=e213905f649075f85f3cb74fb755521a

#  DanaBleed：DanaBot C2 服务器内存泄漏漏洞  
 Ots安全   2025-06-15 06:08  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
本文详细探讨了“DanaBleed”——一种影响DanaBot恶意软件命令与控制（C2）服务器的严重内存泄漏漏洞。该漏洞源于2022年6月DanaBot版本2380的更新，意外导致C2服务器在响应受感染设备时泄露其进程内存片段，类似于2014年的Heartbleed漏洞。这一缺陷持续近三年，暴露了包括威胁行为者用户名、IP地址、私钥、受害者凭据等敏感信息，为研究人员提供了深入了解DanaBot内部运作的独特视角。DanaBot作为一款自2018年起活跃的恶意软件即服务（MaaS）平台，涉及银行欺诈和信息窃取等活动，感染超过30万台计算机，造成约5000万美元损失。文章还提到，2025年5月的“Operation Endgame”执法行动成功摧毁了DanaBot基础设施，并起诉了16名相关成员。通过技术分析，文章揭示了该漏洞源于Delphi编程语言中未初始化的TMemoryStream，导致每次服务器响应最多泄露1792字节的数据。本文由Zscaler的ThreatLabz发布，提供了对这一重大安全事件的全面见解。  
  
介绍  
  
DanaBot是一个恶意软件即服务 (MaaS) 平台，自 2018 年以来一直活跃。DanaBot 采用联盟模式运营，恶意软件开发者将访问权限出售给客户，客户随后分发并使用恶意软件进行凭证盗窃和银行欺诈等活动。开发者负责创建恶意软件、维护命令和控制 (C2) 基础设施以及提供运营支持。DanaBot 参与了多起备受瞩目的攻击活动，例如 对热门 NPM 软件包的 供应链攻击，以及在 2022 年俄罗斯入侵期间针对乌克兰国防部的 分布式拒绝服务 (DDoS)攻击。2025 年 5 月，作为“终局行动”持续努力的一部分，执法部门摧毁了 DanaBot 的基础设施，并起诉了 16 名与该组织有关联的个人。  
  
DanaBot 的一个漏洞直到最近才被公众所知，那 就是其 C2 服务器中存在一个导致内存泄漏的漏洞。2022 年 6 月，ThreatLabz 在野外发现了当时新版本的 DanaBot 恶意软件（版本 2380）。此更新对 C2 协议进行了更改，其中一项更改无意中导致 C2 服务器在响应受感染的受害者时泄露了其进程内存的片段。该内存泄漏堪比 2014 年的Heartbleed漏洞，它为发现该漏洞的人（包括 ThreatLabz）提供了对 DanaBot 内部运作的独特洞察。我们将此漏洞命名为 DanaBleed ，并在本篇博文中展示近三年来从内存泄漏中恢复的一些敏感信息。  
  
关键要点  
- DanaBot 是一个恶意软件即服务平台，于 2018 年出现，具有多种功能，可用于促进银行欺诈、信息盗窃和提供远程访问。  
  
- 该平台已被用于从银行欺诈到间谍活动等各种目的。2022年6月至2025年初，DanaBot命令与控制（C2）服务器中的编程错误导致了内存泄漏。  
  
- 泄露的信息包括：威胁行为者用户名、威胁行为者 IP 地址、后端 C2 服务器 IP 地址和域、感染和泄露统计数据、恶意软件版本更新、私人加密密钥、受害者 IP 地址、受害者凭证以及其他泄露的受害者数据。  
  
- 2025 年 5 月，“终局行动”摧毁了 DanaBot 基础设施，并起诉了该组织的 16 名成员。  
  
技术分析  
  
DanaBleed 内存泄漏始于 2022 年 6 月 DanaBot 版本 2380 发布，并持续到 2025 年初。  
  
DanaBleed漏洞分析  
  
DanaBot 使用 Delphi 编程语言编写，并使用自定义二进制 C2 协议。2022 年 6 月版本更新之前的 C2 请求概述如下：  
1. 生成命令数据（例如密钥交换、系统信息信标、配置文件下载、附加有效载荷下载、新的 C2 信息等）  
  
1. 使用会话密钥加密数据  
  
1. 加密会话密钥  
  
1. 生成基本标题  
  
1. 发送标头和加密数据  
  
2022 年 6 月，恶意软件开发人员引入了一种新的 C2 协议，该协议修改了请求以执行以下步骤：  
- 生成命令数据（例如密钥交换、系统信息信标、配置文件下载、附加有效载荷下载、新的 C2 信息等）  
  
- 表面上附加随机生成的字节（尽管它们不是随机的）  
  
- 使用会话密钥加密数据  
  
- 加密会话密钥  
  
- 发送加密数据长度和数据  
  
C2 服务器向受害者发出的响应使用了与恶意软件本身相同的逻辑，并且很可能使用了相同的底层代码。这种重叠使我们能够对该漏洞进行逆向工程，并推断出 C2 服务器内存泄漏的工作原理。  
  
下图说明了 2022 年 6 月更新中引入的 C2 协议的更改：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3n07nQibVicZvKo3kEicEdvLiaDHibd5omHAFt4icFcQdUkMvuwU5wJ12WrgHg/640?wx_fmt=webp&from=appmsg "")  
  
图 1：2022 年 6 月更新中 DanaBot 引入的 C2 协议更改概览。  
  
DanaBot 的命令数据存储在 Delphi TMemoryStream 中。系统会生成一个随机数（上限为 1,792），用于确定要添加到命令数据缓冲区的填充字节数。虽然缓冲区的大小有所增加，但缓冲区内新分配的内存并未 初始化。乍一看，这部分未初始化的内存似乎是随机的，但仔细检查后发现，它包含 C2 服务器进程内存的任意片段。内存处理方面的这种疏忽导致了 DanaBot 漏洞，从而暴露了该组织敏感的内部数据。  
  
内存泄漏暴露的数据  
  
内存泄漏导致每个 C2 服务器响应最多暴露 1,792 字节。泄漏数据的内容是任意的，取决于特定时间在 C2 服务器进程中执行的代码和操作的数据。尽管如此，我们对泄漏数据的检查使我们能够在近三年的时间里对 DanaBot 进行深入分析。  
  
一些最有趣的泄露信息揭示了与 C2 服务器 Web 界面相关的 HTML 代码片段。下图（已添加高亮显示）提供了这些泄露元素的示例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nbc2y111gpZjVx0A5LyYxnuU6ZgxiahicO0D8bIP2Od4lgHRave8BjYibw/640?wx_fmt=webp&from=appmsg "")  
  
图 2：DanaBot C2 服务器泄露的 HTML 代码示例。  
  
这些 HTML 片段可以与下图（添加了突出显示）进行比较，其中包括来自视频广告 DanaBot 的屏幕截图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nur19xriaicvNb4icTMX7AOzXU0xaQA4cQY4ojibIIluqMLoqjQmOT0T06g/640?wx_fmt=webp&from=appmsg "")  
  
图 3：DanaBot 广告视频的屏幕截图，其内容与 C2 服务器内存泄漏中观察到的数据类似。  
  
内存泄漏暴露了敏感数据，包括：   
- 威胁行为者的用户名和 IP 地址  
  
- 后端 C2 服务器 IP 地址和域名  
  
- 感染和泄露统计数据  
  
- 恶意软件版本更新信息  
  
- 私人加密密钥  
  
- 受害者相关数据，例如 IP 地址、凭证和泄露的信息  
  
DanaBot 开发人员维护了更新日志，其中一些更改也被泄露，如下图所示（添加了突出显示）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nQyy2sadZicxWqia1icz7sEoggaYhEicUrdVEA67PV4Iaywjo5YfpDYcHGA/640?wx_fmt=webp&from=appmsg "")  
  
图 4：在 DanaBot C2 服务器内存泄漏中发现的示例更改日志。  
  
除了 HTML 代码片段外，内存泄漏还暴露了调试信息，包括路径名和日志消息。如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nDickTqr7icV8WGGkdFR5cZTKiaZdc7BYz2dtQLahFfRKELEDh2fTuTmDQ/640?wx_fmt=webp&from=appmsg "")  
  
图 5：DanaBot C2 服务器内存泄漏中识别的示例调试信息。  
  
另一种常见的泄漏类型涉及 SQL 语句。这些泄漏提供了有关 C2 服务器数据库结构的宝贵信息，包括恶意软件 MD5 哈希值、版本更新和受害者 IP 地址等信息。下图（已添加高亮显示）提供了此类泄漏的示例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nqLDjZg0jOkrBhXfycyexEeQeel778xpP0zOBibqbIibtXMQYPdmGgpGg/640?wx_fmt=webp&from=appmsg "")  
  
图 6：DanaBot 的 C2 服务器泄露的示例 SQL 语句。  
  
内存泄漏还暴露了私有加密密钥材料，如下图所示（突出显示）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nvHFSsLXLv3jqGnrJp81IMx5rYt1lMicyMr7HEUicLGWM9hrpgvqVcxPg/640?wx_fmt=webp&from=appmsg "")  
  
图 7：私钥材料泄漏示例。  
  
最后，由于 DanaBot 主要充当信息窃取者，内存泄漏还暴露了大量受害者凭证和其他被窃取的数据。  
  
结论  
  
DanaBot C2 服务器协议在 2022 年 6 月更新中发现的内存泄漏，让 ThreatLabz 和其他研究人员得以一窥 DanaBot 的内部运作。通过分析未初始化 C2 服务器内存泄漏随时间的变化，我们获得了有关 DanaBot 背后的基础设施、流程和威胁参与者的宝贵见解。泄露的信息揭示了从后端服务器数据、调试日志、SQL 语句和加密密钥材料到敏感受害者数据以及 C2 服务器 Web 界面元素的所有内容。目前判断“终局行动”对 DanaBot 的长期影响还为时过早，但 ThreatLabz 将继续跟踪该组织及其附属组织（如果它们再次出现）的活动。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
