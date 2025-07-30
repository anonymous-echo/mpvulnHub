#  同步漏洞行动：“ Lazarus 高级持续性威胁组织”再次故技重施   
原创 Kaspersky  卡巴斯基威胁情报   2025-04-25 06:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTEL7bRhRR4X2ic03VHicVozUSFXRyYOhic6yL5wgv0t7v9Zf4s7T8FKFdA/640?wx_fmt=png&from=appmsg "")  
  
  
自去年 11 月以来，我们一直在跟踪 Lazarus 组织的最新攻击活动，因为它以韩国的组织为目标，将水坑策略与韩国软件中的漏洞利用巧妙结合。这项被称为“SyncHole 行动”的活动已经影响了韩国软件、IT、金融、半导体制造和电信行业的至少六个组织，我们相信还有更多公司实际上受到了威胁。我们立即采取行动，向韩国互联网与安全局（KrCERT/CC）传达有意义的信息，以便在检测到后立即采取行动，我们现在已经确认此活动中被利用的软件已经全部更新到补丁版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTR8ZCxw1icibibqW8tdZpQy7ciceGY2tOoDkWv064dvYFD6Og2jkIpgVLew/640?wx_fmt=png&from=appmsg "")  
  
  
**行动时间表**  
  
  
**我们的发现概括如下：**  
  
• 至少有 6 个韩国组织受到水坑攻击以及 Lazarus 组织对漏洞的利用。  
  
• Innorix Agent 中的单日漏洞也被用于横向移动。  
  
• Lazarus 的恶意工具变体，如 ThreatNeedle、Agamemnon downloader、wAgent、SIGNBT 和 COPPERHEDGE，被发现具有新功能。  
  
**背 景**  
  
  
最初的感染是在去年 11 月发现的，当时我们检测到 ThreatNeedle 后门的变体，这是 Lazarus 集团的旗舰恶意工具之一，用于攻击一家韩国软件公司。我们发现该恶意软件在合法SyncHost.exe进程的内存中运行，并且是作为韩国开发的合法软件 Cross EX 的子进程创建的。这可能是韩国另外五个组织入侵的起点。此外，根据 KrCERT 网站上最近发布的安全公告，Cross EX 中似乎最近修补了漏洞，这些漏洞已在我们的研究时间范围内得到解决。  
  
在韩国的互联网环境中，网上银行和政府网站需要安装特定的安全软件，以支持反键盘记录和基于证书的数字签名等功能。但是，由于这些软件包的性质，它们不断在后台运行以与浏览器交互。Lazarus 组织表现出对这些细节的深刻理解，并正在使用针对韩国的策略，将此类软件中的漏洞与水坑攻击相结合。韩国国家网络安全中心在 2023 年发布了自己的针对此类事件的安全建议，并与英国政府合作发布了额外的联合安全建议。  
  
Cross EX 旨在允许在各种浏览器环境中使用此类安全软件，并且使用用户级权限执行，除非在安装后立即执行。尽管 Cross EX 被利用来传播恶意软件的确切方法尚不清楚，但我们认为攻击者在利用过程中提升了他们的权限，因为我们确认该过程在大多数情况下以高完整性级别执行。下面的事实使我们得出结论，Cross EX 软件中的漏洞很可能在此次作中被利用。  
  
• 事件发生时最新版本的 Cross EX 已安装在受感染的 PC 上。  
  
• 我们在目标组织中观察到的源自 Cross EX 流程的执行链都是相同的。  
  
• Synchost 进程被滥用以注入恶意软件的事件集中在短时间内：2024 年 11 月至 2025 年 2 月之间。  
  
在此次行动的最早攻击中，Lazarus 组织还利用了另一个韩国软件产品 Innorix Agent，利用漏洞促进横向移动，从而能够在他们选择的目标主机上安装其他恶意软件。他们甚至开发了恶意软件来利用这一点，避免重复性任务并简化流程。被利用的软件 Innorix Agent（版本 9.2.18.450 及更早版本）之前曾被 Andariel 集团滥用，而我们获得的恶意软件则针对最新版本 9.2.18.496。  
  
在分析恶意软件的行为时，我们在 Innorix Agent 中发现了一个额外的任意文件下载零日漏洞，我们设法在任何威胁行为者将其用于攻击之前检测到该漏洞。我们向韩国互联网与安全局（KrCERT）和供应商报告了这些问题。此后，该软件已使用修补版本进行了更新。  
  
通过韩国独家开发的软件漏洞安装恶意软件是 Lazarus 集团针对韩国实体战略的关键部分，我们之前在 2023 年披露了类似的案例，ESET 和 KrCERT 也是如此。  
  
**初始传播途径**  
  
  
当目标系统的用户访问多个韩国在线媒体网站时，感染就开始了。在访问一个特定站点后不久，该机器就遭到了 ThreatNeedle 恶意软件的入侵，这表明该站点在后门的初始交付中发挥了关键作用。在分析过程中，发现受感染的系统正在与可疑的 IP 地址通信。进一步检查发现，该 IP 托管了两个域 （T1583.001），这两个域似乎都是使用公开可用的 HTML 模板匆忙创建的汽车租赁网站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTpicibWydxxwI5niaLD2v5TibASLT2zXmxUq2C712ewDvic51CpSy08HvDOQ/640?wx_fmt=png&from=appmsg "")  
  
**www.smartmanagerex 的出现[.]com**  
  
  
第一个域 www.smartmanagerex[.]com 似乎伪装成由分发 Cross EX 的同一供应商提供的软件。根据这些发现，我们重建了以下攻击场景。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTXQWQAzBLtDTnD6WaubsozvTd2rkoOMAMzbCT2Wib1Z1hBiav7EWF0ZPw/640?wx_fmt=png&from=appmsg "")  
  
**初始入侵期间的攻击流**  
  
  
鉴于大量用户通常非常频繁地访问在线媒体网站，Lazarus 组使用服务器端脚本过滤访问者，并将所需目标重定向到攻击者控制的网站 （T1608.004）。我们以中等置信度评估重定向的站点可能已执行恶意脚本 （T1189），针对目标 PC 上安装的 Cross EX （T1190） 中的潜在缺陷，并启动恶意软件。然后，该脚本最终执行了合法SyncHost.exe，并注入了一个 shellcode，将 ThreatNeedle 的变体加载到该进程中。这条链以恶意软件被注入SyncHost.exe结束，在我们确定的所有受影响组织中都是通用的，这意味着 Lazarus 组织在过去几个月中使用相同的漏洞和漏洞对韩国进行了广泛的行动。  
  
**执行流程**  
  
  
我们根据所使用的恶意软件将此作分为两个阶段。第一阶段主要关注涉及 ThreatNeedle 和 wAgent 的执行链。然后是第二阶段，涉及使用 SIGNBT 和 COPPERHEDGE。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicT9ljE6yicPXuqpR7gGiczbQvlBLz4SU1kUQBficqyLo0nCr3aicL2C0uyag/640?wx_fmt=png&from=appmsg "")  
  
  
根据这些阶段，我们从至少 6 个受影响的组织中得出了总共四个不同的恶意软件执行链。在第一个感染案例中，我们发现了 ThreatNeedle 恶意软件的变体，但在随后的攻击中，SIGNBT 恶意软件取而代之，从而启动了第二阶段。我们认为，这是因为我们对第一个受害者采取了迅速而积极的行动。在随后的攻击中，Lazarus 组织引入了包括 SIGNBT 在内的三个更新的感染链，我们观察到目标范围更广，攻击更频繁。这表明该组织可能已经意识到他们精心准备的攻击已经暴露，并从那时起广泛利用了该漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicT02A5dYXmct9V1teHicvZLek8eugDAswsUVExBfsm86eRib38RwHXQamQ/640?wx_fmt=png&from=appmsg "")  
  
**此次行动中的感染链条**  
  
  
**第一阶段恶意软件**  
  
  
在第一个感染链中，使用了 Lazarus 组织以前使用的恶意软件的许多更新版本。  
  
**ThreatNeedle 的变体**  
  
  
此活动中使用的 ThreatNeedle 示例在 ESET 发表的一篇研究论文中也称为“ThreatNeedleTea”;我们相信这是早期 ThreatNeedle 的更新版本。但是，此攻击中看到的 ThreatNeedle 已被修改为附加功能。  
  
此版本的 ThreatNeedle 分为 Loader 和 Core 示例。核心版本从 C_27098.NLS 检索 5 个配置文件到 C_27102.NLS，总共包含 37 个命令。同时，Loader 版本仅引用两个配置文件，并且仅实现四个命令。  
  
Core 组件从 C2 接收特定命令，从而创建一个额外的加载程序文件以实现持久性。此文件可以伪装成 netsvcs 组 （T1543.003）、IKEEXT 服务 （T1574.001） 中合法服务的 ServiceDLL 值，也可以注册为安全服务提供商 （SSP） （T1547.005）。它最终会加载 ThreatNeedle Loader 组件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicT5SVp3kSqiceR3O1I8JGhRJ6aIJ0nvkEMRwPl1vBDh7Mia2jedBdSMO0g/640?wx_fmt=png&from=appmsg "")  
  
**目标服务加载 ThreatNeedle Loader 的行为流程**  
  
  
更新后的 ThreatNeedle 基于 Curve25519 算法（T1573.002）生成一个随机密钥对，将公钥发送到 C2 服务器，然后接收攻击者的公钥。最后，生成的私钥和攻击者的公钥经过标量作以创建共享密钥，然后将其用作 ChaCha20 算法加密数据的密钥 （T1573.001）。数据以 JSON 格式发送和接收。  
  
**LPEClient 公司**  
  
  
LPEClient 是一种以受害者分析和有效载荷交付 （T1105） 而闻名的工具，以前在对国防承包商和加密货币行业的攻击中观察到过。我们披露，当我们首次记录 SIGNBT 恶意软件时，该工具已由 SIGNBT 加载。但是，我们没有观察到 LPEClient 在此活动中由 SIGNBT 加载。它仅由 ThreatNeedle 的变体加载。  
  
**wAgent 的变体**  
  
  
除了 ThreatNeedle 的变体外，在第一个受影响的组织中还发现了 wAgent 恶意软件的变体。wAgent 是我们在 2020 年记录的一种恶意工具，KrCERT 在 Operation GoldGoblin 中也提到了类似的版本。它的创建起源仍然笼罩在谜团中，但我们发现 wAgent 加载程序伪装成 liblzma.dll 并通过命令行执行 rundll32.exe c：Programdataintelutil.dat， afunix 1W2-UUE-ZNO-B99Z （T1218.011）。导出函数检索 C：ProgramData 中给定的文件名 1W2-UUE-ZNO-B99Z，该文件名也用作解密密钥。将此文件名转换为宽字节后，它使用结果值的最高 16 字节作为 AES-128-CBC 算法的密钥，并解密 （T1140） 位于 C：ProgramData （T1027.013） 中的文件内容。解密数据的上四个字节随后表示有效负载 （T1027.009） 的大小，我们将其确定为 wAgent 恶意软件的更新版本。  
  
wAgent 的变体能够接收 form-data 和 JSON 格式的数据，具体取决于它成功访问的 C2 服务器。值得注意的是，它在通信期间 （T1071.001） 请求标头的 Cookie 字段中包含 __Host-next-auth-token 密钥，携带由随机数字附加的通信序列。在此版本中，新观察到的变化是采用开源 GNU 多精度 （GMP） 库来执行 RSA 加密计算，这是 Lazarus 组织使用的恶意软件中以前从未见过的库。根据 wAgent 配置文件，它被标识为 x64_2.1 版本。此版本使用 C STL 映射管理有效负载，重点是从 C2 接收额外的有效负载并将其直接加载到内存中，同时创建共享对象。有了这个对象，主模块就能够与交付的插件交换命令参数和执行结果。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTReDoyn3X9XmXowGVMZznfJ17Taib2lf3nGeB88Qj8By3cia4gmet4fAA/640?wx_fmt=png&from=appmsg "")  
  
**wAgent 变体的作结构**  
  
  
**Agamemnon 下载器的变体**  
  
  
Agamemnon 下载器还负责下载和执行从 C2 服务器接收的额外有效负载。虽然我们没有获取到阿伽门农的配置文件，但它从 C2 接收命令，并根据 ;;字符，用作命令和参数分隔符。通过 2 命令传递的 mode in response 的值决定了如何执行额外的负载，该负载与 3 命令一起提供。有两种执行方法：第一种是反射加载有效载荷 （T1620），这在恶意软件中常用，而第二种是利用开源 Tartarus-TpAllocInject 技术，我们以前在 Lazarus 组织的恶意软件中没有见过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTu99c0fg8a7K9HV8GhEV8sXxxFlnibLXnbGnlPOTWRVZ0edymFtTCH1w/640?wx_fmt=png&from=appmsg "")  
  
**传递附加数据的命令的结构**  
  
  
开源加载程序构建在另一个名为 Tartarus' Gate 的开源加载程序之上。Tartarus' Gate 基于 Halo's Gate，而 Halo's Gate 又基于 Hell's Gate。所有这些技术都旨在绕过安全产品，例如防病毒和 EDR 解决方案，但它们以不同的方式加载有效负载。  
  
**用于横向移动的 Innorix Agent 漏洞**  
  
  
与前面提到的工具不同，Innorix 滥用者用于横向移动。它由 Agamemnon 下载器 （T1105） 下载，并利用韩国开发的文件传输软件工具的特定版本 Innorix Agent 在内部主机上获取其他恶意软件 （T1570）。Innorix Agent 是韩国互联网环境中某些财务和管理任务所必需的另一种软件产品，这意味着它很可能安装在韩国公司和个人的许多 PC 上，任何具有易受攻击版本的用户都可能成为目标。该恶意软件嵌入了一个据称绑定到版本 9.2.18.496 的许可证密钥，该密钥允许它通过生成伪装成针对目标网络 PC 的合法流量的恶意流量来执行横向移动。  
  
Innorix 滥用者从 Agamemnon 下载器获得参数：目标 IP、下载文件的 URL 和文件大小。然后，它会向该目标 IP 发送请求，以检查 Innorix Agent 是否已安装并正在运行。如果返回成功的响应，则恶意软件会假定软件在目标主机上正常运行，并传输流量，由于缺少流量验证，目标可以从给定 URL 下载其他文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTmo1rA6TlCrftFAxsUnKRephibEI2eTyNwOnxo4Q7mBqVMue9xSX0Uiag/640?wx_fmt=png&from=appmsg "")  
  
**通过 Innorix 滥用者部署其他恶意软件的步骤**  
  
  
该行为者通过 Innorix 滥用者在同一路径中创建了一个合法的 AppVShNotify.exe 和一个恶意USERENV.dll文件，然后使用该软件的合法功能执行前者。结果，USERENV.dll 被侧载 （T1574.002），最终导致在目标主机上执行 ThreatNeedle 和 LPEClient，从而在以前未受影响的机器上启动感染链。  
  
由于 Innorix 滥用者的潜在危险影响，我们向 KrCERT 报告了此漏洞，但被告知该漏洞过去曾被利用和报告过。我们已确认，此恶意软件在使用 9.2.18.496 以外的 Innorix Agent 版本的环境中无法有效运行。  
  
此外，在深入研究恶意软件的行为时，我们发现了另一个适用于 9.2.18.538 及以下版本的其他任意文件下载漏洞。它被追踪为 KVE-2025-0014，我们还没有发现任何它在野外使用的证据。KVE 是 KrCERT 独家颁发的漏洞识别号。我们成功联系了 Innorix 通过 KrCERT 分享我们包含漏洞的发现，他们设法在 3 月份发布了一个修补版本，修复了两个漏洞。  
  
**第二阶段恶意软件**  
  
  
该行动的第二阶段还引入了以前在 Lazarus 攻击中发现的更新版本的恶意工具。  
  
**SIGNBT 公司**  
  
  
我们在 2023 年记录的 SIGNBT 是 1.0 版，但在这次攻击中，使用了 0.0.1 版。此外，我们还确定了更新的版本 SIGNBT 1.2。与 1.0 和 0.0.1 版本不同，1.2 版本的远程控制功能最少，专注于执行额外的有效载荷。恶意软件开发人员将此版本命名为“劫持”。  
  
在此作的第二阶段，SIGNBT 0.0.1 是在 SyncHost.exe 的内存中执行的初始植入程序，用于获取其他恶意软件。在此版本中，C2 服务器是硬编码的，没有引用任何配置文件。在本次调查中，我们发现了一个由 SIGNBT 0.0.1 获取的凭证转储工具，与我们在之前的攻击中看到的相同。  
  
对于版本 1.2，它从其资源中获取配置文件的路径，并检索该文件以获取 C2 服务器地址。我们能够从每个已识别的 SIGNBT 1.2 样本中提取两个配置文件路径，如下所示。SIGNBT 1.2 的另一个变化是，以 SIGN 开头的前缀数量减少到只有三个：SIGNBTLG、SIGNBTRC 和 SIGNBTSR。该恶意软件从 C2 接收 RSA 公钥，并使用该公钥加密随机生成的 AES 密钥。所有流量都使用生成的 AES 密钥进行加密。  
  
• 配置文件路径 1：C：ProgramDataSamsungSamsungSettingssettings.dat  
  
• 配置文件路径 2：C：ProgramDataMicrosoftDRMServerdrm.ver  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTXHRTM8krm8ORsRveB8GbcbDO7hxEB4Sxo5wGdibhFhBI1BCiahEI6OEw/640?wx_fmt=png&from=appmsg "")  
  
  
**COPPERHEDGE**  
  
  
COPPERHEDGE 是 US-CERT 于 2020 年命名的恶意工具。它是 Manuscrypt 的一个变体，主要用于 DeathNote 集群攻击。与此作中使用的其他恶意软件不同，COPPERHEDGE 没有太大变化，与旧版本相比，只有几个命令略有变化。但是，此版本从 ADS %appdata%MicrosoftInternet Explorerbrndlog.txt：loginfo （T1564.004） 检索配置信息，例如 C2 服务器地址。然后，恶意软件将 HTTP 流量发送到 C2，每个请求有 3 个或 4 个参数，其中参数名称是从三个名称中以任意顺序随机选择的。  
  
• 第一个 HTTP 参数名称：bih、aqs、org  
  
• 第二个 HTTP 参数名称：wib、rlz、uid  
  
• 第三个 HTTP 参数名称：tib、hash、lang  
  
• 第四个 HTTP 参数名称：ei、ie、oq  
  
该行为者主要使用 COPPERHEDGE 恶意软件在此次行动中进行内部侦察。在 COPPERHEDGE 后门内，共有 30 个命令从 0x2003 到 0x2032，以及 11 个响应代码从 0x2040 到 0x2050。  
  
  
**Lazarus 恶意软件的演变**  
  
  
近年来，Lazarus 组织使用的恶意软件一直在迅速发展，包括轻量级和模块化。这不仅适用于新添加的工具，也适用于过去使用过的恶意软件。几年来，我们已经观察到了这些变化，我们相信还会有更多变化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTSLThhyQX7ggNLSzad6ZAAAiaaRbxqc6BiaCSR2uL0NzibRDyaagwq07Fg/640?wx_fmt=png&from=appmsg "")  
  
  
**发 现**  
  
  
在调查此营销活动期间，我们对 Lazarus 集团的漏洞利用后策略有了广泛的了解。安装 COPPERHEDGE 恶意软件后，该行为者执行了大量 Windows 命令来收集基本系统信息（T1082、T1083、T1057、T1049、T1016、T1087.001），创建恶意服务（T1569.002、T1007）并试图寻找有价值的主机来执行横向移动（T1087.002、T1135）。  
  
在分析 actor 执行的命令时，我们能够识别出 actor 在使用 taskkill 命令时的错误：使用 taskkill 时的 /im 参数表示 imagename，它应该指定进程的镜像名称，而不是进程 ID。这表明 actor 仍在通过手动输入命令来执行内部侦察。  
  
  
**基础设施**  
  
  
在整个作过程中，大部分 C2 服务器都是合法但遭到入侵的韩国网站 （T1584.001），进一步表明该作高度集中在韩国。在第一阶段，其他媒体站点被用作 C2 服务器，以避免检测到媒体发起的水坑攻击。然而，随着感染链转向第二阶段，其他各个行业的合法网站也被利用。  
  
与其他情况不同，LPEClient 的 C2 服务器由与 www.smartmanagerex[.] 相同的托管公司托管。com 的 Alpha Thom 的 S S Thom S Thom 的 S鉴于 Lazarus 组织严重依赖 LPEClient 来提供额外的有效载荷，攻击者很可能故意租用和配置服务器 （T1583.003），分配一个由他们控制的域，以保持完全的作灵活性。除此之外，我们还发现，两个被用作 SIGNBT 0.0.1 的 C2 服务器的域解析为同一托管公司的 IP 范围。  
  
我们确认了域 thek-portal[.]com 在 2020 年之前属于韩国 ISP，并且是一家保险公司的合法域，该保险公司被另一家公司收购。从那时起，该域名一直被停放，其状态在 2025 年 2 月发生了变化，这表明 Lazarus 集团重新注册了该域名，以便在此次作中利用它。  
  
  
**归  因**  
  
  
在整个活动中，使用了几个恶意软件样本，我们通过长期持续和专门的研究，设法将其归因于 Lazarus 组织。恶意软件菌株的历史使用及其 TTP 支持了我们的归因，所有这些都已被众多安全解决方案供应商和政府详细记录。此外，我们还分析了 COPPERHEDGE 恶意软件提供的 Windows 命令的执行时间、我们上面描述的所有恶意样本的构建时间戳以及每台主机的初始入侵时间，表明时间范围主要集中在 GMT 00：00 和 09：00 之间。根据我们对各个时区正常工作时间的了解，我们可以推断出该 actor 位于 GMT 09 时区。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTGmx9XkTYq1zbwAYTPG4qfk8hN1nzlBzNxCan47afyibtia66fNibiaUI6g/640?wx_fmt=png&from=appmsg "")  
  
**恶意活动的时间线**  
  
**受 害 者**  
  
  
我们确定了韩国至少有 6 家软件、IT、金融、半导体制造和电信组织成为“SyncHole 行动”的受害者。但是，鉴于 Lazarus 在此次活动中利用的软件的受欢迎程度，我们相信在更广泛的行业中还有更多受影响的组织。  
  
**结 论**  
  
  
这不是 Lazarus 集团第一次在充分了解韩国软件生态系统的情况下利用供应链。我们已经在 2020 年 Bookcode 集群、2022 年 DeathNote 集群和 2023 年 SIGNBT 恶意软件的分析报告中描述了类似的攻击。所有这些案例都针对韩国供应商开发的软件，这些软件需要安装才能用于网上银行和政府服务。本案中利用的两种软件产品都与过去的案例一致，这意味着 Lazarus 集团正在无休止地采用基于级联供应链攻击的有效策略。  
  
预计 Lazarus 组织针对韩国供应链的专门攻击将在未来继续进行。我们过去几年的研究提供的证据表明，韩国的许多软件开发供应商已经受到攻击，如果产品的源代码遭到泄露，其他零日漏洞可能会继续被发现。攻击者还通过开发新的恶意软件或增强现有恶意软件来努力最大限度地减少检测。特别是，它们引入了与 C2 的通信、命令结构以及它们发送和接收数据的方式的增强功能。  
  
我们已经证明，准确的检测和快速响应可以有效地阻止他们的策略，同时，我们能够修复漏洞并减轻攻击，从而最大限度地减少损害。我们将继续监控该小组的活动，并保持敏捷地响应他们的变化。我们还建议使用可靠的安全解决方案来保持警惕并降低潜在风险。我们的企业产品线有助于在早期阶段识别和防止任何复杂的攻击。  
  
Kaspersky 产品通过以下判定检测此攻击中使用的漏洞和恶意软件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicT7au3erBNpG7QdO6ZYDicz6677otsSFfCCgqmNstfPYM839GFdQCiaw9A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BscvC1hbNBddwLiabU1a3Ghkd3xubFuicTL5g1tOia1o5iaSc15cJRH6K7haglRIhS8mbUJrq9UzXCbDKicGibo1qrKg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
