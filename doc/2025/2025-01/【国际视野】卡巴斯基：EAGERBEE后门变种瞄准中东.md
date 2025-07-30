#  【国际视野】卡巴斯基：EAGERBEE后门变种瞄准中东   
原创 天极智库  天极智库   2025-01-08 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/VIQiaGDYKHjO4QibH8Ziab3hNmpOibsKYJIVjWe14TF3icnWctJEbv8rvrKW3Okj4OIFFKvK3Gp9aIC8dadEWGiacEoQ/640?wx_fmt=gif "")  
  
  
“  
  
**天极按**  
  
  
近日，卡巴斯基发布对EAGERBEE后门调查的相关分析，详细分析了EAGERBEE 后门的功能，重点关注服务注入器、插件编排器模块和相关插件。同时还探讨了EAGERBEE 后门与CoughingDown 威胁组织的潜在联系。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlSEy7k4oG1S3LyzVdibPRVH93zdboxU9zBkVLb8vU8icPqE0UU6dmhoTg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlZkJ3qVplcjGLrYclZIRzjF8gJoHl3LF2c44ibJEP8nLDlxoLgLfQ9vw/640?wx_fmt=jpeg "")  
  
在最近对 EAGERBEE后门的调查中，发现中东地区的互联网服务提供商和政府机构正在部署该后门。相关的分析发现了这些攻击中使用的新组件，包括一个新颖的服务注入器，用于将后门注入运行中的服务。此外，还发现了在安装后门后部署的以前未记录的组件（插件）。这些插件支持一系列恶意活动，如部署附加有效载荷、探索文件系统、执行命令外壳等。主要插件可按其功能分为以下几组：插件编排器、文件系统操纵、远程访问管理器、进程探索、网络连接列表和服务管理。  
  
**初始感染与传播**  
  
  
  
遗憾的是，攻击者最初使用的访问载体仍不清楚。不过，观察到其执行命令部署了名为 “tsvipsrv.dll ”的后门注入程序和有效载荷文件ntusers0.dat，并使用SessionEnv服务运行注入程序，如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlZPoxCGU5gKdfmqDasHHrpkVQuXbpHfXBWXVBdarfLPUO3PN6dDCsHQ/640?wx_fmt=png&from=appmsg "")  
  
**恶意软件组件**  
  
  
  
**服务注入器**  
  
  
服务注入器以Themes服务进程为目标。它首先定位并打开进程，然后在其中分配内存，写入EAGERBEE后门字节（存储在C:\users\public\ntusers0.dat中）以及存根代码字节。存根代码负责解压缩后门字节并将其注入服务进程内存。  
  
为了执行存根代码，注入器会用服务进程内存中的存根代码地址替换原来的服务控制处理程序。然后通过向服务发送SERVICE_CONTROL_INTERROGATE控制代码来触发存根。存根执行完毕后，注入器将存根代码从服务内存中删除，并恢复原来的服务控制处理程序，从而完成清理工作。  
  
**EAGERBEE 后门**  
  
  
在受感染系统中发现的后门程序名为dllloader1x64.dll。它可以创建一个名称为mstoolFtip32W的互斥器（如果还不存在）。之后，它开始收集系统信息：本地计算机的NetBIOS名称、操作系统信息（主版本号和次版本号、构建号、平台标识符、产品套件信息以及系统上安装的最新Service Pack）、本地计算机操作系统的产品类型、处理器架构以及IPv4和IPv6地址列表。  
  
后门具有执行日期和时间检查功能。它将当前系统的日期和时间与硬编码字符串0-6:00:23;6:00:23;进行比较，其中数字的含义如下：  
  
- 0：一周的起始日；  
  
- 6：一周的结束日；  
  
- 00：起始小时；  
  
- 23：结束时间。  
  
  
  
  
  
如果执行日期和时间不匹配，它会休眠15 秒，然后再次检查。在我们看到的案例中，后门被配置为全天候运行。  
  
后门配置要么存储在C:\Users\Public\iconcache.mui中，要么硬编码在二进制文件中。如果存储在文件中，第一个字节将作为解码其余数据的XOR 密钥。如果是硬编码，则使用单字节XOR 密钥(0x57) 对配置进行解码。该配置包括命令与控制(C2) 主机名和端口。  
  
后门通过读取注册表Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer 来获取当前用户的代理主机和端口信息。如果有代理详细信息，后门会通过代理进行连接；否则会直接连接到C2 服务器。  
  
为了建立通信，后门程序会创建一个TCP 套接字，该套接字可在IPv4 和 IPv6上运行。如果 C2端口附加了 “s”，则会启动SSL 会话。根据配置，它可能会使用SCHANNEL 安全软件包，该软件包支持Windows 上的SSL 和 TLS加密。在这种模式下，它可以验证服务器凭据（被动模式）或使用本地客户端凭据来准备发送令牌（主动模式）。  
  
一旦建立连接，后门程序就会将先前收集的特定受害者详细信息传输到C2 服务器。服务器会响应一个字符串，后面是一个称为Plugin Orchestrator的有效载荷。如果响应字符串与后门中的硬编码值（对每个样本都是唯一的）相匹配，后门就会检索接收到的有效载荷中第一个导出方法的原始地址并调用它。值得注意的是，在此阶段，有效负载（Plugin Orchestrator）尚未映射到内存中。  
  
**插件编排器**  
  
  
EAGERBEE 后门下载的有效载荷是一个DLL 文件形式的插件编排器，内部名称为 “sssss.dll”，只导出一个方法： “m”. 如前所述，EAGERBEE不会将插件编排器 DLL直接映射到内存中。相反，它会检索 “m ”导出方法的原始地址并调用它。  
  
插件编排器 DLL的 “m ”方法负责将协调程序注入内存并随后调用其入口点。除了已经收集到的特定于受害者的数据外，插件编排器还收集并向C2 服务器报告以下额外信息：  
  
- 域的 NetBIOS 名称；  
  
- 物理内存和虚拟内存的当前使用情况；  
  
- 系统地域和时区设置；  
  
- Windows 字符编码；  
  
- 当前进程标识符；  
  
- 已加载插件的标识符。  
  
  
  
  
  
在传输此信息后，插件协调器还会报告当前进程是否拥有高级权限。然后，它会收集系统中所有运行进程的详细信息，包括：  
  
- 进程标识符；  
  
- 每个进程启动的执行线程数；  
  
- 父进程的标识符；  
  
- 每个进程可执行文件的完整限定路径。  
  
  
  
  
  
信息发送完毕后，插件协调器就会等待命令的执行。支持以下命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGliaiazslDWzLhrfJMgoJRcd8EM0Uic4UwmFg3Hj9txicZbxWCBFCmuIpuoA/640?wx_fmt=png&from=appmsg "")  
  
**插件**  
  
  
插件是DLL文件，使用序号导出三个方法。插件协调程序首先调用序号为3 的插件导出方法。该方法负责将插件DLL 注入内存。然后，协调器调用插件中序号为1 的导出方法，即DllMain方法。该方法使用所需的数据结构初始化插件。最后，它会调用序号为2 的插件导出方法。该方法实现插件的功能。  
  
所有插件都负责接收和执行来自协调器的命令。下面，我们将简要介绍所分析的插件以及每个插件支持的命令。  
  
**文件管理器插件**  
  
  
该插件可执行多种文件系统功能，包括：  
  
- 列出系统中的驱动器、文件和文件夹；  
  
- 重命名、移动、复制和删除文件；  
  
- 设置 ACL 以管理文件和文件夹权限；  
  
- 在系统中读写文件；  
  
- 向内存注入附加有效载荷。  
  
  
  
  
  
下表列出了它接受的命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlSLStT52vb9bOEPibMPqpN8pW6QKiczjDArZUzeIXKBgXv44EKxGEA9MA/640?wx_fmt=png&from=appmsg "")  
  
**进程管理器**  
  
  
该插件管理与进程相关的活动，例如：  
  
- 列出系统中正在运行的进程；  
  
- 启动新模块和执行命令行；  
  
- 终止现有进程。  
  
  
  
  
  
它接受四种命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlcSicMphibdU1NqDLbjciaFno8NrKZyfKh56KrpoB81IbmUPXCtdyOoekg/640?wx_fmt=png&from=appmsg "")  
  
**远程访问管理器**  
  
  
该插件可促进和维护远程连接，同时还提供命令shell 访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGltIG9KlFQBzKekTicBGKJEpYs8ANH09zYgYB3NpSIoTPOEJULMcJ9tWg/640?wx_fmt=png&from=appmsg "")  
  
攻击者通过向DllHost.exe 进程注入cmd.exe 来启动命令shell。威胁行为者执行了以下命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlxPS5KJ3X5WbbD10zoicBKotePRBPx2wtkQLYoGaMAMdpv0MPwaEvQicQ/640?wx_fmt=png&from=appmsg "")  
  
**服务管理器**  
  
  
该插件用于管理系统服务，包括安装、启动、停止、删除和列出服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlC4XH1UJ1TjYTBgSOOSHtaYMtRnC2QhSDuupOBMZKUC10vYQ4E3uRIg/640?wx_fmt=png&from=appmsg "")  
  
**网络管理器**  
  
  
该插件列出了系统中的网络连接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlib6ajymmEKA4icGoSGGwNcujNdxGZ5iaocIjax0hicLX48a8C4xMIeDhKA/640?wx_fmt=png&from=appmsg "")  
  
**归因**  
  
  
  
EAGERBEE 部署在东亚的多个组织中。其中两家企业通过Exchange 服务器中臭名昭著的ProxyLogon 漏洞(CVE-2021-26855) 遭到入侵，之后恶意webhell 被上传并用于在被入侵的服务器上执行命令。  
  
2023 年5月，遥测结果显示，在东亚的一个受影响组织中，有人执行了多个命令来启动和停止系统服务。攻击者滥用合法的Windows 服务MSDTC、IKEEXT和SessionEnv 来执行恶意DLL：oci.dll、wlbsctrl.dll和TSVIPSrv.dll。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGl5cEnU4dUrRDuMtXhb7PO2lKAQNn8xG2icNKJTiapqlycLHCrrarjicMDw/640?wx_fmt=png&from=appmsg "")  
  
根据遥测，由IKEEXT 和SessionEnv 服务加载和执行的DLL 本质上是加载器，可将EAGERBEE后门加载到内存中。另一家安全厂商也描述了针对日本组织的类似EAGERBEE加载器。下文提供了这些服务加载的文件示例。  
  
**IKEEXT**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlyVLd35EoXY7qKPUs4dgFbfUI1vfWFZI4gshTnxymDaPicAu8cqbn6og/640?wx_fmt=png&from=appmsg "")  
  
**SessionEnv**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGlfH2DHAVrExnicYVonfmGUXXuOeQaFwVAkia28PnSyMx4DK2D8v6QHKcA/640?wx_fmt=png&from=appmsg "")  
  
MSDTC 服务加载并执行了一个名为 “oci.dll ”的DLL 文件。通过分析该文件，确定它就是CoughingDown 核心模块。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VIQiaGDYKHjNJhZNdgxGFzGct8e1ILjGl15CMPFhJVyQbWvw4DWdgqoB1oQ1zYYCFN8aZAtAYvsicVT0lbOUnuuw/640?wx_fmt=png&from=appmsg "")  
  
发现了将EAGERBEE 后门与CoughingDown 小组联系起来的几条线索：  
  
1.根据卡巴斯基威胁归因引擎（KTAE），通过滥用合法的MSDTC 服务执行的上述DLL 之一oci.dll (MD5 f96a47747205bf25511ad96c382b09e8) 与CoughingDown 样本有25% 的匹配度。对该DLL 的分析表明，它是CoughingDown 于2020 年9月底开发的多插件恶意软件的核心模块，并且确实存在大量代码重叠（相同的RC4 密钥、相同的命令编号）。  
  
2.该核心模块被配置为使用IP 地址45.90.58[.]103 和185.82.217[.]164 作为其C2。据其他安全供应商报告，IP地址185.82.217[.]164 被用作EAGERBEE C2。  
  
  
  
**结论**  
  
  
  
随着威胁行为者开发出越来越复杂的恶意活动工具，恶意软件框架也在不断进步。EAGERBEE就是其中之一，它是一种主要在内存中运行的恶意软件框架。这种内存驻留架构增强了其隐身能力，帮助其躲避传统端点安全解决方案的检测。EAGERBEE还将恶意代码注入合法进程（如dllhost.exe），并在explorer.exe或目标用户会话的上下文中执行，从而掩盖其命令外壳活动。这些策略使恶意软件能够与正常系统操作无缝集成，大大增加了识别和分析的难度。  
  
在东亚EAGERBEE 攻击中，组织是通过ProxyLogon 漏洞渗透的。ProxyLogon仍然是攻击者最常用的一种漏洞利用方法，它可以在未经授权的情况下访问Exchange服务器。及时修补此漏洞对于确保网络边界安全至关重要。  
  
由于EAGERBEE 后门和CoughingDown 核心模块在同一天通过相同的webshell 持续创建服务来执行，而且EAGERBEE 后门和CoughingDown 核心模块之间的C2 域重叠，我们以中等可信度评估EAGERBEE 后门与CoughingDown 威胁组织有关。  
  
但是由于无法确定最初的感染载体，也无法确定负责在中东部署EAGERBEE 后门的组织。  
  
  
  
往  
期回顾  
  
[【国际视野】美国国家科学技术委员会发布《数据基础设施互联互通的框架》建议报告](https://mp.weixin.qq.com/s?__biz=MzIyMjQwMTQ3Ng==&mid=2247490876&idx=1&sn=ed83dccee59a436d93af72486c6a810d&scene=21#wechat_redirect)  
  
  
[【国际视野】美国问责局发布《人工智能：国土安全部需要改进关键基础设施部门的风险评估指南》](https://mp.weixin.qq.com/s?__biz=MzIyMjQwMTQ3Ng==&mid=2247490858&idx=1&sn=e225712b755d4cb1d15b667acb453971&scene=21#wechat_redirect)  
  
  
[【国际视野】欧盟发布《2024欧洲网络安全演习》事后报告](https://mp.weixin.qq.com/s?__biz=MzIyMjQwMTQ3Ng==&mid=2247490858&idx=2&sn=d5945685dc9fb61ee5e0a4a8df838fa0&scene=21#wechat_redirect)  
  
  
[【国际视野】欧盟发布《2024 年欧盟网络安全状况报告》](https://mp.weixin.qq.com/s?__biz=MzIyMjQwMTQ3Ng==&mid=2247490858&idx=3&sn=2e77199075787183a7e565de3e4ff181&scene=21#wechat_redirect)  
  
  
  
  
END  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC7keXcZBBPunwickxLjQps0ZRJtxp4yUgmSwGoS66VDw7raBczDs5Q8tWUiafiauiagic3CB6FTPTCNH6A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC7aAThYvAjffwYibQiccfATI6GO14iaBbMsb8nhtuKgCR0Nm8U8rIjiaW79UeAHgfB8WurIywfe5hBicAw/640?wx_fmt=png "")  
  
**天极智库**  
聚焦网络安全相关领域，聚集网络安全职能部门、行业主管部门、科研院所、相关企业和专家学者的力量，组织开展政策研判、事件分析、技术研究、学术交流，为国家网络安全工作提供支撑，增强国家网络空间安全防御能力，提升国家关键信息基础设施安全保障能力和水平。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC7aAThYvAjffwYibQiccfATI6EAQpU4NuLeSO8MtRr3Vpg3cNW60jVP0oEeHEr8lUXIz2HkCekcCOQQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/VIQiaGDYKHjO4QibH8Ziab3hNmpOibsKYJIVq4GptBvicOAVel6uVaamWuxyARD0QA9R4w15wXvHknfQTbXXLyFodkA/640?wx_fmt=gif "")  
  
  
