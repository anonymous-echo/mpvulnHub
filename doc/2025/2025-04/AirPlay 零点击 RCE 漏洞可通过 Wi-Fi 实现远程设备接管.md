#  AirPlay 零点击 RCE 漏洞可通过 Wi-Fi 实现远程设备接管   
会杀毒的单反狗  军哥网络安全读报   2025-04-30 01:01  
  
**导****读**  
  
  
  
苹果 AirPlay 协议中存在一个严重漏洞，称为 AirBorne，该漏洞导致超过 23.5 亿台活跃的苹果设备和数千万台第三方设备面临无需用户交互的远程代码执行 (RCE) 攻击。  
  
  
Oligo Security 研究人员发现，该漏洞允许同一Wi-Fi 网络上的攻击者劫持从 Mac 和 iPhone 到支持 CarPlay 的车辆和智能扬声器等设备。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFLQibeugtZ930jRGsNcwjiaibAkDGODkaE4b1PpbrFJaWzxqiaYfKuCxhygufHmbFxGiceLSBuia6EQslg/640?wx_fmt=png&from=appmsg "")  
  
  
Airborne 漏洞源于 Apple AirPlay 协议及其软件开发工具包 (SDK) 中的缺陷，第三方制造商可利用该工具包集成 AirPlay 兼容性。  
  
  
Oligo 发现了 23 个漏洞，其中 17 个已获得 CVE 编号，包括：  
  
  
CVE-2025-24252：macOS 的 AirPlay 实现中存在一个释放后使用漏洞，当与身份验证绕过 (CVE-2025-24206) 结合使用时，可以在设置为“同一网络上的任何人”的设备上启用零点击 RCE。  
  
  
CVE-2025-24132：AirPlay SDK 中基于堆栈的缓冲区溢出影响扬声器、电视和 CarPlay 系统，允许可蠕虫的零点击漏洞。  
  
  
CVE-2025-24271：访问控制列表 (ACL) 绕过允许攻击者发送未经身份验证的 AirPlay 命令，这些命令可以利用其他缺陷实现一键 RCE。  
  
  
这些漏洞利用了 AirPlay 对属性列表 (plists) 的处理方式，plists 是一种用于序列化命令的结构化数据格式。对 plist 参数的验证不当（例如假设所有输入都是字典）会导致类型混淆、内存损坏和任意代码执行。  
  
  
例如，通过/setProperty命令发送格式错误的 plist 会导致 ControlCenter 进程崩溃，而泛滥的 RTSPSETUP请求可能会导致 WindowServer 服务过载，从而强制注销用户。  
  
### 漏洞影响  
###   
  
攻击者可以在多种情况下利用 Airborne：  
  
  
启用 AirPlay 接收器的 Mac 和 iOS 设备（默认为“当前用户”）如果与 CVE-2025-24206 漏洞结合，容易受到零点击攻击。Oligo 演示了如何利用该漏洞覆盖 Apple 音乐应用中的内存，从而可能在网络中传播恶意软件。  
  
  
使用了存在漏洞的 SDK 的第三方扬声器和 CarPlay 设备同样面临风险。研究人员劫持了一款 Bose 扬声器，使其显示自定义徽标和音频。  
  
  
缓冲区溢出( CVE-2025-24132) 允许自我传播攻击。企业网络上受感染的设备无需用户交互即可感染其他设备，从而实现间谍活动或勒索软件的横向移动。公共 Wi-Fi 热点（例如机场内的热点）是大规模攻击的主要目标。  
  
  
超过 800 款配备无线 CarPlay 的车型容易受到基于近距离的攻击。如果车辆的 Wi-Fi 热点使用了弱密码，范围内的攻击者可以执行远程代码执行 (RCE) 来操纵信息娱乐系统，例如播放干扰性音频、追踪位置或通过内置麦克风窃听。蓝牙配对（需要输入 PIN 码）和 USB 连接也存在风险。  
  
### 苹果的回应和补丁状态  
###   
  
苹果已在 macOS Sequoia 15.4、iOS 18.4 和 AirPlay SDK 2.7.1/3.6.0.126 中发布了补丁来解决这些问题。  
  
  
然而，Oligo 警告称，由于更新机制碎片化，许多第三方设备可能永远无法获得补丁。  
  
  
Oligo 联合创始人 Gal Elbaz强调，“AirPlay 融入不同的生态系统意味着某些设备在未来几年内仍将处于脆弱状态”。  
  
  
为了尽量减少暴露：  
  
更新 Apple 设备：确保所有 Apple 产品都运行最新的操作系统版本。  
  
禁用 AirPlay 接收器：如果不使用，请在设置中关闭 AirPlay。  
  
网络强化：通过防火墙将端口 7000（AirPlay）限制于受信任的设备。  
  
警惕第三方SDK：联系制造商获取 SDK 更新并监控固件补丁。  
  
  
AirBorne 漏洞凸显广泛采用的协议中存在的系统性风险。随着苹果生态系统的扩张（截至 2025 年 1 月，活跃设备数量已达 23.5 亿台）以及第三方集成的激增，协调披露和快速修补至关重要。  
  
  
然而，未修补设备的广泛存在和工业环境中的使用寿命仍然是一个持续的挑战，凸显物联网开发中对主动安全框架的需求。  
  
  
苹果尚未报告主动利用漏洞的情况，但已确认漏洞的严重性，并敦促立即更新。对于企业，Oligo建议对网络进行分段，隔离支持AirPlay的设备，并审核连接的端点是否存在入侵迹象。  
  
  
漏洞公告详情：  
  
https://www.oligo.security/blog/airborne  
  
  
新闻链接：  
  
https://cybersecuritynews.com/airplay-zero-click-rce-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
