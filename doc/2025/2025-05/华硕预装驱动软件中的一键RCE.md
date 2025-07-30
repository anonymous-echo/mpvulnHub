#  华硕预装驱动软件中的一键RCE   
 Ots安全   2025-05-12 03:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
介绍  
  
这个故事始于有关新 PC 零件的对话。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf1GS6omqbBn4UzgLNbPqgTls26w7FvmiaOdVRbicwibbJMiaGicialaUJs30krjmYrPpickVPkMX1kzCwpg/640?wx_fmt=png&from=appmsg "")  
  
不顾朋友的建议，我买了一块新的华硕主板。我有点担心BIOS会默认在后台默默地安装软件到我的操作系统里。不过这个功能可以关掉，所以我想干脆就关掉吧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf1GS6omqbBn4UzgLNbPqgTIa7PEHR9JQbYHaSWGjo7WCVzwTdUtRfUnxUwMIGS66UqDZ3P8pWpEQ/640?wx_fmt=png&from=appmsg "")  
  
登录 Windows 后，我立即收到一条通知，要求管理员权限才能完成 ASUS DriverHub 的安装，因为我忘记更改 BIOS 选项了。反正我得给主板装个 WiFi 驱动程序，所以出于好奇，我安装了它。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf1GS6omqbBn4UzgLNbPqgTwjj8qOCAGrzgmr1Mo9ZGFL4hy4CV9EcQN3TVrxJoYOvfCMJ7WQruMA/640?wx_fmt=png&from=appmsg "")  
  
我没有 DriverHub 的截图，但它在我的屏幕右下角弹出了与此完全相同的窗口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf1GS6omqbBn4UzgLNbPqgTCRiacDt8ysiaSzibEKyqAQkRqcd3k9cicDLEHFxXdOsictGqXvFib7HDffbQ/640?wx_fmt=png&from=appmsg "")  
  
DriverHub 是一款有趣的驱动软件，因为它没有任何图形用户界面 (GUI)。它只是一个后台进程，负责与driverhub.asus.com网站通信，并告诉你系统需要安装哪些驱动程序以及哪些驱动程序需要更新。我自然想知道这个网站是如何知道我的系统需要哪些驱动程序以及如何安装它们的，于是我打开了 Firefox 的网络选项卡。  
  
正如我所料，该网站使用 RPC 与系统上运行的后台进程通信。后台进程在本地托管一个 HTTP 或 Websocket 服务，网站或服务可以通过127.0.0.1向预定义端口（在本例中为 ）发送 API 请求来连接该服务53000。  
  
就在此时，我的精英黑客意识开始活跃起来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rWGOWg48taf1GS6omqbBn4UzgLNbPqgTKmA8YNAssY1ILsqvkRIsf4wJCXg3019CjIc5dLj0ZtmQTXz21WkudQ/640?wx_fmt=gif&from=appmsg "")  
  
这是一种设计驱动程序管理软件的非常粗略的方法。如果 RPC 没有得到妥善保护，攻击者可能会利用它安装恶意应用程序。  
  
寻找漏洞  
  
下一步是看看我是否可以从任何网站调用 RPC，这是通过将浏览器中的请求复制为 curl 命令并将其粘贴到我的终端来复制的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf1GS6omqbBn4UzgLNbPqgT7d0LN6b5Dcm9CiauacxNT7jGIrsa7c7Z2vwoiaGD2mHiaic11qDYicNaEPQ/640?wx_fmt=png&from=appmsg "")  
  
在尝试了一段时间的命令变体后，我的假设得到了证实。DriverHub 仅响应将源标头设置为“driverhub.asus.com”的请求。所以至少这个软件还没有被完全破解，恶意黑客也不能随意向 DriverHub 发送请求。  
  
然而我还没完，大概程序会检查源是否是driverhub.asus.hub，如果是，就会接受 RPC 请求。接下来我查看程序是直接比较，origin == driverhub.asus.hub还是通配符匹配，例如origin.includes("driverhub.asus.com")。  
  
当我将原点切换到时driverhub.asus.com.mrbruh.com，它允许了我的请求。  
  
现在显然存在着严重的威胁。下一步是确定可能造成的损失有多大。  
  
损害程度  
  
通过仔细检查网站上的 Javascript 以及 exe 生成的大约 70 万行反编译代码，我成功创建了一个可调用端点列表，其中包括 exe 中一些未使用的端点。  
- 初始化 该命令用于网站检查软件是否安装，并返回基本的安装信息。  
  
- DeviceInfo 这将返回所有已安装的 ASUS 软件、所有已安装的 .sys 驱动程序、所有硬件组件以及您的 MAC 地址。  
  
- 重新启动 这将立即重新启动目标设备，无需确认。  
  
- 日志 这将返回所有 DriverHub 日志的压缩副本。  
  
- InstallApp 此命令通过 ID 安装应用程序或驱动程序。所有应用程序的 ID 都硬编码在 DriverHub 安装程序提供的 XML 文件中。  
  
- UpdateApp 此程序使用提供的文件 URL 下载并运行，自行更新 DriverHub。  
  
实现 RCE  
  
出于显而易见的原因，我对 UpdateApp 端点非常着迷。因此，我花了几个小时研究 Ghidra 中的代码，并用各种 curl 请求对其进行测试，以了解其复杂的行为机制。  
  
对端点的请求如下所示：  
  
```
curl "http://127.0.0.1:53000/asus/v1.0/UpdateApp" -X POST --data-raw '{"List": [{"Url": "https://driverhub.asus.com/<app.exe>"}]}'
```  
  
  
以下是我当时对 UpdateApp 功能的观察。  
- “Url”参数必须包含“.asus.com”，但与 RPC 来源检查不同，它允许以下愚蠢的行为example.com/payload.exe?foo=.asus.com  
  
- 它使用 URL 末尾指定的文件名保存文件。  
  
- 可以下载任何具有任何扩展名的文件  
  
- 如果该文件是华硕签名的可执行文件，它将自动以管理员权限执行  
  
- 它将运行任何由 ASUS 签名的可执行文件，而不仅仅是 DriverHub 安装程序。  
  
- 如果下载的文件未通过签名检查，则不会被删除。  
  
当我了解到 DriverHub 验证可执行文件的签名时，我怀疑 RCE 可能不再可能，但无论如何我还是坚持了下来。  
  
我首先想到的可能是定时攻击。我告诉 DriverHub 安装一个有效的可执行文件，在它验证签名之后，但在安装该 exe 文件之前，我将其替换为一个恶意的可执行文件。我推测，这可以通过并行发出两个 UpdateApp 请求来实现，其中恶意更新紧接着合法更新。  
  
然而，定时攻击需要极其精确，而由于定时会受到需要下载的文件的影响，因此它是一个非常不可靠的选择。考虑到这一点，我决定退一步思考，看看是否还有其他选择。  
  
最后，我回到了一直想安装的独立 WiFi 驱动程序。该驱动程序包含在以下 zip 文件中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taf1GS6omqbBn4UzgLNbPqgTsmrFyVFQ3ZEVEuhibm0zLoSVXT9ufTmFSh7Kwk3ApBGlpyzs0b1dG4Q/640?wx_fmt=png&from=appmsg "")  
  
这里重要的文件是AsusSetup.exe、AsusSetup.ini和SilentInstall.cmd。执行 AsusSetup.exe 时，它首先读取 AsusSetup.ini 文件，其中包含有关驱动程序的元数据。我对该文件中的一个属性很感兴趣：SilentInstallRun。  
  
双击 AsusSetup.exe 时，它会启动一个简单的 GUI 安装程序。但是，如果您使用-s标志运行 AsusSetup.exe（DriverHub 会使用此标志调用它进行静默安装），它将执行SilentInstallRun 中指定的任何内容。在这种情况下，ini 文件指定了一个 cmd 脚本，用于执行驱动程序的自动无头安装，但它可以运行任何内容。  
  
以下是完整的漏洞利用链  
  
1.driverhub.asus.com.*访问带有子域名的网站  
  
2.网站向 UpdateApp 请求 PoC 可执行文件“calc.exe”  
- “calc.exe”将被下载，签名检查失败，无法执行  
  
3.网站向 UpdateApp 发出自定义 AsusSetup.ini 请求  
- 这也将被下载但不会执行  
  
```
[InstallInfo]
   SilentInstallPath=.\
   SilentInstallRun=calc.exe
```  
  
  
4.网站向 UpdateApp 请求已签名的 ASUS 二进制文件“AsusSetup.exe”  
- 这将以管理员权限下载并执行，并使用进行静默安装-s，这将导致它读取 AsusSetup.ini 文件并以管理员权限运行“SilentInstallRun”中指定的“calc.exe”  
  
PoC 实际操作：  
  
  
报告时间表（日/月/年）  
  
2025年7月4日——发现初始漏洞  
  
2025 年 8 月 4 日 - 将漏洞升级为 RCE  
  
2025 年 8 月 4 日——报告漏洞  
  
2025年9月4日 - 华硕自动回复  
  
2025 年 4 月 17 日 - 我跟进并得到了人工回复，告知我他们已经修补了软件，并向我发送了一个版本以供验证  
  
2025 年 4 月 18 日 - 华硕确认已修复  
  
2025 年 9 月 5 日——CVE-2025-3462 (8.4) 和CVE-2025-3463 (9.4) 发布  
  
评估损失  
  
在向华硕报告了远程代码执行漏洞后，我几乎立即编写了一个脚本来跟踪我的 VPS 上的证书透明度更新，以便查看是否有其他人driverhub.asus.com.*注册了该域名。通过查看其他网站的证书透明度日志，我发现域名和子域名通常会在一个月内出现在日志中。  
  
经过一个月的等待，我很高兴地说，我的测试域名是唯一符合正则表达式的网站，这意味着在我报告之前不太可能有人主动利用它。  
  
漏洞赏金  
  
我问华硕是否提供漏洞赏金。他们回复说不提供，但会把我的名字放进他们的 “名人堂”。这可以理解，因为华硕只是一家 小型初创公司，可能没有足够的资金来支付赏金。  
  
趣味笔记  
  
当我通过华硕的安全公告表单提交漏洞报告时，Amazon CloudFront将附件的 PoC 标记为恶意请求并阻止了提交。因此，我不得不删除部分 PoC 代码，并链接视频录像。  
  
如果您单击 DriverHub 中的“全部安装”，而不是手动单击每个推荐的驱动程序上的安装，它还将安装 ArmouryCrate、ASUS 定制的 CPU-Z、Norton360 和 WinRAR。  
  
他们对 RCE 的 CVE 描述有点误导。他们说“此问题仅限于主板，不影响笔记本电脑和台式电脑”，但这会影响任何安装了 DriverHub 的电脑，包括台式机/笔记本电脑。此外，他们没有说它允许任意/远程代码执行，而是说它“可能允许不受信任的来源影响系统行为”。  
  
我的板载 WIFI 还是不能用，我不得不买个外置 USB WIFI 适配器。真是太感谢 DriverHub 了。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
