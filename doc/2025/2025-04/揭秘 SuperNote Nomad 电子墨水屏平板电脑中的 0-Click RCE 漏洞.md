#  揭秘 SuperNote Nomad 电子墨水屏平板电脑中的 0-Click RCE 漏洞   
 Ots安全   2025-04-25 11:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
概述：  
  
去年，流行的 E-Ink 平板电脑供应商Ratta Software发布了SuperNote A6 X2 Nomad——一款运行 Android 11 的 7.8 英寸平板电脑。  
  
作为效率达人，我们在 2024 年 7 月入手了一台，原本打算用它来做笔记和阅读学术论文。然而，作为一个内心深处的黑客，我们花了整整 24 小时才彻底放弃了这个想法，决定尝试一下。  
  
编辑：此问题在发布后被编号为CVE-2025-32409。编辑：此问题在发布后被编号为CVE-2025-32409。编辑：此问题在发布后被编号为CVE-2025-32409。接下来是一篇博客文章，详细介绍了我们如何将一个漏洞和一些错误配置组合成一个可远程安装的零点击rootkit。与受害者位于同一网络上的恶意攻击者无需任何用户交互即可完全入侵目标设备。编辑：此问题在发布后被编号为CVE-2025-32409。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOB6qkdrePsxSVQAicRBKR6Xs3fdewN5hX5JOAicsjUYtGnZEmmydSYUoA/640?wx_fmt=png&from=appmsg "")  
  
侦察：  
  
这项研究始于一次简单的Nmap扫描，目的只是为了看看在设备默认配置下是否有任何有趣的东西在监听。结果，有一个结果非常引人注目：  
  
如上所示，我们发现 60002 端口处于开放状态并处于监听状态。Nmap 无法直接识别该服务，因此我们决定进一步调查这个神秘端口，并从 Ratta Software 的“更新”页面获取该设备的固件镜像。获取该设备的固件映像，进一步调查这个神秘的端口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOS0H6XUS6yruiathHq8G52VZVj79qpGC4mr5fNoltk08SlnLpUDq6Oxw/640?wx_fmt=png&from=appmsg "")  
  
固件未加密，我们能够挂载各种文件系统映像并通过它们查找与该端口号相关的任何内容。  
  
这让我们找到了SuperNoteLauncher.apk，我们将其放入jadx并开始逆向分析。  
  
逆向 SuperNoteLauncher  
  
定位端口：  
  
名为COMMAND_RECEIVE_FILE_PORT的在 jadx 中打开 apk 后，我们首先搜索了该端口号的具体引用位置。如下所示，我们找到了一个static final int。名为COMMAND_RECEIVE_FILE_PORT。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOA7x4x0V6C8VJUsZbuXADkZZrIibHIuv6LxURxYtKJV9TbAN3ctnewHw/640?wx_fmt=png&from=appmsg "")  
  
通过寻找交叉引用，我们最终找到了它的使用位置：com.ratta.supernote.wifip2p.receive。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOxHjl9kpICZEUM6e4PpfVh14p44gmPwjFDuiaJc9IHicDfVSUPoU7iaHwA/640?wx_fmt=png&from=appmsg "")  
  
识别服务：  
  
我们可以在下图中看到，当端口打开时，通过ServerSocket接收到一些数据后会触发一些函数。具体来说，我们感兴趣的代码位于DeviceThread类中。我们可以在下图中看到，当端口打开时，通过ServerSocket接收到一些数据后会触发一些函数。具体来说，我们感兴趣的代码位于DeviceThread类中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOPc934qfwIq7nuFaR4RarSKjBYma0Vyy8KsbVfeV6fVgJvp7oic3iag6w/640?wx_fmt=png&from=appmsg "")  
  
DeviceThread实现了Runnable 接口，它的 r un()函数非常庞大。即便如此，快速浏览一下它，根据错误消息返回客户端的方式，我们很可能正在处理一个自定义的 HTTP 服务器。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOZhDoI5WB3bic3cgsI9c5DZYeiaObQBgcF5n5e5pbSIpFdV6OPnu8WgPA/640?wx_fmt=png&from=appmsg "")  
  
run()的第一行将套接字传递给getDeviceName()。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOPib4yYIKfsMuc6kdx80SXjicbtlHeeO8pmLFyS5vZbap1VdgickWDnFhQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOYrz8kcAialu5lto7mnhmoUCpX8Yu0XJfFicvzCD0I9TCqVgNeziaAXcibQ/640?wx_fmt=png&from=appmsg "")  
  
眼尖的朋友们应该能看出这段代码在做什么：解析 HTTP 服务器期望的自定义标头。这解释了run() 函数内部的一些奇怪行为——根据客户端传递的自定义标头，不同的操作会被触发。  
  
大于 1 的大于 1 的大于 1 的大于 1 的例如，我们可以通过提供大于 1 的版本标头来触发 501 错误代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOMqsmtCjcbXI9Prs5GQlx2KC87SgzCkbSahdVQd0ibCcuvgIlpYIRh6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOvSeOpEqahsLk1r1MAkljicLZxX6esSb6ibzCQ5ic2IXJwicjKHHawDzBBg/640?wx_fmt=png&from=appmsg "")  
  
而且，当我们发送请求时，我们实际上会收到一个弹出错误，提示 SuperNote 设备不是最新版本  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOBQcZP3T5nh7CyKUwv2YqE9pFnTNHCa1D1qiajbMibXibE63getbaTCtTg/640?wx_fmt=png&from=appmsg "")  
  
文件上传  
  
所有这些都很有趣，但最引起我们兴趣的是类名：RecieverManager和WiFiP2PService。未经身份验证的设备到设备文件共享听起来像是一个潜在的巨大攻击面。  
  
鉴于我们至少知道如何与服务器交互，此时我们继续模拟一个 python 客户端，它只发送一个带有附加文件和所有必要标头的 POST 请求...并且该文件出现在设备的 INBOX 目录中！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOHABSbgp62LRQk8W9QfVpQ7Tsd1BvmvHRrZIEPDqO24pfwP5icUD5ngw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOmo9tYnpzxu0NVcteia9eJkDW3At7V8WC9icwwqwib0nSyibgWktSGDCaRA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOEKziciaGWVibOfJPiaZ5JichWPho43pyM57skg8ibg4IMpRRjplJgGY2GDRA/640?wx_fmt=png&from=appmsg "")  
  
但是，看到文件名末尾那个讨厌的“ (1)”了吗？没错，这很快就会在漏洞利用过程中造成很大的问题。  
  
漏洞利用计划：  
  
到目前为止，我们还没有完全坦诚相待。在深入研究之前，我们曾对如果能够找到任意文件写入漏洞，漏洞利用可能是什么样子有一些想法。这个想法源于我们在侦察过程中发现的三条关键信息。  
1. SuperNote 在固件更新页面上的说明特别要求您将下载的 zip 文件放入 EXPORT 目录中  
  
1. 如果在 EXPORT 目录中找到有效的更新映像，则热插拔事件或重新启动后将自动启动手动固件更新  
  
1. 一位研究人员对上一代 SuperNote 设备进行了研究，发现固件映像使用了公开的调试密钥进行签名，并且引导加载程序默认处于解锁状态……真是太棒了。我们确认，虽然在新设备上密钥已被重命名，但它们仍然相同。  
  
因此，我们认为可以采取以下措施：  
- 创建带有后门的固件映像并使用公开可用的调试密钥对其进行签名  
  
- 使用任意写入将下载直接放入“EXPORT”目录  
  
- 在设备正常使用期间，会自动启动更新，安装我们的恶意 rootkit。  
  
理论上一切都很好，但有一个主要问题  
  
问题  
  
还记得文件名后面附加的“ (1) ”吗？没错，这就是它给我们带来麻烦的地方。你看，在 EXPORT 目录中扫描更新的服务有以下代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOyjYicASM3YqOic2F0usYR1ONI8CtNp1hdStodolObp5V8n6Tnd7wl2zA/640?wx_fmt=png&from=appmsg "")  
  
  
文件名必须完全是update.zip ...而不是update(1).zip因此，我们需要弄清楚为什么路径遍历有效载荷后会附加一个额外的数字，以及如何消除它。因此，我们需要弄清楚为什么额外的数字会附加到我们的路径遍历有效载荷中，以及如何摆脱它。。因此，我们需要弄清楚为什么额外的数字会附加到我们的路径遍历有效载荷中，以及如何摆脱它。  
  
文件名为何改变？  
  
在对启动器 APK 进行进一步逆向后，我们终于找到了问题的根本原因。虽然代码量太大，无法通过截图展示，但文件接收的大致逻辑如下：  
1. “ / receiver_file_cache /file_name ”路径下创建一个文件“ / receiver_file_cache /file_name ”路径下创建一个文件服务器首先在其应用程序目录中的  “ / receiver_file_cache /file_name ”路径下创建一个文件  
  
1. 然后，它将传入的数据流复制到“receiver _file_cache/file_name ”路径中新创建的文件中  
  
1. 当到达传入数据流的末尾时，它会创建一个名为“INBOX/file_name”的新文件  
  
1. 它将内容从“receiver _file_cache/file_name”复制到“ INBOX/file_name”  
  
1. 最后，它除缓存的文件。  
  
问题在于，所有操作都持续使用攻击者提供的文件名。因此，根据我们最初的攻击计划，最终在设备上实际发生的情况是：  
1. /receiver_file_cache/../../../../sdcard/EXPORT/update.zip ”服务器接收并创建“ /，认为这应该是缓存文件接收器_file_cache/../../../../sdcard/EXPORT/update.zip " 文件，认为这应该是缓存文件  
  
1. 再次尝试创建“ 再次尝试创建“ 然后，在接收完数据后，它会创建 INBOX 文件，但实际上会再次尝试创建“ /INBOX/../../../../sdcard/EXPORT/update.zip ”  
  
在每个文件创建事件之前，都会运行以下代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOhzeEKHTz34KmtlyWOEGK6ICIQbS3wBJrbfHYCB8ic3g7fpuAUs9LlWw/640?wx_fmt=png&from=appmsg "")  
  
如图所示，如果要写入新文件的位置已存在该名称，则会在文件名中添加“1”（或下一个后续数字）。因此，第二个文件创建事件不会创建“ /EXPORT/update.zip ”，而是创建“ EXPORT/update(1).zip ”。然后，执行该过程的剩余步骤：复制文件内容，并删除原始文件（“ /EXPORT/update.zip ”），只留下重命名后的文件。  
通过“竞争条件”绕过命名问题  
  
所以，考虑到我们目前的策略，我们陷入了困境。我们需要想办法把实际的更新文件以正确的名称导入到 EXPORT 中。目前，我们花了很多时间试图找到一个真正的命名绕过方法，但最终还是失败了。  
  
最终起作用的是利用逻辑上的“竞争条件”......从技术上讲，它实际上不是一个漏洞或传统的竞争条件，但我们可以利用它来获得优势。  
  
你知道，一个合法的更新文件有1.1GB大。这意味着传输需要相当长的时间。另外三个因素也对我们有利：  
1. 首先创建文件，然后将流逐字节写入其中。  
  
1. 传输完成后，将创建第二个文件，然后开始复制。  
  
1. 该服务器是多线程的，这意味着它可以同时接收多个文件  
  
我们可以利用这三个事实来稍微修改我们的漏洞。  
  
修订后的漏洞利用策略：  
  
利用我们对服务器逻辑的理解，我们可以使用以下技巧来满足我们的命名要求。  
1. 创建一个名为“update.zip”的非常小的虚拟文件  
  
1. 创建一个合法的“update.zip”文件，其中包含我们的恶意后门，并使用公开的开发密钥进行签名  
  
1. 首先发送非常小的虚拟文件  
  
1. 之后立即发送合法的“update.zip”文件。  
  
如果我们这样做，设备上就会发生以下情况（注意 - 线程一为斜体，线程二为粗体）：  
1. `EXPORT/update.zip` 是由虚拟文件在缓存/初始接收步骤中创建的  
  
1. `EXPORT/update(1).zip` 是在缓存/初始接收步骤中由实际更新创建的  
  
1. `EXPORT/update(2).zip` 是由虚拟文件在复制步骤中创建的  
  
1. 复制步骤完成后，虚拟文件会删除“EXPORT/update.zip”  
  
1. `EXPORT/update.zip` 是在复制步骤中由实际更新创建的  
  
1. 复制步骤完成后，真正的更新会删除“EXPORT/update(1).zip”  
  
由于我们的虚拟文件比真正的更新文件小得多，因此它在接收有效更新之前就完成了缓存、复制和删除步骤。这样，在有效更新的复制步骤开始时，EXPORT/update.zip这个名称就可用了。  
  
因此，我们的漏洞利用程序运行后，会留下一个正确命名的恶意更新映像。此外，我们还保留了虚拟文件复制操作留下的“ EXPORT/update(2).zip”文件，但我们并不关心它。如果我们需要清理，可以在安装 rootkit 后进行。  
  
固件映像后门  
  
我们不会深入探讨这一步，但我们在谷歌搜索后找到了所需的开发密钥。之后，我们使用flashable-android-rootkit创建了一个后门，并编写了简单的 C 语言反向 Shell 载荷。为了重新打包固件，我们遵循了之前研究中推荐的方法，并使用了Multi Image Kitchen（注：找到合适的 JDK 版本以使 Multi Image Kitchen 正常工作是本次漏洞利用的难点之一）。  
  
整合起来  
  
一旦有效载荷就位，它将在设备正常运行期间自动安装。安装程序会在热插拔事件（USB-C 插入或拔出设备）或重启期间检查 EXPORT 目录。因此，您只需静待，等待，并祈祷用户不会在 EXPORT 目录中找到可能可疑的 update.zip 文件。请注意，热插拔事件后，用户会收到有关更新的提示。但是，这是一个选择退出的提示，这意味着除非点击“中止”，否则更新将在 30 秒内安装完成。如果一切顺利，您将看到以下内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOjKtj0JpT6gQwGvCdu5lokND9u0ZzoMLsVTTwoKIZqLsYP2k2OxBEKg/640?wx_fmt=png&from=appmsg "")  
  
披露时间表：  
所以，考虑到我们目前的策略，我们陷入了困境。我们需要想办法把实际的更新文件以正确的名称导入到 EXPORT 中。目前，我们花了很多时间试图找到一个真正的命名绕过方法，但最终还是失败了披露时间表：  
- 2024 年 7 月 26 日- PRIZM 联系 Ratta Software 的服务团队  
  
- 2024 年 8 月 15 日- PRIZM 与 Ratta Software 进行后续合作  
  
- 2024 年 9 月 23 日——PRIZM 再次跟进 Ratta Software，通知他们计划在 90 天披露期限（10 月 23 日）公开披露该漏洞  
  
- 2024 年 9 月 30 日——PRIZM 与 Ratta 软件的“反馈”团队联系，以期获得回应。  
  
- 2024年10月2日- Ratta Software 回应，称员工变动导致信息披露出现疏漏。团队要求提供更多信息，以便转达给工程主管。  
  
- 2024 年 10 月 3 日- PRIZM 提供了一份 7 页的技术报告，其中包括用于本地复制的完整漏洞代码  
  
- 2024 年 10 月 15 日- PRIZM 跟进以确保已收到技术细节，并在下周提醒即将到来的 90 天期限。  
  
- 2024 年 10 月 16 日——SuperNote 回复并提到他们计划在 12 月的更新中解决这些问题。  
  
- 2024 年 10 月 16 日——PRIZM 回复并同意推迟至 2024 年 12 月披露任何信息。  
  
- 编辑：2025 年 4 月 8 日 -分配CVE-2025-32409已被分配。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
