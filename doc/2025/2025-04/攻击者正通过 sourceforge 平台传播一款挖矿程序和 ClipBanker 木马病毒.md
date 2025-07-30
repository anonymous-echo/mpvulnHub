#  攻击者正通过 sourceforge 平台传播一款挖矿程序和 ClipBanker 木马病毒   
原创 kaspersky  卡巴斯基威胁情报   2025-04-16 09:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaPhIlPNuMwmOcZHkmicapUeCe5dib6LOe2MOSsicfPYvicQaDnuT0Y2dYPQ/640?wx_fmt=png&from=appmsg "")  
  
  
最近，我们注意到一种相当独特的恶意软件分发方案，该方案利用了SourceForge网站，这是一家提供软件托管、比较和分发服务的热门网站。该网站托管着众多软件项目，任何人都可以上传自己的项目。在主网站sourceforge.net上，有一个名为officepackage的项目，看起来相当无害，它包含从一个合法的GitHub项目复制而来的微软办公软件插件。下面提供的officepackage的描述和内容也来自GitHub。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiah7wUqjcbFWywG59njMvVm6pV3lclSF9DaP375mfiabGuLfpmaxKuicyw/640?wx_fmt=png&from=appmsg "")  
  
**“officepackage”项目的描述**  
  
  
很少有人知道，在sourceforge.net上创建的项目会获得一个sourceforge.io的域名和网站托管服务。这样的页面会被搜索引擎很好地索引，并出现在搜索结果中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaf763TZNXRCf2bUd5GwMWLAibIv0UoYdxPicn4w8QPj8Pt7FWtJYbcy4Q/640?wx_fmt=png&from=appmsg "")  
  
包含“officepackage.sourceforge.io”的搜索查询及结果示例  
  
  
正在调查的这个项目被分配了域名officepackage.sourceforge[.]io，但当你访问该域名时所显示的页面与sourceforge.net上的officepackage项目看起来完全不一样。访客看到的不是从GitHub复制来的描述内容，而是一份令人印象深刻的办公应用程序列表，其中列有各个程序的版本号，还配有“下载”按钮。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaoTp0Fic25ahSAZIl3Z5AfLDaToN6mo2PEcPGZlbI4KQFz4jOicQqmQrA/640?wx_fmt=png&from=appmsg "")  
  
**在 officepackage.sourcefoge.io 域上看到的项目**  
  
  
将鼠标悬停在其中一个按钮上时，浏览器状态栏中会显示一个看似合法的网址：https[:]//loading.sourceforge[.]io/download。由于这些按钮位于该项目的页面上，人们很容易错误地将该网址与officepackage项目联系起来。然而，loading.sourceforge.io这个域名指向的是sourceforge.net上的另一个名为“loading”的项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaDM5poeuUc1ib3C3xLJMtv9pqlL83ZJCXhpqibicz1Ur7PY2dVd9vC9ib0A/640?wx_fmt=png&from=appmsg "")  
  
**与 “下载” 按钮相关联的网址**  
  
  
点击该链接会跳转到一个页面，页面上还有另一个 “下载” 按钮，这次是英文的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiam4mXOniakHCZqv2BwrhkSMe50T8BYe4DxaEFHqwBkXXzoqtEfwRk2lQ/640?wx_fmt=png&from=appmsg "")  
  
**用于下载可疑压缩文件的页面**  
  
  
点击那个按钮最终会下载一个大小约为 7 兆字节、名为 vinstaller.zip 的压缩文件。这就出现了一些警示信号，因为办公应用程序即便经过压缩，也绝不会这么小。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwia6emWAR7piaXevibn4F6bETQAy1KP3mIlvic0by8ibhoUJNL1RKACMrn1fg/640?wx_fmt=png&from=appmsg "")  
  
**感染链条：从搜索办公软件到下载安装程序**  
  
  
下载的压缩文件里包含另一个受密码保护的压缩文件 installer.zip，以及一个带有密码的 Readme.txt 文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiadxxZ3YvRaIiaUpsDgpicc9nSjVHfZKp1q5gOAnLJuGeiacwduf3NEry6w/640?wx_fmt=png&from=appmsg "")  
  
**vinstaller.zip 的内容**  
  
  
在 installer.zip 里面有一个名为 installer.msi 的文件。这是一个 Windows 安装程序文件，大小超过 700 兆字节。显然，这么大的体积是为了让用户相信他们看到的是一个真正的软件安装程序。攻击者使用文件填充技术，通过附加垃圾数据来增大文件大小。上述文件被填充了空字节。我们去除这些垃圾字节后，其真实大小仅为 7 兆字节。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiayic7zUDYdlqkDVTmZ0o09CsPZOiaM44icbx7EcSrav3C4fAOhUSycn89w/640?wx_fmt=png&from=appmsg "")  
  
**installer.zip 的内容**  
  
  
运行该安装程序会创建几个文件，其中有两个文件值得我们关注：UnRAR.exe（一个控制台压缩文件实用程序）以及一个名为 51654.rar 的受密码保护的压缩文件。然后，安装程序会执行一个嵌入的 Visual Basic 脚本。长期以来，攻击者一直将受密码保护的压缩文件与解压缩实用程序一起分发，并通过命令行传递密码。不过，在这种情况下存在一个中间步骤。安装程序文件中没有压缩文件的密码。相反，为了延续感染链条，VB 脚本会运行 PowerShell 解释器，从 GitHub 下载并执行一个名为 confvk 的批处理文件。这个文件包含了 RAR 压缩文件的密码。它还会解压恶意文件并运行下一阶段的脚本。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwia02S5q65GKeBicosw5JYricic5ClD4uxcJ8mgEwQ0Pa7picYHzAPByibiciczg/640?wx_fmt=png&from=appmsg "")  
  
**感染链条：从启动安装程序到下载 confvk 批处理脚本**  
  
  
以下是该批处理脚本的工作原理详解。首先，它会在特定路径下搜索AutoIt解释器，以此来检查是否已经存在感染情况。如果找到了AutoIt，该脚本就会自行删除并退出。如果没有找到，脚本就会检查与杀毒软件、安全解决方案、虚拟环境以及研究工具相关的进程。要是检测到有这类进程，它也会自行删除。  
  
如果这两项检查都通过了，该脚本就会解压RAR压缩文件，并在其代码中运行两个PowerShell脚本。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiakFylGmEfxYoApK359peYY5n4gYcFqernljU64areBiaulgDUWXnE9jg/640?wx_fmt=png&from=appmsg "")  
  
**由批处理文件执行的解压 RAR 压缩文件的命令**  
  
  
其中一个 PowerShell 脚本会使用 Telegram API 向某个聊天群组发送一条消息。该消息包含系统信息、受感染设备的外部 IP 地址及所在国家、CPU 名称、操作系统、已安装的杀毒软件、用户名以及计算机名称。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaBVIAnbpbVfjk0ic1YQuKicTYEysLEkiaZeq6mHrfqGxibY1mJfEQQIuaiag/640?wx_fmt=png&from=appmsg "")  
  
**来自 confvk 的代码片段，其中包含了解压恶意压缩文件以及运行 Telegram 文件发送脚本的命令**  
  
  
另一个 PowerShell 脚本会下载另一个批处理文件 confvz，用于处理从 RAR 压缩文件中提取出来的文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiazbUKaDBoLibPqRDMH4BLBeibs8OXEzXEGvaPQXg5w8qCibfuh6kfSPntQ/640?wx_fmt=png&from=appmsg "")  
  
**RAR压缩文件的内容**  
  
  
压缩文件的内容如上面的截图所示。以下是对每个文件的概述。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaH9sTBFT6fG3KAiaCw1vicGOHKUtibaOomicxSOSzkbPBeJ0lTTtwicEfXtw/640?wx_fmt=png&from=appmsg "")  
  
  
confvz批处理文件会在%ProgramData%路径下创建三个子目录，并将解压后的压缩文件移动到这些子目录中。第一个子目录接收Input.exe和Icon.dll文件，第二个子目录接收另一个带有Kape.dll的Input.exe副本，第三个子目录接收所有的netcat文件。然后，该批处理文件会在%USERPROFILE%\Cookies\路径下创建ini.cmd和init.cmd批处理脚本，以运行它所复制的文件。这些脚本会执行Input.exe（AutoIt解释器），并将Icon.dll和Kape.dll（这两个文件都包含压缩的AutoIt脚本）的路径作为参数传递进去。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiauXwy3fw6JvI3FYJlbMPY5yRJ1Cibbu9mTiaPF8ichjrRW1Nq4iaaswt9mg/640?wx_fmt=png&from=appmsg "")  
  
**confvz 批处理文件的内容**  
  
  
接下来，confvz 会在注册表键 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\* 中生成键值。这些键值会链接到 ini.cmd 和 init.cmd 批处理文件。通过这些键值，可以使用简短的名称来运行文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaU5Cay9BFHkLiclgcpmEaU4trCgwdbgicYO1yf440bWqPUVbkkjKldO7g/640?wx_fmt=png&from=appmsg "")  
  
  
在运行install.exe时会启动ini.cmd。类似地，start.exe被注册为init.exe的一个链接，而Setup.exe则链接到系统实用程序%WINDIR%\System32\oobe\Setup.exe，该程序通常在操作系统安装期间启动。我们稍后会再讲到这个实用程序。  
  
然后，confvz会创建名为NetworkConfiguration（网络配置）和PerformanceMonitor（性能监视器）的服务，以便自动启动这些批处理文件，还会创建一个名为Update（更新）的服务，用于直接运行AutoIt解释器，而无需通过中间的批处理文件。  
  
此外，作为一种备用的自动启动方法，confvz会添加以下注册表项：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiardDIOjvibvW26Hib7icHUDszEzpyLelAib7yXkTKt2k8HZxWYYoXQ2icZsw/640?wx_fmt=png&from=appmsg "")  
  
  
当MicrosoftEdgeUpdate.exe启动时，这会运行一个调试器。该调试器被设置为执行start.exe，根据之前设置的注册表项，start.exe指向init.cmd。  
  
通过使用内置的WMIC（Windows Management Instrumentation Command-line）实用工具，会创建一个事件筛选器，使其每隔80秒触发一次处理程序。虽然在较新的Windows版本中，WMIC默认是禁用状态，但在较旧的系统中它仍然可以使用。  
  
该处理程序会执行以下命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwia8eWjEnmSFky4oDOttyFcKIomJ7V31lCwwGYDZrOfDuRDsy9NjOmaQg/640?wx_fmt=png&from=appmsg "")  
  
  
ShellExperienceHost.exe是来自恶意压缩文件中的netcat可执行文件。上述参数使得该工具与端口445上的命令与控制（C2）服务器apap[.]app建立加密连接，并通过该连接启动一个输入/输出重定向的命令行解释器。这实际上就创建了一个以apap[.]app:445作为命令与控制服务器的远程命令行。  
  
最后，confvz会创建一个文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaEpTaolOytvJS0ibvvhYNhpjufXpibfMic5V0vTZFIDhQ1CibWSHGK8Yibicw/640?wx_fmt=png&from=appmsg "")  
  
  
这是一个你可以在Windows系统中创建的自定义脚本，用于在操作系统安装期间简化故障排除流程。如果发生严重错误，%System32%\oobe\Setup.exe实用程序会找到并执行这个文件。然而，攻击者找到了一种利用它来实现自动启动的方法。他们再次通过使用操作系统内置的WMIC实用工具来建立一个事件筛选器，该筛选器每300秒触发一次处理程序。处理程序被指定为%WINDIR%\System32\cmd.exe /c start Setup.exe，而根据之前创建的注册表项，Setup.exe引用的是实用程序%WINDIR%\System32\oobe\Setup.exe，该实用程序在启动时会执行ErrorHandler.cmd。ErrorHandler.cmd文件包含一个简短的PowerShell脚本，该脚本使用Telegram API来检索并执行一个文本字符串。这是另一个远程命令行，但其输出不会被发送到任何地方。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfPfViaDTTDThIEctw04yCwiaibZzEIsPamSLVxT8M6zFRZlibMzppAwHaFpA5YMNJO2jiaE5E1Lfehq4A/640?wx_fmt=png&from=appmsg "")  
  
**感染链条：从执行confvk到设置所有的自动启动方法**  
  
  
这次恶意攻击活动中的关键恶意行为归根结底就是运行两个AutoIt脚本。Icon.dll会重启AutoIt解释器，并向其中注入一个挖矿程序，而Kape.dll做的也是同样的事，不过注入的是ClipBanker恶意软件。ClipBanker是一类恶意软件，它会将剪贴板中的加密货币钱包地址替换为攻击者自己的地址。加密货币钱包的用户通常是复制地址而不是手动输入地址。如果设备感染了ClipBanker，受害者的钱最终会流向完全意想不到的地方。  
  
**受害者**  
  
  
  
  
officepackage.sourceforge[.]io网站有一个俄语界面，这表明其目标主要是说俄语的用户。我们的监测数据显示，90%的潜在受害者在俄罗斯，在1月初至3月下旬期间，有4604名俄罗斯用户遭遇了这一骗局。  
  
**经验教训**  
  
  
  
  
伪装成盗版软件来传播恶意软件并不是什么新鲜事。当用户试图从官方渠道以外的地方下载应用程序时，攻击者就会提供他们自己的下载途径。他们不断寻找新的方法让自己的网站看起来合法可信。这里所描述的骗局利用了SourceForge的一个功能，即会为每个sourceforge.net存储库创建一个sourceforge.io子域名。  
  
这些保持恶意程序持续运行的方法也值得注意。攻击者通过多种方法（包括一些非传统方法）来确保能够访问受感染的系统。虽然这次攻击主要是通过部署挖矿程序和ClipBanker来针对加密货币，但攻击者也可能会将系统访问权限出售给更危险的不法分子。  
  
我们建议用户不要从不信任的来源下载软件。如果你因为任何原因无法从官方渠道获取某些软件，请记住，寻找替代的下载方式总是会带来更高的安全风险。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BscvC1hbNBfPfViaDTTDThIEctw04yCwia2YMhb0RyoW8akWxP6yo761wxtlsABzfmGInseMqRVmGibVxyt4Ry0xA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
