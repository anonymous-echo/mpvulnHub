#  来事了——微软RDL服务远程代码执行漏洞   
原创 simeon的文章  小兵搞安全   2024-08-10 11:31  
  
   
1.1漏洞详情  
### 1.1.1RDL  
  
     远程桌面许可服务是 Windows Server 的一个组件，用于管理和颁发远程桌面服务的许可证，确保对远程应用程序和桌面的安全且合规的访问。RDL 服务广泛部署在启用了远程桌面服务的机器上。默认情况下，远程桌面服务仅允许同时使用两个会话。要启用多个同时会话，您需要购买许可证。RDL 服务负责管理这些许可证。RDL 被广泛安装的另一个原因是，在Windows 服务器上安装远程桌面服务 (3389) 时，管理员通常会勾选安装 RDL 的选项。这导致许多启用了 3389 的服务器也启用了 RDL 服务。目前不少于17万个活跃的RDL服务直接暴露在公共互联网上，而内部网络中的数量无疑要大得多。此外，RDL服务通常部署在关键业务系统和远程桌面集群中，因此RDL服务中的预认证RCE漏洞对网络世界构成了重大威胁。  
  
     Windows 远程桌面授权服务（RDL）是一个用于管理远程桌面服务许可证的组件，确保对远程桌面连接的合法性。该服务被广泛部署于开启了Windows远程桌面服务（3389端口）的服务器上，但漏洞的利用不是通过3389端口，需要先连接135端口发送访问请求，然后服务器给出一个连接RDL服务的动态高端口，再连接访问，如果服务器对外不开放135端口则不可利用。**注意：RDL服务并非默认启用，但出于扩展功能等目的，许多管理员会手动启用它，例如增加远程桌面会话的数量。在一些特定的场景中，如堡垒机和云桌面VDI环境，RDL服务的启用也是必需的。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibgKbnyV8ZbvVom9uaspYiayic8pzYJxBwTuu5mGWXGJic6387xxnsOX3PQ/640?wx_fmt=png&from=appmsg "")  
### 1.1.2漏洞情况  
  
**2024年7月9日，微软官方发布了一个针对“windows远程桌面授权服务远程代码执行漏洞”（CVE-2024-38077）的修复补丁包，起初并没有引起大家的警觉。在国外某网站上疑似漏洞的作者公开了该漏洞的“POC验证代码”。一时激起千层浪，该漏洞开始疯狂发酵并在安全圈里转发。**  
  
**该文章的原文链接为：**  
  
**https://sites.google.com/site/zhiniangpeng/blogs/MadLicense**  
  
**链接里也附上了漏洞验证视频：**  
  
**https://www.youtube.com/watch?v=OSYOrRS2k4A&t=8s**  
  
**Windows 远程桌面授权服务远程代码执行漏洞(CVE-2024-38077)**  
，该漏洞存在于Windows远程桌面许可管理服务（RDL）中，成功利用该漏洞的攻击者可以实现远程代码执行，获取目标系统的控制权，可能导致敏感数据的泄露、以及可能的恶意软件传播。**该漏洞影响所有启用 RDL 服务的 Windows Server服务器，特别是未及时更新 2024 年 7 月微软最新安全补丁的系统。**  
### 1.1.3 微软7月修复RDP相关漏洞  
  
1.2024年7月，我们报告的以下7个与RDP相关的漏洞已被Microsoft修复：  
  
**CVE-2024-38077：Windows 远程桌面授权服务远程代码执行漏洞**  
  
**CVE-2024-38076：Windows 远程桌面授权服务远程代码执行漏洞**  
  
**CVE-2024-38074：Windows 远程桌面授权服务远程代码执行漏洞**  
  
**CVE-2024-38073：Windows 远程桌面许可服务拒绝服务漏洞**  
  
**CVE-2024-38072：Windows 远程桌面授权服务拒绝服务漏洞**  
  
**CVE-2024-38071：Windows 远程桌面许可服务拒绝服务漏洞**  
  
**CVE-2024-38015：Windows 远程桌面网关（RD 网关）拒绝服务漏洞**  
  
**其中，Windows 远程桌面授权服务中的 3 个 CVSS 评分为 9.8 的 RCE 漏洞值得关注。**  
## 1.2漏洞排查  
### 1.2.1检查是否安装ADL  
  
在 Windows Server 上，您可以通过以下方法检查是否启用了远程桌面许可服务（Remote Desktop Licensing, RDL）：  
  
1. 检查远程桌面许可服务是否安装并运行  
  
（1）打开“服务”管理工具  
  
按 Windows + R 打开运行对话框，输入 services.msc 并按 Enter，查找远程桌面许可服务。在“服务”列表中查找“Remote Desktop Licensing”服务（在某些版本中可能显示为“Remote Desktop Licensing”或类似名称）。确认该服务是否正在运行。如果服务的状态为“正在运行”，则表示该服务已启用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibSCbp9bZtA9ONSoVYMq6nX6slgEmVXYPVFApcWVicVVnSvnLbH5N3wsQ/640?wx_fmt=png&from=appmsg "")  
  
2. 检查远程桌面许可管理器  
  
      打开远程桌面许可管理器，按 Windows + R 打开运行对话框。输入 licmgr.exe 并按 Enter。这将打开远程桌面许可管理器。在远程桌面许可管理器中，查看“许可”部分，检查是否有配置和管理的远程桌面许可。确认是否已经配置了许可证服务器以及许可证的状态。  
  
3. 使用“服务器管理器”  
  
在“服务器管理器”中，选择“角色和功能”。检查是否列出“远程桌面服务”。如果远程桌面服务安装了，可能会看到相关的角色和功能。查看“远程桌面服务”角色。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLib9FwjSrKacBhYINdIeXicZiaKIqZ4dVvhFico3h7TibAH8DVHZMUV4nTiaTQ/640?wx_fmt=png&from=appmsg "")  
  
4. 使用 PowerShell  
  
（1）打开 PowerShell（以管理员身份）  
  
按 Windows + X，然后选择“Windows PowerShell (管理员)”（或“命令提示符 (管理员)”）。  
  
（2）运行以下 PowerShell 命令来查看远程桌面许可服务的状态  
  
Get-Service -Name TermService  
  
这将返回服务的状态。TermService 服务表示远程桌面服务，如果该服务正在运行，则表明远程桌面功能已启用。  
  
（3）检查远程桌面许可服务配置  
  
运行以下命令以获取远程桌面服务的配置：  
  
Get-WmiObject Win32_Process | Where-Object { $_.Name -eq 'svchost.exe' } | Select-Object CommandLine  
  
这将显示远程桌面许可配置的详细信息，包括许可服务器和许可类型，如果没有安装，则显示如下图信息所示。  
  
### 1.2.2 通过进程进行排查  
  
1.青藤云进程查看  
  
青藤云主机进程检测中检查svchost进程中是否包含“-k TSLicensing”。  
  
2.Dos命令下tasklist查看svchost加载的服务  
  
tasklist /svc /fi "imagename eq svchost.exe"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibQvo14Np8fG5QoXzbPwEhYIzxrF4hakeoY3H1uWRknGAcAIGqhaATOA/640?wx_fmt=png&from=appmsg "")  
  
3.通过wmic查看  
  
wmic process where "name='svchost.exe'" get commandline   
  
或者直接用以下命令查看，如果有结果则证明开启了RDL服务。  
  
wmic process where "name='svchost.exe'" get commandline | find "-k TSLicensing"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibqCzTlk8IGQPI5SFochFV7TFGzwWaKmDyEtBLZibEU1KicNQnauyzjk0g/640?wx_fmt=png&from=appmsg "")  
  
4.使用 PowerShell检查svchost进程  
  
Get-WmiObject Win32_Process | Where-Object { $_.Name -eq 'svchost.exe' } | Select-Object CommandLine  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibudSPC0K84UmLGohWtc4CGibjk44dH4FqhuqickD1GCmvUsLqF2IYZewg/640?wx_fmt=png&from=appmsg "")  
## 1.3漏洞修复  
### 1.3.1获取系统当前信息及版本  
  
 1.通过systeminfo 获取当前系统的版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibGibwfy2muXnhrh2S6qy4rohNWUUlO4HlPfMl3QCDoCF4b3xZ8Q5JtGA/640?wx_fmt=png&from=appmsg "")  
### 1.3.2 微软官方查询  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibNFia2ErViaoyNH9MEH5AgDeqU9tJX7UtWggn3ezw5k0tDaDLc53gHOnw/640?wx_fmt=png&from=appmsg "")  
### 1.3.3下载对应版本的程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibg9ShNJ2PGJRsia8fhV3sZbvtMm5VJqujbtBz9XMehJjJViaRTtutg1ibg/640?wx_fmt=png&from=appmsg "")  
  
https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/07/windows6.1-kb5040498-x64_71ee53540b4244e86bd799297fb410595199b38a.msu  
### 1.3.4执行更新  
  
1.由于不存在该漏洞无法执行更新  
  
（1）执行msu失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLib1O4UIEpLHwyx7LJHGlELOWjbS0aoHhT6KiaGe1kVUkO6ibd2Pw6Dp8nA/640?wx_fmt=png&from=appmsg "")  
  
（2）命令行下更新  
  
wusa   
path  
\to\yourfile.msu  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibAStGP3yPTFksLudncZIUHtIJYbxuZNdpOcYCpbKvMbyAfGRrCkPIPw/640?wx_fmt=png&from=appmsg "")  
  
2.存在漏洞的采用Windows自动更新  
  
  Windows系统默认启用 Microsoft Update，当检测到可用更新时，将会自动下载更新并在下一次启动时安装。还可通过以下步骤快速安装更新：  
  
（1）点击“开始菜单”或按Windows快捷键，点击进入“设置”  
  
（2）选择“更新和安全”，进入“Windows更新”（Windows Server 2012以及Windows Server 2012 R2可通过控制面板进入“Windows更新”，步骤为“控制面板”-> “系统和安全”->“Windows更新”）  
  
（3）选择“检查更新”，等待系统将自动检查并下载可用更新  
  
（4）重启计算机，安装更新  
  
系统重新启动后，可通过进入“Windows更新”->“查看更新历史记录”查看是否成功安装了更新。对于没有成功安装的更新，可以点击该更新名称进入微软官方更新描述链接，点击最新的SSU名称并在新链接中点击“Microsoft 更新目录”，然后在新链接中选择适用于目标系统的补丁进行下载并安装。  
### 1.3.5奇安信检测工具  
  
奇安信推出了一款漏洞检测工具，详细请参考文章[https://mp.weixin.qq.com/s/adcmX5b1fH9ouUlxf0RXFg](https://mp.weixin.qq.com/s?__biz=MzU0NDk0NTAwMw==&mid=2247615668&idx=2&sn=9d3df637bb4e094962327f60d416a4cf&scene=21#wechat_redirect)  
  
。其核心原理是  
对目标windows服务器的135端口进行测绘获取banner信息，并对banner信息进行查询是否包含UUID=” 3d267954-eeb7-11d1-b94e-00c04fa3080d”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VEBZicPCIcB0U7p2WtFUCTLibkI52n5OSfLHC4gUuBCm22KUmBtqbCiaIvRju35ZMnstts1vf4kdE4oA/640?wx_fmt=png&from=appmsg "")  
  
Linux平台检测：  
  
Kali系统自带impacket-rpcdump库，直接在shell中执行如下命令：  
  
impacket-rpcdump 192.168.147.233 | grep "3D267954-EEB7-11D1-B94E-00C04FA3080D"  
  
特别注意：  
  
      网上提供的一些所谓poc利用和漏洞检测，一定小心，有些都是捆绑木马后门的。别轻信！！！  
  
