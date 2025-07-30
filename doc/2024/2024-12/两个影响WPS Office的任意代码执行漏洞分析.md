#  两个影响WPS Office的任意代码执行漏洞分析   
zhuanfa  黑客街安全团队   2024-12-03 11:17  
  
**转发 freebuf**  
  
##   
  
****  
ESET研究人员在WPS Office for Windows中发现了一个代码执行漏洞（CVE- 2024-7262），该漏洞正被韩国网络间谍组织APT-C-60滥用。在分析了根本原因后，另一种任意代码执行漏洞（CVE-2924-7263）浮出水面。目前，两个漏洞均已被修复。本文提供了有关漏洞的技术细节。  
##   
  
**概述**  
  
  
##   
  
在调查APT-C-60的活动时，研究人员发现了一个奇怪的电子表格文档，关联了该组织的其中一个下载组件。通过分析，研究人员发现了WPS Office for Windows中的一个代码执行漏洞，该漏洞正被APT-C-60用于攻击东亚国家。最后的有效载荷是一个名为“SpyGlace”的自定义后门，在ThreatBook中公开记录为taskcontroller .dll。  
  
  
据WPS网站称，该软件在全球拥有超过5亿活跃用户，这使其成为恶意行为者接触东亚地区大量个人的诱人目标。在漏洞披露过程中，DBAPPSecurity独立发布了对武器化漏洞的分析，并确认APT-C-60利用该漏洞向中国用户发送恶意软件。  
  
  
从外观上看，该恶意文档（SHA-1: 7509b4c506c1627c1a4c396161d07277f044ac6）是常用的XLS电子表格格式的MHTML导出。但是，它包含一个经过特殊设计的隐藏超链接，用于在使用WPS电子表格应用程序时单击该链接触发任意库的执行。非常规的MHTML文件格式允许在打开文件时立即下载文件；因此，在利用漏洞的同时使用这种技术可以实现远程代码执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3V3WcCanlmQCfcv8nBD7tzrXJtUGtanOI1qzHot4hbTTTWEptKNhXJA/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
【图1：该漏洞利用文档嵌入了一张隐藏恶意超链接的图片】  
###   
### 漏洞利用时间轴  
  
****> 2024-02-29：CVE-2024-7262的漏洞利用文档已上传至  
VirusTotal。  
> 2024-03-??：金山发布了一个更新，悄悄修补了CVE-2024-7672漏洞，因此2024-02-29漏洞不再有效。这是通过分析2024-03至 2024-04 之间所有可访问的  
WPS Office版本后得出的结论，因为金山在尝试修复此漏洞时并未特别提供其操作的精确细节。  
> 2024-04-30：ESET分析了来自VirusTotal的恶意文档，发现它正在积极利用CVE-2024-7262，这是文档首次使用时的一个  
零日漏洞。ESET还发现金山毒霸的静默补丁仅解决了部分错误代码，其余有缺陷的代码仍然可被利用。  
> 2024-05-25：ESET联系了金山软件，报告了其发现。虽然第一个漏洞已经修复，但ESET询问他们是否可以创建CVE条目和/或公开声明，就像他们对CVE-2022-24934所做的那样。  
> 2024-05-30：金山软件承认了这些漏洞并告诉ESET会及时更新信息。  
> 2024-06-17：ESET要求更新。  
> 2024-06-22：金山软件告诉ESET开发团队仍在努力解决这个问题，并计划在即将推出的版本中修复这个问题。  
> 2024-07-31：根据后续测试，ESET发现CVE-2024-7263已被悄悄修复，ESET告知金山软件已预留并正在准备CVE-2024-7262和CVE-2024-7263。  
> 2024-08-11：DBAPPSecurity团队独立发布了其调查结果。  
> 2024-08-15：CVE-2024-7262和CVE-2024-7263发布。  
> 2024-08-16：ESET要求金山软件进行另一次更新。  
> 2024-08-22：金山软件承认已于5月底修复了CVE-2024-7263，这与该公司在2024-06-22声称其开发团队“仍在努力解决该问题”的说法相矛盾。  
> 2024-08-28：金山软件已承认这两个漏洞，并已完成修复。但是，该公司表示无意公开CVE-2024-7262的野外利用情况，因此ESET现在发布此博文，旨在警告金山软件的客户，由于CVE-2024-7262漏洞和漏洞利用的野外利用和第三方披露，他们应紧急更新WPS Office。  
  
  
  
CVE-2024-7262漏洞源于未能对攻击者提供的文件路径进行数据消毒，以及未能对加载的插件进行验证。不过，在分析其补丁后，研究人员又发现了另一种利用该漏洞的方法。  
##   
  
**CVE-2024-7262**  
  
  
## 本节描述了APT-C-60利用的漏洞，该漏洞允许通过劫持WPS Office插件组件promecefpluginhost.exe的控制流来执行代码。同时，还进一步解释了该漏洞是如何被触发并以合法电子表格文档的形式武器化的。  
###   
### 根本原因分析  
  
  
在安装WPS Office for Windows时，该软件套件会注册一个名为ksoqing的自定义协议处理程序，当用户单击以ksoqing://开头的URL时，它允许执行外部应用程序。在Windows操作系统中，自定义协议处理程序的注册在注册表中完成。在这种情况下，密钥HKCR\ksoqing\shell\open\命令下的默认值指示Windows执行C:\Users\<USER>\AppData\Local\Kingsoft\WPS Office\<VERSION>\office6\ WPS .exe，参数为/qingbangong "%1"，其中%1被替换为完整的URL。为了说明这一点，图2显示了当用户在WPS电子表格应用程序（et.exe）中使用自定义协议ksoqing单击超链接时发生的情况。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3Rf6fZ0a1CuqfJvVyTHWialQsu81PDH8bX416PhYs8DzibeRfibfX0Uib2w/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图2：WPS电子表格应用程序启动WPS .exe来处理自定义协议ksoqing】  
  
  
图3概述了CVE-2024-7262漏洞的控制流程。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3ppxLc34uDrcSyicZ0picgsm7hOkjTdxlMeW6HCNjxvZ1910D65bZetMQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图3：该漏洞的控制流概述】  
  
  
一旦启动，wps.exe将加载qingbangong.dll，该组件负责解析和验证来自超链接的某些参数。研究发现的漏洞利用文件中的恶意链接具有以下格式ksoqing://type=ksolaunch&cmd=<base64-encoded string>&token=<MD5 hash>&launchname=promecefpluginhost.exe。根据测试结果显示，这会导致使用攻击者提供的base64编码命令行启动系统上已经存在的应用程序（在本例中为promecefpluginhost.exe）。  
  
  
该token参数是cmd参数的编码值与字符串_qingLaunchKey_和launchname参数的编码值相连接的MD5  
哈希值。最后一个必须是位于C:\Users\<USER>\AppData\Local\Kingsoft\WPSOffice\<VERSION>\office6\下的可执行文件，并使用金山的有效证书进行签名。  
  
  
在解码cmd参数后，研究人员发现命令行/qingbangong -CefParentID=1 -JSCefServicePath=<base64-encoded file path> 被传递给promecefpluginhost.exe。经过一些初始化后，便会加载ksojscore.dll库并解码JSCefServicePath参数。该文件路径是由攻击者定义的，这意味着攻击者可以通过加载任意DLL来执行代码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3XOsesFvQTL8nEjSiaAhaO3JKUyOo1GicO1BWZrcyXejBeZNfEEgwkoicw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图4：参数JSCefServicePath被解码（左）并用作QLibrary::load方法的参数（右）】  
  
  
从本质上讲，存在滥用ksoqing方案协议并创建一个超链接的可能性，当单击该超链接时，将从给定的远程文件路径加载库。APT-C-60将该漏洞武器化，执行其第一阶段木马下载组件（SHA-1: 08906644B0EF1EE6478C45A6E0DD28533A9EFC29）。  
###   
### 漏洞利用方式  
  
  
为了利用此漏洞，攻击者需要将恶意库存储在系统或远程共享中目标计算机可访问的某个位置，并提前知道其文件路径。  
  
****  
**利用MHTML格式下载远程文件**  
  
攻击者选择利用受支持的MHTML文件格式的特定特性，以可预测的方式下载并存储其恶意组件到系统中。  
这种特殊类型的文件是Microsoft Word和Excel应用程序提供的一种导出格式，允许用户在浏览器中查看文档。  
通过在其中一个HTML文件中插入img标记，可以使电子表格应用程序在加载文档时下载远程文件。  
例如，图5显示了一个测试文件，其中img标记及其src元素指向本地存储的库。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3bpiaCWyzH25wqLvfF5YibDWCJicC6qDH7nbmeIjPibIZD69iba1p9BXsNgg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图5：img标签插入】  
  
  
当使用WPS spreadsheet et.exe应用程序打开电子表格文档时，远程库将自动下载并存储在磁盘上，如图6所示。  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3LQHyMxhYEUbC1AUUGUic9WNvEb9iaGXsWA9icznzJMk2IKpHpFwiceYibbQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图6：WPS电子表格应用程序下载并在系统上存储库】  
  
****  
**查找可预测的文件路径**  
  
至于可预测的文件路径问题，研究发现下载的文件存储在%localappdata%\Temp\wps\INetCache\下，文件名是用UTF‑16LE编码的URL的MD5哈希值。例如，研究人员的URL是http://localhost/Dll1.dll，MD5哈希值是914CBE6372D5B7C93ADDC4FEB5E964CD。但是，当试图将变量JSCefServicePath设置为指向这样的文件路径时，它被连接到位于%localappdata%\Kingsoft\WPS Office\<VERSION>\office6\下的WPS Office应用程序的根目录。如果找不到该文件，promecefpluginhost.exe将尝试从其他路径检索库，如图7所示。  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3dplmTYMmfMsK2MgXuLXuHRjiaJDiaakItN5g5JBndg6yiaqfoRViaSlqtg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图7：JSCefServicePath所指向的文件路径被追加到WPS Office的根目录】  
  
****  
**文件扩展问题**  
  
还有最后一个障碍需要克服。聪明的读者可能已经注意到，当promecefpluginhost.exe进程试图加载库时，.dll扩展名被附加到文件名中。如图6所示，在创建下载的文件时不附加扩展名。这个漏洞的作者再一次利用他们对Windows API的了解绕过了这个限制。如前所述，QLibrary::Load方法负责加载库，而库又调用LoadLibraryW。传递给该函数的lpLibFileName参数的文档说明，添加尾随点字符（.）可以防止该函数追加.dll扩展名。因此，将此字符附加到相对路径将允许加载库。  
  
****  
**复制漏洞利用**  
  
当把所有这些放在一起时，为了重现这个漏洞，研究人员遵循了以下步骤：  
- 在web服务器上托管一个自定义库。  
  
- 计算URL的MD5哈希值。  
  
- 构建相应的超链接。  
  
- 创建电子表格文档，插入超链接，并将其导出为MHTML文件。  
  
- 在导出的文件中插入一个img标记以指向URL。  
  
图8说明了如何构建超链接。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT33VVGib5kEWmCCZhMuW8jFt1nia2CzA3ia02Vd81ZX7dsTJLCjAdgMLXPA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图8：创建超链接】  
  
  
在打开文档之后，单击超链接就会触发漏洞，研究人员的定制库就会被加载，如图9所示，更详细地说，如图10所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3RPictXQnTBaq78Y0KEyNREEa5iaqWwKBnkr66hz9UNTqr8bUkMglZ5hg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图9：研究人员的自定义库被写入磁盘并加载】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3q4eWWAAic7icXWOdWdeianOSx6wiad268tUP1c6lGiaPfdSYPewUR7eia99Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图10：正在加载的库的调用堆栈详细信息】  
  
  
加载后，研究人员的自定义库将PID、管理员权限和托管进程的文件路径写入日志文件。研究人员还在不同版本的WPS Office for Windows上复制了这个漏洞，如图11所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3iawmj7zzwOZsSJicG0Xtaicol8m6ZWtJbsk7DnRscl6ggjX3u0D8MUYlw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图11：易受攻击的WPS Office版本的日志文件列表】  
  
  
由于这是一个一键式漏洞，因此开发人员在电子表格中嵌入了电子表格行和列的图片，以欺骗并说服用户该文档是一个普通的电子表格。恶意的超链接被链接到图像上，这样点击图片中的一个单元格就会触发攻击，如图12所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3rIIyJ5Hq2AicZR4UFZFAOwR5lkaaCVaZKmsicHvibYLkpUlDxYfBqWWuQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图12：嵌入常规行和列图像的欺骗性电子表格】  
  
  
关于这个漏洞的另一个有趣的事实是，它也可以通过在Windows资源管理器的预览窗格中单击一次触发，这使得它更加危险。  
###   
### 影响版本  
  
  
受影响的WPS Office for Windows版本范围从2023年8月左右发布的12.2.0.13110到2024年3月发布的12.1.0.16412版本补丁。这份武器化的文件于今年2月首次上传到VirusTotal；根据它们的PE时间戳，一些恶意组件是在2月份构建的。  
##   
  
**CVE-2024-7263**  
  
  
## 本节分析了CVE-2024-7262补丁，并通过劫持相同WPS Office插件组件promecefpluginhost.exe的控制流发现了另一个代码执行漏洞。  
###   
### 根本原因分析  
  
  
在确定哪些版本受到第一个漏洞影响的过程中，研究人员分析了12.1.0.16412版本（在2024年3月左右发布）中静默引入的补丁。结果显示，补丁增加了对JSCefServicePath变量的检查，但未对CefPluginPathU8变量进行类似检查。  
  
  
第一次检查发生在promecefpluginhost.exe迭代其不同的命令行参数时。如果参数与上述变量之一具有相同的名称（区分大小写比较），则该参数将被丢弃，如图13所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3icAovxbwkhLeQDgZKiawQZBuyjyCDWOhanhtT8pFsHQr7fAqhJrqaNYA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图13：检查和丢弃传递参数的代码】  
  
  
之后，它会检索JSCefServicePath的预期文件路径，其中jscefservice.dll应该存储在该路径中。真正的路径应该是%LOCALAPPDATA%\Kingsoft\WPS Office\<VERSION>\office6\addons\kcef\，如图14所示。对于CefPluginPathU8也是如此，真正的路径应该指向%LOCALAPPDATA%\Kingsoft\WPS Office\<VERSION>\office6\addons\cef\。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT37BV1YnZCeibvDRVvSticGTLAfS7CyE2scjBFRY8rj74WdbwVDTn9Daicg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图14：检索要加载的正确库的代码】  
  
  
使用接受的命令行参数构建一个新的命令行，其后是由命名变量标识的检索文件路径。promecefpluginhosts .exe随后加载ksojscore.dll库，并使用重建的命令行调用其导出CefRenderEntryPoint。检查两个命名的变量，但是这次比较不区分大小写（参见图15中的第2行）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3UeXmxakKcgkbSm7sUHqGJXXfGdhaLMlU0ib3yje6WPH03QGm7FknSxw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图15：选取变量不区分大小写】  
  
  
这是第一个逻辑缺陷。如果命名变量中至少有一个字母被更改为大写或小写，则第一次（区分大小写）检查将不会导致攻击者指定的参数被拒绝，并且命令行看起来如下所示（例如）：  
  
-JSCEfServicePath=<ATTACKER_CONTROLLED> <OTHER_PARAMETERS> -JSCEfServicePath=< REAL_PATH>（注意第一个变量名中第一个字母E的大小写变化）。  
  
  
当这样的命令行传递给ksojscore.dll时，它将只接受变量的第一次出现，并且攻击者控制的变量总是放在有效变量之前。  
  
  
但是，在加载JSCefServicePath文件路径给出的库之前，还需要进行第二次检查。调用函数krt::ksafe::KProcess::verifyZhuHaiKingsoftCertSigner来检查库的证书并确保它是属于金山的库，如图16所示。因此，攻击者无法加载任何任意库。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3JLcOPzCOllKwu6Nx0M7WaDMyWvyibkHpfBXMC9GNaqyOuia9NIs4HQrg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图16：检查正在加载的库的签名】  
  
  
但是，没有正确检查CefPluginPathU8变量。这是第二个缺陷。在验证JSCefServicePath文件路径后，加载库jscefservice.dll并使用CefPluginPathU8提供的文件路径连接字符串\libcef.dll调用LoadLibraryExW，而不检查其签名。  
  
  
如果变量CefPluginPathU8的至少一个字母被更改，jscefservice.dll将尝试加载存储在该变量给出的攻击者控制的文件路径下的libcef.dll库，如图17所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3YFMiamcfK0mOzAvnkiaYibIUMpYuOSNHGGia4OFiad77bBMTv7fuUYsWlibQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图17：jscefservice.dll加载攻击者定义的路径所指向的库，而不检查其签名】  
###   
### 漏洞利用方式  
  
  
此漏洞的主要约束是附加到文件路径的字符串libcef.dll。在写这篇博文时，研究人员尚未找到一种方法来下载文件并选择它的文件名。然而，在本地网络上，在共享上托管一个库并让变量CefPluginPathU8指向它可以工作，因为LoadLibraryExW允许指定网络路径。图18所示的屏幕截图说明了如何使用网络路径劫持promecefpluginhost.exe（12.2.0.16909版本，于2024年4月下旬发布）的控制流。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibHW7wfP8O1ghJz5xicEnJT3JdzEddTfvmmzXePJccuk6aMVNZDarq5BN0IibKvNgp1oROdggThxPtQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
【图18：显示自定义库加载的Procmon堆栈视图】  
###   
### 影响版本  
  
  
受影响的WPS Office for Windows版本范围从2023年8月左右发布的12.2.0.13110到2024年5月底发布的12.2.0.17119版本补丁。  
##   
  
**结论**  
  
  
##   
  
由于WPS Office是一个主要分布在亚洲的软件套件，APT-C-60展示了它对东亚国家目标的破坏程度。无论该组织是开发还是购买了CVE-2024-7262的漏洞，都肯定需要对应用程序的内部进行一些研究，还需要了解Windows加载过程的行为。这个漏洞很狡猾，因为它具有足够的欺骗性，可以欺骗任何用户点击看起来合法的电子表格，同时也非常有效和可靠。选择MHTML文件格式允许攻击者将代码执行漏洞转变为远程漏洞。  
  
  
此外，ESET发现的CVE-2024-7263强调了仔细的补丁验证过程以及确保核心问题得到完全解决的重要性。  
  
  
最后，ESET强烈建议WPS Office for Windows用户将其软件更新到最新版本。  
  
  
