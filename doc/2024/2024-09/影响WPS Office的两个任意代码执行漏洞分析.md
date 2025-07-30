#  影响WPS Office的两个任意代码执行漏洞分析   
三沐  三沐数安   2024-09-03 19:15  
  
在 Windows 版 WPS Office 中发现了一个代码执行漏洞 (CVE⁠-⁠2024⁠-⁠7262)，该漏洞正被与韩国结盟的网络间谍组织 APT-C-60 利用。在分析了根本原因后，我们随后发现了另一种利用该错误代码的方法 (CVE-2924-7263)。经过协调披露流程后，这两个漏洞现已得到修补 - 在此博文中，我们提供了技术细节。   
- APT-C-60 利用 Windows 版 WPS Office 中的代码执行漏洞（CVE-2024-7262）来针对东亚国家发动攻击。  
  
- 本文提供了此漏洞的根本原因分析及其武器化的描述。  
  
- 对该漏洞的研究使 ESET 研究人员发现了利用该漏洞 (CVE-2024-7263) 的替代途径。  
  
  
## 概述  
  
在调查 APT-C-60 活动时，我们发现了一份奇怪的电子表格文档，其中引用了该组织众多下载器组件之一。通过分析，我们发现 APT-C-60 在野外利用 WPS Office for Windows 中的代码执行漏洞，针对东亚国家/地区发起攻击。最终的有效载荷是一个自定义后门，我们内部将其命名为 SpyGlace，  
ThreatBook 公开记录  
为TaskControler.dll。  
  
根据  
WPS 网站  
，该软件在全球拥有超过 5 亿活跃用户，因此它成为东亚地区大量个人攻击的良好目标。在我们协调的漏洞披露过程中，DBAPPSecurity 独立发布了[对武器化漏洞的分析](https://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247496709&idx=1&sn=0629689057d2e4c43b1adf59fb75f46a&scene=21#wechat_redirect)  
  
，并确认 APT-C-60 已利用该漏洞向中国用户传播恶意软件。  
  
该恶意文档（SHA-1：7509B4C506C01627C1A4C396161D07277F044AC6）是常用 XLS 电子表格格式的  
MHTML导出文件。但是，它包含一个特制的隐藏超链接，如果在使用 WPS 电子表格应用程序时单击该超链接，则会触发任意库的执行。这种非常规的  
MHTML文件格式允许在打开文档后立即下载文件；因此，在利用漏洞的同时利用此技术可以实现远程代码执行。图 1 显示了文档在 WPS 电子表格中的显示方式：引用  
Coremail  
电子邮件解决方案的行和列图像，用作诱饵。该图像隐藏了恶意超链接。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicausoQ8jdafsicJbEoAnkcx6gYuuQ9qjd28WPZia4aSf3CiaF740rdRFzgg/640?wx_fmt=png&from=appmsg "")  
  
按照我们  
协调的漏洞披露  
政策，从武器化文档上传到 VirusTotal 到本文发布，我们观察到以下时间线：  
- 2024-02-29：CVE-2024-7262 的漏洞利用文档已上传至 VirusTotal。  
  
- 2024-03-??：金山发布了一个更新，悄悄修补了 CVE-2024-7672 漏洞，因此 2024-02-29 漏洞不再有效。这是通过分析 2024-03 至 2024-04 之间所有可访问的 WPS Office 版本后得出的结论，因为金山在尝试修复此漏洞时并未特别提供其操作的精确细节。  
  
- 2024-04-30：我们分析了来自 VirusTotal 的恶意文档，发现它正在积极利用 CVE-2024-7262，这是文档首次使用时的一个零日漏洞。我们还发现金山毒霸的静默补丁仅解决了部分错误代码，其余有缺陷的代码仍然可被利用。  
  
- 2024-05-25：我们联系了金山软件，报告了我们的发现。虽然第一个漏洞已经修复，但我们询问他们是否可以创建 CVE 条目和/或公开声明，就像他们对  
CVE-2022-24934  
所做的那样。  
  
- 2024-05-30：金山软件承认了这些漏洞并告诉我们会及时更新信息。  
  
- 2024-06-17：我们要求更新。  
  
- 2024-06-22：金山软件告诉我们开发团队仍在努力解决这个问题，并计划在即将推出的版本中修复这个问题。  
  
- 2024-07-31：根据后续测试，我们发现 CVE-2024-7263 已被悄悄修复，我们告知金山软件已预留并正在准备 CVE-2024-7262 和 CVE-2024-7263。  
  
- 2024-08-11：DBAPPSecurity 团队独立发布了其调查结果。  
  
- 2024-08-15：  
CVE-2024-7262  
和  
CVE-2024-7263  
发布。  
  
- 2024-08-16：我们要求金山软件进行另一次更新。  
  
- 2024-08-22：金山软件承认已于 5 月底修复了 CVE-2024-7263，这与该公司在 2024-06-22 声称其开发团队“仍在努力解决该问题”的说法相矛盾。  
  
- 2024-08-28：金山软件已承认这两个漏洞，并已修复。但是，该公司表示无意公开 CVE-2024-7262 的野外利用情况，因此我们现在发布此博文，以警告金山软件的客户，由于 CVE-2024-7262 漏洞和漏洞利用的野外利用和第三方披露，他们应紧急更新 WPS Office，这增加了进一步利用的机会。  
  
CVE-2024-7262 漏洞源于攻击者提供的文件路径未经过清理，以及加载插件未经过验证。在分析其补丁后，我们发现了另一种利用该漏洞的方法，即利用另一个逻辑错误。  
## CVE-2024-7262  
  
本节介绍 APT-C-60 利用的漏洞，该漏洞通过劫持 WPS Office 插件组件  
promecefpluginhost.exe  
的控制流来执行代码。我们还解释了如何触发该漏洞，并将其以看似合法的电子表格文档的形式武器化。  
### 根本原因分析  
  
在安装 Windows 版 WPS Office 时，该软件套件会注册一个名为  
ksoqing  
的自定义协议处理程序，该处理程序允许在用户单击以 URI 方案  
ksoqing://  
开头的 URL 时执行外部应用程序。在 Windows 操作系统中，  
自定义协议处理程序的注册  
在注册表中完成。在本例中，  
HKCR\ksoqing\shell\open\command  
项下的默认值指示 Windows使用参数  
/qingbangong "%1"  
执行  
C:\Users\<USER>\AppData\Local\Kingsoft\WPS Office\<VERSION>\office6\wps.exe，  
其中  
%1  
被替换为完整 URL。为了说明这一点，图 2 显示了当用户使用  
WPS 电子表格应用程序 (   
et.exe  
 )中的自定义协议  
ksoqing单击超链接时发生的情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhica1ia5icQMPwawt6SAmv8h224epTlFnracyqFIGnpukvErbjI2LhQrKnFQ/640?wx_fmt=png&from=appmsg "")  
  
图 3 概述了 CVE-2024-7262 漏洞的控制流。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaothnxDhojsFlaOyfNKSEoVtgQwZ1DiafYFmHZJtUiaF8IXSDCfSs0EFw/640?wx_fmt=png&from=appmsg "")  
  
ESET 研究人员在 Windows 版 WPS Office 中发现了一个代码执行漏洞 (CVE⁠-⁠2024⁠-⁠7262)，该漏洞正被与韩国结盟的网络间谍组织 APT-C-60 利用。在分析了根本原因后，我们随后发现了另一种利用该错误代码的方法 (CVE-2924-7263)。经过协调披露流程后，这两个漏洞现已得到修补 - 在此博文中，我们提供了技术细节。   
> 博文的要点：  
> APT-C-60 利用 Windows 版 WPS Office 中的代码执行漏洞（CVE-2024-7262）来针对东亚国家发动攻击。本文提供了此漏洞的根本原因分析及其武器化的描述。对该漏洞的研究使 ESET 研究人员发现了利用该漏洞 (CVE-2024-7263) 的替代途径。  
  
## 概述  
  
在调查 APT-C-60 活动时，我们发现了一份奇怪的电子表格文档，其中引用了该组织众多下载器组件之一。通过分析，我们发现 APT-C-60 在野外利用 WPS Office for Windows 中的代码执行漏洞，针对东亚国家/地区发起攻击。最终的有效载荷是一个自定义后门，我们内部将其命名为 SpyGlace，  
ThreatBook 公开记录  
为  
TaskControler.dll  
。  
  
根据  
WPS 网站  
，该软件在全球拥有超过 5 亿活跃用户，因此它成为东亚地区大量个人攻击的良好目标。在我们协调的漏洞披露过程中，DBAPPSecurity 独立发布了[对武器化漏洞的分析](https://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247496709&idx=1&sn=0629689057d2e4c43b1adf59fb75f46a&scene=21#wechat_redirect)  
  
，并确认 APT-C-60 已利用该漏洞向中国用户传播恶意软件。  
  
该恶意文档（SHA-1：  
7509B4C506C01627C1A4C396161D07277F044AC6  
）是  
常用 XLS 电子表格格式的  
MHTML导出文件。但是，它包含一个特制的隐藏超链接，如果在使用 WPS 电子表格应用程序时单击该超链接，则会触发任意库的执行。这种非常规的  
  
MHTML文件格式允许在打开文档后立即下载文件；因此，在利用漏洞的同时利用此技术可以实现远程代码执行。图 1 显示了文档在 WPS 电子表格中的显示方式：引用  
  
Coremail  
电子邮件解决方案的行和列图像  
，用作诱饵。该图像隐藏了恶意超链接。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicausoQ8jdafsicJbEoAnkcx6gYuuQ9qjd28WPZia4aSf3CiaF740rdRFzgg/640?wx_fmt=png&from=appmsg "图 1. 漏洞文档嵌入了一张隐藏恶意超链接的图片")  
  
图 1. 漏洞文档嵌入了一张隐藏恶意超链接的图片  
  
按照我们  
协调的漏洞披露  
政策，从武器化文档上传到 VirusTotal 到本文发布，我们观察到以下时间线：  
- 2024-02-29：CVE-2024-7262 的漏洞利用文档已上传至 VirusTotal。  
  
- 2024-03-??：金山发布了一个更新，悄悄修补了 CVE-2024-7672 漏洞，因此 2024-02-29 漏洞不再有效。这是通过分析 2024-03 至 2024-04 之间所有可访问的 WPS Office 版本后得出的结论，因为金山在尝试修复此漏洞时并未特别提供其操作的精确细节。  
  
- 2024-04-30：我们分析了来自 VirusTotal 的恶意文档，发现它正在积极利用 CVE-2024-7262，这是文档首次使用时的一个零日漏洞。我们还发现金山毒霸的静默补丁仅解决了部分错误代码，其余有缺陷的代码仍然可被利用。  
  
- 2024-05-25：我们联系了金山软件，报告了我们的发现。虽然第一个漏洞已经修复，但我们询问他们是否可以创建 CVE 条目和/或公开声明，就像他们对  
CVE-2022-24934  
所做的那样。  
  
- 2024-05-30：金山软件承认了这些漏洞并告诉我们会及时更新信息。  
  
- 2024-06-17：我们要求更新。  
  
- 2024-06-22：金山软件告诉我们开发团队仍在努力解决这个问题，并计划在即将推出的版本中修复这个问题。  
  
- 2024-07-31：根据后续测试，我们发现 CVE-2024-7263 已被悄悄修复，我们告知金山软件已预留并正在准备 CVE-2024-7262 和 CVE-2024-7263。  
  
- 2024-08-11：DBAPPSecurity 团队独立发布了其调查结果。  
  
- 2024-08-15：  
CVE-2024-7262  
和  
CVE-2024-7263  
发布。  
  
- 2024-08-16：我们要求金山软件进行另一次更新。  
  
- 2024-08-22：金山软件承认已于 5 月底修复了 CVE-2024-7263，这与该公司在 2024-06-22 声称其开发团队“仍在努力解决该问题”的说法相矛盾。  
  
- 2024-08-28：金山软件已承认这两个漏洞，并已修复。但是，该公司表示无意公开 CVE-2024-7262 的野外利用情况，因此我们现在发布此博文，以警告金山软件的客户，由于 CVE-2024-7262 漏洞和漏洞利用的野外利用和第三方披露，他们应紧急更新 WPS Office，这增加了进一步利用的机会。  
  
CVE-2024-7262 漏洞源于攻击者提供的文件路径未经过清理，以及加载插件未经过验证。在分析其补丁后，我们发现了另一种利用该漏洞的方法，即利用另一个逻辑错误。  
## CVE-2024-7262  
  
本节介绍 APT-C-60 利用的漏洞，该漏洞通过劫持 WPS Office 插件组件  
promecefpluginhost.exe  
的控制流来执行代码。我们还解释了如何触发该漏洞，并将其以看似合法的电子表格文档的形式武器化。  
### 根本原因分析  
  
在安装 Windows 版 WPS Office 时，该软件套件会注册一个名为  
ksoqing  
的自定义协议处理程序，该处理程序允许在用户单击以 URI 方案  
ksoqing://  
开头的 URL 时执行外部应用程序。在 Windows 操作系统中，  
自定义协议处理程序的注册  
在注册表中完成。在本例中，  
HKCR\ksoqing\shell\open\command  
项下的默认值指示 Windows使用参数  
/qingbangong "%1"  
执行  
C:\Users\<USER>\AppData\Local\Kingsoft\WPS Office\<VERSION>\office6\wps.exe，  
其中  
%1  
被替换为完整 URL。为了说明这一点，图 2 显示了当用户使用  
WPS 电子表格应用程序 (   
et.exe  
 )中的自定义协议  
ksoqing单击超链接时发生的情况。  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhica1ia5icQMPwawt6SAmv8h224epTlFnracyqFIGnpukvErbjI2LhQrKnFQ/640?wx_fmt=png&from=appmsg "")  
  
图 2. WPS 电子表格应用程序启动  
wps.exe来处理自定义协议 ksoqing  
  
图 3 概述了 CVE-2024-7262 漏洞的控制流。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaothnxDhojsFlaOyfNKSEoVtgQwZ1DiafYFmHZJtUiaF8IXSDCfSs0EFw/640?wx_fmt=png&from=appmsg "")  
  
图 3. 漏洞利用控制流概述  
  
启动后，  
wps.exe  
会加载  
qingbangong.dll  
，该组件负责解析和验证超链接中的某些参数。我们在漏洞文件中发现的恶意链接格式为  
ksoqing://type=ksolaunch&cmd=<base64-encoded string>&token=<MD5 hash>&launchname=promecefpluginhost.exe  
 。根据我们的分析和测试，这会导致使用攻击者提供的 base64 编码命令  
行启动系统中已经存在的应用程序（在本例中为  
promecefpluginhost.exe ）。  
  
token  
参数是 cmd 参数编码值的 MD5 哈希值，该值与字符串  
_qingLaunchKey_  
连接  
，后跟 launchname 参数的编码值。最后一个必须是位于  
C:\Users\<USER>\AppData\Local\Kingsoft\WPS Office\<VERSION>\office6\  
下的可执行文件，并使用金山软件的有效证书进行签名。  
  
  
  
  
  
解码cmd  
参数后  
，我们发现命令行  
/qingbangong -CefParentID=1 -JSCefServicePath=<base64-encoded file path>  
被传递给了  
promecefpluginhost.exe  
。经过一些初始化后，库  
ksojscore.dll  
被加载并解码  
JSCefServicePath  
参数。结果是一个字符串，作为参数传递给  
Qt 的 QLibrary::load  
方法。这个文件路径是攻击者定义的，这意味着攻击者可以通过加载任意 DLL 来实现代码执行。图4说明了  
ksojscore.dll  
如何处理攻击者控制的  
JSCefServicePath  
参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicabDoHicIGPFUKliaxgvYMVo6b6ccyK8tWmBJr9po5GI8RbslKVUamicvyw/640?wx_fmt=png&from=appmsg "")  
  
本质上，可以滥用  
ksoqing  
方案协议并创建一个超链接，单击该超链接时将从给定的远程文件路径加载库。APT-C-60 利用该漏洞执行其第一阶段木马下载程序组件（SHA-1：  
08906644B0EF1EE6478C45A6E0DD28533A9EFC29  
）。  
### 利用漏洞  
  
为了利用此漏洞，攻击者需要将恶意库存储在目标计算机可访问的某个位置（无论是在系统上还是在远程共享上），并提前知道其文件路径。此漏洞的利用开发人员知道一些帮助他们实现此目的的技巧。  
#### 利用 MHTML 格式下载远程文件  
  
该漏洞的作者选择利用受支持的 MHTML 文件格式的特定功能，以可预测的方式下载并存储其恶意组件。这种特定类型的文件是 Microsoft Word 和 Excel 应用程序提供的一种导出格式，允许用户在其浏览器中查看文档。它是一个  
多部分存档  
，包含 HTML、CSS 和 JavaScript 文件，方便显示文档。通过在其中一个 HTML 文件中插入  
img  
标记，可以让电子表格应用程序在加载文档时下载远程文件。例如，图 5 显示了我们的一个测试文件，其中  
img  
标记及其  
src  
元素指向本地存储的库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicawUSoJCorfTrN7kmReTk9VvwW5fGRBplpXb305YfqAwsJUJaSq7IRYQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
当使用 WPS Spreadsheet et.exe  
应用程序打开电子表格文档时  
，远程库会自动下载并存储在磁盘上，如图 6 所示，使用 ProcMon 观察到的那样。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaT0MGaGa4PLiaYredsLgm574UrKRP1VLYEljKFATAQDc2J31kbKmSbww/640?wx_fmt=png&from=appmsg "")  
#### 查找可预测的文件路径  
  
至于可预测的文件路径问题，我们发现下载的文件存储在  
%localappdata%\Temp\wps\INetCache\  
下，文件名是使用 UTF-16LE 编码的 URL 的 MD5 哈希值。例如，我们的 URL 是  
http://localhost/Dll1.dll  
，其 MD5 哈希值为  
914CBE6372D5B7C93ADDC4FEB5E964CD  
。但是，当尝试将变量  
JSCefServicePath设置为指向此类文件路径时，它会连接到位于  
  
%localappdata%\Kingsoft\WPS Office\<VERSION>\office6\  
下的 WPS Office 应用程序的根目录  
。如果找不到该文件，  
promecefpluginhost.exe  
将尝试从其他路径检索库，如图 7 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaoSjZWeJumeCv8J3cLLbEmpCqdByoPMBclDfgege68bjmPtw4W4icMgA/640?wx_fmt=png&from=appmsg "")  
  
但是，可以使用 WPS Office 应用程序根目录的相对路径，例如  
..\..\..\..\Temp\wps\INetCache\914cbe6372d5b7c93addc4feb5e964cd  
。  
#### 文件扩展名问题  
  
还有最后一个障碍需要克服。精明的读者可能已经注意到，当  
promecefpluginhost.exe进程尝试加载库时，   
.dll  
扩展名会附加到文件名中  
。如图 6 所示，创建下载的文件时不会附加扩展名。漏洞利用者的作者再次利用他们对 Windows API 的了解来绕过此限制。如前所述，QLibrary   
::Load  
方法负责加载库，而库又会调用  
LoadLibraryW  
。传递给此函数  
的 lpLibFileName  
参数的文档指出，添加尾随点字符 (   
.  
 ) 可防止函数附加  
.dll  
扩展名。因此，将此字符附加到相对路径将允许我们的库被加载。  
### 重现漏洞  
  
总而言之，为了重现该漏洞，我们遵循了以下步骤：  
- 在 Web 服务器上托管自定义库。  
  
- 计算 URL 的 MD5 哈希值。  
  
- 建立相应的超链接。  
  
- 创建电子表格文档，插入超链接，并将其导出为 MHTML 文件。  
  
- 在导出的文件内插入一个  
img  
标签以指向 URL。  
  
图 8 说明了如何构建超链接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaxGr9TfQpBMa6TXOVv8KYCbeBDzicsevACVzeBm8S23FbDVTW3TVNJgA/640?wx_fmt=png&from=appmsg "")  
  
打开文档后，单击超链接就会触发漏洞，并且我们的自定义库会被加载，如图 9 所示，更详细的信息则如图 10 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaTkicGRd1icR74j7maEpsQJheOToQJCZAXI6uic7WD3JFiadOGdJjOZhcyg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaibxicB4alMreYrStZxrS8le6iazEYo4DWOt22dqSiaQC9VicEcZwf1ALRuA/640?wx_fmt=png&from=appmsg "")  
  
加载时，我们的自定义库会将 PID、管理员权限的存在以及托管进程的文件路径写入日志文件。我们针对 Windows 版 WPS Office 的不同版本重现了该漏洞，如图 11 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhica0zJGVV3MDft4u4sqSyZNB2xQVe5jnic65psXgb7U5pbVc0LOfj70P4A/640?wx_fmt=png&from=appmsg "")  
  
由于这是一个一键式漏洞，漏洞利用开发人员在电子表格中嵌入了电子表格行和列的图片，以欺骗用户并使其相信该文档是常规电子表格。恶意超链接链接到图像，因此单击图片中的单元格将触发漏洞利用，如图 12 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicahQUWTyVpTmLlHPWexLiav15vUDywhnQVKgpKNctM5qqznKSZxVOLyPA/640?wx_fmt=png&from=appmsg "")  
  
关于此漏洞的另一个有趣的事实是，它也可以通过在 Windows 资源管理器的预览窗格中单击来触发，这使得它更加危险。  
## CVE-2024-7263  
  
本节对 CVE-2024-7262 的补丁进行分析，并发现通过劫持同一个 WPS Office 插件组件的控制流可导致另一个代码执行漏洞：  
promecefpluginhost.exe  
。  
### 根本原因分析  
  
在确定哪些版本受到第一个漏洞影响的过程中，我们分析了版本 12.1.0.16412（2024 年 3 月左右发布）中悄悄引入的补丁，以缓解 CVE-2024-7262。本质上，我们在  
promecefpluginhost.exe  
和  
ksojscore.dll  
组件内部进行了额外的检查，以验证攻击者控制的变量  
JSCefServicePath  
。但是，补丁并未涵盖类似的变量：  
CefPluginPathU8  
。  
  
第一次检查发生在  
promecefpluginhost.exe  
迭代其不同的命令行参数时。如果某个参数与上述变量之一具有相同的名称（  
区分大小写  
比较），则该参数将被丢弃，如图 13 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicats5BRZiaZl13rm0ibB7W2Q3kmpPIQ9BZHyqiaQSBPW4NdULdVWFQXkiaOg/640?wx_fmt=png&from=appmsg "")  
  
  
之后，它会检索  
JSCefServicePath的预期文件路径，   
  
jscefservice.dll  
应该存储在  
该路径中。实际路径应为  
%LOCALAPPDATA%\Kingsoft\WPS Office\<VERSION>\office6\addons\kcef\  
，如图 14 所示。对  
CefPluginPathU8  
执行相同操作，其实际路径应指向  
%LOCALAPPDATA%\Kingsoft\WPS Office\<VERSION>\office6\addons\cef\  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaDT5TtMAuKibRgEWyPCkBJd6V7PaNZSneuico6zXl4D1HMKx11FKSdlOA/640?wx_fmt=png&from=appmsg "")  
  
使用接受的命令行参数构建新命令行，后跟命名变量标识的检索到的文件路径。然后，   
promecefpluginhost.exe  
加载库  
ksojscore.dll  
，并使用重建的命令行调用其导出  
CefRenderEntryPoint  
。检查两个命名变量，但这次比较  
不区分  
大小写（参见图 15 中的第 2 行）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaajWeNrPEic0cSjKTovTRia1t1nsabWmy53oR0B0KW5SjabX1QEK2wjTg/640?wx_fmt=png&from=appmsg "")  
  
这里存在第一个逻辑缺陷。如果命名变量中至少一个字母被更改为大写或小写，则第一次（区分大小写）检查将不会导致攻击者指定的参数被拒绝，命令行将如下所示（例如）：  
  
-JSC   
E  
 fServicePath=<ATTACKER_CONTROLLED> <OTHER_PARAMETERS> -JSCefServicePath=<REAL_PATH>  
（注意第一个变量名中第一个字母 E 的大小写变化）。  
  
当这样的命令行传递给  
ksojscore.dll  
时，它将仅获取第一次出现的变量，并且攻击者控制的变量始终放在有效变量之前。  
  
  
然而，在加载JSCefServicePath  
文件路径给出的库之前  
，引入了第二次检查。调用函数  
krt::ksafe::KProcess::verifyZhuHaiKingsoftCertSigner  
来检查库的证书，并确保它是属于金山的库，如图 16 所示。因此，攻击者无法加载任何任意库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicahUjBxDZxpdBY1PuxBzTgd6ldBJfxU99gZbZMT91hgXkVtdOWNIfdHw/640?wx_fmt=png&from=appmsg "")  
  
  
但是，  
CefPluginPathU8  
变量没有被正确检查。这里存在第二个缺陷。在验证  
JSCefServicePath  
文件路径后，库  
jscefservice.dll  
被加载，并使用  
CefPluginPathU8  
提供的文件路径  
与字符串  
\libcef.dll连接起来调用  
LoadLibraryExW  
，而不检查其签名。  
  
  
  
  
  
如果变量CefPluginPathU8  
中至少一个字母  
发生变化，  
jscefservice.dll  
将尝试加载  
存储在变量给出的攻击者控制的文件路径下的  
libcef.dll库，如图 17 所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicad7OR0Tz9BkHGK3S2hzWiaFLelP6nV3fYtynOJBh9VYZZXbO3d21Txag/640?wx_fmt=png&from=appmsg "")  
### 利用漏洞  
  
此漏洞的主要限制是附加到文件路径的字符串  
libcef.dll  
。截至撰写本文时，我们还没有找到下载文件并选择其文件名的方法。但是，在本地网络上，在共享上托管库并让变量  
CefPluginPathU8  
指向它是可行的，因为  
LoadLibraryExW  
允许指定网络路径。图 18 中显示的屏幕截图说明了如何使用网络路径劫持  
promecefpluginhost.exe  
 （版本 12.2.0.16909，2024 年 4 月下旬发布）的控制流。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8g18DptFHcaeGB6AqGDRhicaJTicMhFKBKUpUh3KUhJyPuHibSYib4U5WBj0cBiaG9HodKu2CM4IqeqbTg/640?wx_fmt=png&from=appmsg "")  
### 受影响的版本  
  
受影响的 Windows 版 WPS Office 版本范围从 2023 年 8 月左右发布的 12.2.0.13110 到 2024 年 5 月底发布补丁的 12.2.0.17119 版本。  
  
由于 WPS Office 是一款主要分布在亚洲的软件套件，APT-C-60 表明了其对东亚国家目标的攻击决心。无论该组织是开发还是购买了 CVE-2024-7262 的漏洞，都肯定需要对该应用程序的内部进行一些研究，还需要了解 Windows 加载过程的行为方式。该漏洞非常狡猾，因为它具有足够的欺骗性，可以诱骗任何用户点击看似合法的电子表格，同时还非常有效和可靠。选择 MHTML 文件格式使攻击者能够将代码执行漏洞转变为远程漏洞。  
  
此外，我们发现 CVE-2024-7263 强调了仔细的补丁验证过程以及确保核心问题得到完全解决的重要性。  
  
**强烈建议 Windows 版 WPS Office 用户将其软件更新到最新版本。**  
  
  
  
