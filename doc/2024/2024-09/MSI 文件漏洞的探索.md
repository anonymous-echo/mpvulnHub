#  MSI 文件漏洞的探索   
Ti  TIPFactory情报工厂   2024-09-02 19:12  
  
我们经常遇到 MSI 文件。开发者使用它们来提供和打包自己的程序。此格式比标准 EXE 格式更方便，原因如下：  
- 能够恢复、安装某些组件  
  
- 数据存储在结构化的表中，可以通过 API 轻松访问  
  
- 通过 SCCM、WEB 端点轻松分发  
  
MSI 文件内部可能存在各种漏洞，大部分漏洞都会导致**权限提升**，既包括逻辑漏洞：DLL/TypeLib/COM/Exe File/Script/etc 劫持、PATH 滥用，也包括 MSI 文件格式本身的漏洞：自定义操作滥用、废弃凭证、特权子进程。  
  
MSI 文件中的漏洞的参考信息：  
- https://cloud.google.com/blog/topics/threat-intelligence/privileges-third-party-windows-installers/  
  
- https://github.com/mandiant/msi-search  
  
- https://intezer.com/blog/incident-response/how-to-analyze-malicious-msi-installer-files/  
  
- https://blog.doyensec.com/2024/07/18/custom-actions.html  
  
- https://www.trendmicro.com/en_us/research/19/d/analysis-abuse-of-custom-actions-in-windows-installer-msi-to-run-malicious-javascript-vbscript-and-powershell-脚本.html  
  
- https://badoption.eu/blog/2023/10/03/MSIFortune.html  
  
推荐一个工具：MyMSIAnalyzer，对找MSI中的漏洞很有帮助。  
# MSI 文件格式  
  
MSI 格式本身与 SQL 数据库有些相似。MSI 文件内部有包含各种数据的表。表之间存在关系。并且在安装 MSI 文件时会分析和使用这个表。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5iccRJWRCIoZZUvxVJ2x5M1hbOlub3kqiax1ZN06KEHtuToKndjlDichFw/640?wx_fmt=png&from=appmsg "")  
  
完整的表格列表参考微软官方文档，只有几个我们需要特别关注：  
- Component Table组件表：一个特殊的表，应用程序所使用的资源（图像、快捷方式、图标等）；  
  
- 每个资源都与特定的功能相关联。因此，有一个Feature Table， ，它通过FeatureComponents Table链接到 Components Table ；  
  
- File Table文件表：指定应该在系统上安装哪些文件的表；  
  
- Directory Table目录表：包含要安装程序的文件夹结构信息的表；  
  
- Installation Actions安装操作— 包含在 MSI 文件安装期间要执行的操作的表（创建快捷方式、创建注册表项、写入值）；  
  
- Custom Actions自定义操作— 在安装过程中需要执行的操作，但是不能通过 Windows 安装程序 API 执行，因此使用第三方程序、DLL 文件、cmd 命令。  
  
# 从PC上找到可利用的MSI文件  
## 手动  
  
可以使用以下命令在PC上检查已安装的程序并进行映射：  
```
wmic product get identifyingnumber,name,vendor,version
```  
```
C:\Users\ops>wmic product get identifyingnumber,name,vendor,version
IdentifyingNumber                       Name                                                            Vendor                      Version
{AC669800-A797-444D-A450-A5109BBC74DE}  Python 3.12.4 Test Suite (64-bit)                               Python Software Foundation  3.12.4150.0
{EE615DC3-96ED-4BAD-8C76-ED4CCB561389}  Python 3.12.4 Add to Path (64-bit)                              Python Software Foundation  3.12.4150.0
{71BC2876-3319-44FC-B5C5-1C0B86FC2733}  Python 3.12.4 Tcl/Tk Support (64-bit)                           Python Software Foundation  3.12.4150.0
{4F815F87-CE9F-45CF-AEDE-EDF03728F8E6}  Python 3.12.4 Core Interpreter (64-bit)                         Python Software Foundation  3.12.4150.0
{7BFF8368-33A0-4DB3-9442-F5C881FE1B4D}  Python 3.12.4 Development Libraries (64-bit)                    Python Software Foundation  3.12.4150.0
{EFA83559-2E1E-4671-85F7-B28AA1DD08D7}  Python 3.12.4 pip Bootstrap (64-bit)                            Python Software Foundation  3.12.4150.0
{AC7F58DC-CF45-4B28-9EAE-AE152C588907}  Python 3.12.4 Documentation (64-bit)                            Python Software Foundation  3.12.4150.0
{754A267E-52AE-4A9F-AFF4-F67EDC4B3610}  Python 3.12.4 Executables (64-bit)                              Python Software Foundation  3.12.4150.0
{62DD7DAF-6279-46FA-A06B-C4A541244045}  Python 3.12.4 Standard Library (64-bit)                         Python Software Foundation  3.12.4150.0
{90160000-008C-0000-1000-0000000FF1CE}  Office 16 Click-to-Run Extensibility Component                  Microsoft Corporation       16.0.14332.20763
{90160000-008C-0804-1000-0000000FF1CE}  Office 16 Click-to-Run Localization Component                   Microsoft Corporation       16.0.17628.20110
{90160000-007E-0000-1000-0000000FF1CE}  Office 16 Click-to-Run Licensing Component                      Microsoft Corporation       16.0.17726.20108
{15EBE210-0A9C-4FCE-B15F-CB79C7EBEFFB}  Pandoc 3.3                                                      John MacFarlane             3.3
{A09F8381-88C3-44C4-9DAB-AC44F4F4DB4B}  Microsoft .NET Host - 6.0.32 (x64)                              Microsoft Corporation       48.128.16743
{0025DD72-A959-45B5-A0A3-7EFEB15A8050}  Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532  Microsoft Corporation       14.36.32532
{3FDCF0A2-7C1F-41C7-9749-0D91EC216AED}  Microsoft .NET Runtime - 6.0.32 (x64)                           Microsoft Corporation       48.128.16743
{667CB653-70E1-4E2B-9C8E-6A02A6CF88B9}  Microsoft .NET Host FX Resolver - 6.0.32 (x64)                  Microsoft Corporation       48.128.16743
{3C4935A5-B72E-4DA4-809E-0287A0BC046F}  Python Launcher                                                 Python Software Foundation  3.12.4150.0
{9AC08E99-230B-47e8-9721-4577B7F124EA}

{C2C59CAB-8766-4ABD-A8EF-1151A36C41E5}  Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532  Microsoft Corporation       14.36.32532
{885F1CFB-4EAC-4C60-97B8-394BD65ED91E}  Microsoft Windows Desktop Runtime - 6.0.32 (x64)                Microsoft Corporation       48.128.16742
{5781DE7C-B66B-4369-9E53-61A3F3F45281}  Go Programming Language amd64 go1.22.5                          https://go.dev              1.22.5
{C6FD611E-7EFE-488C-A0E0-974C09EF6473}  Microsoft Update Health Tools                                   Microsoft Corporation       5.72.0.0
{73F77E4E-5A17-46E5-A5FC-8A061047725F}  Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532     Microsoft Corporation       14.36.32532
{D5D19E2F-7189-42FE-8103-92CD1FA457C2}  Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532     Microsoft Corporation       14.36.32532
```  
  
也可以使用 Powershell 并通过软件名称添加过滤器。  
```
Get-WmiObject -class Win32_Product | ? { $_.Name -like "*Office*" } | select IdentifyingNumber,Name
```  
## 工具  
  
当然，使用自动化工具来收集信息和MSI文件本身会更方便。  
- https://github.com/mandiant/msi-search - 此工具可用于搜索 msi 文件，直接在受害者的机器上分析它们以检测权限提升的可能方法（可以使用MyMSIAnalyzer工具分析权限提升向量:) ）；  
  
- https://github.com/1njected/CMLoot — 非常适合从 SCCM 中提取 MSI 文件。例如，从分发点：  
  
```
PS> Invoke-CMLootInventory -SCCMHost sccm01.domain.local -Outfile sccmfiles.txt
PS> Invoke-CMLootDownload -InventoryFile .\sccmfiles.txt -Extension msi
```  
- https://github.com/shelltrail/cmloot — CMLoot 的 python 版本。  
  
## web  
  
你也可以在互联网上找到要分析的文件。例如，你可以使用 Google Dorks：  
```
ext:msi "download"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd54XQbfrnAtm3YAVe9fEnKH2m6icCmSdLDsiahc6Abfk7iboMxOHbR66SeA/640?wx_fmt=png&from=appmsg "")  
  
或者使用带有 MSI 文件列表的特殊资源：  
- https://github.com/microsoft/winget-pkgs  
  
- https://sourceforge.net/projects/msi-installers/  
  
# 寻找漏洞  
## 废弃凭证  
  
这是最简单的选择。在 MSI 文件中，有可能找到我们作为攻击者可能感兴趣的剩余密码、API 密钥、端点和其他数据。MyMSIAnalyzer 中有一个CredFinder类用于凭证发现。凭证搜索非常简单。它会检查 MSI 文件的所有属性，并尝试通过关键字查找敏感信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5HPayK7dsTNoiaCiaOpGBApXCs4gh9wic3tGk42r6PA3c5HhZsZpfGo5bw/640?wx_fmt=png&from=appmsg "")  
  
由于 MSI 格式接近 SQL 格式，因此您可以通过一个查询获取所有属性。，下面是具有相同逻辑的 Powershell 脚本：  
```
$installerPath = "C:\Windows\Installer"
$package = New-Object -ComObject WindowsInstaller.Installer

function AnalyzeMsiFile {
    param (
        [string]$msiPath
    )
    try {
        $database = $package.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $package, @($msiPath, 0))
        $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @("SELECT * FROM Property"))

        $view.Execute()
        while ($record = $view.Fetch()) {
            $property = $record.StringData(1)
            $value = $record.StringData(2)
            if ($property -match "USERNAME|PASSWORD|USER|PASS") {
                Write-Host "File: $msiPath, Property: $property, Value: $value"
            }
        }
    } catch {
        Write-Host "Error processing file: $msiPath" -ForegroundColor Red
    }
}

Get-ChildItem -Path $installerPath -Filter *.msi -Recurse | ForEach-Object {
    AnalyzeMsiFile $_.FullName
}
```  
# 行为分析  
## MSI 修复模式  
  
MSI 内部凭证很少被发现。通常只有在分析从 SCCM 窃取的 MSI 文件时才会发现。因此，如果我们要寻找特权提升向量，我们需要分析 MSI 文件的行为。  
  
这里我们需要熟悉一个不寻常的功能：MSI 文件修复机制。  
  
MSI 的修复机制允许 Windows 系统重新安装整个产品或产品中的个别组件。实际上，如果在使用或安装过程中出现问题，可以修复程序。  
  
使用 CLI 工具msiexec可以最方便地使用此功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5oibEEIINqM3DwLCxl2D7iaLPU0JYK388NyjFHlb6u0TZOtkjq8xkrfvg/640?wx_fmt=png&from=appmsg "")  
  
此外，由 MSI 文件开发人员创建的 MSI 自定义操作会在恢复模式下被调用。这里也可能存在漏洞，如果自定义操作或整个 MSI 文件配置错误，则恢复过程将以 NT AUTHORITY\SYSTEM 用户的名义执行，这使我们能够提升权限。  
  
例如，如果开发人员已将自定义操作设置为运行 cmd.exe，则在正常安装期间 cmd.exe 将以当前用户身份运行，但在**恢复期间**它将以系统用户身份运行。  
  
还可以通过自定义操作代表系统运行一些图形应用程序，从中可以模拟 Kiosk Bypass，退出 explorer.exe 并从中运行 cmd.exe。cmd.exe 将代表系统启动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd50icgdTZbMP0nYpFJ6YLwfWAYYYrtrWkMqqlulGoPiaVUZYRlNicKn8aeg/640?wx_fmt=png&from=appmsg "")  
  
自定义操作中的 GUI 滥用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5AFRe2ZDKia3Wy9eIWhdTO2vHuGtcvJWExXPUV8LOgdXibEdtkUuocyHg/640?wx_fmt=png&from=appmsg "")  
  
Internet Explorer 安装程序中的滥用示例  
## 如何检测  
  
让我们从检查整个 MSI 文件开始。我们只需要监控两件事：  
- 如果我们想通过 explorer.exe 逃逸进行升级，则需要监控 GUI 界面的存在  
  
- 如果我们想检查文件中是否存在其他漏洞（例如 DLL 劫持），则需要监控在恢复模式下运行 MSI 文件的用户的名称  
  
检测此类 MSI 文件的最简单方法是使用GuiFinder工具：  
```
.\GuiFinder.exe --folder C:\Temp
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5W8E0acweYwMsohzHmTsVu7ribQpALjL41vwwibyTINQoV7BU6vxYvjhA/640?wx_fmt=png&from=appmsg "")  
  
如果您发现自己从 NT AUTHORITY\System 运行，并且存在图形界面，则可以尝试按照上述方法退出环境。  
## 自定义操作  
  
自定义操作也可以代表 NT AUTHORITY\SYSTEM 执行。为此，必须使用 Impersonate=“no”选项配置它们。例如，如下所示  
```
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="{12345678-9259-4E29-91EA-8F8646930000}" Language="1033" Manufacturer="YourCompany" Name="HelloInstaller" UpgradeCode="{12345678-9259-4E29-91EA-8F8646930001}" Version="1.0.0.0">
        <Package Comments="This installer database contains the logic and data required to install HelloInstaller." Compressed="yes" Description="HelloInstaller" InstallerVersion="200" Languages="1033" Manufacturer="YourCompany" Platform="x86" ReadOnly="no" />

        <CustomAction Id="SetRunCommand" Property="RunCommand" Value="[%USERPROFILE]\test.exe" Execute="immediate" />
        <CustomAction Id="RunCommand" BinaryKey="WixCA" DllEntry="WixQuietExec64" Execute="commit" Return="ignore" Impersonate="no" />
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFilesFolder">
                <Directory Id="INSTALLFOLDER" Name="HelloInstaller" ShortName="krp6fjyg">
                    <Component Id="ApplicationShortcut" Guid="{12345678-9259-4E29-91EA-8F8646930002}" KeyPath="yes">
                        <CreateFolder Directory="INSTALLFOLDER" />
                    </Component>
                </Directory>
            </Directory>
        </Directory>
        <Property Id="ALLUSERS" Value="1" />
        <Feature Id="ProductFeature" Level="1" Title="Main Feature">
            <ComponentRef Id="ApplicationShortcut" />
        </Feature>
        <MajorUpgrade DowngradeErrorMessage="A newer version of [ProductName] is already installed." Schedule="afterInstallValidate" />

        <InstallExecuteSequence>
            <Custom Action="SetRunCommand" After="InstallInitialize">1</Custom>
            <Custom Action="RunCommand" After="SetRunCommand">1</Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>
```  
  
这将导致自定义操作以 NT AUTHORITY\SYSTEM 的名义运行。我们创建了一个ActionAnalyzer类来分析自定义操作。  
  
首先，我们还突出显示了自定义操作中会导致权限提升的关键字。毕竟，滥用此功能很容易。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5tGwJrz1n7rWsMZ2fM25ZNPkYr0MHE6liaQzCtibNyWTdzn6FgHX3Iyiag/640?wx_fmt=png&from=appmsg "")  
  
然后，该工具检查自定义操作是否原则上会被调用。为此，它们必须位于 InstallExecuteSequence 和 InstallFinalize 之间的调用序列中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5UgbvBm3X4l2llpoJJt9PiaNDVrbwWXZe0Mchq1vVcr3Onk7IcuCKyxQ/640?wx_fmt=png&from=appmsg "")  
  
获取序列索引  
  
这些索引的验证稍后完成。获取索引后，我们提取所有自定义操作并检查最重要的参数 Impersonate: NO  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd58I9icMQfCnM8oCvRLXibqFqlOUibKcPVDe52PwDKd9KOAyL6Toz3JNafw/640?wx_fmt=png&from=appmsg "")  
  
确保自定义操作代表系统执行并且符合正确的操作序列后，将执行关键字检查  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5ru6zfohALGliaBFvbJVAy8KBA51EVPG1uIib6OeZc64jnBwG9OXlaKvg/640?wx_fmt=png&from=appmsg "")  
  
关键字检查  
  
运行该工具示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5XVXYRxDblvWMGKias8241datCxfx9SvibiaXemlwAQcusoKia3mJb8MttA/640?wx_fmt=png&from=appmsg "")  
  
然后，该工具会调出一些有趣的 CustomActions。然后您就可以开始寻找滥用它们的方法。例如，执行 DLL 侧载、从用户可写路径启动文件、查找另一个漏洞。涵盖了滥用 CustomActions 的最常见方法示例：  
- https://blog.doyensec.com/2024/07/18/custom-actions.html  
  
- https://badoption.eu/blog/2023/10/03/MSIFortune.html  
  
示例漏洞：  
- CVE-2023-26077（MSI 安装程序 DLL 劫持）  
  
- CVE-2023–21800（符号链接滥用）  
  
- CVE-2023–26078（转至 cmd.exe）  
  
## 自定义操作覆盖  
  
还有一个更有趣的方法。我们可以找到一个代表系统运行的 CustomAction。但是我们可能无法使用它。在这种情况下，我们可以尝试覆盖它！当然，如果 MSI 文件的权限允许的话。在某些情况下，管理员会覆盖默认的 DACL，这会导致特权提升。  
  
为了找到这个向量，MyMSIAnalyzer工具包创建了一个Writer类。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5DKL8h8cYR0my8RqDUmfaicHH4NIiaw5Pq5uMGub06PxNjJancn3uYsqg/640?wx_fmt=png&from=appmsg "")  
## 差异  
  
MSI 文件既包含漏洞，又修复了漏洞！因此，我们需要一种方便的方法来实现两个文件的差异来分析补丁。  
  
最简单的方法是使用msidiff：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPCLBuONer5nFWbIc6Ev0WStbQEYgFd5nyOxmZl5ZSjOngozUH8ogdG1kWoXSFgHru24EZVywft2jpDvIpFX1Q/640?wx_fmt=png&from=appmsg "")  
  
Diff 示例  
# 结论  
  
MSI 文件在 Windows 基础架构中被广泛使用。如果开发或部署此类文件的方法不当，则可能导致主机权限提升。  
  
  
