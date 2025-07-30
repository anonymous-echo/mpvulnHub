#  Google Project Zero 的 Windows 漏洞研究：通过 IDispatch 访问受困 COM 对象的漏洞模式   
James Forshaw  securitainment   2025-02-07 08:50  
  
> Project Zero Windows Bug Class Accessing Trapped COM Objects with IDispatch  
  
  
面向对象的远程技术（如 DCOM 和 .NET Remoting）使得开发跨进程和安全边界的面向对象服务接口变得非常容易。这是因为它们被设计成支持广泛的对象类型，不仅限于服务自身实现的对象，还包括任何其他可远程化的兼容对象。例如，若要在客户端 - 服务器边界公开 XML 文档，可以使用现成的 COM 或 .NET 库并将该对象返回给客户端。默认情况下，当对象被返回时采用引用封送（marshaled by reference）方式，这会导致对象驻留在进程外服务器中。  
  
这种灵活性也带来诸多弊端，其中就包括本文要讨论的"受困对象漏洞模式"。并非所有可远程化的对象都具备安全远程化的条件。例如前文提到的 XML 库（包括 COM 和 .NET 版本）都支持在 XSLT 文档上下文中执行任意脚本代码。如果 XML 文档对象被跨边界公开，客户端就能在服务器进程上下文中执行代码，可能导致权限提升或远程代码执行。  
  
该漏洞模式可能通过多种场景引入。最常见的情况是不安全对象被无意间共享。  
CVE-2019-0555  
 就是典型案例。该漏洞的成因是：在开发 Windows 运行时库时需要 XML 文档对象，开发人员决定在现有 XML DOM Document v6 COM 对象中添加暴露运行时特定接口的代码。由于这些运行时接口不支持 XSLT 脚本功能，开发者认为跨权限边界暴露是安全的。但恶意客户端仍可查询到遗留的 IXMLDOMDocument 接口，利用其运行 XSLT 脚本突破沙箱。  
  
另一种场景涉及异步封送原语。当对象可同时通过值（by value）和引用（by reference）封送，而平台默认选择引用方式时就会产生风险。例如   
FileInfo  
 和   
DirectoryInfo  
 这两个 .NET 类都支持序列化，因此可以通过值封送发送到 .NET 远程服务。但它们同时继承自   
MarshalByRefObject  
 类，这意味着它们也可以通过引用封送。攻击者可向服务器发送对象的序列化形式，当反序列化时会在服务器进程中创建新实例。如果攻击者能回读创建的对象，运行时将使用引用封送将其传回，使对象受困于服务器进程。最终攻击者可调用对象方法（如创建新文件），这些操作将以服务器权限执行。该攻击已在我的   
ExploitRemotingService  
 工具中实现。  
  
最后一个与本文最相关的场景是滥用远程技术内置的对象查找和实例化机制来创建意外对象。例如在 COM 中，若能找到调用   
CoCreateInstance  
 API 的代码路径并传入任意 CLSID，使创建的对象被传回客户端，就能利用其在服务器上下文中执行任意代码。  
CVE-2017-0211  
 就是这类漏洞的典型，它通过安全边界暴露了   
Structured Storage  
 对象。该存储对象支持   
IPropertyBag  
 接口，可用于在服务器上下文中创建任意 COM 对象并传回客户端。攻击者可先在服务器创建 XML DOM Document 对象，通过引用封送返回客户端，再利用 XSLT 脚本功能在服务器上下文中执行任意代码实现提权。  
## IDispatch 的角色定位  
  
IDispatch  
 接口是 OLE 自动化功能的核心组件，也是 COM 的原始用例之一。它支持 COM 客户端与服务器之间的后期绑定，使得脚本语言（如 VBA 和 JScript）能够使用对象。该接口完全支持跨进程和权限边界，但更常见于 ActiveX 等进程内组件。  
  
为实现运行时调用 COM 对象，服务器必须向客户端暴露类型信息，以便客户端知道如何通过接口的   
Invoke  
 方法打包参数。这些类型信息存储在开发者定义的磁盘   
类型库  
 文件中，客户端可通过 IDispatch 接口的   
GetTypeInfo  
 方法查询该库。由于类型库接口的 COM 实现采用引用封送，返回的   
ITypeInfo  
 接口将受困于服务器，任何对其方法的调用都将在服务器上下文中执行。  
  
ITypeInfo 接口暴露了两个值得注意的方法：  
Invoke  
 和   
CreateInstance  
。Invoke 方法对本文用途不大，因为它不支持远程调用，只能在加载类型库的当前进程中调用。而 CreateInstance 支持远程调用，它通过调用 CoCreateInstance 从 CLSID 实例化 COM 对象，关键点在于创建的对象将位于服务器进程而非客户端。  
  
但查阅 API 文档会发现 CreateInstance 没有 CLSID 参数，那么类型库接口如何确定要创建的对象？ITypeInfo 接口可表示类型库中的任何类型。通过 GetTypeInfo 返回的类型信息仅包含客户端要调用的接口信息，因此调用 CreateInstance 会报错。但类型库还可以存储"CoClass"类型信息，这些类型定义了要创建对象的 CLSID，此时调用 CreateInstance 就能成功。  
  
如何从接口类型信息对象转换到类类型？ITypeInfo 接口提供了   
GetContainingTypeLib  
 方法，可返回包含它的 ITypeLib 接口引用。通过该接口可以枚举类型库支持的所有类。其中可能存在远程暴露时不安全的类。我们以   
OleView.NET  
 PowerShell 模块为例进行演示：首先查找支持 IDispatch 的 COM 服务目标，这将提供潜在的提权路径。  
```
PS> $cls = Get-ComClass -ServicePS> $cls | % { Get-ComInterface -Class $_ | Out-Null }PS> $cls | ? { $true -in $_.Interfaces.InterfaceEntry.IsDispatch } |         Select Name, ClsidName                                       Clsid----                                       -----WaaSRemediation                            72566e27-1abb-4eb3-b4f0-eb431cb1cb32Search Gathering Manager                   9e175b68-f52a-11d8-b9a5-505054503030Search Gatherer Notification               9e175b6d-f52a-11d8-b9a5-505054503030AutomaticUpdates                           bfe18e9c-6d87-4450-b37c-e02f0b373803Microsoft.SyncShare.SyncShareFactory Class da1c0281-456b-4f14-a46d-8ed2e21a866f
```  
  
通过 Get-ComClass 的 -Service 参数可以获取本地服务中实现的 COM 类。我们首先查询所有支持的接口，由于查询结果已存储在 Interfaces 属性中，因此无需关注该命令的输出。最终筛选出所有公开 IDispatch 接口的 COM 类，共得到 5 个候选对象。接下来我们将选取首个候选类 WaasRemediation，检查其类型库中是否存在有价值的类。  
```
PS> $obj = New-ComObject -Clsid 72566e27-1abb-4eb3-b4f0-eb431cb1cb32PS> $lib = Import-ComTypeLib -Object $objPS> Get-ComObjRef $lib.Instance | Select ProcessId, ProcessNameProcessId ProcessName--------- -----------    27020 svchost.exePS> $parsed = $lib.Parse()PS> $parsedName               Version TypeLibId----               -------- ---------WaaSRemediationLib 1.0      3ff1aab8-f3d8-11d4-825d-00104b3646c0PS> $parsed.Classes | Select Name, UuidName                          Uuid----                          ----WaaSRemediationAgent          72566e27-1abb-4eb3-b4f0-eb431cb1cb32WaaSProtectedSettingsProvider 9ea82395-e31b-41ca-8df7-ec1cee7194df
```  
  
该脚本首先创建 COM 对象，随后通过 Import-ComTypeLib 命令获取类型库接口。我们可以通过 Get-ComObjRef 进行封送处理并提取进程信息，验证类型库接口确实以跨进程方式运行于共享服务可执行文件 svchost.exe 实例中。通过接口直接检查类型库较为繁琐，为便于展示支持的类信息，我们使用 Parse 方法将库解析为更易操作的对象模型，随后即可导出库的详细信息（包括其支持的类列表）。  
  
遗憾的是，该 COM 对象类型库支持的类均已注册在服务中运行，因此我们未能获得新权限。我们需要的是仅在本地进程注册但通过类型库暴露的类。这种可能性确实存在，因为类型库可能同时被本地进程内组件和跨进程服务共享。  
  
笔者检查了其余 4 个 COM 类（其中 1 个因注册错误未被对应服务暴露），但未发现可利用的有效目标。此时您可能考虑放弃，但事实上存在可访问的隐藏类——这是因为类型库可以引用其他类型库，而后者可通过相同接口集进行检查。让我们具体分析：  
```
PS> $parsed.ReferencedTypeLibsName   Version TypeLibId----   ------- ---------stdole 2.0     00020430-0000-0000-c000-000000000046PS> $parsed.ReferencedTypeLibs[0].Parse().Classes | Select Name, UuidName       Uuid----       ----StdFont    0be35203-8f91-11ce-9de3-00aa004bb851StdPicture 0be35204-8f91-11ce-9de3-00aa004bb851PS> $cls = Get-ComClass -Clsid 0be35203-8f91-11ce-9de3-00aa004bb851PS> $cls.Servers           Key Value           --- -----InProcServer32 C:\Windows\System32\oleaut32.dll
```  
  
在本例中，我们可以使用 ReferencedTypeLibs 属性来展示解析类型库时遇到的所有引用库。可以看到仅有一个 stdole 库的条目，这基本上总是会被自动导入。如果运气好，可能还会发现其他可检查的导入库。我们可以解析 stdole 库来检查其类列表，该类型库导出了两个类。当我们检查 StdFont 的服务器配置时，可以发现它仅被指定为进程内创建，至此我们已锁定了一个潜在的漏洞挖掘目标类。为了获取 stdole 类型库的跨进程接口，我们需要找到引用该库的类型。这种引用关系的存在是因为通用接口（如 IUnknown 和 IDispatch）都定义在该库中，因此我们需要通过可直接访问的接口查询其基类型。让我们尝试在 COM 服务中创建该对象。  
```
PS> $iid = $parsed.Interfaces[0].UuidPS> $ti = $lib.GetTypeInfoOfGuid($iid)PS> $href = $ti.GetRefTypeOfImplType(0)PS> $base = $ti.GetRefTypeInfo($href)PS> $stdole = $base.GetContainingTypeLib()PS> $stdole.Parse()Name   Version TypeLibId----   ------- ---------stdole 2.0     00020430-0000-0000-c000-000000000046PS> $ti = $stdole.GetTypeInfoOfGuid("0be35203-8f91-11ce-9de3-00aa004bb851")PS> $font = $ti.CreateInstance()PS> Get-ComObjRef $font | Select ProcessId, ProcessNameProcessId ProcessName--------- -----------    27020 svchost.exePS>  Get-ComInterface -Object $ObjName                 IID                                  HasProxy   HasTypeLib----                 ---                                  --------   ----------...IFont                bef6e002-a874-101a-8bba-00aa00300cab True       FalseIFontDisp            bef6e003-a874-101a-8bba-00aa00300cab True       True
```  
  
我们通过结合使用   
GetRefTypeOfImplType  
（获取实现类型的引用类型）和   
GetRefTypeInfo  
（获取引用类型信息）这两个 API 来查询现有接口的基类型，然后使用 GetContainingTypeLib 获取被引用的类型库接口。通过解析该库我们可以确认已获取到 stdole 库。接下来我们获取 StdFont 类的类型信息并调用 CreateInstance 方法。通过检查对象的进程信息可以确认其确实被创建在进程外，结果显示它被限制在服务进程中。作为最终验证，我们可以查询对象的接口来证明这是一个字体对象。  
  
现在我们需要找到利用这两个类中任意一个的方法，首要问题是只有 StdFont 对象可以被访问。StdPicture 对象设置了检查机制来阻止跨进程使用。虽然我在字体对象中没有发现可利用的有效行为，但也没有投入太多时间深入研究。当然，如果有人想在这个类中寻找合适的漏洞，请自便。  
  
至此，至少在系统服务层面，这项研究陷入了死胡同。可能存在某些可通过沙箱访问的 COM 服务器，但对 AppContainer 可访问的服务器进行初步分析后，并未发现明显的候选目标。不过经过进一步思考，我意识到这可以作为一种注入技术应用于具有相同权限级别的进程。例如，我们可以通过   
TreatAs  
（视为）注册表键劫持 StdFont 的 COM 注册，将其指向其他可利用的类。这个替代类可以是诸如在目标进程中加载 JScript 引擎并执行脚本之类的可利用对象。  
  
虽然注入技术通常不在我的讨论范畴（这更偏向恶意软件领域），但存在一个可能引发有趣安全影响的场景：如果我们能借此注入到 Windows 受保护进程（Protected Process）会怎样？命运的安排总是充满戏剧性，我们刚刚分析的 WaaSRemediationAgent 类或许正是我们的入场券：  
```
PS> $cls = Get-ComClass -Clsid 72566e27-1abb-4eb3-b4f0-eb431cb1cb32PS> $cls.AppIDEntry.ServiceProtectionLevelWindowsLight
```  
  
当我们检查宿主服务的保护级别时，发现其配置为在 PPL-Windows 级别运行！让我们看看能否从这项研究中挖掘出一些价值。  
## 受保护进程注入技术  
  
我曾  
撰文  
（并做过技术分享）讨论过 Windows 受保护进程的代码注入技术。建议读者重新阅读该文章以更好地理解之前的注入攻击背景。但需要明确的是，微软并不将 PPL 视为安全边界，因此他们通常不会在安全公告中及时修复相关漏洞，但可能会在新版 Windows 中予以解决。  
  
其核心思路很简单：我们将重定向 StdFont 类的注册信息指向其他类，这样通过类型库创建时实际会在受保护进程中运行。选择使用 StdFont 类更具通用性，因为即使 WaaSRemediationAgent 被移除，我们也可以切换至其他 COM 服务器。我们只需要找到一个能在受保护进程中实现任意代码执行的合适类。  
  
但这种方法立即排除了 JScript 等脚本引擎。正如我在前文所述，代码完整性模块会明确阻止常见脚本引擎在受保护进程中加载。因此，我们需要寻找一个既能跨进程访问又能加载到受保护进程的类。我意识到一个可行方案是加载已注册的.NET COM 类。虽然我曾  
撰文  
讨论过.NET DCOM 的漏洞利用及其危险性，但此刻我们恰恰需要这种"缺陷特性"。  
  
该文章主要探讨了序列化原语的利用，但我通过 DCOM 使用  
System.Type  
类实现了更简单的攻击方式。通过获取 Type 对象，可以执行任意反射操作并调用任何方法，包括从字节数组加载程序集——这将绕过签名检查，完全控制受保护进程。  
  
微软已  
修复  
此行为，但保留了  
AllowDCOMReflection  
配置项用于重新启用该功能。由于我们不需要提权，且修改 COM 类注册信息需要管理员权限，只需在加载.NET 框架到受保护进程前，向注册表 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft.NETFramework 项写入 DWORD 值 1 的 AllowDCOMReflection 即可启用 DCOM 反射。  
  
实现注入需要以下步骤：  
1. 在注册表中启用 DCOM 反射  
  
1. 添加 TreatAs 键将 StdFont 重定向至 System.Object COM 类  
  
1. 创建 WaaSRemediationAgent 对象  
  
1. 通过类型库获取 StdFont 类类型信息  
  
1. 使用 CreateInstance 方法创建 StdFont 对象（实际加载.NET 框架并返回 System.Object 实例）  
  
1. 通过.NET 反射调用  
System.Reflection.Assembly::Load  
方法加载字节数组  
  
1. 在加载的程序集中创建对象以执行代码  
  
1. 清理所有注册表修改  
  
这些操作需在非.NET 语言中完成，否则序列化机制会在调用进程重建反射对象。我的 PoC 使用 C++ 编写，但 Python 等语言也可实现。虽然不公开具体 PoC，但其代码与我为  
CVE-2014-0257  
编写的漏洞利用非常相似，可作为 C++ 中使用 DCOM 反射的参考。另需注意，.NET COM 对象默认使用 v2 框架运行（现非默认安装），为避免适配 v4 框架的麻烦，我直接通过 Windows 组件安装器安装了 v2 框架。  
  
该 PoC 在 Windows 10 上首次运行即成功，但在 Windows 11 24H2 上却失败。虽然能创建.NET 对象，但调用任何方法都会返回 TYPE_E_CANTLOADLIBRARY 错误。尽管已证明概念可行，但我仍想探究 Windows 11 的问题根源。让我们深入分析以寻求解决方案。  
## Windows 11 的兼容性问题  
  
通过实验证实该问题与受保护进程相关：当服务注册为非保护模式时 PoC 即可正常工作。因此必定存在某种机制在受保护进程中阻止库加载。这种限制似乎不影响常规类型库（如 stdole 的加载正常），问题应特定于.NET。  
  
使用 Process Monitor 观察 PoC 行为发现，服务端加载 mscorlib.tlb 库实现存根类时失败，导致存根创建失败进而引发调用错误。此时我意识到问题本质：在先前关于  
NGEN COM 进程攻击  
的博客中，我讨论过通过修改类型库引入类型混淆来覆盖 KnownDlls 句柄，从而强制加载任意 DLL。根据  
克莱门特·拉布罗（Clément Labro）  
和  
其他研究者  
的工作，大多数 KnownDlls 攻击现已被封堵，但我怀疑还存在针对类型库类型混淆的修复措施。  
  
深入分析 oleaut32.dll 后发现了问题根源——VerifyTrust 方法的修复代码如下：  
```
NTSTATUS VerifyTrust(LoadInfo *load_info) {  PS_PROTECTION protection;  BOOL is_protected;  CheckProtectedProcessForHardening(&is_protected, &protection);if (!is_protected)    return SUCCESS;  ULONG flags;  BYTE level;  HANDLE handle = load_info->Handle;  NTSTATUS status = NtGetCachedSigningLevel(handle, &flags, &level,                                             NULL, NULL, NULL);if (FAILED(status) ||      (flags & 0x182) == 0 ||      FAILED(NtCompareSigningLevels(level, 12))) {    status = NtSetCachedSigningLevel(0x804, 12, &handle, 1, handle);  }return status;}
```  
  
该方法在加载类型库时被调用。它使用缓存签名级别（我在之前的博客文章中提及过）来验证文件是否具有 12 级签名（对应 Windows 签名级别）。如果文件没有适当的缓存签名级别，代码将尝试使用 NtSetCachedSigningLevel 进行设置。若设置失败则假定该文件无法在受保护进程中加载并返回错误，最终导致类型库加载失败。需要说明的是，类似的修复措施也阻止了通过运行对象表（Running Object Table）引用进程外类型库的滥用行为，但这与当前讨论无关。  
  
根据 Get-AuthenticodeSignature 的输出，mscorlib.tlb 文件确实通过目录签名方式进行了签名。其签名证书为 Microsoft Windows Production PCA 2011，与.NET Runtime DLL 使用的证书完全相同，因此理应获得 Windows 签名级别。让我们尝试使用我的  
NtObjectManager  
 PowerShell 模块手动设置缓存签名级别以获取更多信息：  
```
PS> $path = "C:\windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.tlb"PS> Set-NtCachedSigningLevel $path -Flags 0x804 -SigningLevel 12 -Win32PathException calling "SetCachedSigningLevel" with "4" argument(s): "(0xC000007B) - {Bad Image}%hs is either not designed to run on Windows or it contains an error. Try installing the program again using theoriginal installation media or contact your system administrator or the software vendor for support. Error status 0x"PS> Format-HexDump $path -Length 64 -ShowAll          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  - 0123456789ABCDEF-----------------------------------------------------------------------------00000000: 4D 53 46 54 02 00 01 00 00 00 00 00 09 04 00 00  - MSFT............00000010: 00 00 00 00 43 00 00 00 02 00 04 00 00 00 00 00  - ....C...........00000020: 25 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00  - %...............00000030: 2E 0D 00 00 33 FA 00 00 F8 08 01 00 FF FF FF FF  - ....3...........
```  
  
设置签名级别时我们遇到了 STATUS_INVALID_IMAGE_FORMAT（无效镜像格式）错误。查看类型库文件的前 64 字节发现这是原始类型库格式，而非封装在 PE 文件中。这在 Windows 系统中相当罕见——即使文件使用 TLB 扩展名，类型库通常仍会以资源形式嵌入 PE 文件。看来我们运气不佳：除非能为该文件设置缓存签名级别，否则其加载到受保护进程的请求将被拦截，而我们需要它成功加载以支持通过 DCOM 调用.NET 接口的存根类。  
  
值得一提的是，我手头某个 Windows 11 虚拟机中的非 DLL 格式类型库文件却可以成功设置缓存签名级别。我必定在虚拟机配置中进行了某些调整以支持此特性，但具体修改内容已无从追溯，且我决定不再深究此问题。  
  
理论上我们可以尝试寻找既有效签名又封装于 PE 文件的历史版本类型库，但笔者更倾向于另辟蹊径。当然，完全存在其他可替代.NET 加载的 COM 对象可能实现任意代码执行，但笔者已决心坚持当前技术路线。最终解决方案比预期简单：出于某种原因，32 位版本的类型库文件（即位于 Framework 目录而非 Framework64）以 DLL 形式封装，我们可成功为其设置缓存签名级别。  
```
PS> $path = "C:\windows\Microsoft.NET\Framework\v4.0.30319\mscorlib.tlb"PS> Format-HexDump $path -Length 64 -ShowAll          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  - 0123456789ABCDEF-----------------------------------------------------------------------------00000000: 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  - MZ..............00000010: B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  - ........@.......00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  - ................00000030: 00 00 00 00 00 00 00 00 00 00 00 00 B8 00 00 00  - ................PS> Set-NtCachedSigningLevel $path -Flags 0x804 -SigningLevel 12 -Win32PathPS> Get-NtCachedSigningLevel $path -Win32PathFlags               : TrustedSignatureSigningLevel        : WindowsThumbprint          : B9590CE5B1B3F377EAA6F455574C977919BB785F12A444BEB2...ThumbprintBytes     : {185, 89, 12, 229...}ThumbprintAlgorithm : Sha256
```  
  
因此，在 Windows 11 24H2 系统中，我们可以通过将类型库注册路径从 64 位版本切换至 32 位版本并重新运行漏洞利用程序来实现攻击。VerifyTrust 函数会自动为我们设置缓存签名级别，因此无需额外操作即可生效。尽管从技术角度而言这是不同版本的类型库，但这对我们的使用场景毫无影响，存根生成器代码也不会对此产生任何反应。  
## 结论  
  
本文探讨了 Windows 系统中一类有趣的漏洞类型，尽管该漏洞类型同样适用于任何类似的面向对象跨进程远程协议。通过利用 OLE 自动化特性（特别是 IDispatch 接口和类型库），我们展示了如何让 COM 对象陷入更高权限的进程中。  
  
虽然未能成功演示权限提升过程，但本文展示了如何利用 WaaSRemediationAgent 类暴露的 IDispatch 接口向 PPL-Windows 进程注入代码。尽管这不是最高级别的保护机制，但它允许访问包括 LSASS 在内的大多数受保护进程。我们发现微软已采取一些措施来缓解类型库类型混淆等现有攻击，但在本案例中这些缓解措施不应阻止类型库加载，因为我们无需修改类型库本身。虽然本次攻击需要管理员权限，但通用技术本身并不依赖于此。若能找到暴露 IDispatch 的合适 COM 服务器，攻击者可以通过修改本地用户的 COM 和.NET 注册配置，以普通用户权限向 PPL 进程注入代码。  
  
