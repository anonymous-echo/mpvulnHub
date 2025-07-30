#  【OleView.NET】Windows COM 攻击面漏洞扫描工具   
 独眼情报   2024-12-13 03:22  
  
这是关于我最近对 OleView.NET(http://oleview.net/) 工具进行的一些改进的简短博客文章，该工具已作为 1.16 版本发布。该工具旨在发现 Windows COM 的攻击面，并找出诸如权限提升和远程代码执行等安全漏洞。这些更新最近在位于雷德蒙德的微软蓝帽子大会上以"给每个人的 DCOM 研究(https://github.com/tyranid/infosec-presentations/blob/master/Bluehat/2024/DCOM%20Research%20for%20Everyone!.pdf)"为主题进行了演示。这篇博客将对在 45 分钟的时间槽中无法详细阐述的主题进行扩展，提供更多背景和细节。本文假定读者已了解 COM 的基本知识，因此只会描述有限的术语。  
# 使用 OleView.NET 工具  
  
在开始讨论之前，了解如何获取 OleView.NET 工具以及基本用法很重要。获取工具最简单的方法是通过 PowerShell 库使用 Install-Module OleViewDotNet 命令进行安装。这将同时安装 PowerShell 模块和图形用户界面。  
  
接下来，您需要将 COM 注册工件解析到内部数据库中。可以通过运行 Get-ComDatabase 命令来完成。完成后，您就可以开始了。您会注意到这个过程可能需要很长时间，每次想要开始研究时都这样做会很烦人。因此，您可以使用 Set-ComDatabase -Default 命令将数据库写入默认存储位置。这样，下次启动 PowerShell 时，您只需运行检查命令（如 Get-ComClass），默认数据库就会自动加载。  
  
这个默认数据库还与图形界面共享，您可以通过运行 Show-ComDatabase 命令启动。对于一般研究，我发现图形界面更容易使用，您可以四处点击查看 COM 注册信息。对于分析，通过 PowerShell 进行脚本编写更为重要。  
# 研究 COM 服务  
  
在 COM 中执行安全研究通常涉及以下步骤：  
- 枚举潜在的感兴趣的 COM 类。这些可能是在沙盒外可访问、以高权限运行或设计为远程公开的类。  
  
- 验证这些 COM 类是否真正可从攻击位置访问。COM 有各种安全控制，决定了哪些用户可以启动、激活和访问对象。了解这些安全控制可以将感兴趣的 COM 类列表限制为实际攻击面的一部分。  
  
- 枚举公开的接口，确定它们的功能并调用方法以测试安全漏洞。  
  
最后一步是工具更新的重点，使确定公开接口的功能和调用方法以测试行为变得更加容易。目标是最大限度地减少所需的逆向工程工作（尽管通常仍然需要一些），并避免需要在工具之外编写代码来与被测试的 COM 服务交互。  
  
为实现这一目标，OleView.NET 将汇集其拥有的所有接口信息源，然后通过用户界面或 PowerShell 提供检查和调用接口方法的机制。它目前汇集的信息源包括：  
1. 已知接口，无论是定义在基础 .NET 框架类库中还是 OleView.NET 内部。  
  
1. 全局程序集缓存中存在的 COM 接口定义。  
  
1. 已注册的类型库。  
  
1. Windows 运行时接口。  
  
1. 提取的代理类封送处理信息。  
  
收集这些信息的一个有用好处是，该工具将接口格式化为"源代码"，以便您可以手动检查。  
# 接口定义格式化  
  
OleView.NET 工具使用数据库对象来表示系统上已分析的所有工件。最新发布的版本定义了一些对象可以转换为"源代码"。例如，如果工具能够确定一些元数据来表示工件，则可以进行转换：  
- COM 接口  
  
- COM 代理  
  
- COM Windows 运行时类  
  
- 类型库、接口和类  
  
获取这种转换的方式取决于您是使用 PowerShell 还是用户界面。最简单的方法是通过 PowerShell，使用 ConvertTo-ComSourceCode 命令。例如，以下命令将接口对象转换为源代码：  
```
PS\> Get-ComInterface -Name IMyInterface | ConvertTo-ComSourceCode -Parse

```  
  
请注意，我们还需要传递 -Parse 选项。某些元数据（如类型库和代理）解析起来可能很昂贵，因此不会自动进行。但是，一旦在当前会话中解析，元数据就会被缓存以供进一步使用，例如，如果您格式化了类型库中的单个接口，则所有其他接口现在也已解析并可以格式化。  
  
该命令的输出是转换后的"源代码"文本。格式取决于元数据源。例如，以下是 Windows 运行时类型的输出：  
```
[Guid("155eb23b-242a-45e0-a2e9-3171fc6a7fdd")]
interface IUserStatics
{
    /* Methods */
    UserWatcher CreateWatcher();
    IAsyncOperation<IReadOnlyList<User>> FindAllAsync();
    IAsyncOperation<IReadOnlyList<User>> FindAllAsync(UserType type);
    IAsyncOperation<IReadOnlyList<User>> FindAllAsync(UserType type,
        UserAuthenticationStatus status);
    User GetFromId(string nonRoamableId);
}

```  
  
由于 Windows 运行时类型使用类似 .NET 的元数据定义，因此输出是伪 C# 格式。相比之下，对于类型库或代理，它看起来更像以下内容：  
```
[
    odl,
    uuid(00000512-0000-0010-8000-00AA006D2EA4),
    dual,
    oleautomation,
    nonextensible
]
interface _Collection : IDispatch {
    [id(1), propget]
    HRESULT Count([out, retval] int* c);
    
    [id(0xFFFFFFFC), restricted]
    HRESULT _NewEnum([out, retval] IUnknown** ppvObject);
    
    [id(2)]
    HRESULT Refresh();
};

```  
  
这是 Microsoft 接口定义语言（MIDL）格式，类型库版本应该相当准确，甚至可以由 MIDL 编译器重新编译。对于代理，一些信息会丢失，因此生成的 MIDL 不完全准确，但正如我们稍后将看到的，重新编译的理由有限。  
  
需要注意的是，代理在从 MIDL 编译为 C 封送表示时会丢失名称信息。因此，工具只生成占位符名称，例如，方法名称采用 "ProcN" 的形式。如果代理是具有已知定义的类型（例如来自 Windows 运行时类型或类型库），则工具将尝试自动应用名称。如果没有，您需要手动更改它们，如果希望它们不是默认名称。  
  
您可以从 PowerShell 通过直接修改代理对象来更改名称。例如，"IBitsTest1"接口在执行任何操作之前看起来如下：  
```
[
    object,
    uuid(51A183DB-67E0-4472-8602-3DBC730B7EF5),
]
interface IBitsTest1 : IUnknown {
    HRESULT Proc3([out, string] wchar_t** p0);
}

```  
  
您可以使用以下脚本修改 "Proc3"：  
```
PS\> $proxy = Get-ComProxy -Iid 51A183DB-67E0-4472-8602-3DBC730B7EF5
PS\> $proxy.Procedures[0].Name = "GetBitsDllPath"
PS\> $proxy.Procedures[0].Parameters[0].Name = "DllPath"

```  
  
现在格式化的输出如下所示：  
```
[
    object,
    uuid(51A183DB-67E0-4472-8602-3DBC730B7EF5),
]
interface IBitsTest1 : IUnknown {
    HRESULT GetBitsDllPath([out, string] wchar_t** DllPath);
}

```  
  
这种重命名在我们返回调用代理方法时将变得很重要。显然，每次都运行此脚本会很烦人，因此您可以使用以下命令缓存名称：  
```
PS\> Export-ComProxyName -Proxy $p -ToCache

```  
  
这将把描述名称的文件写入本地缓存文件。当在另一个会话中再次加载代理时，此缓存文件将自动应用。Export-ComProxyName 和对应的 Import-ComProxyName 命令允许您读取和写入表示代理名称的 XML 或 JSON 文件，如果使用文本编辑器修改更容易的话。  
# 从代理定义生成接口  
  
现在来到这些更新的更重要方面：能够调用要研究的对象公开的接口方法。该工具一直都能通过反射调用方法，只要对象有一个可以通过 .NET 接口调用的方法。这可以通过已知接口类型（如内置接口或 Windows 运行时接口）或按需将类型库转换为 .NET 程序集来实现。  
  
新增的是基于代理定义生成接口并使用它调用方法的能力。最初，我尝试通过动态生成 .NET 接口来实现这一点，然后使用现有的 .NET 互操作来调用代理方法。这对于简单的代理可以正常工作，但很快就遇到了更复杂的问题：  
- 某些类型很难用易用的 .NET 类型表示，比如指向结构的指针。类型库转换器通过将它们导出为 IntPtr 参数来"处理"这个问题，这意味着调用者必须手动封送数据。处理不当就会导致工具崩溃。  
  
- 任何结构都需要准确地布局，以便本机封送器可以正确读取和写入字段位置。处理不当就会导致工具崩溃。  
  
- 我是不是提到过，处理不当就会导致工具崩溃？  
  
幸运的是，我已经有了一个解决方案。我的沙盒库已经能够从解析的 NDR 数据动态生成 .NET 类，实际上我已经在使用该库解析代理的 NDR 数据，所以我意识到可以重新利用现有的客户端构建器用于 COM 代理客户端。我需要对代码进行一些简单的重构，使其能够从 COM 代理实例而不是 RPC 服务器构建，但很快就有了一个 RPC 客户端。这个 RPC 客户端不直接与任何本机封送代码交互，因此不太可能崩溃。另外，任何复杂的结构都以一种易于从 .NET 修改的方式构建，从而避免了指针相关的问题。使用 RPC 客户端方法的一个问题是，同一个接口可能用于进程内和进程间对象。由于 COM 的设计方式，客户端通常不需要关心对象的位置，但在这种情况下，它必须可通过代理访问。这不是太大的问题，进程内 COM 对象之间没有安全边界，因此能够调用其方法并不特别有趣。  
  
下一个问题是 RPC 传输。COM 调用有额外的输入和输出参数，ORPTHIS 和 ORPCTHAT 结构，需要添加到调用中。这些参数可以添加到 RPC 客户端中，但似乎最好让客户端对传输不可知。相反，由于我的 RPC 代码具有可插拔的 RPC 传输，我能够在现有的 ALPC 和 TCP 传输之上重新实现一个自定义版本，为任何调用添加额外的参数。但这还不是全部，ALPC 需要一对额外的参数 LocalThis 和 LocalThat，这取决于 Windows 的版本可能有所不同。还需要添加对额外服务（如 OXID 解析器和与本地 DCOM 激活器）的支持。虽然我实现了所有这些，但并不像我希望的那样可靠，不过仍然存在于源代码中，如果你想尝试的话。  
  
顺便说一下，Clement Rouault，最初研究 ALPC RPC 协议的人之一（我的实现部分灵感来源于此），最近发布了一个非常类似的项目用于他们的 Python 工具，实现了 ALPC DCOM 协议。  
  
我意识到需要一种不同的方法。在 COM 运行时中，代理实例使用的 RPC 通道由 IRpcChannelBuffer 接口表示。实现此接口的对象在初始化期间连接到代理，然后用于从客户端向服务器发送和接收 NDR 格式的数据。实现处理所有特殊情况，如额外的参数、处理 OXID 解析和引用计数。如果我们能获得代理对象的 IRpcChannelBuffer 实例，就可以使用它而不是实现自己的协议，挑战在于如何获取它。  
  
经过一番研究，我发现可以使用文档化的 NdrProxyInitialize 函数，通过传入代理的接口指针，从其 MIDL_STUB_MESSAGE 结构中获取接口。虽然不如完全自定义的实现灵活，但这为我提供了一种处理传输的简单方法，无需担心平台或协议差异。它还可以处理现有的 COM 对象，只需查询适当的接口，提取缓冲区并对远程服务器进行调用。  
  
当然，事情并不那么简单。我发现虽然 IRpcChannelBuffer 对象是一个 COM 对象，但它对 IMarshal 的实现是有缺陷的。由于 .NET 的 COM 互操作在生成运行时可调用包装器时会尝试查询 IMarshal，它将立即崩溃进程。我不得不手动通过本机委托分派调用，但至少可以正常工作。  
# 调用接口方法  
  
那么，如何使用工具调用任意方法呢？对于图形界面（GUI），操作方式与以往一样。当你创建一个COM对象实例时，通常是通过在视图中右键点击某个条目并选择“创建实例”，然后会出现一个新的对象信息窗口，类似以下截图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2NqnSH9TMYae5NPgSAnIqicw46RnOgdwNibNrp1ptsuBAT0Y2G96fMAjA/640?wx_fmt=png&from=appmsg "")  
  
右键点击视图中的条目并选择创建实例后显示的窗口  
  
窗口底部会列出支持的接口。在右侧列中，有一个指示器显示是否为该接口提供了查看器。如果显示为“是”，你可以双击它，打开一个调用窗口，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2fNBowe8C56AmOmrFWNhNeAEfaHCsMZK5VHPkQVjp6Jfj3RV0ibqJ6uw/640?wx_fmt=png&from=appmsg "")  
  
OleView.NET工具中显示已调用的方法  
  
在这个窗口中，你可以双击某个方法，弹出一个新对话框，在那里你可以指定参数并调用该方法，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2kV4PmfxznaQAqt7DSnrxUsRiao8gzic58qDEbpQnrZFDZsddmkNic1P3g/640?wx_fmt=png&from=appmsg "")  
  
调用 GetBitsDllPath 方法，操作成功的截图  
  
调用完成后，窗口会显示输出参数的结果。如果返回值是整数，则会假定它是一个HRESULT错误码。无论是“反射”接口（如类型库和Windows运行时接口）还是代理客户端，这些窗口的功能都是一致的。如果更改了代理方法的名称，接口窗口中的名称不会自动更新。需要回到对象信息窗口，重新双击接口以重新创建客户端。  
  
对于PowerShell，你可以在使用 New-ComObject 命令时指定 -Iid 参数，或者使用 Get-ComObjectInterface 命令查询现有的COM对象以获取新接口。工具会根据可用选项选择最佳方法来调用接口，包括动态生成RPC客户端。  
```
PS> $obj = New-ComObject -Clsid 4991D34B-80A1-4291-83B6-3328366B9097

PS> $test = Get-ComObjectInterface $o -Iid 51A183DB-67E0-4472-8602-3DBC730B7EF5

PS> $test.GetBitsDllPath()

DllPath                      retval

-------                      ------

c:\windows\system32\qmgr.dll      0

```  
  
为了方便在PowerShell中调用接口方法，工具会对对象暴露的方法进行修改，将输出参数封装到单个返回值中。你可以在上面的例子中看到，DllPath 参数本来是一个仅输出参数。工具会自动创建一个包含 DllPath 和HRESULT返回值的结构体来简化脚本。如果参数是输入输出类型，方法签名会接受输入值，而返回值中包含输出值。  
  
如果你的接口定义尚不存在，可以将它们导入到工具中以供自动接口选择使用。要做到这一点，需要将接口定义为.NET类型并编译成一个程序集。然后，在GUI中使用“文件→导入互操作程序集”菜单选项，或者在PowerShell中使用 Add-ComObjectInterface 命令。无论使用哪种方式，程序集都会在下次启动工具时自动加载。此过程会将DLL文件复制到一个中央位置，即使之后删除了库也能继续访问。  
  
如果你只有一份接口定义语言（IDL）文件，可以借助Windows SDK间接导入到工具中。首先使用MIDL编译器编译IDL文件以生成类型库（type library），然后使用 TLBIMP 命令从类型库生成程序集文件。最后，可以通过前述方法将其导入。  
  
OleView.NET 中还有许多功能没有涉及到。我鼓励你亲自尝试，或者查看 GitHub上的源码 获取更多信息。  
  
  
