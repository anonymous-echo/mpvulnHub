#  （滥用） ClickOnce 实现可信任意代码执行   
Nick Powers  securitainment   2025-01-04 23:04  
  
> Less SmartScreen More Caffeine (Ab)Using ClickOnce for Trusted Code Execution  
  
  
随着初始访问的门槛不断提高，我们花时间研究了 ClickOnce 部署的一些可能较少人知的武器化选项。通过实施这些武器化选项，我们希望克服以下一些障碍：  
- 无需管理员权限即可安装/执行应用程序  
  
- 使用声誉良好的已知文件进行执行  
  
- 简化流程，需要最少的用户交互  
  
- 易于重新部署执行实现  
  
最终，我们希望利用第三方应用程序的信任来扩展 ClickOnce 这种相对常见的初始访问技术的价值，以用于攻击场景。  
## ClickOnce 概述和当前的武器化方式  
> "ClickOnce 是一种部署技术，使您能够创建可自我更新的 Windows 应用程序，这些应用程序可以通过最少的用户交互来安装和运行" -  
MSDN  
  
  
ClickOnce 是用于安装和更新 .NET 应用程序的工具。部署可以通过多种选项发布（例如网络文件共享、传统媒体[CD-ROM]和网页）。我们将重点关注通过网页方式发布部署。许多合法应用程序都使用 ClickOnce 部署来安装或更新软件，如 Chrome（以前）、Fidelity 等。  
  
ClickOnce 部署依赖于以特定方式格式化的清单。就像 .NET 应用程序一样，需要考虑不同类型的清单。在讨论 ClickOnce 部署时，需要熟悉三种类型的清单：  
> ClickOnce 部署清单  
  
- 文件扩展名为 *.application  
  
- 引用要部署的 ClickOnce 应用程序清单  
  
- APPREF-MS 文件将指向此清单（如果使用）  
  
> ClickOnce 应用程序清单  
  
- 文件扩展名为 *.exe.manifest  
  
- 指定部署的依赖项（说明将使用的 .NET 版本）  
  
- 对部署清单进行完整性检查  
  
- 引用依赖项和其他待交付文件  
  
> 嵌入式应用程序和程序集清单  
  
- 应用程序清单也称为非托管或融合清单  
  
- 程序集清单也称为托管清单  
  
- 在运行时，ClickOnce 会对这些清单进行比较  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJgVibuzZb6fEMHwBEdE4Qsz1icSPaTpptFC2ud7qb5rU6ANR801nrWVzQ/640?wx_fmt=png&from=appmsg "")  
  
嵌入式程序集清单  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJlw8Fibozv4etcdkhnsQicjD86MiaXAGfVEicJfurz1sTKF6Ticib3RZOo3Lg/640?wx_fmt=png&from=appmsg "")  
  
嵌入式应用程序清单  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJ5uKGpS5y8H5ibvS3XdYRD9O9c36Efs5icMiaPlPlhgc9xbK8zyCGbzictg/640?wx_fmt=png&from=appmsg "")  
  
ClickOnce 部署清单、可执行文件和应用程序清单  
  
通过使用浏览器访问 *.application  
 部署清单，可以将 ClickOnce 应用程序部署到客户端。标准 ClickOnce 部署的下载和执行过程要求最终用户使用 Microsoft Edge 或 Internet Explorer 浏览器。如果目标用户不使用 Edge 或 Internet Explorer 访问部署清单，另一种选择是  
利用 APPREF-MS  
。创建 *.appref-ms  
 文件时需要使用 UTF-16 LE 编码。如果最终用户使用 Chrome 或 Firefox 等浏览器访问应用程序，则会使用 appref-ms  
 文件。  
> **注意：**  
 在到达登陆页面之前，可以进行简单的用户代理检查，以确定传入请求应指向标准部署清单还是 appref-ms 文件。  
  
  
清单中指定的主机程序集将作为 'dfsvc.exe  
' 的子进程生成，后者处理从 'System.Deployment.dll  
' 导入的 ClickOnce 部署功能。ClickOnce 应用程序清单的内容将指定在部署过程中要交付的依赖项和其他资源。部署的内容最终将保存到：  
  
C:\Users\%USERNAME%\AppData\Local\Apps\2.0\<randomstring>  
  
一旦用户同意运行应用程序，部署清单将查看 ClickOnce 应用程序清单以获取需要下载的所有文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJ0azjo8erXOPTXmoqXgicHZpfibibqF8thfickKfj9heWdw9uokydsRYAag/640?wx_fmt=png&from=appmsg "")  
  
ClickOnce 部署清单示例  
  
在整个清单中会有不同的信息片段，看起来与 .NET 应用程序清单非常相似。这将包含部署正确执行所需的所有文件和依赖项。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJHZ5KHt9TtOqI7POlRibPm0iaESkFeSDAyxwNS1IeOKKVpGSZEIDk8tuQ/640?wx_fmt=png&from=appmsg "")  
  
ClickOnce 应用程序清单示例  
  
dfsvc  
 进程将发出一系列 HTTP 请求进行下载，并保存在上述 %LocalAppData%  
 位置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJZeibLRmL3WNOd2BGuQxjS2PcJaicc1GOpSTWqk05UaxyDEXzkPCITzFw/640?wx_fmt=png&from=appmsg "")  
  
下载 ClickOnce 应用程序时的 HTTP 请求  
  
在某些情况下，用户可能想要与 ClickOnce 应用程序交互，但没有使用 Microsoft Edge 或 Internet Explorer。可以创建一个 appref-ms 文件，它的作用类似于 LNK 或快捷方式文件，其中包含部署清单的 URL 和其他一些信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJFxbNYhiaiayh01Ao2aG9pvHmU8cQjxOQe9NfY8at6wvKcTH60F9rLyiaA/640?wx_fmt=png&from=appmsg "")  
  
APPREF-MS 示例  
  
在所有下载发生之前的过程中，System.Deployment DLL 将被用于运行各种检查，并确保 ClickOnce 应用程序可以正确执行。需要注意的一个重要检查是在程序集和部署清单中配置的 .NET 应用程序和 ClickOnce 部署标识。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJMuPVKrWFHJy2gcrnhicjlLZGsbrVWTLTOnEaXBW068VkuCAvicxnYDnA/640?wx_fmt=png&from=appmsg "")  
  
System.Deployment.dll 解析清单的逻辑  
  
通常，在制作初始访问载荷并使用 ClickOnce 时，您会使用像 Visual Studio 这样的 IDE 编写并构建 ClickOnce 应用程序。那么，使用新创建的 .NET 应用程序的标准 ClickOnce 部署执行是什么样的呢？  
  
  
演示 1 — 当前 ClickOnce 武器化示例  
## 当前 ClickOnce 武器化的压力点  
  
正如在第一个演示中看到的，我们遇到了一些问题。例如，触发了 Microsoft SmartScreen。这是因为最终执行我们任意代码的程序集是最近编译的，SmartScreen 以前从未见过。Microsoft SmartScreen 的信誉可以基于多个因素，例如主机程序集的哈希值或用于签名程序集的证书。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJiaE8BEibJqkkQ17AsF8LOAVZImMG5Bz7AFux1wAnJZdjHfaSuxZvXLFw/640?wx_fmt=png&from=appmsg "")  
  
BloodHound Slack 关于 ClickOnce 的讨论  
在 Microsoft SmartScreen 或 EDR 产品已知并信任的应用程序上下文中实现任意代码执行可以降低被阻止的可能性。在考虑如何进行代码执行时，特别是在初始访问尝试期间，应用程序控制或白名单预防解决方案值得注意。扩展验证 (EV) 代码签名证书可用于获得即时 SmartScreen 信誉，但验证过程和价格增加了准入门槛。使用代码签名证书时，还需要考虑额外的归因问题。  
  
通常，要确保 ClickOnce 部署成功，可能会很繁琐，需要"万事俱备"。人们通常认为 ClickOnce 部署繁琐，且有许多配置要求。我们希望接下来的几个部分能概述 ClickOnce 清单中需要关注的重要字段，以帮助复现这些技术。  
## 缓解 ClickOnce 武器化压力点  
  
如果合法的 .NET 应用程序使用 ClickOnce，而我们可以可靠地旁加载或劫持这些 .NET 应用程序，为什么不直接后门现有的部署呢？例如，一个已经有有效 EV 代码签名和 SmartScreen 信誉的现有部署？  
> **注意：**  
 我们将后门 ClickOnce 部署的依赖项，而不是主机程序集本身。我们_保持与该主机程序集相关的有效签名_。  
  
  
识别现有的 ClickOnce 部署可以像利用几个搜索引擎 dorking 技术一样简单（或使用稍后将介绍的 ClickonceHunter 工具）。在这个过程中可以使用多个工具（例如 dnSpy、reshacker、mage、sigcheck 等）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJa5cGqHS0vkKC9Bt1BibmvPtQHNmJECJPe7ibNwpF8z5e7wWkly49enRw/640?wx_fmt=png&from=appmsg "")  
  
从 Google 发现的 ClickOnce 应用程序下载  
  
我们需要为 ClickOnce 部署将执行的目标 .NET 程序集的依赖项识别旁加载机会。我们要寻找的是在应用程序入口点之后劫持执行流程的任何方法。通常，这个过程包括使用 dnSpy 反编译目标 .NET 程序集，以充分理解执行流程来识别旁加载机会。  
  
一旦确定了理想的后门 DLL，使用 dnSpy 将代码添加到目标 DLL 中。此时，需要调整您选择的部署的 ClickOnce 清单以通过其完整性检查。如果您无法在现有代码路径中识别理想的旁加载机会，AppDomainManager 注入或 .NET 反序列化滥用等技术在这里会很有帮助。  
  
下图是旁加载现有签名 ClickOnce 部署的快速示例。首先，我们找到一个在线发布的 ClickOnce 部署，下载它，并验证部署执行的程序集是否满足我们的需求（有效的代码签名、SmartScreen 信誉等）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJyoCfvuU7LRdwuUSJHibiaUXXfBrFFsIQbib8RpUYBMXX22yaaehPsGiaKg/640?wx_fmt=png&from=appmsg "")  
  
已签名 ClickOnce 应用程序示例  
  
接下来，我们查看我们想要旁加载的已签名 .NET 程序集中的引用。程序集使用的一些 DLL 没有强名称，这在某些情况下可能有帮助：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJWG2cDiaaK7ZFLu1IwibTKueticUmew34Pnav9wf3636GOrkzrpJzPItUw/640?wx_fmt=png&from=appmsg "")  
  
目标程序集的依赖项  
  
使用 DnSpy 从目标 .NET 程序集的入口点开始，我们跟踪代码到第一个方法调用"SetDpiAwareness()"。此函数存在于之前识别的 DLL 之一中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJZiby9mexjbhgricpPg2eYdFJLhDXlX20DpVIFZRb8gS7KHVFglvQY4Ng/640?wx_fmt=png&from=appmsg "")  
  
跟踪代码路径  
  
我们观察此方法中的代码，并验证它是否存在于 DLL 依赖项中（而不是主机 .NET 程序集中）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJ5NoHLHCzlDG9ekzXcBWLoSXSa9uuKpu22aAjbQF9XJykbuT2XJPs8g/640?wx_fmt=png&from=appmsg "")  
  
已识别放置额外代码的位置  
  
可以在这里添加我们想要用于旁加载 ClickOnce 部署的额外代码。出于概念验证的目的，我们只会启动记事本并显示一个 MessageBox：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJianls6zd7GvVuedCjdQxkRtw7tuZsYb9ickWVK9XgoUs6wmqPnO9uMYQ/640?wx_fmt=png&from=appmsg "")  
  
向目标依赖项添加代码  
  
此时，dnSpy 可以将您的更改添加到中间语言 (IL) 中，您将拥有目标 ClickOnce 应用程序的后门依赖项。现在是测试并确保运行主机 .NET 程序集时您添加的额外代码正确执行的好时机。  
> **注意：**  
 我们之前认为先决条件是只针对非强名称 DLL。我们发现这不是必需的，因为修改 DLL 不会修改 DLL 的 PublickeyToken 值。PublickeyToken 值是指程序集的嵌入式清单的哈希值，而不是代码本身。如果不修改清单，PublickeyToken 值保持不变，仍然可以成功加载。  
  
  
现在我们有了现有 ClickOnce 部署的一部分的已签名 .NET 应用程序的旁加载，我们最后一步是调整两个 ClickOnce 清单，使部署期间发生的完整性检查不会失败。以下是一些有望加快这个过程的提示：  
- **publicKeyToken**  
 — 这个值是必需的，但可以通过用 16 个零替换值来清空  
  
- **<hash>**  
 — 这个块是可选的，可以删除或重新计算（例如：openssl -dgst -binary -sha1 Program.exe.manifest |openssl enc -base64  
）  
  
- **<publisherIdentity>**  
 — 如果清单已签名则包含，但是可选的，可以删除  
  
关于修改现有 ClickOnce 清单的一个值得注意的提醒是，如果清单是用有效证书签名的，那么进行这些修改将破坏该完整性。对最终用户来说，差异是最小的，许多合法的 ClickOnce 部署根本不签名它们的清单。我们仍然可以控制目标用户观察到的提示，例如"名称"和"来自"。已签名与未签名的对比如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJzQARn6jsCkn7P2KaOusGG1yTYic0PKxJuGtnXz5lv7c7ZqoFQ53gicjw/640?wx_fmt=png&from=appmsg "")  
  
已签名和未签名部署清单的区别  
  
所以提出的问题是：我们真的需要代码签名证书来有效地武器化 ClickOnce 部署吗？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJanXoM9iaqdZhTFRiaKW8PaSQcZ7AaxR6GexkYH7ZCHv8Rg4dYibX90kGg/640?wx_fmt=png&from=appmsg "")  
  
  
  
演示 2 — 后门第三方 ClickOnce 部署  
## 超越现有 ClickOnce 部署  
  
通过 dorking 轻松识别的已发布 ClickOnce 部署数量是有限的。这不是一项新技术，也不是部署和更新 .NET 应用程序最流行的方式。我们预见到这可能是一个潜在问题，并寻求找到一种方法，可以获取_任何_理想的 .NET 程序集，识别旁加载机会，并将其包装为新的 ClickOnce 部署。事实证明，这是可能的，但有一些先决条件。  
1. 嵌入式应用程序清单中的 <assemblyIdentity>  
 字段必须_不存在_，或者整个嵌入式应用程序清单必须不存在（稍后会详细介绍）  
  
1. UAC 设置不能设置为 'requireAdministrator' 或 'highestAvailable'  
  
满足这些先决条件的 .NET 程序集可以相对容易地被武器化为后门 ClickOnce 部署。System.Deployment  
 DLL 有检查程序集标识的代码，该标识在嵌入式应用程序清单中找到。此检查交叉引用应用程序清单的标识以确保标识值相同。下图显示了如果存在嵌入式程序集清单，默认标识将是什么。  
```
<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <!-- UAC Manifest Options
            If you want to change the Windows User Account Control level replace the 
            requestedExecutionLevel node with one of the following.

            <requestedExecutionLevel  level="asInvoker" uiAccess="false" />
            <requestedExecutionLevel  level="requireAdministrator" uiAccess="false" />
            <requestedExecutionLevel  level="highestAvailable" uiAccess="false" />

            Specifying requestedExecutionLevel node will disable file and registry virtualization.
            If you want to utilize File and Registry Virtualization for backward 
            compatibility then delete the requestedExecutionLevel node.
        -->
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>

  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- A list of all Windows versions that this application is designed to work with. 
      Windows will automatically select the most compatible environment.-->

      <!-- If your application is designed to work with Windows 7, uncomment the following supportedOS node-->
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>

      <!-- If your application is designed to work with Windows 8, uncomment the following supportedOS node-->
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>

      <!-- If your application is designed to work with Windows 8.1, uncomment the following supportedOS node-->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>

      <!-- This Id value indicates the application supports Windows Threshold functionality-->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</asmv1:assembly>
```  
  
第二个必需条件是 UAC 设置不能是 requiredAdministrator 或 highestAvailable。System.Deployment DLL 的另一个检查是它会查看 UAC 设置，如果设置了不允许的值就会返回错误。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJR3EeF6pPUMRZDCOPxRX8Krml4bu3fOle3FiajJQPmNlribCc3cDvASIQ/640?wx_fmt=png&from=appmsg "")  
  
System.Deployment DLL 中的 UAC 检查  
  
如果存在 UAC 信息，或者它被设置为 'asInvoker'，程序集将可以作为 ClickOnce 部署工作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMXApKKRf59yv46oPmnDZTJPTgNzyFicTicLwIicH3gR1tlo4Mr5WdMJ5Jt3LpwhUeYh4WlKD3CxgZlA/640?wx_fmt=png&from=appmsg "")  
  
没有 UAC 信息的程序集  
  
由于我们是从头开始创建 ClickOnce 应用程序，而不是像之前那样修改现有的 ClickOnce 清单，我们需要创建新的清单。Microsoft 有一个专门用于此任务的工具，称为清单生成和编辑工具（Mage）。Microsoft 提供了两种不同的工具可供使用：MageUI 和 Mage。Mage 是 Windows SDK 附带的命令行工具，在本博客中我们将重点介绍这个工具。  
  
一旦你完成了识别可以打包为 ClickOnce 部署的 .NET 程序集的过程，你就需要创建程序集、依赖项和额外文件的目录结构。如前所述，需要使用 Mage 创建两个清单 — 部署清单和应用程序清单。可以使用以下命令创建应用程序清单：  
```
"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\mage.exe" -New Application -Processor amd64 -ToFile AppVStreamingUX.exe.manifest -name "TargetApp" -Version 1.0.0.0 -FromDirectory .
```  
  
接下来你需要创建部署清单。可以使用以下命令完成：  
```
"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\mage.exe" -New Deployment -Processor amd64 -Install false -ProviderUrl "http://localhost/dist/TargetApp.application" -AppManifest TargetApp.exe.manifest -ToFile TargetApp.application
```  
  
ProviderUrl  
 参数是部署清单将被托管的位置，因为我们主要介绍的是基于 Web 的应用程序。一旦创建了清单，你会看到使用 Mage  
 创建了一些签名值。就像编辑现有清单时所介绍的那样，这些值并不总是必需的，可以删除。如果对整体部署进行任何更改，签名将失效，必须重新生成，这可能会导致不必要的故障排除。如前所述，这些值包括：  
- **<publicKeyToken>**  
，必需但可以用 16 个零来置空  
  
- **<hash>**  
 代码块可以完全删除，不是必需的  
  
- **Publisher identity**  
 代码块可以完全删除  
  
现在我们已经确定了一个可以作为 ClickOnce 应用程序部署的现有签名 .NET 程序集，我们可以按照与其他技术相同的后门步骤进行操作。我们将遵循代码路径，识别被调用的 DLL，并将我们的代码放在这些 DLL 中。最后，我们可以使用 Mage 创建清单，准备部署。  
  
DEMO3 — 对任意 .NET 程序集进行后门处理并部署为 ClickOnce  
  
**.NET 程序集和 ClickOnce 应用程序的识别**  
  
到目前为止，我们已经介绍了可以被武器化的应用程序类型，现在我们要发现潜在的目标。我们发布了两个工具，可以帮助发现现有的 ClickOnce 应用程序和可以被武器化用于 ClickOnce 的 .NET 程序集。  
  
>   
ClickonceHunter  
- 在线搜索现有的 ClickOnce 发布代码  
  
- Google dorks、Github 等  
  
>   
AssemblyHunter  
- 搜索文件路径或文件，查找给定的条件（签名、身份信息、架构、UAC 等）  
  
- 帮助识别要武器化的目标应用程序  
  
ClickonceHunter 将自动化可以通过 Google 或其他相关搜索手动完成的工作。  
  
虽然 ClickonceHunter 会在互联网上寻找现有应用程序，但 AssemblyHunter 会递归搜索本地文件系统，寻找符合作为 ClickOnce 应用程序部署的常规 .NET 程序集标准的程序集。  
  
使用 AssemblyHunter，我们可以快速识别主机文件系统中的程序集，并查找对我们有用的值。  
  
AssemblyHunter 还会向我们展示那些对我们没有用处的程序集（如果我们想看的话）。  
## 检测和预防机会  
  
对于想要识别恶意 ClickOnce 部署的防御者来说，一个主要优势是 ClickOnce 在许多企业环境中并不常用。防御者可以对其环境进行基线检查，了解它们的普及程度，并做出检测或预防决策。在识别或预防恶意 ClickOnce 使用时，我们建议关注以下几点：  
  
**>**  
 监控 dfsvc.exe  
 进程活动  
- 监控子进程活动（例如带有未签名模块加载的子进程）  
  
- 对必需的 ClickOnce 活动进行基线检查，将具有有效业务用例的应用程序列入白名单  
  
- 监控与 dfshim.dll  
 相关的活动（也可用于启动 ClickOnce 部署）  
  
> 评估与 ClickOnce 部署执行相关的 ETW 遥测数据  
- 注意 ETW 绕过或 <etwEnable>  
 .NET 配置值  
  
> 对默认的 ClickOnce 安装目录进行基线检查  
- %LOCALAPPDATA%\Apps\2.0\<string>  
  
> 对从未见过进行互联网连接的应用程序进行基线检查  
  
>   
禁用来自互联网的所有 ClickOnce 安装，同时仍允许来自其他信任区域的安装  
- 选项包括：Enabled、AuthenticodeRequired 和 Disabled  
  
- 区域包括：MyComputer、LocalIntranet、TrustedSites、Internet、UntrustedSites  
  
- 要禁用来自互联网的安装：\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\Security\TrustManager\PromptingLevel — Internet:Disabled  
  
> 如果部署了应用程序控制解决方案  
- 防止加载不可信的 DLL  
  
如果使用上述注册表键禁用了来自互联网的 ClickOnce 应用程序执行，用户将收到一个提示，该提示不会给他们运行应用程序的选项。  
## 结语  
  
基于所有涵盖的内容，我们认为 ClickOnce 是最佳的初始访问机会之一。仍然有很多领域需要深入研究，并且还有更多的进攻性用例潜力。我们要感谢几个为这项工作铺平道路的人：Lee Christensen (  
@tifkin_  
)，如果没有他，这项技术的探索就不可能实现；Casey Smith (  
@subTee  
) 的先前 .NET 研究，以及 William Burke (  
@0xF4B0  
) 的  
先前 ClickOnce 研究  
。  
  
