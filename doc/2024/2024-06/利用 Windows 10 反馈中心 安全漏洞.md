#  利用 Windows 10 反馈中心 安全漏洞   
 Ots安全   2024-06-09 12:17  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
反馈中心是 Windows 10 中的一项功能，允许用户向 Microsoft 报告问题或建议。它依赖于以系统权限运行的“diagtrack”服务，或更广为人知的“连接用户体验和遥测”  
  
当反馈中心收集信息以将其发送给 MS 时，它会执行大量文件操作，其中大部分由 SYSTEM 用户执行。事实证明，此应用程序和在收集过程中运行的相关服务/可执行文件存在大量逻辑错误，可以通过 RPC 控制通过“目录连接”或符号链接加以利用。  
  
这些“漏洞”可能允许恶意用户执行以下操作：  
- 任意文件读取（信息泄露）  
  
- 使用攻击者无法控制的内容覆盖任意文件（篡改）  
  
- 任意文件覆盖/写入，内容由攻击者控制（提升权限）  
  
- 任意文件/文件夹删除（提升权限）  
  
在我的调查中，我能够在各种情况下执行所有这些操作。  
  
今天我将向您展示如何执行任意文件覆盖/写入，这很容易导致 EoP。我在 Windows 10 Preview 到 Build v10.0.19592.1001 中发现了这个问题。在 Windows 10“标准”版本中，这个漏洞更容易被利用。  
  
该问题已在CVE-2020-0942 中以“非预期”的方式修复，并随后在最新的 WIP Build（10.0.19608.1006）中得到修复。  
  
先决条件  
- 拥有 Windows 10 计算机（虚拟或物理）的标准 Windows 10 / 域用户  
  
- 诊断和反馈必须设置为“完整”模式  
  
- 如果首次登录时选择了“基本”，则登录用户可以在设置->隐私->诊断和反馈中将“必需”切换为“可选”  
  
描述  
  
当通过反馈中心应用程序发送附件并且您选择“保存本地副本...”时，diagtrack 服务将执行多个文件操作，主要使用 SYSTEM 用户权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1e8dgiclEqaiasKlr0SXDeE70YO4njP5baCuw5xdYI1yWp21KocVTZJLaw/640?wx_fmt=png&from=appmsg "")  
  
以下是最重要的操作的概述。  
  
首先，diagtrack服务通过模拟当前用户在“c:\Users\user\Appdata\local\temp”目录下创建一个名为diagtracktempdir<XX..X>的临时随机文件夹：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eUCtYpp9yrwCQGR0trew0oYP9oVGdAmRia6xAQbNf8ZsXhhvUqgVGOBw/640?wx_fmt=png&from=appmsg "")  
  
在创建目录期间，模拟用户还会设置新的权限。这些权限不会从父文件夹继承，而且非常严格。事实上，正如我们在下面的截图中看到的那样，当前目录中的权限不包括当前用户：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eqnXRX2SGvesGgA5KNvlhRvfnulUTrwcWhJkhGTHUgnWeC3QKGwxuXw/640?wx_fmt=png&from=appmsg "")  
  
而对于里面的子目录和文件，当前用户是有一定的权限的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eHicriaQLuCtCcIHib4BUn5qm7Ey8MCtCL92UwMYibj0tQbDDBqEMsKDjZA/640?wx_fmt=png&from=appmsg "")  
  
在下一个屏幕截图中，我们可以观察到文件和文件夹的创建没有经过用户模拟，因此是作为 SYSTEM 创建的。还应注意，即使作为反馈附件上传的文件（在本例中为windowscoredeviceinfo.dll）现在也被复制到临时文件夹中。此外，在临时路径中创建或复制的所有文件和文件夹都将继承这些新权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eHb5p8b5YWboG5qdC9HNLf0rbe40u7r9eibV0QuYTXJZCw9MuHDnkdmw/640?wx_fmt=png&from=appmsg "")  
  
该过程完成后，diagtracktempdir<XX..X>将被重命名并移至当前用户 FeedbackHub 路径。重命名文件夹的第一个目录上再次设置了后续限制性权限：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eGE4WHCBs9J9pOqoXTntRxvYvxg597qRwKbBdGsiceaJmOASTjpj4nFQ/640?wx_fmt=png&from=appmsg "")  
  
所以问题是：  
  
是否仍然可以滥用特制的“连接点”？  
  
理论上是的：主文件夹diagtracktempdir<XX..X>由当前用户创建。即使权限以更严格的方式依次更改，例如仅授予用户 READ 权限，他仍然可以修改，因为用户是目录的所有者。  
  
实际上，存在一个竞争条件。具体来说，在 SYSTEM 未模拟身份的情况下创建子目录之前，必须更改diagtracktempdir<XX..X>上的权限。这样，新的权限就会传播，攻击者将拥有对所有内容的完全访问权限。  
  
赢得这样的竞争条件很难。两个事件之间的时间以毫秒为单位，你必须注入“恶意”代码来更改权限……  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eNQqcYuIw4xR37S0vqIYDQLKWbg8NK9pxzjdD3e7b6PQtbJ1Tu0xB9g/640?wx_fmt=png&from=appmsg "")  
  
尽管如此，我还是找到了几个解决方案来解决竞争条件，并在 VS2019 C++ 中开发了一个 POC/工具  
  
注意：为了加快测试速度，请始终在反馈中心选择“建议功能”。  
  
仅有 1 个硬盘****  
  
我在物理机和虚拟机上测试了此过程。根据硬件、性能和当前工作负载，我能够在第一次运行时执行漏洞利用。在某些情况下，最多需要 10/15 次尝试。  
  
首先，运行“反馈中心”应用程序并退出。如果之前从未启动过，这将创建初始目录和设置。  
  
这是我的 Poc/工具的“逻辑流程”：  
1. **线程 1：**  
对目录运行文件监视程序：“c:\users\<user>\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\LocalState\DiagOutputDir”，  
  
这将拦截目录的创建并保存目录 {GUID}，以供以后使用  
  
1. **线程 2：**  
对目录“c:\users\<user>\appdata\local\temp”运行文件监视程序，这将拦截文件夹diagtracktempdir<XX..X>  
的创建  
  
创建目录后，立即更改权限，例如：everyone:full。  
  
注意：SetSecurityInfo API 函数不适用，因为它很慢（它在“后台”做了很多无用的工作），NtSetSecurityObject更快，因为更“原子化”  
  
我们知道最终的路径名是这样的：  
  
“diagtracktempdir<XX..X> \get info T0FolderPath\ <{GUID}>”  
- 循环创建从已识别路径到目标目录的“连接点”。循环直到错误为“未找到路径/文件”。  
  
如果一切正常，我们应该已经将文件复制到目标目录中。否则，循环将以拒绝访问错误退出，这意味着我们来不及了。  
  
以下屏幕截图是我如何在c:\windows\system32中写入之前附加的WindowsCoreDeviceInfo.dll的 PoC ：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1elnNyVV9ZPyqicoVIWBs4OhZqc23lOTTjCqspODPWzA65XMgxq7ibgsvg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1ewHjPjfGr57jbYgjN4tm6BCM2c31QLjtPQU5VO7LiaiamlcjbTXsPp4FA/640?wx_fmt=png&from=appmsg "")  
  
以下截图显示漏洞执行的SetSecurity发生在目录创建之前“get info T0FolderPath  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eQLBgupgswu4doQlEp04hKnTgdd8p1R6NOwQddk7a9WJsjFqXia2icOYg/640?wx_fmt=png&from=appmsg "")  
  
并且目录成功挂载：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eqBZpliclqpPlCNaw4WvpvE4raQ82G3Z1NehfHZSzqib72yZbkR8Gbw9g/640?wx_fmt=png&from=appmsg "")  
  
最后，文件复制到目标目录中，距离 EoP仅一步之遥 😉  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eI68ia39QqsqNgoISWzXQePFU8aiaBnbp3ONebibPJdjicBKibX18fb6ltiaw/640?wx_fmt=png&from=appmsg "")  
  
存在两个或更多硬盘/分区（包括安装外部 USB 磁盘的可能性）  
  
我在物理机和虚拟机上测试了此过程。在我的测试环境（具有 2 个分区的物理机和虚拟机）中，我能够在第一次运行时执行漏洞利用。此解决方案更加可靠。  
  
标准用户可以在物理机上安装外部 USB 磁盘****  
  
首先，运行“反馈中心”应用程序并退出。如果之前从未启动过，这将创建初始目录和设置。  
  
在此场景中，我们将创建从目录“c:\user\<user>\documents\feedbackhub”到位于另一个驱动器上的目录的连接点。这将在每次打开文件时强制执行“重新解析”操作，这会导致延迟，尤其是当连接点指向不同的驱动器/分区时。  
  
当连接到位时，用户的“...appdata\local\temp”目录不再使用，并且diagtracktempdir<XX..X>目录直接写入 feedbackhub 下。  
  
唯一的先决条件是feedbackhub文件夹必须为空，这意味着不需要使用以前的带有本地保存附件的 Feedback Hub，因为一旦创建了文件夹和文件，用户就无法删除它们。  
  
要赢得竞争条件，需要以下步骤：  
  
1、创建连接点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1e8NEF14OKL3uKRbmbDpwnyDtvFBjrWbeTovfHcTIpyKFGSr8lXzRaVQ/640?wx_fmt=png&from=appmsg "")  
  
2、在 C++ 漏洞利用中使用连接目录而不是“…appdata\local\temp”：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eTXJVO4ibicP53naxBs86ZWBlFT9ncPJiawDFz73X1kXzluUbbyPiaEAp6Q/640?wx_fmt=png&from=appmsg "")  
  
3、提交新的反馈并加载恶意 DLL 作为附件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1e1muhT8HLxV2J6hVLcoH58DIeiaeuia0hj8gEvTTghnmC1eUtbgqk7eWg/640?wx_fmt=png&from=appmsg "")  
  
瞧！我们的 dll 已被复制到 System32 文件夹中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadyNCqBxo9zZabukhM9FF1eY1HvvsmYvH3Hh3ibiboPBiabZbl0wKk7fAJYX2ghFhojkKM1hC636ZNCQ/640?wx_fmt=png&from=appmsg "")  
  
**结论**  
  
这只是通过滥用 Windows 10 中的通用“错误报告”功能执行特权文件操作的众多可能性之一。  
  
如果你正在寻找 CVE，也许这个值得一试。你所需要的只是Procmon、时间和耐心😉  
POC 可在此处下载：  
h  
ttps://drive.google.com/open?id=1t0w14yO7kJ__nZnATnKj3NnsrAK3ebt_  
```
Exploiting Feedback Hub in Windows 10
https://decoder.cloud/2020/04/28/exploiting-feedback-hub-in-windows-10/
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
  
