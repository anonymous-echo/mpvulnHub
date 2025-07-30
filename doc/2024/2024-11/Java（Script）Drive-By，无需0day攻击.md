#  Java（Script）Drive-By，无需0day攻击   
 Ots安全   2024-11-19 11:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac2IsKtF17FCJiaWmLpfr9yoxtmib9bCyVib65LibSAiaQ9Q6W3okCibFh8AleqozlD7HSskevAtic5ic5teQ/640?wx_fmt=png&from=appmsg "")  
  
Google Chrome 中的远程代码执行链允许攻击者在主机上执行代码，其成本可能高达25 万美元至 50 万美元。如今，这种能力通常只有政府和间谍机构才能拥有。但不久前，普通脚本小子也能获得类似的能力。  
  
**Java 驱动**  
  
2008 年，当我刚刚开始接触编码和安全时，我了解到一种被称为“驱动下载”的技术，特别是“Java 驱动下载”。当时，你可以将 Java 小程序（用 Java 编程语言编写的小应用程序）嵌入到网页中。虽然这些小程序旨在增强 Web 功能，但它们也允许攻击者在用户的机器上运行任意代码。  
  
签名的小程序与未签名的小程序相比，在安全沙箱和权限级别方面存在很大差异。本质上，签名的小程序可以以与桌面应用程序相同的访问级别运行，即使它们在浏览器中运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac2IsKtF17FCJiaWmLpfr9yoqYXwEa4SO1NcVtxwTRGVewLXKtjytHlvneWtPpbHzlVK3qgBhBWGaw/640?wx_fmt=png&from=appmsg "")  
  
然而，由于签名缺乏可信证书颁发机构的认可，因此无法验证签名。这会导致弹出安全警告，用户至少有 50% 的机会做出错误选择。单击“运行”按钮可能会立即危及您的系统。  
  
这不是一个漏洞，而只是一个坏主意。  
  
**JavaScript 驱动**  
  
2022 年，我开始研究文件系统访问 API。此 API 允许网站读取和写入用户选择的文件，但 Chrome 认为某些文件属于系统文件，因此存在一些值得注意的例外。我甚至报告了一个与其处理符号链接的方式有关的漏洞，Google 已修复该漏洞。  
  
但即使在漏洞修复后，有些事情仍然困扰着我。这个 API 太强大了。要了解原因，我们必须首先了解操作系统的安全边界。这个 API 绕过了 Windows 和 macOS 的安全机制，但出于本文的目的，我将重点介绍 macOS。  
  
值得注意的是，此问题不仅影响 Google Chrome，还影响所有基于 Chromium 的浏览器，例如 Microsoft Edge、Brave 和 Opera，因为它们都共享相同的底层架构和 API。  
  
**Gatekeeper**  
  
macOS 上的 Gatekeeper 是一项安全功能，可防止用户运行不受信任的软件。它涉及三个主要步骤：  
1. 文件隔离：于 2007 年推出，在执行从互联网下载的文件之前向用户发出警告。  
  
1. Gatekeeper：基于 OSX Lion (10.7) 中的文件隔离功能，它可以检查下载的应用程序是否来自已识别的开发商，并阻止那些不是的开发商。  
  
1. 公证：在 macOS Catalina (10.15) 中引入，要求应用程序在运行前经过 Apple 扫描和批准。  
  
此外，macOS 还包含一个应用沙盒，用于限制应用对系统资源和用户数据的访问。Chrome 浏览器不使用此沙盒功能，这也是文件系统访问 API 如此危险的另一个原因。  
  
当用户使用文件系统访问 API 与网站交互时，系统会提示他们批准写入权限。此时，用户成为唯一的防线。如果他们错误地授予了错误文件的访问权限，则所有先前的安全边界都将被绕过。虽然文件系统访问 API 正确地添加了 com.apple.quarantine 属性，表明该文件是从互联网上下载的，不应信任，但 macOS Gatekeeper 的一个限制是，当由另一个应用程序（在我们的例子中是 Google Chrome 本身）执行时，它不会重新检查此二进制文件。  
  
这让人回想起旧时的 Java 驱动下载，一次错误的点击就可能导致系统受到损害。  
  
**绕过 Chrome 阻止列表**  
  
Chrome 确实会根据阻止列表限制对文件和目录的写入权限。但是，我发现，如果用户拖放文件，Chrome 似乎不会根据阻止列表对其进行检查。  
  
话虽如此，我不认为修复这个绕过问题会解决文件系统访问 API 的根本问题。有太多文件可以覆盖以获取代码执行，你总会错过任何一个。  
  
与 Java 小程序类似，不存在任何可以指出的漏洞，因此，本文的其余部分将重点介绍如何滥用文件系统访问 API 来攻击他人。  
  
**漏洞利用与符号链接**  
  
成功利用该漏洞的关键在于我们能否说服用户授予我们对特定目标文件的写入权限。可以利用许多文件来实现代码执行，但我最喜欢的是 Google Chrome Helper。  
  
Google Chrome 帮助程序充当 Chrome 与任何已安装插件之间的中介，通过启动外部内容（如视频播放器、扩展程序或嵌入内容）的进程来促进它们的运行。执行某些操作（如window.print()命令）时，可能会创建 Google Chrome 帮助程序进程来管理这些操作所需的必要外部交互和资源。这就是为什么覆盖它可以让我们立即执行代码。  
  
下一步是编造一个令人信服的故事或理由，让用户在授予此访问权限时感到安全。我发现最好的方法是使用符号链接——本质上是重定向到另一个文件或目录的指针。符号链接非常适合此目的，因为大多数人不了解它们是什么，即使是那些了解的人也经常忽略它们。它们是此目的的理想选择，因为它们从用户的角度创造了一种安全的假象。很容易假设没有风险：“我只是授予网站对我从中下载的文件的写访问权限——可能出什么问题？”  
  
**概念验证**  
  
随着 Web 平台提供更多高级应用程序（如 IDE、3D 编辑器等），授予文件的读写权限变得越来越被接受。  
  
为了证明其影响，我开发了两个概念证明，并且随着人工智能的炒作，我选择了第一个概念证明，它是一个自称是浏览器人工智能助手的网站，它可以与我们的目标文件“Google Chrome Helper”配合使用。  
  
  
第二个 PoC 是一个名为“邪恶代码编辑器”的伪造的基于 Web 的 IDE。在此演示中，系统会提示用户下载示例项目并打开它以熟悉编辑器。  
  
  
您可以在以下位置找到两者的代码：  
  
https：//github.com/ron-imperva/javascript-drive-by  
  
如随附视频所示，如果用户按照这些步骤操作，攻击者就可以在他们的机器上执行任意命令。在我们的例子中，我们只是打开计算器，但任何命令都可以在 Chrome 和 macOS 沙盒之外执行。  
  
我们在这里利用的唯一漏洞是绕过 Chrome 阻止列表，该列表通常会阻止对 macOS 上的 /Applications 文件夹的读写访问。但是，可以使用阻止列表中未包含的许多其他文件来实现类似的结果。  
  
**负责任的披露和结论**  
  
我们向 Google 报告了绕过黑名单的情况，Google 确认了此漏洞并表示他们已经意识到了这个问题并正在努力修复。在撰写本文时，此绕过漏洞仍未修复。由于已经过去 10 多个月，我们决定公布漏洞详情和概念验证代码。  
  
我们认为，Google 解决此问题的一种方法是删除文件系统访问 API 修改的文件的执行权限。我们向 Chromium 团队推荐了此解决方案，但在撰写本文时，它仍处于待考虑状态。  
  
Google 告知我们，他们计划将文件系统访问 API 限制在 Chrome 应用程序包中，这应该可以缓解本博文中讨论的特定攻击。这些更改预计将在 Chrome 132 中实现。  
  
总之，网络技术的快速发展不断突破着网络的极限。然而，正如文件系统访问 API 相关的风险所表明的那样，这一进步也带来了一系列挑战，凸显了功能性和安全性之间的微妙平衡。   
  
就像 Java 驱动下载的旧时代一样，即使在今天，几次错误的点击也可能导致严重的安全问题。在允许访问您的文件之前，请保持警惕并三思而后行。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
