#  使 Mojo 漏洞利用变得更加困难   
 Ots安全   2024-03-16 14:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**前言：**  
  
这篇文章介绍了一项针对 Microsoft Edge 浏览器的新安全保护措施，旨在使攻击者利用渲染器进程中的漏洞来逃离沙箱变得更加困难。这项保护措施针对的是 Mojo JavaScript 绑定（MojoJS），它防止了恶意代码利用漏洞启用 MojoJS 以实现对浏览器进程的攻击。  
  
MojoJS 是一种允许在渲染器进程中运行的 JavaScript 代码访问 Chromium Mojo 接口的机制。攻击者可能通过简单地修改渲染器的属性来启用 MojoJS，从而使其能够直接访问浏览器进程的资源。这种攻击向量的简单性以及不需要插入可执行代码的特点使其对于攻击者来说相对容易实施。  
  
为了应对这种威胁，Microsoft Edge 添加了一个新的保护层，用于保护 MojoJS 启用/禁用状态。该保护层包括一个新的布尔属性，指示是否允许为渲染器处理的站点启用 MojoJS。这个属性存储在一个特殊的内存位置中，一旦被攻击者尝试修改，渲染器进程就会立即崩溃，从而有效阻止了攻击者的进一步行动。  
  
这项新的保护措施已经在 Microsoft Edge 的 Canary、Dev 和 Beta 渠道中为 50% 的用户启用，并计划在 Edge 123 中向稳定用户推出。此外，目前该保护仅适用于 Windows 10 和 Windows 11，但未来将考虑添加对其他平台的支持。  
## 正文介绍  
  
今天，我们很高兴地宣布 Microsoft Edge 中提供了一项新的安全保护，可防止攻击者利用渲染器进程中的漏洞来逃离渲染器沙箱。此更改可防止攻击者利用漏洞为其渲染器中的站点上下文启用 Mojo JavaScript 绑定 (MojoJS)。在下一节中，我们将解释 Mojo 和 MojoJS 是什么、攻击者如何滥用它们，以及新行为如何阻止攻击者使用它们。  
## 什么是 Mojo 和 MojoJS？  
  
基于 Chromium 的浏览器使用多进程  
架构。在此架构中，网站内容（包括所有不受信任的 JavaScript 代码）在称为渲染器进程的特殊类型“沙箱”进程中进行解析和执行。  
此类进程无法访问各种重要资源，因此损害它们所造成的直接损害是有限的。因此，攻击者的主要目标是“逃离沙箱”并危害更高权限的进程，从而获得对关键资源（例如核心浏览器进程）的更多访问权限。  
  
对于要进行通信的进程，需要通过 IPC（进程间通信）通道发送消息。Mojo  
是 IPC 功能的 Chromium 实现的名称。它是运行时库的集成集合，提供常见 IPC 原语的平台无关抽象。它还提供了一个绑定库，可以生成多种目标语言的代码。  
  
关于绑定库，这项工作特别感兴趣的是JavaScript 绑定 API  
，在本文的其余部分中我们将其称为 MojoJS。MojoJS 允许在渲染器进程中运行的 JavaScript 代码访问 Chromium 公开的某些 Mojo 接口。  
  
MojoJS 带来了固有的风险，因为它可能允许不受信任的 JavaScript 调用另一个进程（例如更高权限的浏览器进程）中的任意 Mojo 接口方法。虽然 Mojo 界面应防止恶意使用，但可利用的错误确实会发生。从不受信任的 JavaScript 轻松调用 Mojo 接口方法的能力将使攻击者更容易利用任何此类漏洞并获得沙箱逃逸。因此，MojoJS 无法对任意 Web 内容启用。一般来说，只有某些受信任功能的渲染器（相应的 JavaScript 本身是受信任的）才会启用此功能。主要示例是托管WebUI 内容的  
渲染器，其中 JavaScript 由 Microsoft Edge（或其他相关 Chromium 实现）源本身提供，而不是外部世界。模糊测试人员  
还通过特殊的命令行选项使用 MojoJS，尽管此用例与新保护无关或不受新保护影响。  
## 攻击面  
  
尽管 MojoJS 通常被禁用，但如果攻击者发现渲染器漏洞可以为他们提供任意读/写原语，则可以启用它。通过更改“ RenderFrame  
 ”（表示 Web 文档内容的对象）的两个简单属性之一，然后重新加载页面，攻击者可以强制为其站点启用 MojoJS。此时，任何受支持的 Mojo 接口都可以从 JavaScript 中调用，从而允许它们直接访问浏览器进程的安全边界，并使它们更接近完全沙箱逃逸。  
  
除了是一种相对简单的攻击向量（因为它只需要翻转布尔值或附加按位标志）之外，这种方法还具有不需要攻击者插入可执行代码的优点。启用 MojoJS 后，Mojo 代码的执行是直接从不受信任的 JavaScript 完成的，因此不受任意代码防护 (ACG)  
（在 Edge 中作为增强安全模式  
的一部分提供）等缓解措施的保护。因此，这可能是大多数攻击者将渲染器中的可利用漏洞转变为完整沙箱逃逸攻击时采取的第一步。  
## 新的保护层  
  
为了对抗这种攻击媒介，我们添加了一个新层来保护 MojoJS 启用/禁用状态。虽然上述 RenderFrame 的两个简单属性仍用于确定是否应为特定站点启用 MojoJS，但添加了 Renderer Process 的新属性。这个新属性是一个布尔值，指示是否可以为渲染器处理的任何单个站点上下文启用 MojoJS。这个新值存储在一个特殊的内存位置中，当渲染器处理站点内容时，该位置保持为只读。因此，如果攻击者尝试使用任意读写原语来更改该值，进程将立即崩溃。  
  
当代码启用 MojoJS 时，如果状态值表示应该为站点启用它，则代码会在启用绑定之前检查这个新的“受保护”布尔属性。如果该值为 false，则代码会立即使渲染器进程崩溃，因为这表明渲染器已受到损害。攻击者无法启用 MojoJS，并且无法在沙箱逃逸尝试中使用此机制。  
  
典型用户不会注意到任何更改，因为对于 WebUI 主机和使用 MojoJS 的其他受信任场景，新属性设置为 true。  
  
我们在以下更改列表中向 Chromium 项目贡献了这一新的保护：  
  
5161001：恢复基础::ProtectedMemory  
  
5218835：使用 base::ProtectedMemory 强化 MojoJS 支持  
  
因此，所有基于 Chromium 的浏览器都将能够从这一新的保护中受益。  
  
我们要感谢 Google 的 Will Harris 对这项工作的贡献，包括提供背景研究、帮助设计以及提供他早期探索解决此问题的原型代码。我们还要感谢 Chromium 审阅者，他们花时间审阅这些更改列表并提供宝贵的反馈。  
## Microsoft Edge 的当前状态和后续步骤  
  
它已在 Canary、Dev 和 Beta 渠道中为 50% 的用户启用，并将在 Edge 123 中向稳定用户推出。此外，目前此保护仅适用于 Windows 10 和 Windows 11。我们将添加未来对其他平台的支持。  
  
这只是 Edge 保护用户的众多方式之一。在即将发布的博客文章中，我们将分享对各种其他攻击媒介的详细分析以及 Edge 如何防御它们。敬请关注！  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
