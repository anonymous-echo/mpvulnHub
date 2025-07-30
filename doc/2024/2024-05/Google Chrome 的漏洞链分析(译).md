#  Google Chrome 的漏洞链分析(译)   
3072  3072   2024-05-23 23:02  
  
##  0day工程洞察   
### Google Chrome 在 Viz 和 v8-wasm 上的“积极利用”漏洞链 (2024年5月)  
###### 概述  
  
Google 最近为 Chrome 浏览器发布了两个正在被积极利用的漏洞链的紧急安全更新。这些漏洞分别在 5月9日 （沙箱绕过）和 5月13日 （远程代码执行）被修复。这篇简短的技术笔记从尖端漏洞研究的角度审视了这个漏洞链，将根本原因分析置于系统内部和攻击研究趋势的背景中。免责声明：由于基于反向工程安全补丁的理论分析方法，有关漏洞的一些细节可能存在偏差。  
###### 攻击洞察  
  
从一般的攻击和防御角度来看，这个漏洞链相当常见。它基于两个漏洞，第一个是破坏渲染器（v8 中的远程代码执行），第二个是从浏览器沙箱中逃逸。可能还涉及第三个漏洞，用于提升到内核级别的权限，这也是“野外”常见的安排，但尚未公开披露。然而，从漏洞研究的角度来看，这两个漏洞都相当有趣，这也是本技术笔记的主要话题。基于我的评估，有 Chrome 漏洞利用知识和经验的人可以在大约一周内重新创建这个漏洞，因此绝对值得尽快更新基于 Chrome 的基础设施。  
###### 根本原因分析：远程代码执行  
  
浏览器渲染器进程因 v8 中的一个类型混淆漏洞而被破坏，补丁在 这里 （CVE-2024-4761）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGrE6htUkxOSCuuBHibn3MMANQ3SgSTcnPcjZuvCEMNU2GlOMnDUTprszwicmupKmzKAgUg8hUictXMQ/640?wx_fmt=png&from=appmsg "JSReceiver::SetOrCopyDataProperties 中缺少检查 (CVE-2024-4761)")  
  
JSReceiver::SetOrCopyDataProperties 中缺少检查 (CVE-2024-4761)  
  
JSReceiver::SetOrCopyDataProperties 中缺少检查 (CVE-2024-4761)  
  
SetOrCopyDataProperties 是一个核心引擎函数，它“读取源对象的所有可枚举自有属性，并将它们添加到目标对象，根据 use_set 参数使用 Set 或 CreateDataProperty。”（js-objects.h）。这个函数并不直接暴露给 JavaScript，而是在涉及对象属性慢速复制的各种运行时场景中内部使用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGrE6htUkxOSCuuBHibn3MMAYWZezJRX7TUjz6Bsh3IibNa3lSudvibYqqicsXTAhMGKgpP51UoNNXwTA/640?wx_fmt=png&from=appmsg "SetOrCopyDataProperties 到内置函数")  
  
SetOrCopyDataProperties 到内置函数  
  
SetOrCopyDataProperties 到运行时  
  
从 JavaScript 代码在发布配置中触发这个漏洞的最简单方法似乎是通过调用 Object.assign（通过 Builtin::kSetDataProperties）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGrE6htUkxOSCuuBHibn3MMALo8jpRuQpPmUapIoYQiaaX5ibbMjHnzfGK7ARgeicW8582cib7zUPKnyPw/640?wx_fmt=png&from=appmsg "Object.assign 到 JSReceiver::SetOrCopyDataProperties")  
  
Object.assign 到 JSReceiver::SetOrCopyDataProperties  
  
Object.assign 到 JSReceiver::SetOrCopyDataProperties  
  
问题的根本原因在于函数内部执行对象属性规范化的分支（使用 JSObject::NormalizeProperties）。代码错误地假设，在经过一些初步检查后，目标只能是 JSObject 类型，这导致在目标对象映射规范化时发生内存损坏，因为它试图将源对象内容低级复制到不兼容的结构类型。实际上，这个假设可以被破坏，例如，目标是一个 WebAssembly 对象，正如 这个概念验证  （感谢 buptdsb）所示。补丁增加了一个最小的检查，以确保目标是一个 JSObject。  
  
这个漏洞代表了 JavaScript 引擎漏洞中与 WebAssembly 相关的新趋势。Wasm 长期以来一直被用于 JavaScript 引擎漏洞利用，但以前主要是为了利用原语。  
###### 根本原因分析：沙箱逃逸  
  
沙箱逃逸漏洞是一个在 Visuals 中的 Use-after-free，补丁在 这里 （CVE-2024-4671）。  
  
Visuals 是 Chrome 中的一个特权子系统，作为使用 GPU 渲染图形的各种操作的后端。这段文档摘录给出了它的使用方式：  
  
Viz（Visuals）服务是一系列子服务的集合：组合、gl、命中测试和媒体。如果没有更具体的组件（例如 Internals>Compositing、Internals>GPU），则使用 Internals>Viz 组件跟踪 Viz 错误。Viz 有两种类型的客户端：一个特权客户端和一个或多个非特权客户端。特权客户端负责在崩溃后启动和重启 Viz，并负责促进来自非特权客户端（例如浏览器进程或窗口服务器）的连接。所有其他客户端都信任特权客户端，并且预期它长期存在且不易崩溃。非特权客户端可能会恶意或随时崩溃。非特权客户端预期彼此互不信任。因此，不能向非特权客户端提供可以影响另一个客户端操作的接口。例如，只能由特权客户端分配到 GL 服务的通道，但可以由非特权客户端使用。GL 命令通过客户端库向命令缓冲区公开为稳定的公共 API，而底层 IPC 消息及其语义在没有深入的实现细节知识的情况下不断变化且毫无意义。-- viz/README.md  
  
Viz 建立在 Mojo 之上，Mojo 是 Chrome 的现代 IPC/RPC，它使得特权较低的渲染器进程和各种特权后端（如浏览器进程和 GPU 进程）之间能够进行通信。通常在 Mojo 中，客户端（如渲染器进程）可以自由实现他们自己的协议来调用后端服务，而 Mojo 提供了一个通用的低级通信框架。在 viz 中具体的工作方式是，客户端-服务器数据在 blink 中被分割成 'frames'，这些 frames 被打包成 'bundles'，在 flush 事件中通过名为 'sinks' 的端点提交。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGrE6htUkxOSCuuBHibn3MMAvmTzgdsUHj6f9vpNc940J9MEaWCfJjWicB4S9WZk3mucVvSeXcILwxw/640?wx_fmt=png&from=appmsg "frame_sink_bundle.mojom 的片段")  
  
frame_sink_bundle.mojom 的片段  
  
Visuals 客户端提交（Blink 端）  
  
在服务端，也就是漏洞存在的地方，这些 bundles 将被反序列化回单独的 frames，并进一步调度到关联的处理程序在特权 GPU 进程中进行处理。  
  
这里是补丁中最重要的片段，几乎完全解释了漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGrE6htUkxOSCuuBHibn3MMAqDYvczgmddf89obCRqeyNRcW3aA3bicWbiaRyvkZTA8pictHQRp9wtDfg/640?wx_fmt=png&from=appmsg "已修复的 FrameSinkBundleImpl::Submit (CVE-2024-4671)")  
  
已修复的 FrameSinkBundleImpl::Submit (CVE-2024-4671)  
  
已修复的 FrameSinkBundleImpl::Submit (CVE-2024-4671)  
  
在这段代码中，从 blink 端提交的帧 bundles 通过将它们分组到关联的帧 sinks (viz::FrameSinkBundleImpl::SinkGroup *) 进行预处理。一个名为 groups 的局部集合保存当前 bundle 中的 sink groups 指针，而活动的 sink groups 在类作用域的其他地方独立存储和管理。如果一个 sink group 在这段代码中被释放 - 这似乎很可能会因为这里有很多远程获取和潜在的异步调用，那么在 groups 集合中指向它的悬空指针将指向攻击者控制的内存，出现 use-after-free 情况。随着 group->DidFinishFrame(); 和 group->FlushMessages(); 中的虚拟调用，use-after-free 可以被利用来在特权 GPU 进程的上下文中执行攻击者的代码。  
  
存在问题的函数 FrameSinkBundleImpl::Submit 直接可以从渲染器进程访问，正如这个 mojo 接口定义所建议的 - 但不是从网页 JavaScript 在发布配置中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGrE6htUkxOSCuuBHibn3MMASnGibkETf0WZZwZvhK1WLUB55SZaH7rXYxRWdHV2TYhs7xA98Nfpp7g/640?wx_fmt=png&from=appmsg "frame_sink_bundle.mojom 的片段")  
  
frame_sink_bundle.mojom 的片段  
  
frame_sink_bundle.mojom 的片段  
  
补丁的逻辑可能对不熟悉专门的 Chrome  
  
漏洞利用缓解措施的人难以理解，所以让我们再次看看它。虽然受影响代码中的算法大多未变（groups 变量从集合变为了映射？），但安全性是通过加强指针来实现的。特别是，SinkGroup 指针在本地被包装在 raw_ptr<> 类型中，这是一种旨在保护代码免受 Use-after-free 漏洞的智能指针；也被称为 MiraclePtr 漏洞利用缓解措施。此外，应用了 WeakPtr<> 智能指针类型来使释放的指针为空（尽管 Chrome 开发者文档 声称 WeakPtr 不是智能的，我就把它放在这里）。我发现这个漏洞有趣的地方在于 MiraclePtr 缓解措施 自 2022 年以来就应用到了这个子系统，这表明在这里找到另一个可利用的 Use-after-free 并不简单。  
###### 结论  
  
针对 Google Chrome 的完整链漏洞利用多年来一直在遵循大致相同的趋势，尽管有许多加固代码的举措。绕过相关的漏洞利用缓解措施是 0 日漏洞开发工作流程的重要组成部分。虽然可以说 MiraclePtr 缓解措施在这里技术上并没有被“绕过”，因为它从一开始就没有在那里，但相关的 代码加固公告 确实给人留下了这样的印象，即这个攻击面应该由它来覆盖。研究人员也很快通过反向工程补丁。重要的是要意识到，除了 Google 的 Chrome 浏览器外，Chromium 开源项目和 v8 开源 JavaScript 引擎都在大量独立开发的应用程序中广泛使用，例如那些构建在 Electron 框架上的应用程序。在这些情况下，修补 Chromium 嵌入代码由应用程序开发人员自行决定。因此，如果你怀疑你的软件中使用了 Chromium 代码，值得与应用程序开发人员检查他们的补丁程序，特别是如果该软件不是广泛使用或众所周知。  
###### 参考资料  
  
供应商公告 - 桌面版稳定频道更新  (5月13日，CVE-2024-4761，v8) 桌面版稳定频道更新  (5月9日，CVE-2024-4671，viz)  
  
- END -  
  
  
