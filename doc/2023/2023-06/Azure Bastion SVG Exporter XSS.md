#  Azure Bastion SVG Exporter XSS   
枇杷五星加强版  黑伞安全   2023-06-15 19:03  
  
下面我们将演示精心设计的 postMessage 如何能够操纵 Azure Bastion Topology View SVG 导出器来执行 XSS。  
#### 什么是 Azure Bastion？  
  
Azure Bastion 是 Microsoft Azure 提供的一项服务，它提供了一种安全无缝的方式来访问 Azure 云环境中的虚拟机 (VM)。  
它充当跳转服务器，提供专用且强化的网关来安全地连接到 VM，而不会将它们暴露在公共互联网上。  
  
Azure Bastion 通过在用户的本地计算机和 Azure VM 之间创建私有远程桌面协议 (RDP) 或安全外壳 (SSH) 会话来工作。  
这消除了对 VM 上的公共 IP 地址或虚拟专用网络 (VPN) 连接的需要。  
相反，用户可以使用 Azure Bastion 提供的安全连接，通过 Azure 门户、Azure PowerShell 或 Azure CLI 直接访问他们的 VM。  
  
当我们第一次开始审查 Azure Bastion 服务时，我们决定重点关注以下可能的攻击向量：  
1. 堡垒主机能力如何被滥用  
  
1. 操纵 iframe 嵌入选项  
  
1. “连接疑难解答”选项  
  
在下一段中，我们将演示如何使用精心设计的 postMessage 来操纵 Topology View SVG 导出器以执行 XSS。  
  
我们首先使用 Azure 门户设置新的 Azure Bastion 服务 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDkbo0mzU60VVg88BThlsLaZQ5ibuodZWhq1yJZ0YPCzwdwxK1fibdLCeg/640?wx_fmt=png "")  
  
设置服务后，我们将选择左侧的“连接”选项，以启动与新创建的堡垒主机的连接 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXD8Zwf6Ku52JEkokn8CWg5TsplicFqrtjrIVY0iakHUPG8eD6Kpibk6odFg/640?wx_fmt=png "")  
  
在这里，我们展示了连接到远程 IP 地址的能力，使用两种主要协议——RDP 和 SSH，为了实现这一点，我们需要提供凭证。  
在这种情况下，凭据并不是很重要，因此我们将设置与随机凭据的连接。  
  
注意：默认情况下，连接将在新选项卡中打开。  
这很重要，因为我们稍后会滥用此功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDN81JFBELkHFiala7GIF8Jic03D1IsdJpp6z6jOSjPMPSYgL4t4IyxjqA/640?wx_fmt=png "")  
  
单击“连接”后，将打开一个新选项卡 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXD0udBItuQevXKOia33q0icRPCLuGRkxibSbugoGUMiclrxwicz1lB4g3yfBg/640?wx_fmt=png "")  
  
正如我们所看到的，一个新选项卡已打开，其中包含我们的堡垒主机地址和一个客户端主机（在本例中为 base64 编码和混淆）。  
我们收到连接错误，但没关系。  
### Iframes 结构  
  
接下来，我们决定再次检查相同的工作流程，这次未选中“在新浏览器选项卡中打开”选项。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDPt6jeWF9GzJ0cicme6FickxV1eiaiaEFQLthqxia1T460Fg2fjc5e6S08ww/640?wx_fmt=png "")  
  
接下来，我们点击连接 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDPsxoNZicEoWoI34InZThGianxhXrFscCjMq7zCudN3RWO7XI8PicvpK0g/640?wx_fmt=png "")  
  
好吧，这有点混乱，但它非常简单——一旦我们决定在不打开新标签页的情况下连接到主机，我们就会看到如下工作的模板：  
```
<https://portal.azure.com> 端点将托管两个主要的 iframe：
A. BastionHostIFrame.html
B. 我们的堡垒主机端点，就像在新选项卡选项中打开连接时一样。
```  
  
我们可以从上面的屏幕截图中看到，两个端点（BastionHostIFrame.html  
和我们的堡垒端点）都设置了不同的沙箱属性。  
  
BastionHostIFrame.html  
框架：  
```
<iframe class=”fxs-part-frame” sandbox=”allow-same-origin allow-scripts allow-popups allow-modals allow-
forms allow-downloads” allow=”microphone *; 加密媒体 *；剪贴板读取；”
role=”presentation” src=”<https://hybridnetworking.hosting.portal.azure.net/hybridnetworking
/>Content/23.4.0.11-230406-2239/BastionHost/BastionHostIFrame.html?clientOptimizations
=undefined&l=en。zh-cn&trustedAuthority=https%3A%2F%2Fportal.azure.com&shellVersion=
undefined#fb4af48503d940fcb1766b787b06ac42″ allowfullscreen=”true”></iframe>
```  
  
我们的终点：  
```
<iframe class=”bastion-host-iframe” id=”bastion-host” role=”document” sandbox=”allow-scripts allow-same-origin allow-popups” frameborder=”0″ src=”https:// [堡垒主机]?trustedAuthority=https%3A%2F%2Fhybridnetworking.hosting.portal.azure.net” aria-label=”Console”></iframe>

```  
  
我们注意到使用带有属性的沙盒 iframeallow-scripts  
可能allow-same-origin  
会带来安全风险。  
这些属性实质上使任何脚本都可以在 iframe 中执行，并且在某些情况下，脚本可能具有修改沙盒属性本身的能力，这可能导致称为 DOM Clobbering vector 的漏洞。  
  
这意味着整个沙箱环境可能会受到损害，从而破坏其预期的安全措施。  
在使用沙盒 iframe 时，了解这些风险并采取适当的预防措施以确保 Web 应用程序的整体安全性非常重要。  
  
我们考虑过尝试使用 DOM Clobbering 来逃离沙箱，但没有成功。  
此外，我们的沙箱未设置允许模态属性，这将不允许我们执行任何提示或警报（暂时 (:)）。  
  
继续，我们决定检查连接字符串   
  
https://portal.azure.com/#view/Microsoft_Azure_HybridNetworking/BastionHostFrame/resourceId/   
%2Fsubscriptions%2F12345678-1234-1234-1234-123456789012%2FresourceGroups%2FOrca-Research%2Fproviders%2FMicrosoft.Network%2Fbh-hostConnect%2F127.0.0.1  
/dnsName/  
[CUSTOM_ENDPOINT_HERE]  
/   
newTab~/false  
/username/test/hostname/127.0.0.1/password/1/privateKey~/null/passphrase~ /null/protocol/rdp/port/3389/vnetId//bastionId/%2Fsubscriptions%2F12345678-1234-1234-1234-123456789012%2FresourceGroups%2FOrca-Research%2Fproviders%2FMicrosoft.Network%2FbastionHosts%2Forca-bastion-poc/keyboardLanguage/en-us-qwerty  
  
红色——我们的自定义端点，可以是任何端点（Burp Collaborator、ngrok 等、IP 等）。   
绿色——可以完全删除，连接仍然会通过。  
橙色 - 新标签选项（假/真）  
  
所以最终我们只剩下：  
  
https://portal.azure.com/#view/Microsoft_Azure_HybridNetworking/BastionHostFrame/resourceId//dnsName/[CUSTOM_ENDPOINT_HERE]/newTab~/false  
  
我们决定使用 Burp Collaborator 对其进行测试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXD4Z3xfhC8eG5OgffxPjlFDTTYsOHjZU0h0qDnwhUhW24ukCpoFlZQnw/640?wx_fmt=png "")  
  
它毫无问题地加载了 Burp Collaborator，正如预期的那样——为其创建了一个指定的 iframe，并将其设置在 BastionHostIFrame.html iframe 下。  
  
这就是它的样子——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDHVIvBk3nSWiaePiaIRAk7GFJyUDUqibeUuN3BhwiadDqR0LrlmBjp0rUAQ/640?wx_fmt=png "")  
  
接下来，我们尝试执行 XSS，以便可以将其用于单击操作并代表受害者执行 XSS。  
  
我们设置了一个 ngrok 服务器，托管了一个简单的 XSS html 文件并触发了——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDVw7PFzEfXYs1h3sh7gq2ncaRAx4fFxJrx8sgwKTnhs7opE7lSmEfzg/640?wx_fmt=png "")  
  
但正如预期的那样——由于缺少 allow-modals 属性，没有执行任何警报。  
### postMessage 向量  
  
在进入并解释我们的具体案例之前，我们将首先更深入地解释什么是 postMessage 及其目的：  
  
postMessage 是一种 Web API，它允许在网页中的不同来源（即不同的域、协议或端口）之间进行通信。  
它允许一个页面上的脚本将消息发送到另一个页面，即使它们来自不同的来源。  
这很重要，因为同源策略 (SOP) 限制来自不同域的网页之间的通信。  
  
postMessage 的工作原理是使用 postMessage 方法将消息发送到目标窗口或 iframe，由其来源（即协议、主机名和端口）标识。  
目标窗口或 iframe 必须使用 addEventListener 方法注册一个事件监听器，它监听消息事件。  
收到消息后，事件侦听器可以通过 event.data 属性访问该消息。  
  
在我们的场景中，在 BastionHostIFrame.html 文件中嵌入自定义端点或堡垒主机端点时，在将端点设置为 iframe 之前验证和批准端点的来源至关重要。  
下面的截图突出了两个重要方面：  
1. global.addEventListener：这表示接收传入消息并使用不同函数处理它们的 postMessage 侦听器/处理程序。  
  
1. isTrustedOrigin：此函数在验证 postMessage 来源方面起着至关重要的作用。  
它根据预定义的可接受来源列表检查来源，确保只允许受信任的来源。  
  
通过实现 isTrustedOrigin 函数，我们可以有效地控制和验证 postMessage 请求的来源，降低 iframe 中未经授权访问或恶意活动的风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDVF5X1IRm3rEibLMvHszHwNflcpFMDxYNON36ic88G8MkzicJojDTCIiczQ/640?wx_fmt=png "")  
  
在上面的截图中我们可以看到一个在 Azure postMessages Handlers 中实践中非常典型的常见问题——  
  
<table><tbody style="text-rendering: optimizelegibility;"><tr style="text-rendering: optimizelegibility;"><td style="text-rendering: optimizelegibility;border-color: initial;padding: 0.5em;"><span style="text-rendering: optimizelegibility;vertical-align: inherit;">const isValidOrigin = isTrustedOrigin(evt.origin)</span></td></tr></tbody></table>  
通常，evt 包含完整的 postMessage 即  
  
<table><tbody style="text-rendering: optimizelegibility;"><tr style="text-rendering: optimizelegibility;"><td style="text-rendering: optimizelegibility;border-color: initial;padding: 0.5em;"><span style="text-rendering: optimizelegibility;vertical-align: inherit;">{ “signature”: “FxFrameBlade”, “kind”: “ChangeContrast”, “data”: { “high”: “flow”, “rotate”: true }}</span></td></tr></tbody></table>  
在门户中使用连接操作时，将发送以下 postMessage –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDfsTxAHfVUKDCNX1hpHgqcOLsiarO7sKqNh36r90CG6dg4vcQE5wzHnQ/640?wx_fmt=png "")  
  
如上所示，在屏幕截图的  
左侧  
，有 3 个主要端点（在这种特定情况下）正在处理 postMessage 通信：  
1. Azure  
门户  
(   
https://portal.azure.com  
 )  
  
1. 托管新 iframe 的 BastionHostIFrame.html 端点 (   
https://hybridnetworking.hosting.portal.azure.net/hybridnetworking/Content/23.4.0.11-230406-2239/BastionHost/BastionHostIFrame.html  
 )  
  
1. 新的端点 Iframe（在这种特定情况下，我们的  
ngrok  
服务器）。  
  
在屏幕截图的  
中间  
，我们可以看到在不同端点之间发送的不同消息。  
在右侧，我们可以看到从 https://portal.azure.com 发送到 BastionHostIFrame.hml 的 postMessage 示例 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDyGZc46n4vQAf3eGZiaDB1ianiaJUbZ8H9u0ibO76ARbXh8hABxgtNRibmJA/640?wx_fmt=png "")  
  
每条消息都有自己的种类，因此它将与每种消息类型的不同处理程序相匹配。  
在上面的例子中，这是 Initialize 告诉 BastionHostIFrame.html 它想要托管我的ngrok  
服务器（uri 变量）。如前所述，上述 postMessage 被成功接受，我们的ngrok  
端点被嵌入。  
但是，请注意，我们嵌入了一个包含 HTML 文件 (iframe.html) 的端点，该文件包含以下内容：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDUJxmR6UufnqxIaccoSxVCUNoyqLkt1V9iaHOmRyDkKBQezRnRG3pMAw/640?wx_fmt=png "")  
  
上面的文件是在我尝试执行警告框失败时设置的文件，并且由于 allow-modals 失败。  
  
以下是到目前为止我们所发现的内容的摘要：  
1. 我们通过操纵冗长的连接 URL 成功地嵌入了各种类型的端点，从而产生了明显更短的 URL。  
  
1. 但是，我们无法对新嵌入的 iframe 执行任何跨站点脚本 (XSS) 攻击，因为缺少沙箱属性。  
  
1. 虽然 DOM Clobbering 可能是一个值得探索的潜在途径，但我们目前选择不优先考虑它。  
  
1. 我们可以操纵用户点击合法的 URL，然后执行恶意的 JavaScript 代码。  
  
### 连接故障排除  
  
经过几个小时的工作并尝试使用嵌入的自定义端点来操纵 BastionHostIFrame.html 端点后，我想出了  
Azure Bastion 中的  
连接故障排除功能 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDaicMX9olMticdZ6zXuIInPSxibdIkAbh5BVqReTvPGNOl7wegUVmhWHkg/640?wx_fmt=png "")  
  
连接故障排除允许我们检查堡垒主机和所需端点之间的连接。  
我将设置一个新的连接测试 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDabFTY9wQYgSS9s6VF2UKrOC1FkPzk7yuR1thJWellLP93EmkcMYUPw/640?wx_fmt=png "")  
  
如上所示，我已将 127.0.0.1 设置为所需的测试端点，并将随机端口设置为 123。  
  
单击“检查”后，测试开始，几秒钟后，测试结果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDCttVPEiaJCHLTtTfgM8ZNicRnwMoxJj9uTjIvCibpXicpXRiblmK7V4YFgg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDGwXwn17ia7REFuIcEoTEewAwwxyBaurnoKxicIjjqXXvvvxnxVPKx4IA/640?wx_fmt=png "")  
  
在上面的截图中，我们得到了两种类型的结果——  
1. 网格视图  
  
1. 拓扑视图  
  
以下每个视图发送不同类型的 postMessages：  
  
发送的第一条消息是  
网格视图准备就绪后发送的  
就绪消息（请参阅上面的网格视图表）。  
  
一旦我们切换到拓扑视图，就会发生一些有趣的事情，这就是我们的漏洞所在。  
  
在下面的屏幕截图中，您可以看到正在发送的两个不同的 postMessages。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDVewYYuIovwysaKuib30F2SUNN3KO9Oqnp7PfvQ2qKFKNwIzkicUk4xBA/640?wx_fmt=png "")  
  
在跳转并查看拓扑视图的第二个 postMessage 之前，我想简要回顾一下处理此消息的 postMessage 监听器 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDdvzddfkXTEm90Cwn4wVa6PQYyjHZdVIaCwmlcMfViaicUxanWoR2piahw/640?wx_fmt=png "")  
  
如前所述，postMessage 正在检查各种类型的数据类型，例如 Origin、Signature、Kind 和 Type。  
  
这些是可信来源：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDkgrXMtZ2ezPwntBuxbxuibGwZN82WSrtq8MYVFHTNYMIEXwke3jxWicg/640?wx_fmt=png "")  
  
在连接测试后查看拓扑视图时，我注意到以下端点嵌入在  
https://portal.azure.com  
页面中：**   
https://network.hosting.portal.azure.net/network /Content/4.30.1.216/Topology/connectivity.html**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXD4pHpZzgMEIuCd9dqPvt9tQkWXATyPAJIrqDkUtjCXQ2oESQibST6WNg/640?wx_fmt=png "")  
  
让我们回顾一下 connectivity.html：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDuXUGQQqyIQWv5pqsygiayZqcpNicQyGWmVylhJevJS7ewC8B2HicGLCnw/640?wx_fmt=png "")  
  
在上面的屏幕截图中，我们可以看到 postMessage 是如何被处理的，与其他 postMessage 处理程序类似，它也会检查有效的 Origin、Type 和 Method。  
  
让我们关注正在发送的 postMessage 以显示拓扑图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDZIMwQGcHBAbPZMuhQSEHUN9DdoSqzrHugvAEBibMgXdBvSTbmZ1JunA/640?wx_fmt=png "")  
  
首先，我们可以立即注意到这条消息的 render 方法，如果我们查看上面之前的屏幕截图，我们可以看到处理程序检查消息本身是否包含 render 方法（第 57 行）。  
如果是这样，它将通过各种检查和条件，直到创建图形（connectivityGraph.run 函数），正如我将很快演示的那样，创建的相同拓扑图将通过 exportSVG() 函数。  
  
在查看 postMessage 内容时，我几乎立即注意到我的拓扑视图中的两个节点实际上是 SVG 图像，可以在上面的屏幕截图（第 11 行和第 26 行）中观察到。  
据我所知，如果处理不当，SVG 也能够执行恶意 Javascript 代码。  
  
我已经修改了 postMessage，所以它会包含一个恶意脚本并再次发送 postMessage –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDrnfrsBoov56X1VRsRQiczBic6cF6ecHQaqAnun9CicsXWTGPW3cEib2nicg/640?wx_fmt=png "")  
  
结果——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDAlkrAF9gTnibOYlOneFFFyUohCjjunH8VgQiblO2wdwBib0xiaiczAibtvnw/640?wx_fmt=png "")  
  
好的，这很有趣。  
似乎 SVG 内容没有被正确清理，这为操纵和潜在的 XSS 攻击留下了空间。  
但是，由于显而易见的原因，  
我们无法控制主要端点，在本例中为“   
https://portal.azure.com ”，这是一个限制。  
因此，我们无法操纵它发送 postMessage，除非我们使用 postMessages 的外部扩展重现该场景。  
此类扩展的一个示例是由 enso security 开发的 Posta Extension，它通过提供一个用户友好的界面来查看和发送 postMessages，做得非常出色。  
### 端点枚举 FTW  
  
在这个阶段，我有一个可靠的向量来尝试和利用，但找不到控制发送 postMessage 的端点的方法，更不用说我必须通过 Origin Policy ，所以从任何远程服务器  
发送  
恶意 postMessage (例如 ngrok）将不起作用。  
  
我决定尝试寻找另一个端点并遇到了 index.html ，那时我仍然不确定它的目的是什么，因为它在生成拓扑视图等过程中没有任何作用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDjA6fMFHXTnETlS2UDiaxrUIBE9hKwQGiatEI2HgF7ggDtuT6h1ppRKZA/640?wx_fmt=png "")  
  
查看端点本身与查看 connectivity.html 非常相似，尽管它有细微的差异，很快就会派上用场。  
  
我们可以看到 index.html 也在验证其  
trustedAuthority  
查询字符串  
  
（例如？trustedAuthority=https://portal.azure.com）——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDr5Umkib4dViad2tyCv4oiaSw9lyVnozu0TWIrFXwdFnqJOiaK7aWoSWbbQ/640?wx_fmt=png "")  
  
按照代码，我们现在看到以下内容 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDfXOrXwpdkF1CD3LyvrleJvjwgnB69t55oOib32rgBEmbztSItWHeQYQ/640?wx_fmt=png "")  
  
我们可以看到 postMessage 处理程序正在检查 3 种不同的情况/种类的 postMessage –  
1. NetworkWatcherTopology_showTopology  
  
1. NetworkWatcherTopology_clearGraph  
  
1. NetworkWatcherTopology_showLoading  
  
与仅检查渲染类型的 connectivity.html 相比  
  
我决定创建以下场景：  
  
1、  
使用  
ngrok  
，并在其上托管一个  
包含以下内容的  
index2.html文件 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDicXcmsu7hxT7YYCXRTkUEv7DXRoWJmLalfjibAHDLQMjapsxA2s9dgxA/640?wx_fmt=png "")  
1. 我们可以看到我已经创建了一个 sendMessageToIframe() 函数，它将首先从 BastionHostIFrame.html iframe 中获取 bastion-host 元素并将其设置在 iframeElement 变量中。  
  
1. 我将创建一个名为message  
的新变量  
，它将保存一个正确的 postMessage json，该 json 与将由 index.html 中的 postMessage 处理程序接收的有效 postMessage 相对应。  
  
1. postMessage 的类型将是 NetworkWatcherTopology_showTopology。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDBGAEIekFR9FWNp90vgEic1TXJx0lOOp8Mib9w8iaOXEdkt9DSAefz5jDA/640?wx_fmt=png "")  
1. 我将使用之前的 iframeElement，并将向其发送 postMessage（注意“*”代表任何来源）。  
  
1. 在上面的第二个红色矩形中，我创建了一个简单的“发送按钮”，因此单击后发送 postMessage 会容易得多。  
  
1. 最后但同样重要的是，我将使用所有相关属性（包括allow-modals  
）  
为 index.html 重新创建相同的 iframe  
  
最终嵌入的  
ngrok  
 +index.html 将如下所示 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDAfF9TfiacWjMRYTVibWLwZ2YmI27mYpcM8aGF8EmdIyVfxjeHubn0jag/640?wx_fmt=png "")  
  
从上面我们可以看到旨在发送 postMessage 的“发送”按钮。  
红色箭头表示我的 postMessage 将到达的第一个函数 (receiveMessage)。  
我会设置一个断点来调试它并逐步查看它。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDMXpM0ia6l23kMtSQ3Q5sY8n169UPVggKkoWfHYMuNDccVibGExYf6Gicg/640?wx_fmt=png "")  
  
单击后，将发送 postMessage 并在函数处停止。  
  
事件——这是完整的 postMessage 内容。  
event.data——只代表数据本身（postMessage Kind 等）  
  
我们可以在屏幕截图（开发控制台）的底部看到这两个值。  
  
接下来，消息将检查  
有效  
来源。  
在我们的例子中，它是有效的，因为它是按如下方式发送的：  
  
https://network.hosting.portal.azure.net/network/Content/4.30.1.216/Topology/index.html?trustedAuthority=https://network.hosting.portal.azure.net  
  
这意味着 https://network.hosting.portal.azure.net 是列表中 [portal.azure.net](<https://network.hosting.portal.azure.net>) 的子域。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDdpdCSjjGLxmMzGYvrBBcFstAS8ChBTZ9Olibxt3onTicicfMhEUxMkibzg/640?wx_fmt=png "")  
  
继续前进，我们也可以看到实物支票 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDEFnoZ3Uv3kVq9spxwJmpvH334OUB8LwAtc7Sds80WkZuoGbcQOuz2A/640?wx_fmt=png "")  
  
检查数据后，data.kind我们的postMessage进入开关集——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDfXOrXwpdkF1CD3LyvrleJvjwgnB69t55oOib32rgBEmbztSItWHeQYQ/640?wx_fmt=png "")  
  
代码开始通过 NetworkWatcherTopology_showTopology，在检查不同的文件依赖关系后，它被“发送”到 topology.run 方法，该方法从 postMessage 获取所有变量和参数，并准备一个空结构以由 SVG 填充——在我们的如果包含空结构的 svgurl 现在被发送到 exportSVG()。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDTwy9gHwWm0m6bc6XDOeyqlk0YkRWyWS5OOpDZjZPJZXibfGg62CW6bw/640?wx_fmt=png "")  
  
exportSVG() 函数使用来自外部模块 ( yfiles  
 )的不同内置组件  
，并开始为每个节点 (Node=host/endpoint) 构建 SVG 图像。  
  
每个节点都被设置为 createNodes 函数，这是获取 SVG 并呈现它的关键模块。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDPH6Z19QQyVw6GhYESia4FYicg6RVp6ic0Vq4MzGHn05mG7w6B9xrc1Kbw/640?wx_fmt=png "")  
  
从那里，它进入下一步设置节点本身的样式，即用 SVG 填充每个图像 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDMqibfALsibEQHWuYj7iaiaViabbPDlMoeiaDSIUfmQH5McAhQmuqMj7lM5MA/640?wx_fmt=png "")  
  
使用断点，我们可以看到我的恶意 SVG（包含 onmouseover=alert(document.domain)）已被接收并到达 createHTMLDocument 接收器。  
最后，一旦单击，我们的 SVG 就会显示在恶意 iframe 上。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDKTo9cRxmd259hiaJdkriblDYAxpNNkiaTvcu0BuBQpaibLlDicuxMsC9N5w/640?wx_fmt=png "")  
  
将图像悬停后，我们可以看到 alert() 正在执行，但在预期的沙箱中！  
  
最后我们要做的就是构建完整的场景：  
1. 远程攻击者将通过滥用 Bastion 主机连接来创建合法但恶意的端点，但这次它将自动打开，因为 newTab 设置为  
true。  
  
https://portal.azure.com/#view/Microsoft_Azure_HybridNetworking/BastionHostFrame/resourceId//dnsName/d52d-XX-XX-XX-XX.ngrok-free.app%2Findex.html/newTab~/true  
1. 将打开一个新选项卡，其中包含作为 iframe 嵌入的易受攻击的端点 (index.html) –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDxbaVu70JYkjuBP4qCaUgI7RM9ichPzgcuYOJJx0F5TCoWJOED6oGDeg/640?wx_fmt=png "")  
1. 出于演示目的，我创建了一个发送按钮，它将向易受攻击的端点发送恶意的 postMessage，因为这也可以在没有任何用户交互的情况下自动执行。  
  
1. 单击“发送”后，我创建了两个新的 iframe 来演示托管 iframe 的网站是什么，以及易受攻击的 iframe 本身。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDugDuicrWDBSSgia02hLaHKPLjVCSFY8qEmHh40SoAUVpJnnoyFSMFDFQ/640?wx_fmt=png "")  
  
5我们可以看到我已经创建了一个演示 SVG，其中包含一个漂亮的 Orca Security 鲸鱼，其中嵌入了 onmouseover 事件。加上两个新的 iframe（空白的 index.html 和ngrok本身）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDlX9GwbunMXozYWMCbnG2lCBc210cvFKCNdbAOLsgibQfNmex7gaOnZg/640?wx_fmt=png "")  
  
悬停后，alert（document.domain）弹出！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXDxj1onUkk8aic9KY4giaOXIPpMExcQ8hvSCGnIB7VXqXH7hT5xfIsSVhA/640?wx_fmt=png "")  
  
我还附上了没有用户交互的完整 POC（没有发送按钮）：  
  
https://www.dropbox.com/s/ehinlsdg48a6q69/azure_bastion_xss.mov?dl=0  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrcUdMELoyew2IBYzA2WaXD2yULVbNmPDCvIicQ84J9OzVVsUY1WgwGK5KCUagoIz5a0Iavbn57PgA/640?wx_fmt=png "")  
  
  
