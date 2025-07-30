#  带你体验一款主流且开源的Web漏洞扫描工具   
原创 筑梦网安  全栈安全   2024-10-07 16:22  
  
>   
> OWASP ZAP是世界上最受欢迎的Web应用漏洞扫描工具，不仅免费而且还开源。ZAP可以帮助我们在开发和测试应用程序过程中，自动发现 Web应用程序中的安全漏洞。另外，它也是一款提供给具备丰富经验的渗透测试人员进行人工安全测试的优秀工具。接下来从四个方面进行详细介绍。  
  
# 1. ZAP简介  
  
由Checkmarx公司贡献给OWASP的Zed Attack Proxy（ZAP）是一个免费的开源渗透测试工具。ZAP是专门为测试web应用程序而设计的，既灵活又可扩展。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSva6zvSRksJ0KPCfTpS267A7kQicuIiatwsibTn0guEibQTdnMPjdjcgzSrQ/640?wx_fmt=png&from=appmsg "")  
  
中间代理  
  
ZAP的核心是“中间代理操纵器”。它位于测试人员的浏览器和web应用程序之间，与Burp工作原理一样，因此它可以拦截和检查浏览器和web程序之间发送的消息（包含https），根据需要修改内容，然后将这些数据包转发到目的地。它可以用作独立的应用程序，也可以用作守护进程。  
  
从开发人员到安全测试新手，再到安全测试专家，ZAP都能为其提供强大的能力支撑，此外很多附加功能可从ZAP市场中的各种插件免费获得。  
>   
> 因为ZAP是开源的，所以可以查阅源代码以了解其功能是如何实现的，企业可以根据自身情况对其进行二次开发或参照其实现原理来开发自研Web漏洞扫描工具或服务。  
  
# 2. 安装和配置ZAP  
  
ZAP有适用于Windows、Linux和macOS的安装程序。  
## 2.1. 安装  
  
ZAP需要Java 11+才能运行，Docker版本不需要你安装Java，但仅支持命令行方式使用，ZAP的docker镜像提供了一种自动化ZAP的简单方法，特别是在CI/CD环境中。  
  
国内ZAP镜像拉取方式：docker pull ghcr.io/zaproxy/zaproxy:stable  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvEmKAS8PIZuNSQtFVuJNiceFxwDpiamc6D1XnS4yFESxnoNJDQ0rGRkag/640?wx_fmt=png&from=appmsg "")  
  
拉取ZAP镜像  
>   
> 注意：由于国内Docker Hub被封禁，所以我们选用了Github的镜像仓库进行拉取。  
  
  
本文为了方便介绍，采用了安装包方式，安装包下载地址：https://www.zaproxy.org/download/。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvZMNvUUx5QlRCH5BdRlI6XSROeQ4xUb5Pib2GAcMqF1oa7OEmlr9glyA/640?wx_fmt=png&from=appmsg "")  
  
ZAP下载界面  
  
安装包下载完成后，双击启动安装即可。  
## 2.2. 配置  
  
首次启动ZAP时，系统会提示我们是否要继续ZAP会话。默认情况下，ZAP会话始终以默认名称和位置记录到HSQLDB数据库。如果不持久化会话，退出ZAP时这些文件将被删除。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvwYXnPia6rytZahkqT2mcH7vBEE1T2y8MsOwldp5ibspgrJNMspP8MJAw/640?wx_fmt=png&from=appmsg "")  
  
持久化配置  
  
如果选择持久化会话，会话信息将保存在本地数据库中，以便后续可以访问它，推荐大家选择挺久化会话。  
# 3. ZAP功能介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvSGsxLFK0mNEbva4oTialKf5syzPZlAnpYFHDSZrMBZPiafn9U7EObIcw/640?wx_fmt=png&from=appmsg "")  
  
ZAP界面功能  
  
ZAP桌面UI由以下六个模块组成：  
1. 菜单栏：提供对许多自动和手动工具的访问。  
  
1. 工具栏：包括按钮，可轻松访问最常用的功能。  
  
1. 树窗口：显示站点树和脚本树。  
  
1. 工作区窗口：显示请求、响应和脚本，并且支持编辑。  
  
1. 信息窗口：显示自动和手动工具的详细信息。  
  
1. 页脚：显示发现的告警摘要和主要自动化工具的状态。  
  
>   
> ZAP还支持强大的API和命令行功能，具体细节可参考官方文档。  
  
  
建议大家使用ZAP来攻击自己有权使用主动攻击进行测试的应用程序。因为ZAP会模拟真实攻击，可能会对网站的功能、数据等造成实际损害。  
  
当然如果你担心使用ZAP，还可以通过切换到安全模式来防止它造成伤害（尽管ZAP的功能将大大降低）。  
  
要将ZAP切换到安全模式，请单击主工具栏上模式下拉列表上的箭头，展开下拉列表并选择安全模式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvbjiaiaxRzfOD8HvtOVbOKnShicia06TUPd4ia6UcMWVOym4ayZuZJRp8MTA/640?wx_fmt=png&from=appmsg "")  
  
扫描模式切换  
# 4. 使用技巧  
## 4.1. 自动化扫描  
- 启动ZAP，然后单击『工作空间』窗口的『自动扫描』选项卡。  
  
- 单击『自动扫描』按钮。  
  
- 在『要攻击的URL』文本框中，输入要攻击的web应用程序的完整URL。  
  
- 点击『攻击』。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvdticHdjqnAhicMlAcDTpjSZXmqmDMjZunGaypPhU0ejibH24AmHuLnfnQ/640?wx_fmt=png&from=appmsg "")  
  
  
ZAP使用spider抓取web应用程序，并深入探索找到的每个页面。然后ZAP将使用主动扫描程序攻击所有发现的页面、功能和参数。  
  
ZAP提供了2个用于抓取web应用程序的spider，可以在界面上选择使用其中一个或两个。  
- **传统的spider**：通过检查web应用程序响应中的HTML来发现链接。这个spider很快，但在探索使用JavaScript生成链接的AJAX web应用程序时，它并不总是有效的。  
  
- **AJAX spider**：此spider通过调用浏览器来探索web应用程序，然后浏览器会跟踪已生成的链接。AJAX spider比传统spider慢，需要额外的配置才能在“无头”环境中使用。  
  
## 4.2. 解读测试结果  
  
当ZAP抓取web应用程序时，它会构建web应用程序页面和用于呈现这些页面的资源的映射（与AWVS类似）。然后，它会记录发送到每个页面的请求和响应，并在请求或响应可能出现问题时生成告警。  
### 4.2.1. 查看探索页面  
  
要查看浏览页面的树视图，请单击树窗口中的“站点”选项卡可以展开节点以查看访问的各个URL。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvAAhoHHEUD2LX5yQpXyvcsfic5froch4HLaGB6cA80UkXWzGumf1Xib9A/640?wx_fmt=png&from=appmsg "")  
  
image  
### 4.2.2. 查看告警和告警详细信息  
  
页脚的左侧包含测试期间发现的警报计数，按风险类别细分。这些风险类别见下图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvbULoaibxTNBO7ZfY22yia2vdlLicH7iarC3OuVVQbX8rLsoPicmZdXUibqcQ/640?wx_fmt=png&from=appmsg "")  
  
告警分级图标  
  
要查看测试期间创建的告警，请执行以下操作：  
- 单击信息窗口中的『告警』选项卡。  
  
- 单击该窗口中显示的每个告警，在信息窗口的右侧显示URL和检测到的漏洞。  
  
- 在“工作区窗口”中，单击『响应』选项卡以查看响应的标题和正文内容。将突出显示生成告警的响应部分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSv0ZferVFJpvCgEPicESCD09PMLYwMelwgAJxVV4oEkKwjBAMrsrLx3NQ/640?wx_fmt=png&from=appmsg "")  
  
告警详细信息  
## 4.3. 手动探索应用程序  
  
被动扫描和自动攻击功能是开始对web应用程序进行漏洞评估的好方法，但它有一些局限性。具体如下：  
- **身份验证问题**：在被动扫描期间，无法发现受登录页面保护的任何页面，因为除非配置了ZAP的身份验证功能，否则ZAP将无法处理所需的身份验证。  
  
- **过程控制问题**：无法控制被动扫描中的探索顺序或自动攻击中执行的攻击类型。  
  
- **自动探索能力有限**：spider是探索基本网站的好方法，但它们应该与手动探索相结合才能更有效。  
  
例如，Spider只会在web应用程序的表单中输入基本的默认数据，但用户可以输入更多相关信息，这反过来又会将更多的web应用程序暴露给ZAP。对于需要有效电子邮件地址的注册表单等情况尤其如此。spider可能会输入一个随机字符串，但这将导致错误。用户将能够对该错误做出反应并提供格式正确的字符串，这可能会导致在提交和接受表单时暴露更多的应用程序。  
  
**为了解决以上三个问题，有时我们还需要手工探索应用程序**，操作步骤如下：  
- 启动ZAP，然后单击『工作空间』窗口的『手动浏览』选项卡。  
  
- 单击大的『手动浏览』按钮。  
  
- 在『要浏览的URL』文本框中，输入要浏览的web应用程序的完整URL。  
  
- 选择要使用的浏览器并单击『启动浏览器』。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvia1AB8yXQBWrnFDSMLlSDiaqre766RM2HtJiaRfCNf0RdMj49VwUcPjDQ/640?wx_fmt=png&from=appmsg "")  
  
手动浏览  
  
以上操作将启动安装了新配置文件的最常见的浏览器（有点类似于Burp的内置浏览器）。若要使用具有系统中现有的浏览器，就还需要手动配置浏览器以通过ZAP代理，并导入和信任ZAP根CA证书。不同系统中不同浏览器配置代理的详细步骤可参阅：https://www.zaproxy.org/docs/desktop/start/proxies/。  
  
最后，推荐大家在手动探索应用程序时结合ZAP提供的以下三个工具：  
- **Spider 爬虫**：使用 ZAP 的 Spider 工具，可以爬取 Web 应用中的所有链接和页面。在左侧 Sites 面板中，右键点击目标网站 URL，选择 『Attack』 -> 『Spider』。  
  
- **Fuzzer 模糊测试**：使用 ZAP 的 Fuzzer 工具，可以进行模糊测试。在 History 面板中，右键点击一个请求，选择 Fuzz，配置模糊测试参数并运行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvCuVeibboEApzE9k0Jeh48pRfNfgZRqfNXRs2ICAarcEsQhIxRwFP4UQ/640?wx_fmt=png&from=appmsg "")  
  
  
- **Breakpoint 断点调试**：ZAP 提供断点功能，允许用户在请求和响应之间设置断点，进行调试。在 Break 面板中，点击 『Add Break』按钮，配置断点条件。  
  
## 4.4. 平视显示器  
  
平视显示器（HUD，Heads Up Display）是ZAP独有的创新界面，可以直接在浏览器中访问ZAP功能。它非常适合刚接触网络安全的人，也允许经验丰富的渗透测试人员专注于应用程序功能，同时提供关键的安全信息和功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSv08Go5sXLgFCX9LUzwDInjOYX98bpS2m0jhuzQtMID1jLHFZmzDibKYQ/640?wx_fmt=png&from=appmsg "")  
  
ZAP HUD  
  
当通过"手动浏览”屏幕或工具栏选项启用时，HUD会覆盖在浏览器中的目标应用程序之上。仅支持Firefox和Chrome等主流浏览器。  
>   
> 默认情况下，ZAP平视显示器（HUD）将启用。在启动浏览器之前取消选中此屏幕上的相关选项将禁用HUD。  
  
# 5. 扩展：ZAP市场  
  
ZAP可以动态添加新功能。在线市场提供了大量的ZAP插件，为ZAP添加了许多附加功能。市场上的所有附加组件也都是完全免费的。  
  
可以通过工具栏上的“管理附加组件”按钮从ZAP中访问市场。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvlgXZDBcY3W71QvjHdFuaibibNO1b2VKCIbyJicKd14lGRT5rZTq6lRD0w/640?wx_fmt=png&from=appmsg "")  
  
免费插件市场  
# 6. 参考链接  
- https://www.zaproxy.org/  
  
- https://www.zaproxy.org/getting-started/  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp96ESyOVzbdpib1WTt7jNwSvtZIUicejU0JKmqxL2ZmuhVTJs07ouaZVjiaCavDqKdmwToGpicwxBXPxQ/640?wx_fmt=png&from=appmsg "")  
  
