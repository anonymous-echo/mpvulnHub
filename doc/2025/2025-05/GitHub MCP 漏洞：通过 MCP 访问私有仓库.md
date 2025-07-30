#  GitHub MCP 漏洞：通过 MCP 访问私有仓库   
 Ots安全   2025-05-30 10:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
我们展示了 GitHub 官方 MCP 服务器的一个严重漏洞，该漏洞允许攻击者访问私有存储库数据。该漏洞是 Invariant 用于检测恶意代理流的安全分析器首次发现的漏洞之一。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeNOicZNpDib6Xn64fz5JsAe6O3zr8PNo1sbskVsVRl1ssQePT7FkQJfPh6mnCm0LA4tpVxr2bJ5Vhg/640?wx_fmt=png&from=appmsg "")  
  
Invariant 发现了一个影响广泛使用的GitHub MCP 集成（GitHub 上 1.4 万颗星）的严重漏洞。该漏洞允许攻击者通过恶意 GitHub Issue 劫持用户代理，并迫使其泄露私有代码库中的数据。  
  
这个问题是 Invariant 自动安全扫描程序首次发现的，用于检测所谓的“有毒代理流”。在这种情况下，代理会被操纵执行非预期的操作，例如泄露数据或执行恶意代码。更多信息，请参阅下文。  
  
此时提高对此问题的认识非常重要，因为业界正在竞相广泛部署编码代理和 IDE，这可能会使用户面临针对关键软件开发工具的类似攻击。  
  
攻击设置  
  
在此攻击设置中，用户使用 Claude Desktop 等 MCP 客户端，并将  
Github MCP 服务器 https://github.com/github/github-mcp-server 连接到他们的帐户。  
  
我们假设用户创建了两个存储库：  
- <user>/public-repo：一个可公开访问的存储库，允许 GitHub 上的每个人创建问题和错误报告。  
  
- <user>/private-repo：私人存储库，例如具有专有代码或私人公司数据。  
  
根据标准的 GitHub 规则，攻击者现在可以在公共存储库上创建恶意问题，其中包含等待代理交互的提示注入。  
  
一旦 GitHub 帐户的用户和所有者使用良性请求查询其代理（例如查看中的未解决的问题）<user>/public-repo ，就会触发实际攻击，这将导致代理从公共存储库中获取问题并被注入。  
  
请参阅下文以了解后续流程的说明。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeNOicZNpDib6Xn64fz5JsAe6HsaBLbK28KJOyL1s2vdcu6TvBPiaz147Hb4wvpwN4yjkz6oqScialljg/640?wx_fmt=png&from=appmsg "")  
  
如此处所示，一旦代理遇到恶意的 GitHub 问题，它就会被迫将私有存储库数据拉入上下文，并将其泄露到公共存储库中自主创建的 PR 中，攻击者或任何其他人都可以自由访问。  
  
有毒流我们将这种利用间接提示注入来触发恶意工具使用序列的行为称为“有毒代理流”。我们通过将 Invariant 的安全分析器应用于 GitHub MCP 发现了此漏洞，从而能够自动化在野外发现该流的过程。  
  
攻击演示  
  
为了更具体地说明，我们使用一组演示存储库实际实现了这种攻击：  
- ukend0464/pacman：一个带有 Pacman 游戏简单实现的公共存储库（可在此处获取：https://github.com/ukend0464/pacman）  
  
- 多个私人存储库包含个人项目和有关用户的敏感信息。  
  
“关于作者”注入我们现在在公共存储库中放置一个恶意问题，攻击者可以访问该问题。该问题包含一个有效载荷，代理程序在查询公共存储库的问题列表时将立即执行该载荷。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeNOicZNpDib6Xn64fz5JsAe6dM06ia0XKnTCUC2KiaXNicSrzdicoGR0IgI39SYDMAh2HMlMOwuC08T14w/640?wx_fmt=png&from=appmsg "")  
  
用户交互要触发攻击，用户只需向Claude 4 Opus发出以下请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeNOicZNpDib6Xn64fz5JsAe6ZshCJNVMwASFdtv4Q2Gbe8lz4OB0ic9F79LOxJ04a4SRyPicPmYtXX4A/640?wx_fmt=png&from=appmsg "")  
  
然后，Claude 使用 GitHub MCP 集成来执行这些指令。在此过程中，Claude Desktop 默认要求用户确认每个工具调用。然而，许多用户在使用代理时已经选择了“始终允许”的确认策略，不再监控单个操作。  
  
攻击部署代理程序现在会遍历问题列表，直到找到攻击载荷。它会主动将私有存储库数据拉取到上下文中，并将其泄露到存储库的拉取请求pacman中。由于存储库是公开的，因此攻击者可以自由访问。  
  
该拉取请求包含以下新信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeNOicZNpDib6Xn64fz5JsAe6B339AiaZjzepQQX5Dz0WOJcYOQ7E24ib06AXzx8xTXf3KlSI1FZXibsxg/640?wx_fmt=png&from=appmsg "")  
  
因此，我们成功窃取了有关用户的几条私人信息ukend0464：有关他们的私人存储库的信息，例如Jupiter Star，他们搬迁到南美的计划，甚至他们的薪水。  
  
下面，我们附上了与代理的完整聊天截图，展示了其推理和工具使用顺序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeNOicZNpDib6Xn64fz5JsAe646of2mSVq6YSMVF1cdbO2OSS90dACa7yeGMHobNX5ibUdZX4vqQZsqA/640?wx_fmt=png&from=appmsg "")  
  
https://explorer.invariantlabs.ai/trace/5f3f3f3c-edd3-4ba7-a35f-c1664d993a89  
  
检测有毒剂流动  
  
与之前发现的针对 MCP 的工具投毒攻击不同，此漏洞不需要 MCP 工具本身被攻陷。相反，即使使用完全受信任的工具，也会出现此问题，因为代理在连接到 GitHub 等外部平台时可能会接触到不受信任的信息。  
  
范围和缓解措施  
  
虽然我们的实验主要针对 Claude Desktop，但该漏洞并非针对任何特定代理或 MCP 客户端。它会影响任何使用 GitHub MCP 服务器的代理，无论其底层模型或实现如何。  
  
重要的是，这不是 GitHub MCP 服务器代码本身的缺陷，而是一个必须在代理系统层面解决的根本架构问题。这意味着 GitHub 无法独自通过服务器端补丁解决此漏洞。  
  
结论  
  
在本篇博文中，我们展示了一个影响 GitHub MCP 服务器的严重漏洞，该漏洞允许攻击者通过恶意 GitHub Issue 劫持用户代理，并迫使其泄露私有代码库中的数据。该漏洞是 Invariant 用于检测恶意代理流的安全分析器首次发现的漏洞之一。  
  
虽然我们发现的漏洞特定于 GitHub MCP，但类似的攻击在其他环境中不断出现。例如，Legit Security最近报告了  
GitLab Duo中的一个漏洞https://www.legitsecurity.com/blog/remote-prompt-injection-in-gitlab-duo。  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
