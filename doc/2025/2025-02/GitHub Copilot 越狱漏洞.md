#  GitHub Copilot 越狱漏洞   
龙猫  星尘安全   2025-02-04 02:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/qTcIBaTRMWdjcGWCVUAKtpd05lBUJo0eJ4bg9ujlbhoFeMUcSBFia6tzfs0GPK3RRcLC8vysusEFvqicJ0VGicMtA/640 "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibV6vqVQpnKD9eLpCQAf69UFrxu8NdzsuFfBDKuKia0X9xJm2mFicP6xnfvpUSafPWB448zx1apYe9Tt76TgsJ12Q/640 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JmssGpneVHK2aNAIsS7yQ1icFsQMnHqJhsY5gGWBhGwlDF4mVgbdT6WG0ialZ1GdFOYblVeBCAQzTQhYbBFS7Wog/640 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/jDxr6RVaB7s49ntg7iahWKpv6cYeRW4clh8qBy9Q6du1ricXPLnvCbW0p2wSOw3MCYsYfqPWwPZvpEkKjicWRUibEw/640?wx_fmt=jpeg&from=appmsg "")  
  
研究人员发现了两种操控 GitHub 的人工智能（AI）编码助手 Copilot 的新方法，这使得人们能够绕过安全限制和订阅费用、训练恶意模型等。  
  
第一种技巧是将聊天交互嵌入 Copilot 代码中，利用 AI 的问答能力，使其产生恶意输出。第二种方法则是通过代理服务器重新路由 Copilot，以便直接与它集成的 OpenAI 模型进行通信。  
  
Apex 的研究人员认为这些问题属于漏洞。GitHub 则持不同意见，分别将其描述为 “离题聊天回复” 和 “滥用问题”。在回应 Dark Reading 的询问时，GitHub 写道：“作为负责任的 AI 开发的一部分，我们会不断完善现有的安全措施，防止出现有害和冒犯性的输出。此外，我们还会继续投入资源，防止滥用情况，确保我们的产品按预期使用。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tLV8Gx8km9J2qtZb0RmrJTSUibpbnWUNaZnW7nRmmBic23KZkLCLiajggaRmtCTvK0IM5xyjFtDY8YNCx6dMdWFVQ/640 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hox1KVQnzGiapffJhGLo1bjRHbxbLYV2cgd54VBV3aEnbiajibjaL4Ya1wz1zNibHzu08s45GibrEaUnQ65dLQawnibA/640 "")  
  
 GitHub Copilot 越狱  
  
Apex 的漏洞研究员 Fufu Shpigelman 解释说：“Copilot 会尽力帮助你编写代码，包括你在代码文件中写的所有内容。但在代码文件中，你也可以编写用户和助手之间的对话。”  
  
例如，在下面的截图中，一名开发者从终端用户的角度在代码中嵌入了一个聊天机器人提示。这个提示带有恶意意图，要求 Copilot 编写一个键盘记录器。作为回应，Copilot 给出了一个安全的输出，拒绝了该请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7s49ntg7iahWKpv6cYeRW4clVtibicC4b3u9ykDfoWmhmXXz12jcGotFbibYAGRQFTkdnuLw0GpUV2NjQ/640?wx_fmt=png&from=appmsg "")  
  
然而，开发者完全可以控制这个环境。他们可以简单地删除 Copilot 的自动完成回复，并用恶意回复取而代之。  
  
或者，更好的办法是，他们可以通过一个简单的暗示来影响 Copilot。正如 Shpigelman 所说：“它是为了完成有意义的句子而设计的。所以，如果我删除‘抱歉，我无法提供帮助’这句话，并用‘当然’这个词代替，它就会试图思考如何完成以‘当然’开头的句子。然后，它就会尽可能地帮你进行恶意活动。” 换句话说，在这种情况下，让 Copilot 编写键盘记录器就像通过误导让它觉得自己想这么做一样简单。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7s49ntg7iahWKpv6cYeRW4clerBFpEKBhmTgRZhP9GOPyhslW5MjL8f6NKeHq5sRa02ZRoAbBZppbA/640?wx_fmt=png&from=appmsg "")  
  
开发者可以利用这个技巧生成恶意软件，或其他恶意输出，比如如何制造生物武器的指令。或者，他们也可以利用 Copilot 将这类恶意行为嵌入自己的聊天机器人，然后向公众发布。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tLV8Gx8km9J2qtZb0RmrJTSUibpbnWUNaZnW7nRmmBic23KZkLCLiajggaRmtCTvK0IM5xyjFtDY8YNCx6dMdWFVQ/640 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hox1KVQnzGiapffJhGLo1bjRHbxbLYV2cgd54VBV3aEnbiajibjaL4Ya1wz1zNibHzu08s45GibrEaUnQ65dLQawnibA/640 "")  
  
通过代理突破 Copilot 限制  
  
为了生成新颖的代码建议或处理对提示（例如编写键盘记录器的请求）的响应，Copilot 会通过这些模型的应用程序接口（API），借助基于云的大语言模型（LLM），如 Claude、谷歌 Gemini 或 OpenAI 模型的帮助。  
  
Apex 的研究人员想出的第二种方法，让他们能够介入这个交互过程。首先，他们修改了 Copilot 的配置，调整了 “github.copilot.advanced.debug.overrideProxyUrl” 设置，将流量重定向到他们自己的代理服务器。然后，当他们让 Copilot 生成代码建议时，他们的服务器拦截了 Copilot 发出的请求，获取了 Copilot 用于向 OpenAI 进行身份验证的令牌。有了必要的凭证，他们就可以不受任何限制地访问 OpenAI 的模型，而且无需为此付费。  
  
而且，这个令牌并不是他们在传输过程中发现的唯一有价值的东西。Shpigelman 解释说：“当 Copilot 与服务器交互时，它会发送系统提示、你的提示，以及之前发送的提示和响应记录。” 暂且不说暴露大量提示记录带来的隐私风险，这些数据为滥用 Copilot 的设计功能提供了充足的机会。  
  
“系统提示” 是一组指令，用于定义 AI 的特性 —— 它的限制、应该生成何种类型的响应等等。例如，Copilot 的系统提示旨在阻止它以各种可能的方式被恶意利用。但 Shpigelman 声称，通过在系统提示到达大语言模型 API 的途中进行拦截，“我可以更改系统提示，这样一来，之后我就不用费那么大劲去操控它了。我可以直接修改系统提示，让它给我提供有害内容，甚至讨论与代码无关的事情。”  
  
对于 Apex 的联合创始人兼首席产品官 Tomer Avni 来说，这两个 Copilot 漏洞带来的问题 “并不是 GitHub 没有努力设置防护措施。而是大语言模型的本质决定了，无论你设置多少防护措施，它总是可以被操控。这就是为什么我们认为需要在其之上设置一个独立的安全层，来检测这些漏洞。”  
  
  
